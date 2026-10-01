"""Analyst authentication (Bible Ch13 step 3; Architecture §25).

The basic version the FYP core needs: one analyst role, a password login and
a short-lived bearer token. RBAC, refresh tokens, lockout and an identity
provider are Chapter 18 (production extension).

Passwords
    scrypt from the standard library (``hashlib.scrypt``), with a random
    16-byte salt per password, stored as
    ``scrypt$<n>$<r>$<p>$<salt b64>$<hash b64>``. scrypt is a memory-hard
    password KDF, so no hashing dependency is added (C13-3). Comparison is
    constant-time. A malformed stored hash never verifies.

Tokens
    HS256 JWT (PyJWT) signed with ``SECRET_KEY``. Claims: ``sub`` (username),
    ``uid`` (analyst id), ``role``, ``iss``, ``iat``, ``exp``. ``exp`` and
    ``sub`` are required on decode, and only HS256 is accepted, so an
    unsigned (``alg: none``) or re-signed token is refused.

The secret
    ``auth_problem`` refuses an unset secret, the ``.env.example``
    placeholder and anything shorter than 32 characters. The API then issues
    no token and says why (503), instead of signing with a guessable key.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import jwt

ALGORITHM = "HS256"
ISSUER = "cira-backend"
MIN_SECRET_LENGTH = 32
MIN_PASSWORD_LENGTH = 12
PLACEHOLDER_SECRETS = frozenset({"changeme-generate-a-real-secret", "changeme", "secret"})

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
_SALT_BYTES = 16


class AuthNotConfiguredError(RuntimeError):
    """No usable SECRET_KEY; no token can be issued or checked."""


class InvalidTokenError(ValueError):
    """The bearer token is missing, malformed, expired or not ours."""


def auth_problem(secret: str | None) -> str | None:
    """Why ``secret`` cannot sign tokens, or None when it can."""
    if not secret:
        return "SECRET_KEY is not set"
    if secret.strip() in PLACEHOLDER_SECRETS:
        return "SECRET_KEY is still the .env.example placeholder"
    if len(secret) < MIN_SECRET_LENGTH:
        return f"SECRET_KEY is shorter than {MIN_SECRET_LENGTH} characters"
    return None


def require_secret(secret: str | None) -> str:
    problem = auth_problem(secret)
    if problem:
        raise AuthNotConfiguredError(f"{problem}; generate one with "
                                     "`python -c \"import secrets; print(secrets.token_urlsafe(48))\"`")
    return secret  # type: ignore[return-value]


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen,
                          maxmem=128 * r * (n + p + 2))


def password_problem(password: str) -> str | None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return f"password must be at least {MIN_PASSWORD_LENGTH} characters"
    return None


def hash_password(password: str) -> str:
    problem = password_problem(password)
    if problem:
        raise ValueError(problem)
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str | None) -> bool:
    try:
        scheme, n, r, p, salt, digest = (stored or "").split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest, validate=True)
        got = _scrypt(password, base64.b64decode(salt, validate=True), int(n), int(r), int(p), len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


# A hash of a random password, verified against when the username does not
# exist, so a login for an unknown user costs the same as one for a real user.
_DUMMY_HASH = None


def dummy_verify(password: str) -> None:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(24))
    verify_password(password, _DUMMY_HASH)


def create_access_token(*, username: str, analyst_id: int, role: str, secret: str | None, minutes: int,
                        now: datetime | None = None) -> tuple[str, datetime]:
    key = require_secret(secret)
    if minutes < 1:
        raise ValueError("token lifetime must be at least one minute")
    issued = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    expires = issued + timedelta(minutes=minutes)
    claims = {"sub": username, "uid": int(analyst_id), "role": role, "iss": ISSUER,
              "iat": int(issued.timestamp()), "exp": int(expires.timestamp())}
    return jwt.encode(claims, key, algorithm=ALGORITHM), expires


def decode_access_token(token: str, secret: str | None) -> dict:
    key = require_secret(secret)
    if not token:
        raise InvalidTokenError("no bearer token")
    try:
        claims = jwt.decode(token, key, algorithms=[ALGORITHM], issuer=ISSUER,
                            options={"require": ["exp", "sub", "iat"]})
    except jwt.ExpiredSignatureError as exc:
        raise InvalidTokenError("token expired") from exc
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(f"invalid token: {type(exc).__name__}") from exc
    if not isinstance(claims.get("uid"), int):
        raise InvalidTokenError("invalid token: no analyst id")
    return claims
