"""Analyst accounts and login (Bible Ch13 step 3).

There is no registration endpoint. Accounts are created from the command
line by someone with database access, so the API never lets a stranger give
themselves access to insider-risk data:

    python -m app.services.accounts create --username alice --email alice@example.org
    python -m app.services.accounts deactivate --username alice

The password is read with getpass, or from ``CIRA_ANALYST_PASSWORD`` for a
scripted setup. Every account change and every login attempt writes an
``audit_logs`` row (Architecture §20): ``analyst_created``,
``analyst_deactivated``, ``analyst_login``, ``analyst_login_failed``. The
account row and its audit row are one transaction. None of these actions is
``alert_run_loaded``, so they never count as a stored alert run (N58).

Roles: ``analyst`` and ``admin``. Both read everything the API serves; role
checks beyond that are Chapter 18 (RBAC hardening).
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    AuthNotConfiguredError,
    InvalidTokenError,
    create_access_token,
    decode_access_token,
    dummy_verify,
    hash_password,
    password_problem,
    require_secret,
    verify_password,
)
from app.database.models import AuditLog, User

from .errors import BadRequest, Conflict, NotFound, Unauthorized, Unavailable

ROLES = ("analyst", "admin")
LOGIN_FAILED = "invalid username or password"


def analyst_dict(u: User, expires_at: datetime | None = None) -> dict:
    return {"id": u.id, "username": u.username, "email": u.email, "role": u.role, "department": u.department,
            "is_active": u.is_active, "created_at": u.created_at, "token_expires_at": expires_at}


def _audit(action: str, actor: str, target: str | None, details: dict | None = None) -> AuditLog:
    return AuditLog(action=action, actor=(actor or "?")[:128], target_type="analyst",
                    target_id=None if target is None else str(target)[:128], details=details)


async def login(session: AsyncSession, username: str, password: str, *, secret: str | None, minutes: int) -> dict:
    try:
        require_secret(secret)
    except AuthNotConfiguredError as exc:
        raise Unavailable(f"login is disabled: {exc}", component="auth") from exc
    user = (await session.execute(select(User).where(User.username == username))).scalars().first()
    ok = False
    if user is None:
        dummy_verify(password)                  # same cost as a real check; no username probing by timing
    else:
        ok = verify_password(password, user.hashed_password) and bool(user.is_active)
    if not ok:
        session.add(_audit("analyst_login_failed", username, None if user is None else user.id))
        await session.commit()
        raise Unauthorized(LOGIN_FAILED)
    token, expires = create_access_token(username=user.username, analyst_id=user.id, role=user.role, secret=secret,
                                         minutes=minutes)
    session.add(_audit("analyst_login", user.username, user.id, {"expires_at": expires.isoformat()}))
    await session.commit()
    return {"access_token": token, "token_type": "bearer", "expires_at": expires}


async def analyst_from_token(session: AsyncSession, token: str | None, *, secret: str | None) -> dict:
    try:
        claims = decode_access_token(token or "", secret)
    except AuthNotConfiguredError as exc:
        raise Unavailable(f"authentication is not configured: {exc}", component="auth") from exc
    except InvalidTokenError as exc:
        raise Unauthorized(str(exc)) from exc
    user = await session.get(User, claims["uid"])
    if user is None or not user.is_active or user.username != claims["sub"]:
        raise Unauthorized("the account behind this token no longer exists or is deactivated")
    return analyst_dict(user, datetime.fromtimestamp(claims["exp"], tz=timezone.utc))


async def create(session: AsyncSession, *, username: str, email: str, password: str, role: str = "analyst",
                 department: str | None = None, actor: str = "cli:app.services.accounts") -> dict:
    if role not in ROLES:
        raise BadRequest(f"role must be one of {ROLES}")
    if not username or len(username) > 255 or not email:
        raise BadRequest("username (1-255 characters) and email are required")
    problem = password_problem(password)
    if problem:
        raise BadRequest(problem)
    if (await session.execute(select(User.id).where(User.username == username))).first() is not None:
        raise Conflict(f"analyst {username} already exists")
    user = User(username=username, email=email, role=role, department=department,
                hashed_password=hash_password(password), is_active=True)
    session.add(user)
    await session.flush()
    session.add(_audit("analyst_created", actor, user.id, {"username": username, "role": role}))
    await session.commit()
    return analyst_dict(user)


async def deactivate(session: AsyncSession, *, username: str, actor: str = "cli:app.services.accounts") -> dict:
    user = (await session.execute(select(User).where(User.username == username))).scalars().first()
    if user is None:
        raise NotFound(f"no analyst {username}")
    user.is_active = False
    session.add(_audit("analyst_deactivated", actor, user.id, {"username": username}))
    await session.commit()
    return analyst_dict(user)


# --- command line -------------------------------------------------------------

def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m app.services.accounts", description=__doc__.split("\n\n")[0])
    p.add_argument("--database-url", default=None, help="default: DATABASE_URL from .env")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create")
    c.add_argument("--username", required=True)
    c.add_argument("--email", required=True)
    c.add_argument("--role", default="analyst", choices=ROLES)
    c.add_argument("--department", default=None)
    d = sub.add_parser("deactivate")
    d.add_argument("--username", required=True)
    return p.parse_args(argv)


async def _run(args) -> dict:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.core.config import settings

    engine = create_async_engine(args.database_url or settings.database_url)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as session:
            if args.command == "create":
                password = os.environ.get("CIRA_ANALYST_PASSWORD") or getpass.getpass("password: ")
                return await create(session, username=args.username, email=args.email, password=password,
                                    role=args.role, department=args.department)
            return await deactivate(session, username=args.username)
    finally:
        await engine.dispose()


def main(argv=None) -> int:
    from .errors import ServiceError

    args = _parse_args(argv)
    try:
        out = asyncio.run(_run(args))
    except ServiceError as exc:
        print(f"accounts: {exc.message}", file=sys.stderr)
        return 2
    print(f"{args.command}: analyst {out['username']} (id {out['id']}, role {out['role']}, active {out['is_active']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
