"""Chapter 13 rules that hold without data: auth, layering, label isolation, OpenAPI, the N56 policy helpers."""
from __future__ import annotations

import ast
import asyncio
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import numpy as np
import pandas as pd
import pytest
from app.core import security

APP = Path(__file__).resolve().parents[2] / "app"
SECRET = "unit-test-secret-" + "y" * 40


# --- passwords and tokens ---------------------------------------------------------

def test_password_hash_round_trip_and_salting():
    h1, h2 = security.hash_password("a long enough password"), security.hash_password("a long enough password")
    assert h1 != h2 and h1.startswith("scrypt$")                             # salted
    assert security.verify_password("a long enough password", h1)
    assert not security.verify_password("a long enough passworD", h1)
    for broken in (None, "", "scrypt$x", "bcrypt$1$2$3$4$5", h1.replace("scrypt", "md5")):
        assert not security.verify_password("a long enough password", broken)
    with pytest.raises(ValueError, match="at least"):
        security.hash_password("short")


@pytest.mark.parametrize("secret,ok", [(None, False), ("", False), ("changeme-generate-a-real-secret", False),
                                       ("x" * 31, False), ("x" * 32, True)])
def test_secret_must_be_real(secret, ok):
    assert (security.auth_problem(secret) is None) is ok
    if not ok:
        with pytest.raises(security.AuthNotConfiguredError):
            security.create_access_token(username="a", analyst_id=1, role="analyst", secret=secret, minutes=5)


def test_token_round_trip_expiry_and_tampering():
    token, exp = security.create_access_token(username="alice", analyst_id=7, role="analyst", secret=SECRET, minutes=5)
    claims = security.decode_access_token(token, SECRET)
    assert claims["sub"] == "alice" and claims["uid"] == 7 and claims["exp"] == int(exp.timestamp())
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(token, SECRET.replace("y", "z"))           # another key
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(token[:-3] + "abc", SECRET)              # altered signature
    old, _ = security.create_access_token(username="alice", analyst_id=7, role="analyst", secret=SECRET, minutes=1,
                                          now=datetime.now(timezone.utc) - timedelta(hours=1))
    with pytest.raises(security.InvalidTokenError, match="expired"):
        security.decode_access_token(old, SECRET)
    unsigned = jwt.encode({"sub": "alice", "uid": 7, "iss": security.ISSUER, "iat": 1, "exp": 4102444800},
                          key=None, algorithm="none")
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(unsigned, SECRET)                        # alg none refused
    foreign = jwt.encode({"sub": "alice", "uid": 7, "iss": "someone-else", "iat": 1, "exp": 4102444800}, SECRET,
                         algorithm="HS256")
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(foreign, SECRET)                         # wrong issuer


# --- accounts on an in-memory database --------------------------------------------

def test_accounts_create_login_and_deactivate():
    from app.database.base import Base
    from app.database.models import AuditLog
    from app.services import accounts
    from app.services.errors import BadRequest, Conflict, Unauthorized, Unavailable
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    async def go():
        engine = create_async_engine("sqlite+aiosqlite://")
        async with engine.begin() as c:
            await c.run_sync(Base.metadata.create_all)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as s:
            a = await accounts.create(s, username="alice", email="a@example.org", password="p" * 12)
            assert a["is_active"] and a["role"] == "analyst"
            with pytest.raises(Conflict):
                await accounts.create(s, username="alice", email="a@example.org", password="p" * 12)
            with pytest.raises(BadRequest):
                await accounts.create(s, username="bob", email="b@example.org", password="short")
            with pytest.raises(BadRequest):
                await accounts.create(s, username="bob", email="b@example.org", password="p" * 12, role="root")
            with pytest.raises(Unavailable):
                await accounts.login(s, "alice", "p" * 12, secret="changeme", minutes=5)
            with pytest.raises(Unauthorized) as wrong:
                await accounts.login(s, "alice", "q" * 12, secret=SECRET, minutes=5)
            with pytest.raises(Unauthorized) as ghost:
                await accounts.login(s, "ghost", "q" * 12, secret=SECRET, minutes=5)
            assert wrong.value.message == ghost.value.message                  # no username probing
            tok = await accounts.login(s, "alice", "p" * 12, secret=SECRET, minutes=5)
            me = await accounts.analyst_from_token(s, tok["access_token"], secret=SECRET)
            assert me["username"] == "alice" and me["token_expires_at"] == tok["expires_at"]
            await accounts.deactivate(s, username="alice")
            with pytest.raises(Unauthorized):
                await accounts.analyst_from_token(s, tok["access_token"], secret=SECRET)   # token outlives no account
            with pytest.raises(Unauthorized):
                await accounts.login(s, "alice", "p" * 12, secret=SECRET, minutes=5)
            actions = [r.action for r in (await s.execute(select(AuditLog).order_by(AuditLog.id))).scalars()]
        await engine.dispose()
        return actions

    actions = asyncio.run(go())
    assert actions == ["analyst_created", "analyst_login_failed", "analyst_login_failed", "analyst_login",
                       "analyst_deactivated", "analyst_login_failed"]
    assert "alert_run_loaded" not in actions                                   # N58


# --- layering (Bible Ch13 step 2) ----------------------------------------------------

ROUTER_IMPORTS = ("fastapi", "typing", "datetime", "app.api.deps", "app.schemas", "app.services")


def _imports(tree: ast.AST) -> list[str]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            out.append(("." * node.level) + (node.module or ""))
    return out


@pytest.mark.parametrize("path", sorted((APP / "api" / "v1").glob("*.py")), ids=lambda p: p.name)
def test_routers_only_marshal(path):
    tree = ast.parse(path.read_text())
    bad = [m for m in _imports(tree) if not (m.startswith(ROUTER_IMPORTS) or m.startswith("."))]
    assert not bad, f"{path.name} imports {bad}; routers call app.services only"
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = [b for b in node.body if not (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant))]
            assert len(body) == 1 and isinstance(body[0], ast.Return), \
                f"{path.name}:{node.name} must be a single return of a service call"


def _modules(*packages):
    for pkg in packages:
        yield from sorted((APP / pkg).rglob("*.py"))


@pytest.mark.parametrize("path", list(_modules("api", "services", "schemas")), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_api_layer_is_label_free(path):
    text = path.read_text()
    mods = _imports(ast.parse(text))
    forbidden = ("app.evaluation", "app.ingestion.ground_truth", "app.baselines", "app.tabnet.train",
                 "app.scoring.select", "app.scoring.gbdt_candidate")
    assert not [m for m in mods if m.startswith(forbidden)], f"{path.name} reaches label or offline code (N5)"
    assert not re.search(r"labels/|insider_user_days|account_user_days|answers/|ground_truth", text), path.name


@pytest.mark.parametrize("path", list(_modules("services", "schemas")), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_services_and_schemas_do_not_import_fastapi(path):
    assert not [m for m in _imports(ast.parse(path.read_text())) if m.startswith(("fastapi", "starlette"))]


def test_no_service_writes_alert_rows():
    """N58: only app.alerts.load writes the alert tables."""
    for path in _modules("services", "api"):
        text = path.read_text()
        for table in ("Alert(", "AlertMember(", "AlertReason(", "RiskScore(", "AnomalyScore(", "insert(", "delete("):
            assert table not in text, f"{path.name} contains {table}"


# --- OpenAPI ----------------------------------------------------------------------

@pytest.fixture(scope="module")
def openapi():
    from app.main import app

    return app.openapi()


def test_every_list_is_paginated_with_a_hard_cap(openapi):
    from app.services.common import MAX_LIMIT

    lists = 0
    for path, ops in openapi["paths"].items():
        for method, op in ops.items():
            params = {p["name"]: p for p in op.get("parameters", [])}
            ref = (((op.get("responses", {}).get("200", {}).get("content") or {}).get("application/json") or {})
                   .get("schema") or {}).get("$ref", "")
            schema = openapi["components"]["schemas"].get(ref.rsplit("/", 1)[-1], {}) if ref else {}
            if "items" in schema.get("properties", {}):
                lists += 1
                assert "page" in schema["properties"], f"{path} returns a list without page info"
                assert params["limit"]["schema"]["maximum"] == MAX_LIMIT, path
    assert lists >= 3                                                       # alerts, events, investigations


def test_no_score_is_called_a_probability(openapi):
    text = str(openapi)
    for m in re.finditer(r"probabilit", text):
        assert re.search(r"not (a )?$", text[max(0, m.start() - 8):m.start()]), text[m.start() - 60:m.end() + 20]


def test_every_api_group_of_the_architecture_is_present(openapi):
    groups = {p.split("/")[3] for p in openapi["paths"] if p.startswith("/api/v1/")}
    assert groups == {"auth", "users", "events", "features", "anomaly", "risk", "alerts", "investigations", "mitre",
                      "explanations", "models", "health"}


def test_only_auth_and_health_are_public(openapi):
    from app.api.v1 import PROTECTED, auth, health

    assert auth not in PROTECTED and health not in PROTECTED and len(PROTECTED) == 10


# --- N56: one rule for the batch and the API -----------------------------------------

def test_policy_helpers_are_what_triggers_uses():
    from app.alerts.policy import AlertPolicy, band_trigger, top_k_eligible, triggers

    rng = np.random.default_rng(0)
    n = 60
    risk = pd.DataFrame({"user_id": [f"u{i % 7}" for i in range(n)], "date": [f"2010-01-{1 + i // 7:02d}" for i in range(n)],
                         "severity": rng.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], n),
                         "anomaly_score": rng.random(n), "cri_score": rng.random(n) * 100})
    activity = rng.integers(0, 3, n).astype(float)
    policy = AlertPolicy()
    t = triggers(risk, policy, activity)
    assert (t["by_band"].to_numpy() == band_trigger(risk["severity"], policy)).all()
    eligible = top_k_eligible(activity, policy, n)
    assert not t.loc[~eligible, "by_top_k"].any()
    assert top_k_eligible(None, AlertPolicy(require_activity=False), 3).all()
    with pytest.raises(Exception, match="requires activity"):
        top_k_eligible(None, policy, 3)
