"""Chapter 13 end to end: the synthetic chain of Chapters 5-12, loaded into a database, served by the API.

    Chapters 5-11 world -> alert batch -> bounded load -> analyst account
    -> FastAPI app with its real lifespan (served model, CRI, MITRE, explainer)
    -> httpx.AsyncClient(transport=ASGITransport(app)) -> every route group

The database, in order of preference:

    CIRA_TEST_DATABASE_URL   a PostgreSQL at Alembic head (shared; assertions are scoped to this run)
    testcontainers           a fresh postgres:17 container per test module, migrated with Alembic
    SQLite (aiosqlite)       a file created from the ORM, when neither is available

``test_database_is_postgres`` is skipped on SQLite, so a run without
PostgreSQL shows the Bible's "real database" item as not exercised.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa

REPO = Path(__file__).resolve().parents[3]
BACKEND = REPO / "backend"
SECRET = "test-secret-" + "x" * 40
PASSWORD = "correct horse battery staple"


def _module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


T12 = _module(Path(__file__).with_name("test_ch12_pipeline.py"), "ch12_world_for_ch13")
T11 = T12.T11
world = T12.world
alerts = T12.alerts


@pytest.fixture(autouse=True)
def _pins(world, monkeypatch):
    for k, v in T11._env(world).items():
        monkeypatch.setenv(k, v)
    for k in [k for k in os.environ if k.startswith(("CRI_", "MITRE_"))]:
        monkeypatch.delenv(k)
    from app.core import config

    monkeypatch.setattr(config.settings, "cert_processed_dir", str(world["processed"]))


def _start_container():
    try:
        try:                       # testcontainers moved the module; the old path is deprecated
            from testcontainers.community.postgres import PostgresContainer
        except ImportError:
            from testcontainers.postgres import PostgresContainer

        c = PostgresContainer("postgres:17", driver="asyncpg")
        c.start()
        return c
    except Exception:            # no Docker on this machine
        return None


def _migrate(url: str) -> None:
    from alembic import command
    from alembic.config import Config
    from app.core import config

    old = config.settings.database_url
    config.settings.database_url = url
    try:
        cfg = Config(str(BACKEND / "alembic.ini"))
        cfg.set_main_option("script_location", str(BACKEND / "alembic"))
        command.upgrade(cfg, "head")
    finally:
        config.settings.database_url = old


@pytest.fixture(scope="module")
def db(world, alerts):
    """Load the alert run, create an analyst. Yields (kind, async url, run id, username)."""
    from app.alerts import load as alert_load
    from app.database.base import Base

    container = None
    url = os.getenv("CIRA_TEST_DATABASE_URL")
    kind = "postgresql (CIRA_TEST_DATABASE_URL)" if url else None
    if not url:
        container = _start_container()
        if container is not None:
            url = container.get_connection_url()
            _migrate(url)
            kind = "postgresql (testcontainers)"
    if url:
        load_url = api_url = url
    else:
        path = world["root"] / "ch13.sqlite"
        engine = sa.create_engine(f"sqlite:///{path}")
        Base.metadata.create_all(engine)
        with engine.begin() as c:              # the equivalent of `alembic stamp head` for an ORM-built schema
            c.execute(sa.text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)"))
            c.execute(sa.text("INSERT INTO alembic_version VALUES ('9f3b2c7d4e81')"))
        engine.dispose()
        load_url, api_url, kind = f"sqlite:///{path}", f"sqlite+aiosqlite:///{path}", "sqlite"
    mp = pytest.MonkeyPatch()
    for k, v in T11._env(world).items():
        mp.setenv(k, v)
    try:
        assert alert_load.main(T12._args(world, "--database-url", load_url)) == 0
    finally:
        mp.undo()
    username = f"analyst-{uuid.uuid4().hex[:8]}"

    async def create():
        from app.services import accounts
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        eng = create_async_engine(api_url)
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                await accounts.create(s, username=username, email=f"{username}@example.org", password=PASSWORD)
        finally:
            await eng.dispose()

    asyncio.run(create())
    yield {"kind": kind, "url": api_url, "run_id": alerts["alert_run_id"], "username": username}
    if container is not None:
        container.stop()


class _Settings:
    def __init__(self, secret=SECRET):
        from app.core.config import settings

        self.secret_key = secret
        self.access_token_minutes = 30
        self.cors_origins = settings.cors_origins


def run_api(db, scenario, *, url: str | None = None, secret: str = SECRET, login: bool = True):
    """Start the real app (lifespan included) on ``db`` and run ``scenario(client, headers, engine)``."""
    import httpx
    from app.api import deps
    from app.main import app
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    async def go():
        engine = create_async_engine(url or db["url"], connect_args={"timeout": 3} if "asyncpg" in (url or db["url"])
                                     else {})
        maker = async_sessionmaker(engine, expire_on_commit=False)

        async def session():
            async with maker() as s:
                yield s

        app.dependency_overrides.update({deps.get_session: session, deps.get_engine: lambda: engine,
                                         deps.get_app_settings: lambda: _Settings(secret)})
        try:
            async with app.router.lifespan_context(app):
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                    headers = {}
                    if login:
                        r = await client.post("/api/v1/auth/token",
                                              data={"username": db["username"], "password": PASSWORD})
                        assert r.status_code == 200, r.text
                        headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
                    return await scenario(client, headers, engine)
        finally:
            app.dependency_overrides.clear()
            await engine.dispose()

    return asyncio.run(go())


async def _scalar(engine, sql, **params):
    async with engine.connect() as c:
        return (await c.execute(sa.text(sql), params)).scalar()


# --- health and auth --------------------------------------------------------------

def test_health_reports_components_and_routes(db):
    async def scenario(client, headers, engine):
        root = (await client.get("/health")).json()
        v1 = (await client.get("/api/v1/health")).json()
        return root, v1

    root, v1 = run_api(db, scenario, login=False)
    for body in (root, v1):
        assert body["status"] == "healthy" and body["anomaly_model"]["status"] == "loaded"
        assert body["database"]["status"] == "reachable" and body["auth"]["status"] == "configured"
        assert SECRET not in str(body)
        r = body["routes"]
        assert r["alerts_risk_investigations"] == {"ready": True, "reason": None, "alert_run_id": db["run_id"]}
        assert all(v["ready"] for v in r.values()), r
    assert set(root) == set(v1)


def test_login_tokens_and_every_protected_route(db):
    async def scenario(client, headers, engine):
        bad = await client.post("/api/v1/auth/token", data={"username": db["username"], "password": "wrong" * 4})
        ghost = await client.post("/api/v1/auth/token", data={"username": "nobody", "password": PASSWORD})
        me = await client.get("/api/v1/users/me", headers=headers)
        forged = await client.get("/api/v1/users/me", headers={"Authorization": headers["Authorization"][:-2] + "xx"})
        paths = (await client.get("/openapi.json")).json()["paths"]
        unauth = {}
        for path, ops in paths.items():
            if path.startswith(("/api/v1/auth", "/api/v1/health")):
                continue
            p = (path.replace("{alert_id}", "1").replace("{user_id}", "u0002").replace("{day}", "2010-01-26")
                 .replace("{technique_id}", "T1052.001"))
            for method in ops:
                resp = await client.request(method.upper(), p, json={} if method == "post" else None)
                unauth[f"{method} {path}"] = resp.status_code
        logins = await _scalar(engine, "SELECT count(*) FROM audit_logs WHERE action = 'analyst_login' "
                                       "AND actor = :u", u=db["username"])
        failed = await _scalar(engine, "SELECT count(*) FROM audit_logs WHERE action = 'analyst_login_failed' "
                                       "AND actor IN (:u, 'nobody')", u=db["username"])
        health = (await client.get("/health")).json()
        loaded = await _scalar(engine, "SELECT count(*) FROM audit_logs WHERE action = 'alert_run_loaded'")
        return bad, ghost, me, forged, unauth, logins, failed, health, loaded

    bad, ghost, me, forged, unauth, logins, failed, health, loaded = run_api(db, scenario)
    assert bad.status_code == ghost.status_code == 401
    assert bad.json() == ghost.json()                                  # no hint whether the user exists
    assert bad.headers["www-authenticate"] == "Bearer"
    assert me.status_code == 200 and me.json()["username"] == db["username"] and "hashed_password" not in me.json()
    assert forged.status_code == 401
    assert len(unauth) >= 17 and set(unauth.values()) == {401}, unauth
    assert logins >= 1 and failed >= 2
    assert health["database"]["alert_runs_loaded"] == loaded            # login audit rows never count as a load (N58)


def test_login_refused_without_a_real_secret(db):
    async def scenario(client, headers, engine):
        r = await client.post("/api/v1/auth/token", data={"username": db["username"], "password": PASSWORD})
        h = (await client.get("/health")).json()
        return r, h

    r, h = run_api(db, scenario, secret="changeme-generate-a-real-secret", login=False)
    assert r.status_code == 503 and r.json()["detail"]["component"] == "auth"
    assert h["auth"]["status"] == "unavailable" and "placeholder" in h["auth"]["reason"]
    assert h["routes"]["auth"]["ready"] is False


# --- alerts -------------------------------------------------------------------------

def test_alert_queue_is_the_stored_policy_view(db, alerts):
    async def scenario(client, headers, engine):
        q = (await client.get("/api/v1/alerts", params={"limit": 200}, headers=headers)).json()
        two = (await client.get("/api/v1/alerts", params={"limit": 2, "offset": 1}, headers=headers)).json()
        sup = (await client.get("/api/v1/alerts", params={"status": "suppressed", "limit": 200}, headers=headers)).json()
        over = await client.get("/api/v1/alerts", params={"limit": 201}, headers=headers)
        db_open = await _scalar(engine, "SELECT count(*) FROM alerts WHERE alert_run_id = :r AND status = 'open'",
                                r=db["run_id"])
        return q, two, sup, over, db_open

    q, two, sup, over, db_open = run_api(db, scenario)
    s = alerts["summary"]
    assert q["counts"] == {"open": s["open_alerts"], "suppressed": s["suppressed_alerts"]} and db_open == s["open_alerts"]
    assert q["page"]["total"] == s["open_alerts"] and q["page"]["max_limit"] == 200
    assert q["queue"]["ordered_by"] == "anomaly_score" and q["run"]["alert_run_id"] == db["run_id"]
    items = q["items"]
    assert [a["queue_score"] for a in items] == sorted((a["queue_score"] for a in items), reverse=True)
    assert all(a["status"] == "open" and a["queue_score"] == a["peak_anomaly_score"] for a in items)       # N55
    assert all({"peak_anomaly_score", "max_cri_score", "max_severity"} <= set(a) for a in items)          # N34
    assert not any(a["in_sample"] for a in items)                                                           # N31
    assert sum(a["suppressed"]["count"] for a in items) == len(sup["items"])                               # N57, N60
    assert [a["id"] for a in two["items"]] == [a["id"] for a in items[1:3]]
    assert over.status_code == 422                                                                         # HCEA §13
    assert all(a["suppressed"] is None and a["duplicate_of_id"] is not None for a in sup["items"])


def test_alert_detail_traces_members_and_suppressed_repeats(db):
    async def scenario(client, headers, engine):
        q = (await client.get("/api/v1/alerts", params={"limit": 200}, headers=headers)).json()["items"]
        with_sup = next((a for a in q if a["suppressed"]["count"]), None)
        target = with_sup or q[0]
        d = (await client.get(f"/api/v1/alerts/{target['id']}", headers=headers)).json()
        child = None
        if d["suppressed_alerts"]:
            child = (await client.get(f"/api/v1/alerts/{d['suppressed_alerts'][0]['id']}", headers=headers)).json()
        stored = {}
        for m in d["members"]:
            stored[m["id"]] = await _scalar(engine, "SELECT r.cri_score FROM risk_scores r JOIN alert_members m ON "
                                                    "m.risk_score_id = r.id WHERE m.id = :i", i=m["id"])
        missing = await client.get("/api/v1/alerts/987654321", headers=headers)
        return target, d, child, stored, missing

    target, d, child, stored, missing = run_api(db, scenario)
    assert d["alert"]["id"] == target["id"] and len(d["members"]) >= 1
    assert sum(m["is_peak"] for m in d["members"]) == 1
    assert all(m["by_band"] or m["by_top_k"] for m in d["members"])
    assert all(stored[m["id"]] == m["cri_score"] for m in d["members"])
    assert len(d["suppressed_alerts"]) == target["suppressed"]["count"]
    if child is not None:
        assert child["alert"]["status"] == "suppressed" and child["duplicate_of"]["id"] == target["id"]
    assert missing.status_code == 404 and missing.json()["detail"]["code"] == "not_found"


def test_explanations_keep_their_sections_and_mitre_context(db):
    async def scenario(client, headers, engine):
        q = (await client.get("/api/v1/alerts", params={"limit": 200}, headers=headers)).json()["items"]
        tech_alert = next(a for a in q if a["techniques"])
        e = (await client.get(f"/api/v1/explanations/alerts/{tech_alert['id']}", headers=headers)).json()
        m = (await client.get(f"/api/v1/mitre/alerts/{tech_alert['id']}", headers=headers)).json()
        day = e["members"][0]
        one = (await client.get(f"/api/v1/explanations/users/{day['user_id']}/days/{day['activity_date']}",
                                headers=headers)).json()
        t = (await client.get(f"/api/v1/mitre/techniques/{tech_alert['techniques'][0]}", headers=headers)).json()
        unknown = await client.get("/api/v1/mitre/techniques/T9999", headers=headers)
        return tech_alert, e, m, one, t, unknown

    alert, e, m, one, t, unknown = run_api(db, scenario)
    for x in e["members"]:
        s = x["sections"]
        assert all(f["source"]["kind"] == "model" for f in s["model"] + s["model_lowering"])            # N50
        assert all(c["source"]["kind"] == "cri" for c in s["cri"])                                     # N34
        assert all(mm["source"]["kind"] == "mitre" for mm in (s["mitre"] or {}).get("matches", []))     # N45
        rr = x["reason_rows"]
        assert rr.get("model", 0) == len(s["model"]) and rr.get("cri", 0) == len(s["cri"])
        assert rr.get("mitre", 0) == len((s["mitre"] or {}).get("matches", []))
        if x["corroboration"]:
            assert "never a reason" in x["corroboration"]["note"]                                       # N48
        assert "not a probability" in x["text"]                                                         # N20
    assert one["member_id"] == e["members"][0]["member_id"]
    assert {tt["technique_id"] for tt in m["techniques"]} == set(alert["techniques"])
    assert all(d["status"] in ("mapped", "unmapped", "not_evaluated") for d in m["days"])
    assert "not a reason the model" in m["note"]
    assert t["technique_id"] == alert["techniques"][0] and t["attack_version"] == "19.2" and t["rules"]
    assert unknown.status_code == 404


# --- risk, investigations, lineage --------------------------------------------------

def test_overview_history_investigations_and_lineage(db, alerts):
    async def scenario(client, headers, engine):
        g = lambda p, **kw: client.get(p, params=kw or None, headers=headers)  # noqa: E731
        ov = (await g("/api/v1/risk/overview")).json()
        subjects = (await g("/api/v1/investigations", limit=200)).json()
        demo = (await g("/api/v1/investigations", scope="demo", limit=200)).json()
        user = ov["top_users"][0]["user_id"]
        inv = (await g(f"/api/v1/investigations/{user}")).json()
        day = (await g(f"/api/v1/risk/users/{user}/history")).json()
        week = (await g(f"/api/v1/risk/users/{user}/history", bucket="week")).json()
        member = inv["alerts"][0]["peak_date"]
        risk = (await g(f"/api/v1/risk/users/{user}/days/{member}")).json()
        an = (await g(f"/api/v1/anomaly/users/{user}/days/{member}")).json()
        fv = (await g(f"/api/v1/features/users/{user}/days/{member}")).json()
        ev = (await g("/api/v1/events", user_id=user, limit=5)).json()
        ev_all = (await g("/api/v1/events", user_id=user, limit=200)).json()
        models = (await g("/api/v1/models")).json()
        no_user = await g("/api/v1/investigations/nobody-at-all")
        return ov, subjects, demo, user, inv, day, week, risk, an, fv, ev, ev_all, models, no_user

    ov, subjects, demo, user, inv, day, week, risk, an, fv, ev, ev_all, models, no_user = run_api(db, scenario)
    s = alerts["summary"]
    assert ov["counts"] == {"open": s["open_alerts"], "suppressed": s["suppressed_alerts"]}
    assert sum(ov["open_by_severity"].values()) == s["open_alerts"]
    assert sum(w["count"] for w in ov["new_open_alerts"]) == s["open_alerts"]
    assert ov["open_never_above_low"] == ov["open_by_severity"]["LOW"]
    assert [u["max_queue_score"] for u in ov["top_users"]] == sorted((u["max_queue_score"] for u in ov["top_users"]),
                                                                     reverse=True)
    demo_users = set(alerts["demo_sample"]["users"])
    assert {x["user_id"] for x in demo["items"]} == demo_users and all(x["in_demo_sample"] for x in demo["items"])
    assert not any(x["in_sample"] for x in subjects["items"])                                           # N31, N59
    assert inv["subject"]["user_id"] == user and inv["subject"]["open_alerts"] == ov["top_users"][0]["open_alerts"]
    assert sum(b["days"] for b in day["buckets"]) == day["coverage"]["persisted_days"] == inv["coverage"]["persisted_days"]
    assert sum(b["days"] for b in week["buckets"]) == day["coverage"]["persisted_days"]
    assert len(week["buckets"]) <= len(day["buckets"])
    assert all(b["max_cri_score"] >= b["mean_cri_score"] and 0 <= b["max_anomaly_score"] <= 1 for b in day["buckets"])
    assert risk["anomaly_score"] == an["anomaly_score"] and risk["anomaly_score_id"] == an["id"]          # N34
    assert an["role"] == "served" and an["feature_vector_id"] == fv["id"] and risk["alert_ids"]
    assert fv["model_inputs"] == models["served"]["n_input_columns"]
    assert not any(v["model_input"] for v in fv["values"] if v["static"])                               # N25
    assert len(ev["items"]) == min(5, ev["page"]["total"]) and ev["page"]["total"] == ev_all["page"]["total"] > 0
    assert len(ev_all["items"]) == min(200, ev_all["page"]["total"])                                     # HCEA §13 cap
    assert all(e["user_id"] == user for e in ev_all["items"])
    times = [e["event_time"] for e in ev_all["items"]]
    assert times == sorted(times)
    assert models["shadow"] and all(x["role"] == "shadow" and "N32" in x["use"] for x in models["shadow"])
    assert [m["model_version"] for m in models["in_database"]] == [models["served"]["model_version"]]
    assert no_user.status_code == 404


# --- scoring on demand --------------------------------------------------------------

def test_on_demand_scoring_reproduces_the_stored_chain(db):
    async def scenario(client, headers, engine):
        q = (await client.get("/api/v1/alerts", params={"limit": 200}, headers=headers)).json()["items"]
        a = q[0]
        user, day = a["user_id"], a["peak_date"]
        fv = (await client.get(f"/api/v1/features/users/{user}/days/{day}", headers=headers)).json()
        features = {v["column"]: v["value"] for v in fv["values"]}
        risk = (await client.get(f"/api/v1/risk/users/{user}/days/{day}", headers=headers)).json()
        stored = (await client.get(f"/api/v1/explanations/users/{user}/days/{day}", headers=headers)).json()
        an = (await client.post("/api/v1/anomaly/score", json={"user_id": user, "date": day, "features": features},
                                headers=headers)).json()
        full = (await client.post("/api/v1/risk/score", json={"user_id": user, "date": day, "features": features,
                                                              "role": risk["ldap_role"]}, headers=headers)).json()
        short = dict(features)
        short.pop(next(iter(short)))
        bad = await client.post("/api/v1/anomaly/score", json={"features": short}, headers=headers)
        rows_before = await _scalar(engine, "SELECT count(*) FROM anomaly_scores")
        await client.post("/api/v1/anomaly/score", json={"features": features}, headers=headers)
        rows_after = await _scalar(engine, "SELECT count(*) FROM anomaly_scores")
        return risk, stored, an, full, bad, rows_before, rows_after

    risk, stored, an, full, bad, before, after = run_api(db, scenario)
    assert an["role"] == "served" and an["persisted"] is False
    assert an["anomaly_score"] == pytest.approx(risk["anomaly_score"], abs=1e-9)
    assert full["anomaly"]["anomaly_score"] == pytest.approx(risk["anomaly_score"], abs=1e-9)
    assert full["risk"]["cri_score"] == pytest.approx(risk["cri_score"], abs=1e-6)                    # same CRI, recomputed
    assert full["risk"]["severity"] == risk["severity"]
    assert full["risk"]["anomaly_score"] == full["anomaly"]["anomaly_score"]                             # N34
    trig = full["alert_trigger"]
    assert trig["by_top_k"] is None and trig["policy_version"] == "c12-alert-policy-v1"
    assert trig["by_band"] == (risk["severity"] in ("HIGH", "CRITICAL")) and trig["eligible_for_top_k"] is True
    e = full["explanation"]
    assert e["status"] == "complete" and e["headline"]["model_name"] == stored["headline"]["model_name"]
    assert [f["feature"] for f in e["model_factors"]] == [f["feature"] for f in stored["sections"]["model"]]
    assert bad.status_code == 422 and bad.json()["detail"]["code"] == "invalid_feature_vector"
    assert before == after                                                                              # nothing stored


# --- failure modes (Architecture §36) ------------------------------------------------

def test_alert_routes_refuse_a_run_built_for_another_model(db, monkeypatch):
    monkeypatch.setenv("CIRA_SERVED_MODEL", "tabnet:v0001")            # a rollback without new runs (N28)
    monkeypatch.delenv("CIRA_SHADOW_MODEL")

    async def scenario(client, headers, engine):
        return (await client.get("/api/v1/alerts", headers=headers),
                await client.get("/api/v1/alerts", params={"alert_run_id": db["run_id"]}, headers=headers),
                (await client.get("/health")).json())

    current, pinned, health = run_api(db, scenario)
    assert current.status_code == 503 and "N28" in current.json()["detail"]["message"]
    assert pinned.status_code == 409 and pinned.json()["detail"]["code"] == "other_model"
    assert health["routes"]["alerts_risk_investigations"]["ready"] is False


def test_database_outage_is_a_visible_503(db):
    if db["kind"] == "sqlite":
        bad = "postgresql+asyncpg://cira:x@127.0.0.1:1/none"
    else:
        bad = db["url"].rsplit("@", 1)[0] + "@127.0.0.1:1/none"

    from app.core.security import create_access_token

    token, _ = create_access_token(username=db["username"], analyst_id=1, role="analyst", secret=SECRET, minutes=5)

    async def scenario(client, headers, engine):
        return (await client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"}),
                await client.post("/api/v1/auth/token", data={"username": db["username"], "password": PASSWORD}),
                (await client.get("/health")).json())

    alerts_r, login_r, health = run_api(db, scenario, url=bad, login=False)
    assert login_r.status_code == 503 and login_r.json()["detail"]["code"] == "database_unavailable"
    assert alerts_r.status_code == 503 and alerts_r.json()["detail"]["component"] == "database"   # never an empty list
    assert health["database"]["status"] == "unavailable" and health["routes"]["auth"]["ready"] is False
    assert health["routes"]["alerts_risk_investigations"]["ready"] is False


def test_database_is_postgres(db):
    if db["kind"] == "sqlite":
        pytest.skip("no PostgreSQL: set CIRA_TEST_DATABASE_URL or install Docker for testcontainers")

    async def scenario(client, headers, engine):
        return engine.dialect.name, await _scalar(engine, "SELECT version_num FROM alembic_version")

    dialect, rev = run_api(db, scenario)
    assert dialect == "postgresql" and rev == "9f3b2c7d4e81"



# --- the verifier ----------------------------------------------------------------------

def _verify_in_process(db, tmp_path, monkeypatch, *extra):
    from app.api import deps
    from app.main import app
    from fastapi.testclient import TestClient
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    verify = T12._module(REPO / "scripts" / "verify_chapter13.py", "verify_chapter13")
    engine = create_async_engine(db["url"], poolclass=NullPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    async def session():
        async with maker() as s:
            yield s

    app.dependency_overrides.update({deps.get_session: session, deps.get_engine: lambda: engine,
                                     deps.get_app_settings: lambda: _Settings()})
    monkeypatch.setenv("CIRA_ANALYST_PASSWORD", PASSWORD)
    try:
        with TestClient(app) as client:
            return verify.main(["--username", db["username"], "--sample", "5", "--results-dir", str(tmp_path), *extra],
                               client=client)
    finally:
        app.dependency_overrides.clear()


def test_verifier_passes_and_catches_a_tampered_score(db, tmp_path, monkeypatch, capsys):
    assert _verify_in_process(db, tmp_path, monkeypatch) == 0
    out = capsys.readouterr().out
    assert " 0 FAIL" in out and "CRI reproduces the stored one" in out

    async def tamper(delta):
        from sqlalchemy.ext.asyncio import create_async_engine

        eng = create_async_engine(db["url"])
        try:
            async with eng.begin() as c:
                rid = (await c.execute(sa.text(
                    "SELECT m.risk_score_id FROM alert_members m JOIN alerts a ON a.id = m.alert_id "
                    "WHERE a.alert_run_id = :r AND a.status = 'open' AND m.is_peak "
                    "ORDER BY a.queue_score DESC, a.peak_date, a.id LIMIT 1"), {"r": db["run_id"]})).scalar()
                await c.execute(sa.text("UPDATE risk_scores SET cri_score = cri_score + :d WHERE id = :i"),
                                {"d": delta, "i": rid})
        finally:
            await eng.dispose()

    asyncio.run(tamper(1.0))
    try:
        assert _verify_in_process(db, tmp_path, monkeypatch) == 1
        assert "FAIL scoring    CRI reproduces the stored one" in capsys.readouterr().out
    finally:
        asyncio.run(tamper(-1.0))
