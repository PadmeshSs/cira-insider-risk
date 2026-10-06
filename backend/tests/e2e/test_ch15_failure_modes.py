"""Chapter 15: Architecture §36 failure modes, end to end on PostgreSQL (N58, N68).

    load, connection refused       -> NOT STORED, exit 3, nothing in the database
    load, connection lost mid-way  -> rolled back after rows were written, nothing stays
    API, database cut while serving -> 503 component database, /health says why;
                                       recovers when the database returns, no restart
    API, no alert run loaded       -> 503 naming the load command; routes not ready
    API, no served model           -> 503 anomaly_model; nothing invented

The database cut goes through a small TCP proxy in front of PostgreSQL, so
the server itself never stops and the test can restore it.
"""
from __future__ import annotations

import asyncio
import socket
import threading
import uuid

import pytest

import ch15_stack
from ch15_api import run_api

pytestmark = pytest.mark.e2e


# --- loads --------------------------------------------------------------------------------

def test_a_refused_connection_stores_nothing_and_says_so(stack):
    r = stack.loads["refused_connection"]
    assert r["exit_code"] == 3 and "NOT STORED" in r["stderr"]
    assert set(r["counts_after"].values()) == {0}, r["counts_after"]


def test_a_connection_lost_mid_load_rolls_everything_back(stack):
    r = stack.loads["mid_load_failure"]
    assert r["exit_code"] == 3 and "NOT STORED" in r["stderr"]
    written = r["tables_written_before_failure"]
    assert {"feature_vectors", "event_logs", "anomaly_scores", "risk_scores", "alerts", "alert_members"} <= set(written)
    assert written[-1] == "alert_reasons"
    assert set(r["counts_after"].values()) == {0}, r["counts_after"]       # rows were sent, none survived


def test_the_real_load_after_the_failures_is_the_only_claim(stack):
    after = stack.loads["real"]["counts_after"]
    assert after["alert_run_loaded"] == 1 and after["alerts"] > 0 and after["event_logs"] > 0
    lines = (stack.root / "runlog.jsonl").read_text(encoding="utf-8").splitlines()
    statuses = [x for x in lines if "chapter12_alert_load" in x]
    assert sum('"not_stored"' in x for x in statuses) == 2 and sum('"stored"' in x for x in statuses) == 1


# --- a TCP proxy that can cut PostgreSQL ------------------------------------------------------

class CuttableProxy:
    """127.0.0.1:<port> -> PostgreSQL. ``cut()`` refuses new connections and drops open ones; ``restore()`` undoes it."""

    def __init__(self, host: str, port: int):
        self.target = (host, port)
        self.loop = asyncio.new_event_loop()
        self.server = None
        self.links: set[asyncio.StreamWriter] = set()
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def _call(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(10)

    async def _pipe(self, reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def _handle(self, c_reader, c_writer):
        try:
            s_reader, s_writer = await asyncio.open_connection(*self.target)
        except OSError:
            c_writer.close()
            return
        self.links |= {c_writer, s_writer}
        await asyncio.gather(self._pipe(c_reader, s_writer), self._pipe(s_reader, c_writer))
        self.links -= {c_writer, s_writer}

    async def _start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", self.port, reuse_address=True)

    async def _cut(self):
        self.server.close()
        for w in list(self.links):                 # drop live connections first: wait_closed waits for them
            w.transport.abort()
        self.links.clear()
        await self.server.wait_closed()

    def start(self):
        self._call(self._start())
        return self

    cut = lambda self: self._call(self._cut())       # noqa: E731
    restore = start

    def close(self):
        try:
            self._call(self._cut())
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)


def _through(url: str, port: int) -> str:
    from sqlalchemy.engine import make_url

    return make_url(url).set(host="127.0.0.1", port=port).render_as_string(hide_password=False)


def test_a_database_cut_is_a_visible_503_and_the_api_recovers_without_restart(stack):
    from sqlalchemy.engine import make_url

    u = make_url(stack.db.url)
    proxy = CuttableProxy(u.host or "127.0.0.1", u.port or 5432).start()
    try:
        async def scenario(client, headers, engine):
            g = lambda p: client.get(p, headers=headers)  # noqa: E731
            before = await g("/api/v1/alerts")
            proxy.cut()
            during_alerts = await g("/api/v1/alerts")
            during_overview = await g("/api/v1/risk/overview")
            during_health = (await client.get("/api/v1/health")).json()
            during_login = await client.post("/api/v1/auth/token", data={"username": stack.username,
                                                                         "password": stack.password})
            proxy.restore()
            after = await g("/api/v1/alerts")
            after_health = (await client.get("/api/v1/health")).json()
            return before, during_alerts, during_overview, during_health, during_login, after, after_health

        before, d_alerts, d_over, d_health, d_login, after, a_health = run_api(stack, scenario,
                                                                                url=_through(stack.db.url, proxy.port))
    finally:
        proxy.close()
    assert before.status_code == 200 and before.json()["items"]
    for r in (d_alerts, d_over, d_login):
        assert r.status_code == 503, r.text                                       # never an empty list
        assert r.json()["detail"]["code"] == "database_unavailable" and r.json()["detail"]["component"] == "database"
    assert d_health["database"]["status"] == "unavailable"
    assert d_health["routes"]["alerts_risk_investigations"]["ready"] is False                    # N68
    assert d_health["routes"]["auth"]["ready"] is False
    assert "database" in d_health["routes"]["alerts_risk_investigations"]["reason"]
    assert after.status_code == 200 and after.json()["items"] == before.json()["items"]
    assert a_health["database"]["status"] == "reachable" and a_health["routes"]["alerts_risk_investigations"]["ready"]


# --- empty database, missing model ---------------------------------------------------------------

def test_no_loaded_run_means_routes_not_ready_and_the_reason(stack):
    """A migrated database with an analyst but no load: 503 that names the command, never an empty queue."""
    import asyncio as aio

    from sqlalchemy.engine import make_url

    admin = stack.db.admin_url or stack.db.url
    name = f"cira_e2e_empty_{uuid.uuid4().hex[:8]}"
    aio.run(ch15_stack._admin(admin, f'CREATE DATABASE "{name}"'))
    url = make_url(stack.db.url).set(database=name).render_as_string(hide_password=False)
    try:
        ch15_stack.migrate(url)
        username = ch15_stack.create_analyst(url)

        class S:  # the same stack, another database and analyst
            db = ch15_stack.Database(url=url, kind=stack.db.kind, name=name)
            secret, password = stack.secret, stack.password

        S.username = username

        async def scenario(client, headers, engine):
            return ((await client.get("/api/v1/alerts", headers=headers)),
                    (await client.get("/api/v1/risk/overview", headers=headers)),
                    (await client.get("/api/v1/health")).json())

        alerts, overview, health = run_api(S, scenario)
    finally:
        aio.run(ch15_stack._admin(admin, f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    for r in (alerts, overview):
        assert r.status_code == 503 and r.json()["detail"]["component"] == "alerts"
        assert "app.alerts.load" in r.json()["detail"]["message"]
    route = health["routes"]["alerts_risk_investigations"]
    assert route["ready"] is False and health["database"]["status"] == "reachable"


def test_no_served_model_means_no_score_anywhere(stack, monkeypatch, tmp_path):
    """§36 model unavailable: read and score routes refuse with the component; /health is degraded."""
    import pandas as pd

    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "no-registry"))
    fm = pd.read_parquet(stack.world["gbdt"]["features"]["path"])
    row = fm[(fm["user_id"] == stack.trace["user_id"]) & (fm["date"].astype(str) == stack.trace["date"])].iloc[0]
    features = {k: (None if pd.isna(v) else float(v)) for k, v in row.items() if k not in ("user_id", "date")}

    async def scenario(client, headers, engine):
        return ((await client.get("/api/v1/alerts", headers=headers)),
                (await client.post("/api/v1/risk/score", json={"user_id": stack.trace["user_id"], "date": stack.trace["date"], "features": features}, headers=headers)),
                (await client.get("/api/v1/health")).json())

    alerts, score, health = run_api(stack, scenario)
    assert alerts.status_code == 503 and alerts.json()["detail"]["component"] == "anomaly_model"
    assert score.status_code == 503 and score.json()["detail"]["component"] == "anomaly_model"
    assert health["status"] != "healthy" and health["anomaly_model"]["status"] != "loaded"
    assert health["routes"]["risk_score"]["ready"] is False
