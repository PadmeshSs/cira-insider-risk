"""Chapter 15: build the whole CIRA chain once, from raw CSV to a loaded PostgreSQL.

    raw CERT-shaped CSV  (fixtures/synthetic_ch6: 32 users, 13 planted insiders)
      -> Chapter 5 Stage 0 (Chapter 4 policy) -> user-day feature matrix
      -> Chapter 8 XGBoost candidate (served)  +  Chapter 7 TabNet (shadow, N32)
      -> Chapter 8 batch scoring (served + shadow)
      -> Chapter 9 CRI calibration, Chapter 10 MITRE reference and enrichment
      -> Chapter 9 CRI run with mitre_context
      -> Chapter 11 explanations (TreeSHAP, bounded KernelSHAP)
      -> Chapter 12 alert batch
      -> fresh PostgreSQL database, Alembic head
      -> two loads that must fail and store nothing (§36, N58)
      -> the real load, read back
      -> one analyst account (N65)

Every stage is the production entry point with the arguments an operator
would give it; nothing is mocked. The only test-specific inputs are the
synthetic CSV tree and the small training budget (3 TabNet epochs).

Which raw event is traced: the top open alert's peak day, and on that day
one raw CSV row of the alert's user (a USB connect if there is one, then a
logon, then anything). The row is chosen after the run, from what the
pipeline decided, so nothing is planted to make the trace pass.

Where PostgreSQL comes from, in order:

    CIRA_E2E_DATABASE_URL    any database on a server the tests may create
                             databases on; a fresh ``cira_e2e_<hex>`` is
                             created and dropped afterwards
    CIRA_TEST_DATABASE_URL   used the same way (only its server is used)
    testcontainers           a postgres:17 container for the session

There is no SQLite fallback: the Bible's Chapter 15 item is "against
testcontainers Postgres". Without PostgreSQL the stack is not built and the
e2e tests are skipped with the reason, which ``scripts/verify_chapter15.py``
counts as a FAIL.

Used by ``backend/tests/e2e/conftest.py`` and ``scripts/e2e_stack.py``
(the Playwright click-through). Nothing in ``app/`` imports this module.
"""
from __future__ import annotations

import asyncio
import contextlib
import csv
import json
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

REPO = Path(__file__).resolve().parents[3]
BACKEND = REPO / "backend"
TESTS = BACKEND / "tests"
for p in (str(BACKEND), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

PASSWORD = "e2e correct horse battery staple"
SECRET = "ch15-e2e-secret-" + "k" * 40
STATIC = "psych_,peer_department_size"
TRACE_PREFERENCE = (("device", "connect"), ("logon", "logon"), ("http", None), ("email", None), ("file", None))
DOMAIN_FILES = {"logon": "logon.csv", "device": "device.csv", "file": "file.csv", "email": "email.csv",
                "http": "http.csv"}


class StackUnavailable(RuntimeError):
    """The stack cannot be built here (no PostgreSQL). Tests skip with this reason."""


# --- environment ---------------------------------------------------------------------

def pins(root: Path) -> dict[str, str]:
    """The environment every stage and the API need: registry, served/shadow pins, CRI and MITRE pins."""
    exp = root / "experiments"
    return {"CIRA_RUNLOG": str(root / "runlog.jsonl"), "MODEL_PATH": str(root / "models"),
            "CIRA_SERVED_MODEL": "gbdt:v0001", "CIRA_SHADOW_MODEL": "tabnet:v0001",
            "CIRA_CRI_CALIBRATION": str(exp / "chapter9_cri_calibration.json"),
            "CIRA_MITRE_REFERENCE": str(exp / "chapter10_mitre_reference.json"),
            "CERT_PROCESSED_DIR": str(root / "processed")}


@contextlib.contextmanager
def pinned_env(root: Path) -> Iterator[None]:
    """Set the pins, remove any developer CRI_/MITRE_ override, and restore everything afterwards."""
    saved = dict(os.environ)
    try:
        for k in [k for k in os.environ if k.startswith(("CRI_", "MITRE_"))]:
            del os.environ[k]
        os.environ.update(pins(root))
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


# --- PostgreSQL --------------------------------------------------------------------------

@dataclass
class Database:
    url: str                       # postgresql+asyncpg://.../<fresh db>
    kind: str                      # "server (CIRA_E2E_DATABASE_URL)" | "server (CIRA_TEST_DATABASE_URL)" | "testcontainers"
    name: str
    admin_url: str | None = None   # where the fresh database was created from
    container: Any = None

    def drop(self) -> None:
        if self.container is not None:
            self.container.stop()
            return
        if self.admin_url:
            asyncio.run(_admin(self.admin_url, f'DROP DATABASE IF EXISTS "{self.name}" WITH (FORCE)'))


async def _admin(url: str, sql: str) -> None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(url, isolation_level="AUTOCOMMIT", connect_args={"timeout": 5})
    try:
        async with engine.connect() as c:
            await c.execute(text(sql))
    finally:
        await engine.dispose()


def _as_asyncpg(url: str) -> str:
    from sqlalchemy.engine import make_url

    u = make_url(url)
    if not u.drivername.startswith("postgresql"):
        raise StackUnavailable(f"{u.drivername} is not PostgreSQL")
    return u.set(drivername="postgresql+asyncpg").render_as_string(hide_password=False)


def provision_database() -> Database:
    from sqlalchemy.engine import make_url

    for var in ("CIRA_E2E_DATABASE_URL", "CIRA_TEST_DATABASE_URL"):
        server = os.getenv(var)
        if not server:
            continue
        admin = _as_asyncpg(server)
        name = f"cira_e2e_{uuid.uuid4().hex[:10]}"
        try:
            asyncio.run(_admin(admin, f'CREATE DATABASE "{name}"'))
        except Exception as exc:                                   # no CREATEDB, server down, ...
            raise StackUnavailable(f"{var} is set but a database could not be created on it: "
                                   f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}") from exc
        url = make_url(admin).set(database=name).render_as_string(hide_password=False)
        return Database(url=url, kind=f"server ({var})", name=name, admin_url=admin)
    try:
        try:
            from testcontainers.community.postgres import PostgresContainer
        except ImportError:
            from testcontainers.postgres import PostgresContainer
        c = PostgresContainer("postgres:17", driver="asyncpg")
        c.start()
    except Exception as exc:
        raise StackUnavailable("no PostgreSQL for the e2e suite: set CIRA_E2E_DATABASE_URL to a server the tests "
                               "may create databases on, or start Docker for testcontainers "
                               f"({type(exc).__name__}: {str(exc).splitlines()[0][:160] if str(exc) else ''})") from exc
    return Database(url=c.get_connection_url(), kind="testcontainers", name=make_url(c.get_connection_url()).database,
                    container=c)


def migrate(url: str) -> str:
    """alembic upgrade head on ``url``; returns the revision now stored there."""
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
    return asyncio.run(scalar(url, "SELECT version_num FROM alembic_version"))


async def _query(url: str, sql: str, params: dict | None = None, one: bool = False):
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(url, connect_args={"timeout": 5} if "asyncpg" in url else {})
    try:
        async with engine.connect() as c:
            r = await c.execute(text(sql), params or {})
            return r.scalar() if one else [dict(x._mapping) for x in r.all()]
    finally:
        await engine.dispose()


def scalar(url: str, sql: str, **params):
    return _query(url, sql, params, one=True)


def rows(url: str, sql: str, **params) -> list[dict]:
    return asyncio.run(_query(url, sql, params))


# --- the world (Chapters 5-12 on raw CSV) ----------------------------------------------------

def build_world(root: Path) -> dict:
    """Raw synthetic CERT tree -> alert run, through the production entry points. Returns every run record."""
    from app.alerts import batch as alert_batch
    from app.cri import batch as cri_batch
    from app.cri import calibrate as cri_calibrate
    from app.explainability import batch as explain_batch
    from app.feature_engineering.pipeline import run_pipeline
    from app.ingestion.ground_truth import build_insider_label_tables
    from app.mitre import batch as mitre_batch
    from app.mitre import calibrate as mitre_calibrate
    from app.scoring import batch as score_batch
    from app.scoring import gbdt_candidate
    from app.tabnet.train import _parse_args as tabnet_args
    from app.tabnet.train import run as tabnet_run
    from fixtures import synthetic_ch6

    timings: dict[str, float] = {}

    def timed(name, fn):
        t0 = time.perf_counter()
        out = fn()
        timings[name] = round(time.perf_counter() - t0, 2)
        return out

    paths = synthetic_ch6.build(root)
    processed, models, splits = root / "processed", root / "models", root / "splits"
    exp = root / "experiments"
    w: dict[str, Any] = {"root": root, "raw": paths["raw"], "ground_truth": paths["gt"], "processed": processed,
                         "models": models, "splits": splits, "insiders": paths["insiders"], "timings": timings}
    common = ["--processed-dir", str(processed), "--profile", "full", "--splits-dir", str(splits),
              "--models-dir", str(models)]
    with pinned_env(root):
        timed("chapter5_features", lambda: run_pipeline(paths["raw"], processed, profile="full",
                                                         ground_truth_dir=paths["gt"]))
        timed("labels", lambda: build_insider_label_tables(paths["gt"], processed))
        w["gbdt"] = timed("chapter8_gbdt_train", lambda: gbdt_candidate.run(gbdt_candidate._parse_args(
            common + ["--results-dir", str(root / "r8"), "--device", "cpu"])))
        w["tabnet"] = timed("chapter7_tabnet_train", lambda: tabnet_run(tabnet_args(
            common + ["--checkpoint-dir", str(root / "ckpt"), "--results-dir", str(root / "r7"), "--max-epochs", "3",
                      "--batch-size", "512", "--virtual-batch-size", "128", "--device", "cpu",
                      "--exclude-features", STATIC])))
        w["batch"] = timed("chapter8_batch", lambda: score_batch.run(score_batch._parse_args(
            ["--processed-dir", str(processed), "--profile", "full", "--with-shadow", "--splits-dir", str(splits)])))
        cri = ["--processed-dir", str(processed), "--profile", "full", "--models-dir", str(models),
               "--pin-path", str(exp / "chapter9_cri_calibration.json")]
        rc = timed("chapter9_calibrate", lambda: cri_calibrate.main(cri + ["--min-reference-rows", "50"]))
        if rc != 0:
            raise RuntimeError(f"CRI calibration exited {rc}")
        timed("chapter10_reference", lambda: mitre_calibrate.run(mitre_calibrate._parse_args(
            common + ["--pin-path", str(exp / "chapter10_mitre_reference.json"), "--min-reference-rows", "50"])))
        w["mitre"] = timed("chapter10_enrich", lambda: mitre_batch.run(mitre_batch._parse_args(
            ["--processed-dir", str(processed), "--profile", "full", "--models-dir", str(models),
             "--pin-path", str(exp / "chapter10_mitre_reference.json")])))
        w["cri"] = timed("chapter9_cri", lambda: cri_batch.run(cri_batch._parse_args(
            cri + ["--mitre-run-id", w["mitre"]["mitre_run_id"]])))
        w["explain"] = timed("chapter11_explain", lambda: explain_batch.run(explain_batch._parse_args(
            ["--processed-dir", str(processed), "--profile", "full", "--splits-dir", str(splits),
             "--max-bounded-rows", "40", "--n-background", "20"])))
        w["alerts"] = timed("chapter12_alerts", lambda: alert_batch.run(alert_batch._parse_args(
            ["--processed-dir", str(processed), "--profile", "full"])))
    return w


def reproduce_training(w: dict) -> dict:
    """§45 item 16 on the fixture: the same split and seed train the same model with the same metrics."""
    from app.scoring import gbdt_candidate

    root = w["root"]
    with pinned_env(root):
        again = gbdt_candidate.run(gbdt_candidate._parse_args(
            ["--processed-dir", str(w["processed"]), "--profile", "full", "--splits-dir", str(w["splits"]),
             "--models-dir", str(root / "models_repeat"), "--results-dir", str(root / "r8_repeat"),
             "--device", "cpu"]))

    def metrics(run: dict) -> dict:
        r = json.loads(Path(run["results_path"]).read_text(encoding="utf-8"))["models"]["gbdt"]
        return {"model_version": r["metadata"]["model_version"],
                "validation": r["validation"]["primary"], "test": r["test"]["primary"]}

    first, second = metrics(w["gbdt"]), metrics(again)
    for m in (first, second):                       # wall-clock fields are not results
        for part in ("validation", "test"):
            m[part] = {k: v for k, v in m[part].items() if "seconds" not in k}
    return {"first": first, "second": second, "identical": first == second}


# --- the traced raw event ----------------------------------------------------------------------

def choose_trace(w: dict) -> dict:
    """The raw CSV row followed through the chain. Chosen from the pipeline's decisions, never planted."""
    import pandas as pd

    alerts = pd.read_parquet(w["alerts"]["outputs"]["alerts.parquet"])
    top = alerts[alerts["status"] == "open"].sort_values(["queue_score", "peak_date"], ascending=[False, True]).iloc[0]
    user, day = str(top["user_id"]), str(top["peak_date"])
    for domain, activity in TRACE_PREFERENCE:
        with open(w["raw"] / DOMAIN_FILES[domain], newline="", encoding="utf-8") as fh:
            for line_no, row in enumerate(csv.DictReader(fh), start=2):
                if row["user"].strip().casefold() != user:
                    continue
                if pd.to_datetime(row["date"], format="%m/%d/%Y %H:%M:%S").strftime("%Y-%m-%d") != day:
                    continue
                if activity and row.get("activity", "").strip().casefold() != activity:
                    continue
                return {"domain": domain, "raw_id": row["id"].strip(), "raw_file": str(w["raw"] / DOMAIN_FILES[domain]),
                        "raw_line": line_no, "raw_row": row, "user_id": user, "date": day,
                        "alert_key": str(top["alert_key"]), "queue_score": float(top["queue_score"])}
    raise RuntimeError(f"no raw event of {user} on {day}: the alert's peak day has no activity, which the "
                       "policy's require_activity rule forbids (N56)")


# --- loads (§36 / N58) -----------------------------------------------------------------------

LINEAGE_TABLES = ("alerts", "alert_members", "alert_reasons", "feature_vectors", "event_logs", "anomaly_scores",
                  "risk_scores", "mitre_mappings", "model_versions")


def table_counts(url: str) -> dict[str, int]:
    out = {t: asyncio.run(scalar(url, f"SELECT count(*) FROM {t}")) for t in LINEAGE_TABLES}
    out["alert_run_loaded"] = asyncio.run(scalar(url, "SELECT count(*) FROM audit_logs WHERE action = 'alert_run_loaded'"))
    return out


def _load(w: dict, url: str, *extra: str) -> tuple[int, str]:
    import io

    from app.alerts import load as alert_load

    err = io.StringIO()
    with pinned_env(w["root"]), contextlib.redirect_stderr(err):
        rc = alert_load.main(["--processed-dir", str(w["processed"]), "--profile", "full",
                              "--database-url", url, *extra])
    return rc, err.getvalue()


def refused_connection_load(w: dict, db: Database) -> dict:
    """The database refuses the connection: NOT STORED, exit 3, nothing in the real database."""
    from sqlalchemy.engine import make_url

    dead = make_url(db.url).set(host="127.0.0.1", port=1).render_as_string(hide_password=False)
    rc, err = _load(w, dead, "--connect-timeout", "3")
    return {"exit_code": rc, "stderr": err[-600:], "counts_after": table_counts(db.url)}


def mid_load_failure(w: dict, db: Database) -> dict:
    """The connection breaks after alerts and members are written: the transaction rolls back, nothing stays."""
    from app.alerts import persistence

    original = persistence._insert
    seen: list[str] = []

    def failing_insert(conn, table, rows_):
        seen.append(table.name)
        if table.name == "alert_reasons":
            raise ConnectionResetError("e2e: connection lost while writing alert_reasons")
        return original(conn, table, rows_)

    persistence._insert = failing_insert
    try:
        rc, err = _load(w, db.url)
    finally:
        persistence._insert = original
    return {"exit_code": rc, "stderr": err[-600:], "tables_written_before_failure": seen,
            "counts_after": table_counts(db.url)}


def real_load(w: dict, db: Database) -> dict:
    rc, err = _load(w, db.url)
    if rc != 0:
        raise RuntimeError(f"the real load failed with exit {rc}: {err[-800:]}")
    return {"exit_code": rc, "counts_after": table_counts(db.url)}


def create_analyst(url: str) -> str:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.services import accounts

    username = f"e2e-analyst-{uuid.uuid4().hex[:6]}"

    async def go():
        engine = create_async_engine(url)
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as s:
                await accounts.create(s, username=username, email=f"{username}@example.org", password=PASSWORD)
        finally:
            await engine.dispose()

    asyncio.run(go())
    return username


# --- the stack -------------------------------------------------------------------------------

@dataclass
class Stack:
    root: Path
    world: dict
    db: Database
    alembic_revision: str
    alert_run_id: str
    username: str
    password: str
    secret: str
    trace: dict
    loads: dict
    reproducibility: dict
    build_seconds: dict = field(default_factory=dict)

    def manifest(self) -> dict:
        """What the Playwright click-through and the verifier need, as JSON."""
        return {"root": str(self.root), "database": {"kind": self.db.kind, "name": self.db.name, "url": self.db.url},
                "alembic_revision": self.alembic_revision, "alert_run_id": self.alert_run_id,
                "username": self.username, "password": self.password, "secret": self.secret,
                "trace": {k: v for k, v in self.trace.items() if k != "raw_row"} | {"raw_row": self.trace["raw_row"]},
                "pins": pins(self.root), "loads": self.loads, "reproducibility": self.reproducibility,
                "build_seconds": self.build_seconds, "timings": self.world["timings"]}


def build_stack(root: Path, db: Database | None = None) -> Stack:
    """Everything in the module docstring, in order. Raises StackUnavailable when there is no PostgreSQL."""
    t0 = time.perf_counter()
    root.mkdir(parents=True, exist_ok=True)
    db = db or provision_database()
    try:
        t_db = time.perf_counter()
        revision = migrate(db.url)
        migrate_s = time.perf_counter() - t_db
        t_w = time.perf_counter()
        world = build_world(root)
        world_s = time.perf_counter() - t_w
        trace = choose_trace(world)
        loads = {"refused_connection": refused_connection_load(world, db),
                 "mid_load_failure": mid_load_failure(world, db)}
        t_l = time.perf_counter()
        loads["real"] = real_load(world, db)
        load_s = time.perf_counter() - t_l
        username = create_analyst(db.url)
        repro = reproduce_training(world)
    except Exception:
        db.drop()
        raise
    return Stack(root=root, world=world, db=db, alembic_revision=revision,
                 alert_run_id=world["alerts"]["alert_run_id"], username=username, password=PASSWORD, secret=SECRET,
                 trace=trace, loads=loads, reproducibility=repro,
                 build_seconds={"total": round(time.perf_counter() - t0, 1), "migrate": round(migrate_s, 1),
                                "chapters_5_to_12": round(world_s, 1), "load": round(load_s, 1)})


def write_manifest(stack: Stack, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(stack.manifest(), indent=2, default=str), encoding="utf-8")
    return path


__all__ = ["Database", "Stack", "StackUnavailable", "build_stack", "pinned_env", "pins", "provision_database",
           "rows", "scalar", "table_counts", "write_manifest", "PASSWORD", "SECRET", "asdict"]
