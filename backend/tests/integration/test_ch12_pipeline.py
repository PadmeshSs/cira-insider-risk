"""Chapter 12 end to end on the synthetic CERT tree, with real models:

Chapters 5-11 (as in the Chapter 11 test) -> alert batch -> verifier ->
bounded load into a database -> verifier with the database checks ->
validation readout -> verifier again -> reload refused -> outage refused
visibly -> tampering caught -> API health.

The database is SQLite by default (created from the ORM; the migration itself
is checked against the ORM in the unit tests). Set ``CIRA_TEST_DATABASE_URL``
to a PostgreSQL URL at the Chapter 12 head (``alembic upgrade head``) to run
the same load through asyncpg as well.
"""
import importlib.util
import json
import os
from pathlib import Path

import pandas as pd
import pytest
import sqlalchemy as sa

import app.database.models  # noqa: F401
from app.alerts import batch as alert_batch
from app.alerts import evaluate as alert_evaluate
from app.alerts import load as alert_load
from app.alerts.sources import ALERTS_OUTPUT, MEMBERS_OUTPUT, REASONS_OUTPUT, load_records, read_explanations
from app.database.base import Base
from app.explainability import batch as explain_batch

REPO = Path(__file__).resolve().parents[3]


def _module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


T11 = _module(Path(__file__).with_name("test_ch11_pipeline.py"), "ch11_world")


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    w = T11.world.__wrapped__(tmp_path_factory)
    mp = pytest.MonkeyPatch()
    for k, v in T11._env(w).items():
        mp.setenv(k, v)
    try:
        w["explain"] = explain_batch.run(explain_batch._parse_args(T11._explain_args(w)))
    finally:
        mp.undo()
    w["readout12"] = w["root"] / "experiments" / "chapter12_validation_readout.json"
    w["db"] = w["root"] / "cira.sqlite"
    engine = sa.create_engine(f"sqlite:///{w['db']}")
    Base.metadata.create_all(engine)
    engine.dispose()
    return w


@pytest.fixture(autouse=True)
def _pins(world, monkeypatch):
    for k, v in T11._env(world).items():
        monkeypatch.setenv(k, v)
    for k in [k for k in os.environ if k.startswith(("CRI_", "MITRE_"))]:
        monkeypatch.delenv(k)


def _args(world, *extra):
    return ["--processed-dir", str(world["processed"]), "--profile", "full", *extra]


@pytest.fixture(scope="module")
def alerts(world):
    mp = pytest.MonkeyPatch()
    for k, v in T11._env(world).items():
        mp.setenv(k, v)
    try:
        return alert_batch.run(alert_batch._parse_args(_args(world)))
    finally:
        mp.undo()


def _verify(world, *extra):
    verify = _module(REPO / "scripts" / "verify_chapter12.py", "verify_chapter12")
    return verify.main(_args(world, "--readout-path", str(world["readout12"]), "--results-dir",
                             str(world["root"] / "r12"), *extra))


def test_alert_run_is_built_from_one_lineage(world, alerts):
    assert alerts["explain_run"]["explain_run_id"] == world["explain"]["explain_run_id"]
    assert alerts["risk_run"]["cri_run_id"] == world["explain"]["risk_run"]["cri_run_id"]
    assert alerts["served"]["model_name"] == "gbdt" and alerts["policy_overrides"] == {}
    s = alerts["summary"]
    assert s["open_alerts"] > 0 and s["member_days"] >= s["alerts"] > 0
    assert s["candidate_rows_by_model_split"].keys() <= {"validation", "test", "unassigned"}          # N31
    assert "open_alerts_led_by_usb_disconnect_count" in s and s["other_ordering_view"]["ordering"] == "cri_score"
    v = s["activity_rule_view"]
    assert v["require_activity"] is False and v["top_k_user_days_changed"] >= v["top_k_dates_changed"] >= 0
    d = Path(alerts["outputs"][ALERTS_OUTPUT]).parent
    members = pd.read_parquet(d / MEMBERS_OUTPUT)
    expl = read_explanations(d)
    assert len(expl) == len(members) and all(e["headline"]["model_name"] == "gbdt" for e in expl)
    reasons = pd.read_parquet(d / REASONS_OUTPUT)
    assert set(reasons["section"]) <= {"model", "model_lowering", "cri", "mitre"} and "mitre" in set(reasons["section"])
    lines = [json.loads(x) for x in (world["root"] / "runlog.jsonl").read_text().splitlines()]
    assert any(x.get("stage") == "chapter12_alert_batch" and x["alert_run_id"] == alerts["alert_run_id"] for x in lines)


def test_verifier_load_readout_and_database(world, alerts, capsys):
    assert _verify(world, "--no-readout") == 0
    assert " 0 FAIL" in capsys.readouterr().out
    url = f"sqlite:///{world['db']}"
    assert alert_load.main(_args(world, "--database-url", url)) == 0
    assert "stored alert run" in capsys.readouterr().out
    assert len(load_records(Path(alerts["outputs"][ALERTS_OUTPUT]).parent)) == 1
    assert alert_load.main(_args(world, "--database-url", url)) == 2                  # loaded once
    assert "already loaded" in capsys.readouterr().err
    readout = alert_evaluate.run(alert_evaluate._parse_args(_args(world, "--readout-path", str(world["readout12"]))))
    assert readout["part"] == "validation" and readout["other_ordering_view"]["ordering"] == "cri_score"
    assert alert_evaluate.main(_args(world, "--readout-path", str(world["readout12"]))) == 2          # written once
    assert _verify(world, "--database-url", url) == 0
    out = capsys.readouterr().out
    assert " 0 FAIL" in out and "every member traces alert -> risk -> anomaly" in out
    engine = sa.create_engine(url)
    with engine.connect() as c:
        roles = {r[0] for r in c.execute(sa.text("SELECT DISTINCT role FROM anomaly_scores"))}
        n = c.execute(sa.text("SELECT count(*) FROM alerts WHERE alert_run_id = :r"), {"r": alerts["alert_run_id"]}).scalar()
    assert roles == {"served"} and n == alerts["summary"]["alerts"]


def test_outage_is_visible_and_claims_nothing(world, alerts, capsys):
    before = len(load_records(Path(alerts["outputs"][ALERTS_OUTPUT]).parent))
    bad = "postgresql+asyncpg://cira:x@127.0.0.1:1/none"
    assert alert_load.main(_args(world, "--database-url", bad, "--connect-timeout", "3")) == 3
    assert "NOT STORED" in capsys.readouterr().err
    assert len(load_records(Path(alerts["outputs"][ALERTS_OUTPUT]).parent)) == before
    lines = [json.loads(x) for x in (world["root"] / "runlog.jsonl").read_text().splitlines()]
    assert lines[-1]["stage"] == "chapter12_alert_load" and lines[-1]["status"] == "not_stored"


@pytest.mark.skipif(not os.getenv("CIRA_TEST_DATABASE_URL"), reason="set CIRA_TEST_DATABASE_URL to a PostgreSQL at head")
def test_postgres_load_through_asyncpg(world, alerts, capsys):
    url = os.environ["CIRA_TEST_DATABASE_URL"]
    rc = alert_load.main(_args(world, "--database-url", url))
    assert rc in (0, 2), capsys.readouterr().err
    assert _verify(world, "--no-readout", "--database-url", url) == 0


def test_tampering_is_caught(world, alerts, tmp_path, capsys):
    d = Path(alerts["outputs"][ALERTS_OUTPUT]).parent
    path = d / ALERTS_OUTPUT
    original = path.read_bytes()
    try:
        frame = pd.read_parquet(path)
        frame.loc[0, "max_severity"] = "CRITICAL" if frame.loc[0, "max_severity"] != "CRITICAL" else "LOW"
        frame.to_parquet(path, index=False)
        assert _verify(world, "--no-readout") == 1
        assert "FAIL alerts       alerts, spans, peaks and statuses reproduce" in capsys.readouterr().out
    finally:
        path.write_bytes(original)


def test_batch_refuses_a_model_that_did_not_score(world, alerts, monkeypatch, capsys):
    monkeypatch.setenv("CIRA_SERVED_MODEL", "tabnet:v0001")                        # a rollback without new runs
    monkeypatch.delenv("CIRA_SHADOW_MODEL")
    assert alert_batch.main(_args(world)) == 2
    assert "(N28, N30)" in capsys.readouterr().err
    assert alert_load.main(_args(world, "--database-url", f"sqlite:///{world['db']}")) == 2
    assert "N28" in capsys.readouterr().err


def test_readout_refuses_test(world, alerts):
    with pytest.raises(alert_evaluate.ReadoutRefused, match="validation only"):
        alert_evaluate.run(alert_evaluate._parse_args(_args(world, "--part", "test", "--readout-path",
                                                            str(world["root"] / "x.json"))))


def test_api_health_shows_the_alert_run(world, alerts, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.setenv("CERT_PROCESSED_DIR", str(world["processed"]))
    monkeypatch.setenv("CIRA_PROFILE", "dev")
    from app.core import config

    monkeypatch.setattr(config.settings, "cert_processed_dir", str(world["processed"]))
    # CIRA_PROFILE is the batch budget; the API must follow the served
    # model's profile even when the budget says dev (found on the dev machine).
    monkeypatch.setattr(config.settings, "cira_profile", "dev")
    with TestClient(app) as client:
        body = client.get("/health").json()
    a = body["alerts"]
    assert a["status"] == "loaded" and a["alert_run_id"] == alerts["alert_run_id"]
    assert a["policy"]["version"] == "c12-alert-policy-v1" and a["shadow"].startswith("never")
