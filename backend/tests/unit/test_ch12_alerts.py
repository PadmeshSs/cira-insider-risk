"""Chapter 12 unit tests: policy, correlation, deduplication, demo sample, entities, migration, persistence."""
import ast
import asyncio
import importlib.util
from datetime import date, datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.orm import Session

import app.database.models as models
from app.alerts.correlation import alert_key, correlate
from app.alerts.deduplication import deduplicate, signature
from app.alerts.demo import demo_sample
from app.alerts.explain import reason_rows
from app.alerts.persistence import AlreadyLoadedError, LoadPlan, PersistenceError, check_stored, loaded_runs, persist
from app.alerts.policy import POLICY_VERSION, AlertPolicy, AlertPolicyError, daily_top_k, triggers
from app.database.base import Base
from app.explainability.reason_builder import build_explanation, model_evidence

VERSIONS = Path(__file__).resolve().parents[2] / "alembic" / "versions"
CH12_REVISION = "9f3b2c7d4e81"
SERVING = ("policy", "correlation", "deduplication", "demo", "explain", "sources", "batch", "persistence", "load", "runtime")


def _days(rows):
    """rows: (user, date, score[, band, top_k, top_feature, techniques])."""
    out = []
    for r in rows:
        u, d, s = r[:3]
        out.append({"user_id": u, "date": d, "model_split": "test", "anomaly_score": s, "cri_score": 100 * s,
                    "severity": "HIGH" if (len(r) > 3 and r[3]) else "LOW", "by_band": bool(len(r) > 3 and r[3]),
                    "by_top_k": bool(r[4]) if len(r) > 4 else True,
                    "top_feature": r[5] if len(r) > 5 else "usb_connect_count",
                    "techniques": r[6] if len(r) > 6 else None})
    return pd.DataFrame(out)


# --- policy -------------------------------------------------------------------------------

def test_policy_defaults_hash_and_overrides():
    p = AlertPolicy()
    assert p.to_dict()["version"] == POLICY_VERSION and p.ordering == "anomaly_score" and p.require_activity
    assert (p.band_severities, p.top_k_per_day, p.correlation_gap_days, p.max_span_days, p.cooldown_days) == \
        (("HIGH", "CRITICAL"), 1, 3, 14, 7)
    assert AlertPolicy.from_dict(p.to_dict()) == p and AlertPolicy().policy_hash == p.policy_hash
    assert p.overrides() == {} and AlertPolicy(tie_break_seed=7).overrides() == {}       # the seed follows CIRA_SEED
    assert AlertPolicy(cooldown_days=10).overrides() == {"cooldown_days": 10}
    assert AlertPolicy(cooldown_days=10).policy_hash != p.policy_hash
    for bad in (dict(ordering="probability"), dict(band_severities=("SEVERE",)), dict(band_severities=(), top_k_per_day=0),
                dict(max_span_days=0)):
        with pytest.raises(AlertPolicyError):
            AlertPolicy(**bad)
    with pytest.raises(AlertPolicyError, match="version"):
        AlertPolicy.from_dict({**p.to_dict(), "version": "c12-alert-policy-v0"})


def test_seeded_top_k_matches_the_evaluation_harness():
    from app.evaluation.metrics import daily_top_k as harness

    rng = np.random.default_rng(3)
    dates = pd.Series(np.repeat(["2010-01-04", "2010-01-05", "2010-01-06"], 40))
    s = np.round(rng.random(120), 1)                       # many ties
    for k in (1, 3):
        assert (daily_top_k(dates, s, k, seed=42) == harness(dates, s, k, seed=42)).all()


def test_triggers_band_or_top_k_and_idle_days_never_take_a_slot():
    risk = pd.DataFrame({"user_id": ["a", "b", "c", "a", "b"], "date": ["2010-01-04"] * 3 + ["2010-01-05"] * 2,
                         "severity": ["LOW", "LOW", "HIGH", "LOW", "LOW"], "anomaly_score": [0.9, 0.5, 0.1, 0.2, 0.3],
                         "cri_score": [10, 60, 80, 5, 50]})
    activity = np.array([0, 12, 3, 5, 0])                  # a is idle on the 4th, b on the 5th
    t = triggers(risk, AlertPolicy(), activity)
    assert t["by_band"].tolist() == [False, False, True, False, False]
    assert t["by_top_k"].tolist() == [False, True, False, True, False]     # the idle top scorer is skipped
    t2 = triggers(risk, AlertPolicy(require_activity=False), activity)
    assert t2["by_top_k"].tolist() == [True, False, False, False, True]
    t3 = triggers(risk, AlertPolicy(ordering="cri_score"), activity)
    assert t3["by_top_k"].tolist() == [False, False, True, True, False]
    with pytest.raises(AlertPolicyError, match="activity"):
        triggers(risk, AlertPolicy())


# --- correlation --------------------------------------------------------------------------

def test_related_days_become_one_alert_not_four():
    """Bible Ch12 acceptance: unusual logon, large copy, archive, external visit -> one alert."""
    days = _days([("u1", "2010-03-01", 0.6), ("u1", "2010-03-02", 0.9), ("u1", "2010-03-03", 0.7),
                  ("u1", "2010-03-04", 0.8)])
    alerts, members = correlate(days, AlertPolicy())
    assert len(alerts) == 1 and len(members) == 4
    a = alerts.iloc[0]
    assert (a["first_date"], a["last_date"], a["n_days"], a["peak_date"]) == ("2010-03-01", "2010-03-04", 4, "2010-03-02")
    assert a["queue_score"] == 0.9 and members["is_peak"].sum() == 1
    assert a["alert_key"] == alert_key(AlertPolicy().policy_hash, "u1", "2010-03-01")


def test_gap_span_and_users_split_alerts():
    days = _days([("u1", "2010-03-05", 0.5), ("u1", "2010-03-08", 0.5),          # Friday -> Monday: 3 days, one alert
                  ("u1", "2010-03-12", 0.5),                                   # 4 days later: a new alert
                  ("u2", "2010-03-05", 0.5)])                                  # another user: never merged
    alerts, _ = correlate(days, AlertPolicy())
    assert sorted(zip(alerts["user_id"], alerts["first_date"], alerts["n_days"])) == \
        [("u1", "2010-03-05", 2), ("u1", "2010-03-12", 1), ("u2", "2010-03-05", 1)]
    daily = _days([("u1", str(d.date()), 0.5) for d in pd.date_range("2010-04-01", periods=30)])
    alerts, _ = correlate(daily, AlertPolicy())
    assert alerts["span_days"].max() <= 14 and alerts["n_days"].tolist() == [14, 14, 2]
    with pytest.raises(ValueError, match="twice"):
        correlate(pd.concat([days, days.iloc[:1]]), AlertPolicy())


def test_alert_carries_context_but_never_changes_a_score():
    days = _days([("u1", "2010-03-01", 0.6, True, False, "http_leak_paste_count", "T1567.002"),
                  ("u1", "2010-03-02", 0.9, False, True, "usb_disconnect_count", "T1052.001,T1567.002")])
    alerts, members = correlate(days, AlertPolicy())
    a = alerts.iloc[0]
    assert a["techniques"] == "T1052.001,T1567.002" and a["max_severity"] == "HIGH" and a["triggers"] == "band,top_k"
    assert a["top_feature"] == "usb_disconnect_count"                         # the peak day's factor (N52)
    assert members["anomaly_score"].tolist() == [0.6, 0.9]


# --- deduplication ------------------------------------------------------------------------

def _alerts(rows):
    return pd.DataFrame([{"alert_key": k, "user_id": u, "first_date": f, "last_date": l, "techniques": t, "top_feature": tf}
                         for k, u, f, l, t, tf in rows])


def test_repeat_inside_cooldown_is_suppressed_and_kept():
    a = deduplicate(_alerts([
        ("A", "u1", "2010-03-01", "2010-03-02", "T1052.001", "usb_connect_count"),
        ("B", "u1", "2010-03-07", "2010-03-07", "T1052.001", "usb_connect_count"),     # same pattern, 5 days later
        ("C", "u1", "2010-03-12", "2010-03-12", "T1052.001,T1567.002", "usb_connect_count"),  # new technique
        ("D", "u1", "2010-03-30", "2010-03-30", "T1052.001", "usb_connect_count"),     # cooldown over
        ("E", "u2", "2010-03-03", "2010-03-03", "T1052.001", "usb_connect_count"),     # other user
    ]), AlertPolicy())
    got = dict(zip(a["alert_key"], zip(a["status"], a["duplicate_of"])))
    assert got["A"] == ("open", None) and got["B"] == ("suppressed", "A")
    assert got["C"] == ("open", None) and got["D"] == ("open", None) and got["E"] == ("open", None)


def test_suppression_compares_with_open_alerts_only_and_needs_a_signature():
    a = deduplicate(_alerts([
        ("A", "u1", "2010-03-01", "2010-03-01", None, "usb_connect_count"),
        ("B", "u1", "2010-03-05", "2010-03-05", None, "usb_connect_count"),            # suppressed by A
        ("C", "u1", "2010-03-12", "2010-03-12", None, "usb_connect_count"),            # 11 days after A: open
        ("D", "u2", "2010-03-01", "2010-03-01", None, None),
        ("E", "u2", "2010-03-04", "2010-03-04", None, None),                           # nothing identifies it: open
    ]), AlertPolicy())
    got = dict(zip(a["alert_key"], a["status"]))
    assert got == {"A": "open", "B": "suppressed", "C": "open", "D": "open", "E": "open"}
    assert signature("T1,T2", "x") == ["T1", "T2", "factor:x"] and signature(None, None) == []


# --- demo sample --------------------------------------------------------------------------

def test_demo_sample_is_out_of_sample_bounded_and_deterministic():
    dates = [str(d.date()) for d in pd.date_range("2010-01-01", periods=60)]
    keys = pd.DataFrame([(u, d, s) for u, s in [("t1", "test"), ("t2", "test"), ("t3", "test"), ("v1", "validation"),
                                                ("tr", "train")] for d in dates], columns=["user_id", "date", "model_split"])
    alerts = pd.DataFrame([{"user_id": "t2", "peak_date": "2010-02-10", "status": "open", "model_split": "test", "queue_score": 0.9},
                           {"user_id": "t2", "peak_date": "2010-02-12", "status": "open", "model_split": "test", "queue_score": 0.8},
                           {"user_id": "tr", "peak_date": "2010-01-05", "status": "open", "model_split": "train", "queue_score": 1.0}])
    rows, info = demo_sample(keys, alerts, window_days=10, max_users=3, max_alerting_users=1, seed=42)
    assert info["window"] == {"start": "2010-02-10", "end": "2010-02-19"}
    assert info["users"][0] == "t2" and len(info["users"]) == 3 and "tr" not in info["users"]
    assert set(rows["user_id"]) <= {"t1", "t2", "t3", "v1"} and len(rows) == 30
    again, _ = demo_sample(keys, alerts, window_days=10, max_users=3, max_alerting_users=1, seed=42)
    assert again.equals(rows)


# --- explanation rows ---------------------------------------------------------------------

def test_reason_rows_keep_section_and_source():
    risk = {"user_id": "u1", "date": "2010-03-02", "model_version": "mv", "anomaly_score": 0.9, "cri_score": 60.0,
            "severity": "HIGH", "points_anomaly": 50.0, "points_historical_deviation": 10.0, "historical_top_feature": None,
            "cri_run_id": "r", "calibration_id": "c", "cri_config_hash": "h"}
    model = model_evidence({"raw_score": 2.2, "expected_value": -1.0}, [
        {"feature": "usb_connect_count", "contribution": 2.5, "feature_value": 4.0},
        {"feature": "http_request_count", "contribution": -0.3, "feature_value": 20.0}],
        method="treeshap", model_name="gbdt", model_version="mv", registry_version="v0003", anomaly_score=0.9)
    expl = build_explanation("u1", "2010-03-02", model=model, risk=risk, mitre=None, mitre_unavailable_reason="none joined")
    expl.update(alert_key="K", explain_run_id="E")
    rows = reason_rows(expl)
    by = {r["section"]: r for r in rows}
    assert set(by) == {"model", "model_lowering", "cri"}
    assert by["model"]["subject"] == "usb_connect_count" and by["model"]["weight"] == 2.5 and '"kind": "model"' in by["model"]["source"]
    assert by["cri"]["subject"] == "historical_deviation" and by["cri"]["weight"] == 10.0
    assert by["model_lowering"]["text"][0].isupper() and all(r["model_version"] == "mv" for r in rows)


# --- entities and migration ---------------------------------------------------------------

def _engine():
    engine = sa.create_engine("sqlite://")
    with engine.connect() as c:
        c.exec_driver_sql("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    return engine


def _base_rows(s):
    mv = models.ModelVersion(model_name="gbdt", registry_version="v0001", model_version="mv", files={"m.json": "abc"})
    fv = models.FeatureVector(user_id="u1", activity_date=date(2010, 3, 2), profile="full", features_fingerprint="fp",
                              source_path="x", values={"a": None}, loaded_for="alert", first_alert_run_id="r")
    s.add_all([mv, fv])
    s.flush()
    return mv, fv


def test_entities_refuse_what_the_chapter_forbids():
    engine = _engine()
    with Session(engine) as s:
        mv, fv = _base_rows(s)
        s.commit()
        mv_id, fv_id = mv.id, fv.id
    common = dict(user_id="u1", activity_date=date(2010, 3, 2), feature_vector_id=fv_id, model_version_id=mv_id,
                  model_name="gbdt", model_version="mv", registry_version="v0001", model_split="test", raw_score=1.0,
                  anomaly_score=0.7, batch_run_id="b")
    with Session(engine) as s, pytest.raises(sa.exc.IntegrityError):
        s.add(models.AnomalyScore(role="shadow", **common))                       # N32
        s.commit()
    alert = dict(alert_run_id="run", user_id="u1", first_date=date(2010, 3, 1), last_date=date(2010, 3, 3),
                 peak_date=date(2010, 3, 2), n_days=2, peak_anomaly_score=0.7, peak_cri_score=50, max_cri_score=50,
                 max_severity="HIGH", queue_score=0.7, ordering="anomaly_score", model_split="test",
                 explanation_status="complete", policy_version=POLICY_VERSION, policy_hash="h", model_version_id=mv_id,
                 model_version="mv", batch_run_id="b", cri_run_id="c", explain_run_id="e")
    for bad in (dict(alert_key="k1", status="suppressed"),                                        # names no original
                dict(alert_key="k2", status="open", peak_date=date(2010, 3, 9)),                   # peak outside span
                dict(alert_key="k3", status="open", explanation_status="guessed")):
        with Session(engine) as s, pytest.raises(sa.exc.IntegrityError):
            s.add(models.Alert(**{**alert, **bad}))
            s.commit()
    with Session(engine) as s:
        s.add(models.Alert(alert_key="ok", status="open", **alert))
        s.commit()
    with Session(engine) as s, pytest.raises(sa.exc.IntegrityError):
        s.add(models.AlertReason(alert_id=1, member_id=1, user_id="u1", activity_date=date(2010, 3, 2), section="mitre",
                                 rank=1, subject="T1567", text="x", source={}, model_version="mv", explain_run_id="e"))
        s.commit()                                                                                  # names no rule (N45)


def _mods():
    out = []
    for p in VERSIONS.glob("*.py"):
        spec = importlib.util.spec_from_file_location(p.stem, p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        out.append(m)
    return out


def test_migration_is_the_head_and_the_chain_matches_the_orm():
    mods = _mods()
    heads = {m.revision for m in mods} - {m.down_revision for m in mods}
    assert heads == {CH12_REVISION}
    by = {m.down_revision: m for m in mods}
    chain, rev = [], None
    while rev in by:
        chain.append(by[rev])
        rev = by[rev].revision
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            for m in chain:
                m.upgrade()
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            chain[-1].downgrade()
        names = sa.inspect(conn).get_table_names()
        assert "alerts" not in names and "event_logs" not in names
        assert "alert_id" not in [c["name"] for c in sa.inspect(conn).get_columns("mitre_mappings")]


# --- persistence --------------------------------------------------------------------------

def _plan(run="run-1", **over):
    d = "2010-03-02"
    fv = {"user_id": "u1", "activity_date": d, "profile": "full", "features_fingerprint": "fp", "pipeline_version": "p",
          "source_path": "m.parquet", "values": {"total_event_count": 3.0, "hour": None}, "loaded_for": "alert"}
    demo = {**fv, "user_id": "u2", "loaded_for": "demo"}
    ev = {"source_type": "device", "event_type": "device_connect", "event_id": "{E1}", "user_id": "u1", "device_id": "pc-1",
          "event_time": datetime(2010, 3, 2, 23, 5, tzinfo=timezone.utc), "activity_date": d,
          "details": {"activity": "connect"}, "source_path": "part-0.parquet", "loaded_for": "alert"}
    score = {"model_name": "gbdt", "model_version": "mv", "registry_version": "v0001", "role": "served", "model_split": "test",
             "raw_score": 1.0, "anomaly_score": 0.73, "batch_run_id": "b"}
    risk = {"cri_score": 55.0, "severity": "HIGH", "components": {"anomaly": 0.9}, "points": {"anomaly": 54.0},
            "model_version": "mv", "cri_version": "v", "cri_config_hash": "h", "cri_variant": "default",
            "calibration_id": "c", "formula_hash": "f", "cri_run_id": "cri", "mitre_run_id": "m", "anomaly_score": 0.73}
    alert = {"alert_run_id": run, "alert_key": "K1", "user_id": "u1", "status": "open", "duplicate_of": None,
             "first_date": d, "last_date": d, "peak_date": d, "n_days": 1, "peak_anomaly_score": 0.73, "peak_cri_score": 55.0,
             "max_cri_score": 55.0, "max_severity": "HIGH", "queue_score": 0.73, "ordering": "anomaly_score",
             "triggers": ["band"], "techniques": ["T1052.001"], "signature": ["T1052.001"], "top_feature": "usb_connect_count",
             "model_split": "test", "explanation_status": "complete", "policy_version": POLICY_VERSION, "policy_hash": "h",
             "model_version": "mv", "batch_run_id": "b", "cri_run_id": "cri", "explain_run_id": "e", "mitre_run_id": "m"}
    member = {"alert_key": "K1", "user_id": "u1", "activity_date": d, "is_peak": True, "by_band": True, "by_top_k": False,
              "explanation_status": "complete", "explanation_reason": None, "explanation_text": "HIGH RISK",
              "explanation": {"status": "complete"}, "kernel_top5_overlap": None, "kernel_deletion_beats_random": None,
              "explain_run_id": "e"}
    reason = {"alert_key": "K1", "user_id": "u1", "activity_date": d, "section": "model", "rank": 1,
              "subject": "usb_connect_count", "rule_id": None, "value": 4.0, "weight": 2.1, "text": "x",
              "source": {"kind": "model"}, "model_version": "mv", "explain_run_id": "e"}
    mitre = {"user_id": "u1", "activity_date": d, "status": "mapped", "technique_id": "T1052.001", "tactic": "exfiltration",
             "rule_id": "R01", "evidence": "observed", "trigger_column": "file_event_count", "trigger_value": 3.0,
             "strength": 0.2, "mitre_context": 0.3, "ruleset_version": "c10-rules-v1", "ruleset_hash": "rh",
             "attack_version": "19.2", "reference_id": "ref", "mitre_run_id": "m"}
    plan = LoadPlan(run, {"alerts": 1}, {"model_name": "gbdt", "registry_version": "v0001", "model_version": "mv",
                                         "files": {"model.json": "abc"}},
                    feature_vectors=[fv, demo], events=[ev],
                    anomaly_scores=[{"user_id": "u1", "activity_date": d, **score}, {"user_id": "u2", "activity_date": d, **score}],
                    risk_scores=[{"user_id": "u1", "activity_date": d, **risk}, {"user_id": "u2", "activity_date": d, **risk}],
                    alerts=[alert], members=[member], reasons=[reason],
                    mitre_mappings=[mitre, {**mitre, "user_id": "u2", "status": "unmapped", "technique_id": None,
                                            "tactic": None, "rule_id": None, "evidence": None, "trigger_column": None,
                                            "trigger_value": None, "strength": None, "mitre_context": 0.0}],
                    configuration=[{"key": "c12-alert-policy-v1:h", "value": '{"top_k_per_day": 1}', "description": "p"},
                                   {"key": f"c12-demo-sample-v1:{run}", "value": '{"users": ["u2"]}', "description": "d"}])
    for k, v in over.items():
        setattr(plan, k, v)
    return plan


def test_load_is_one_transaction_and_is_read_back():
    engine = _engine()
    plan = _plan()
    with engine.begin() as conn:
        counts = persist(conn, plan)
    assert counts["alerts"] == {"inserted": 1, "open": 1, "suppressed": 0}
    with engine.connect() as conn:
        assert check_stored(conn, plan) == [] and loaded_runs(conn) == ["run-1"]
        linked = conn.execute(sa.text("SELECT user_id, alert_id FROM mitre_mappings ORDER BY user_id")).all()
        assert linked[0][1] is not None and linked[1][1] is None                  # member day linked; demo day not
        ev = conn.execute(sa.text("SELECT feature_vector_id FROM event_logs")).scalar()
        assert ev is not None
    with engine.begin() as conn, pytest.raises(AlreadyLoadedError):
        persist(conn, plan)
    second = _plan("run-2")                                                         # a second run reuses lineage rows
    with engine.begin() as conn:
        counts = persist(conn, second)
    assert counts["feature_vectors"] == {"inserted": 0, "reused": 2} and counts["event_logs"]["reused"] == 1
    assert counts["configurations"] == {"inserted": 1, "already_recorded": 1}      # same policy, new demo record
    third = _plan("run-3")
    third.configuration = [{"key": "c12-alert-policy-v1:h", "value": '{"top_k_per_day": 5}', "description": "p"}]
    with pytest.raises(PersistenceError, match="different value"):
        with engine.begin() as conn:
            persist(conn, third)


def test_a_failure_mid_load_leaves_nothing_behind():
    """§36: an error after most rows were written rolls everything back, audit row included."""
    engine = _engine()
    plan = _plan()
    plan.reasons = [{**plan.reasons[0], "section": "mitre", "rule_id": None}]       # violates a check at the very end
    with pytest.raises(sa.exc.IntegrityError):
        with engine.begin() as conn:
            persist(conn, plan)
    with engine.connect() as conn:
        for t in ("alerts", "feature_vectors", "event_logs", "anomaly_scores", "risk_scores", "audit_logs"):
            assert conn.execute(sa.text(f"SELECT count(*) FROM {t}")).scalar() == 0, t


def test_plan_inconsistencies_are_refused():
    engine = _engine()
    plan = _plan()
    plan.members = [{**plan.members[0], "user_id": "u9"}]
    with pytest.raises(PersistenceError, match="no risk score"):
        with engine.begin() as conn:
            persist(conn, plan)
    plan = _plan()
    plan.alerts = [plan.alerts[0], {**plan.alerts[0], "alert_key": "K2", "status": "suppressed", "duplicate_of": "NOPE"}]
    with pytest.raises(PersistenceError, match="not an open alert"):
        with engine.begin() as conn:
            persist(conn, plan)


def test_unreachable_database_is_reported_not_hidden():
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.alerts.runtime import database_status

    engine = create_async_engine("postgresql+asyncpg://cira:x@127.0.0.1:1/none")
    out = asyncio.run(database_status(engine, timeout=5))
    assert out["status"] == "unavailable" and "§36" in out["effect"]


# --- isolation and API --------------------------------------------------------------------

def test_serving_modules_never_import_labels_or_the_readout():
    import app.alerts as pkg

    for name in SERVING:
        tree = ast.parse((Path(pkg.__file__).parent / f"{name}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mods = [("." * node.level) + (node.module or "")]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            else:
                continue
            for m in mods:
                assert "ground_truth" not in m and "evaluation.labels" not in m and "evaluation.metrics" not in m, (name, m)
                assert not m.endswith("evaluate"), (name, m)


def test_api_health_has_alerts_and_database_blocks(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.delenv("CIRA_SERVED_MODEL", raising=False)
    monkeypatch.setenv("CIRA_SERVING_DECISION", str(tmp_path / "missing.json"))
    with TestClient(app) as client:
        body = client.get("/health").json()
    assert body["alerts"]["status"] == "unavailable" and body["alerts"]["policy_version"] == POLICY_VERSION
    assert body["database"]["status"] in ("reachable", "unavailable")
