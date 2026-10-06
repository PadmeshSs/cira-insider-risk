"""Chapter 15, step 1 automated: one raw event followed through every stage.

    Raw event -> normalized event -> features -> model -> anomaly score
    -> CRI -> MITRE -> explanation -> alert -> PostgreSQL

The traced row is a line of the raw CSV, chosen after the run from the top
open alert's peak day (``ch15_stack.choose_trace``). Each test checks one
hop, and each hop is checked against the value the previous hop produced,
not against a constant. The API and dashboard hops are in
``test_ch15_api_journey.py`` and ``frontend/e2e/``.

The Bible's literal chain says "TabNet -> anomaly score". In this repository
the served model is XGBoost and TabNet is the shadow model (Chapter 8
decision C8-1, N28, N32). The tests follow the chain as built: the served
score comes from XGBoost, TabNet is trained and scores every row as shadow,
and the shadow score is checked to reach nothing downstream.
"""
from __future__ import annotations

import csv
import glob
import json
from datetime import datetime

import pandas as pd
import pytest

from ch15_stack import rows

pytestmark = pytest.mark.e2e


def _frame(path) -> pd.DataFrame:
    return pd.read_parquet(path)


def _day(frame: pd.DataFrame, user: str, day: str) -> pd.DataFrame:
    return frame[(frame["user_id"].astype(str) == user) & (frame["date"].astype(str) == day)]


# --- raw -> normalized ---------------------------------------------------------------------

def test_the_traced_row_is_a_line_of_the_raw_csv(stack):
    t = stack.trace
    with open(t["raw_file"], newline="", encoding="utf-8") as fh:
        lines = list(csv.DictReader(fh))
    row = lines[t["raw_line"] - 2]
    assert row == t["raw_row"] and row["id"] == t["raw_id"]
    assert row["user"].casefold() == t["user_id"]
    assert datetime.strptime(row["date"], "%m/%d/%Y %H:%M:%S").strftime("%Y-%m-%d") == t["date"]


def test_chapter3_and_chapter4_normalize_the_row_as_stage0_stored_it(stack):
    """The per-event contract (Ch3 loader + Ch4 normalize) and the vectorised Stage 0 agree on the row."""
    from app.ingestion.cert_loader import iter_cert_domain_events
    from app.preprocessing.normalize import normalize_event

    t = stack.trace
    want = f"cert-r4.2:{t['domain']}:{t['raw_id']}"
    event = next(e for e in iter_cert_domain_events(stack.world["raw"], t["domain"]) if e.event_id == want)
    norm = normalize_event(event)
    month = t["date"][:7]
    parts = glob.glob(str(stack.root / "processed" / "events" / "profile=full" / f"source_type={t['domain']}"
                          / f"month={month}" / "*.parquet"))
    s0 = pd.concat([pd.read_parquet(p) for p in parts])
    hit = s0[s0["event_id"] == t["raw_id"]]
    assert len(hit) == 1, f"Stage 0 holds {len(hit)} rows for {t['raw_id']}"
    r = hit.iloc[0]
    assert norm.user_id == r["user_id"] == t["user_id"]
    assert norm.device_id == r["device_id"]
    assert pd.Timestamp(norm.timestamp) == pd.Timestamp(r["timestamp"])
    assert norm.metadata["source_record_id"] == t["raw_id"]
    for forbidden in ("label", "insider", "scenario", "malicious"):         # N5: no label in either form
        assert not any(forbidden in k for k in norm.model_dump()["details"]), forbidden
        assert not any(forbidden in c for c in s0.columns), forbidden


# --- normalized -> features ------------------------------------------------------------------

def test_the_user_day_feature_counts_the_raw_rows(stack):
    """The feature the traced row feeds equals a count taken straight from the raw CSV."""
    t = stack.trace
    fm = _frame(stack.world["gbdt"]["features"]["path"])
    row = _day(fm, t["user_id"], t["date"])
    assert len(row) == 1
    column, activity = {"device": ("usb_connect_count", "connect"), "logon": ("login_count", "logon")}.get(
        t["domain"], (None, None))
    if column is None:
        pytest.skip(f"no single-count feature to recompute for domain {t['domain']}; the row's presence is checked")
    with open(t["raw_file"], newline="", encoding="utf-8") as fh:
        n = sum(1 for r in csv.DictReader(fh)
                if r["user"].casefold() == t["user_id"] and r["activity"].strip().casefold() == activity
                and datetime.strptime(r["date"], "%m/%d/%Y %H:%M:%S").strftime("%Y-%m-%d") == t["date"])
    assert n >= 1 and float(row.iloc[0][column]) == float(n)


# --- features -> model -> anomaly score ---------------------------------------------------------

def test_the_served_model_scored_the_day_and_tabnet_scored_it_as_shadow(stack):
    t = stack.trace
    batch = _frame(stack.world["batch"]["output"])
    day = _day(batch, t["user_id"], t["date"])
    served, shadow = day[day["role"] == "served"], day[day["role"] == "shadow"]
    assert len(served) == 1 and len(shadow) == 1
    assert served.iloc[0]["model_name"] == "gbdt" and shadow.iloc[0]["model_name"] == "tabnet"
    assert 0.0 <= served.iloc[0]["anomaly_score"] <= 1.0 and 0.0 <= shadow.iloc[0]["anomaly_score"] <= 1.0
    assert served.iloc[0]["model_split"] in ("validation", "test")                  # N31: alerts are out of sample
    assert stack.world["batch"]["summary"]["shadow_score_failures"] == 0
    reg = stack.world["tabnet"]["registry"]
    assert reg["registry_version"] == "v0001" and "tabnet_model.zip" in reg["files"]


def test_score_event_reproduces_the_batch_with_its_model_version(stack):
    """Chapter 8's interface, score_event(feature_vector) -> anomaly score + model version, on the traced day."""
    from ch15_stack import pinned_env

    from app.scoring.service import AnomalyScoringService
    from app.scoring.serving_config import resolve_serving_config

    t = stack.trace
    vec = _day(_frame(stack.world["gbdt"]["features"]["path"]), t["user_id"], t["date"]).iloc[0].to_dict()
    batch = _frame(stack.world["batch"]["output"])
    stored = _day(batch, t["user_id"], t["date"])
    stored = stored[stored["role"] == "served"].iloc[0]
    with pinned_env(stack.root):
        svc = AnomalyScoringService.load(resolve_serving_config())
        out = svc.score_event({k: v for k, v in vec.items() if k not in ("user_id", "date")},
                              user_id=t["user_id"], date=t["date"])
    assert out.anomaly_score == pytest.approx(float(stored["anomaly_score"]), abs=1e-9)
    assert out.model_version == stored["model_version"] and out.role == "served"


def test_a_missing_model_is_an_error_not_a_score(stack, tmp_path):
    """Chapter 8 / §36 "model unavailable": no fabricated score when the registry has no model."""
    from ch15_stack import pinned_env

    from app.scoring.service import AnomalyScoringService
    from app.scoring.serving_config import resolve_serving_config

    with pinned_env(stack.root):
        import os

        os.environ["MODEL_PATH"] = str(tmp_path / "empty-registry")
        svc = AnomalyScoringService.load(resolve_serving_config())
    assert not svc.available and svc.unavailable_reason
    with pytest.raises(Exception):
        svc.score_event({"login_count": 1.0})


# --- anomaly score -> CRI ------------------------------------------------------------------------

def test_the_cri_row_carries_the_same_anomaly_score_and_a_band(stack):
    t = stack.trace
    risk = _day(_frame(stack.world["cri"]["output"]), t["user_id"], t["date"])
    batch = _frame(stack.world["batch"]["output"])
    served = _day(batch, t["user_id"], t["date"])
    served = served[served["role"] == "served"].iloc[0]
    assert len(risk) == 1
    r = risk.iloc[0]
    assert float(r["anomaly_score"]) == float(served["anomaly_score"])               # N34: two values, same source
    assert 0.0 <= float(r["cri_score"]) <= 100.0
    maxima = stack.world["cri"]["config"]["severity_maxima"]
    cri = float(r["cri_score"])
    expect = "LOW" if cri <= maxima["LOW"] + 1 - 1e-9 else "MEDIUM" if cri < maxima["MEDIUM"] + 1 else \
        "HIGH" if cri < maxima["HIGH"] + 1 else "CRITICAL"
    assert r["severity"] == expect, (cri, r["severity"], maxima)
    points = {k: v for k, v in r.items() if str(k).startswith("points_") and pd.notna(v)}
    assert sum(points.values()) == pytest.approx(cri, abs=1e-6)                      # the points are the score
    assert stack.world["cri"]["mitre"]["mitre_run_id"] == stack.world["mitre"]["mitre_run_id"]


def test_the_shadow_score_reaches_nothing_downstream(stack):
    """N32: the CRI and the alerts were computed from the served model's scores only."""
    cri = stack.world["cri"]
    assert cri["served"]["model_name"] == "gbdt"
    alerts = stack.world["alerts"]
    assert alerts["served"]["model_name"] == "gbdt" and "never" in json.dumps(alerts).lower()
    members = _frame(alerts["outputs"]["alert_members.parquet"])
    batch = _frame(stack.world["batch"]["output"])
    served = batch[batch["role"] == "served"].set_index(["user_id", "date"])["anomaly_score"]
    for m in members.itertuples():
        assert m.anomaly_score == served.loc[(m.user_id, str(m.date))]


# --- CRI -> MITRE --------------------------------------------------------------------------------

def test_the_mitre_layer_evaluated_the_day_and_every_match_is_traceable(stack):
    t = stack.trace
    ctx = _day(_frame(stack.world["mitre"]["outputs"]["context"]), t["user_id"], t["date"])
    assert len(ctx) == 1
    status = ctx.iloc[0]["mitre_status"]
    assert status in ("mapped", "unmapped", "not_evaluated")
    matches = _frame(stack.world["mitre"]["outputs"]["matches"])
    matches = matches[(matches["user_id"].astype(str).str.casefold() == t["user_id"])
                      & (matches["date"].astype(str) == t["date"])]
    if status == "mapped":
        assert len(matches) >= 1
        for m in matches.itertuples():
            assert m.rule_id and m.technique_id.startswith("T") and m.trigger_column and m.evidence
    else:
        assert matches.empty                                                         # never force-mapped
    whole = _frame(stack.world["mitre"]["outputs"]["matches"])
    assert not whole.empty, "the planted cloud-storage visits should map at least one day (R03)"


# --- MITRE -> explanation ------------------------------------------------------------------------

def test_the_explanation_adds_up_to_the_served_score(stack):
    """N47: TreeSHAP contributions plus the expected value equal the served margin; every factor is a model input."""
    t = stack.trace
    ex = _day(_frame(stack.world["explain"]["outputs"]["explanations.parquet"]), t["user_id"], t["date"])
    assert len(ex) == 1
    e = ex.iloc[0]
    assert e["method"] == "treeshap" and e["model_name"] == "gbdt"
    assert abs(float(e["additivity_error"])) <= stack.world["explain"]["explainer"]["additivity_tolerance"]
    attr = _frame(stack.world["explain"]["outputs"]["attributions.parquet"])
    mine = attr[(attr["user_id"].astype(str) == t["user_id"]) & (attr["date"].astype(str) == t["date"])]
    assert not mine.empty
    cols = set(_frame(stack.world["gbdt"]["features"]["path"]).columns)
    feature_col = next(c for c in ("feature", "column", "subject") if c in mine.columns)
    assert set(mine[feature_col]) <= cols


# --- explanation -> alert --------------------------------------------------------------------------

def test_the_day_is_a_member_of_the_traced_alert(stack):
    t = stack.trace
    members = _frame(stack.world["alerts"]["outputs"]["alert_members.parquet"])
    m = members[(members["alert_key"] == t["alert_key"]) & (members["user_id"].astype(str) == t["user_id"])
                & (members["date"].astype(str) == t["date"])]
    assert len(m) == 1 and bool(m.iloc[0]["is_peak"]) and m.iloc[0]["explanation_status"] == "complete"
    assert bool(m.iloc[0]["by_band"]) or bool(m.iloc[0]["by_top_k"])


# --- alert -> PostgreSQL ---------------------------------------------------------------------------

LINEAGE_SQL = """
SELECT e.event_id, e.source_type, e.event_type, e.user_id, e.activity_date, e.source_path,
       fv.id AS fv_id, fv.features_fingerprint, fv.values AS fv_values,
       an.id AS anomaly_id, an.anomaly_score, an.model_name, an.model_version, an.role, an.batch_run_id,
       mv.id AS model_version_row,
       r.id AS risk_id, r.cri_score, r.severity, r.anomaly_score AS risk_anomaly, r.cri_run_id, r.mitre_run_id,
       m.id AS member_id, m.is_peak, m.explanation_status,
       a.id AS alert_id, a.alert_key, a.alert_run_id, a.status
FROM event_logs e
JOIN feature_vectors fv ON fv.id = e.feature_vector_id
JOIN anomaly_scores an ON an.feature_vector_id = fv.id AND an.role = 'served'
JOIN model_versions mv ON mv.id = an.model_version_id
JOIN risk_scores r ON r.anomaly_score_id = an.id
JOIN alert_members m ON m.risk_score_id = r.id
JOIN alerts a ON a.id = m.alert_id
WHERE e.source_type = :domain AND e.event_id = :raw_id
"""


def test_postgres_holds_the_whole_lineage_by_foreign_keys(stack):
    """Architecture §37 in the database: the raw id reaches the alert through foreign keys only."""
    t = stack.trace
    found = rows(stack.db.url, LINEAGE_SQL, domain=t["domain"], raw_id=t["raw_id"])
    assert len(found) == 1, found
    r = found[0]
    batch = _frame(stack.world["batch"]["output"])
    served = _day(batch, t["user_id"], t["date"])
    served = served[served["role"] == "served"].iloc[0]
    risk = _day(_frame(stack.world["cri"]["output"]), t["user_id"], t["date"]).iloc[0]
    assert r["user_id"] == t["user_id"] and str(r["activity_date"]) == t["date"]
    assert r["alert_key"] == t["alert_key"] and r["alert_run_id"] == stack.alert_run_id and r["status"] == "open"
    assert r["anomaly_score"] == float(served["anomaly_score"]) == r["risk_anomaly"]
    assert r["cri_score"] == pytest.approx(float(risk["cri_score"]), abs=1e-9) and r["severity"] == risk["severity"]
    assert r["batch_run_id"] == stack.world["batch"]["batch_run_id"]
    assert r["cri_run_id"] == stack.world["cri"]["cri_run_id"] and r["mitre_run_id"] == stack.world["mitre"]["mitre_run_id"]
    assert r["is_peak"] and r["explanation_status"] == "complete"
    fm = _day(_frame(stack.world["gbdt"]["features"]["path"]), t["user_id"], t["date"]).iloc[0]
    for col, v in r["fv_values"].items():                                            # the stored vector is the matrix row
        if v is None:
            assert pd.isna(fm[col]), col
        else:
            assert float(v) == pytest.approx(float(fm[col]), rel=1e-6), col
    reasons = rows(stack.db.url, "SELECT section, count(*) AS n FROM alert_reasons WHERE member_id = :m GROUP BY section",
                   m=r["member_id"])
    assert {x["section"] for x in reasons} >= {"model"}
    mitre = rows(stack.db.url, "SELECT status, technique_id FROM mitre_mappings WHERE user_id = :u AND activity_date = :d "
                 "AND mitre_run_id = :run", u=t["user_id"], d=datetime.strptime(t["date"], "%Y-%m-%d").date(),
                 run=stack.world["mitre"]["mitre_run_id"])
    ctx = _day(_frame(stack.world["mitre"]["outputs"]["context"]), t["user_id"], t["date"]).iloc[0]
    if ctx["mitre_status"] == "not_evaluated":
        assert mitre == []
    else:
        assert {m["status"] for m in mitre} == {ctx["mitre_status"]}


def test_postgres_stores_no_label_and_no_training_user(stack):
    """N5 and N31 in the database: no label key in any stored vector or event, no alert on a training user."""
    keys = rows(stack.db.url, "SELECT DISTINCT jsonb_object_keys(values::jsonb) AS k FROM feature_vectors")
    detail_keys = rows(stack.db.url, "SELECT DISTINCT jsonb_object_keys(details::jsonb) AS k FROM event_logs "
                       "WHERE details IS NOT NULL")
    for k in [x["k"] for x in keys + detail_keys]:
        assert not any(w in k.lower() for w in ("label", "malicious", "insider", "scenario")), k
    splits = rows(stack.db.url, "SELECT DISTINCT model_split FROM alerts")
    assert {s["model_split"] for s in splits} <= {"validation", "test"}


def test_the_database_was_migrated_to_head_by_alembic(stack):
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    from ch15_stack import BACKEND

    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    assert stack.alembic_revision == ScriptDirectory.from_config(cfg).get_current_head()


def test_training_is_reproducible_on_the_fixture(stack):
    """§45 item 16 on the fixture: same split and seed give the same model version and the same metrics."""
    r = stack.reproducibility
    assert r["identical"], json.dumps({"first": r["first"], "second": r["second"]}, default=str)[:2000]
