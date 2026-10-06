"""Chapter 15: the traced alert, read through the API the way the dashboard reads it.

Chapter 13's tests check every route's shape. This file checks one thing
they cannot: that the alert built from the traced raw row in
``test_ch15_chain.py`` reaches an analyst through the routes each dashboard
view calls, with the same numbers PostgreSQL and the Parquet runs hold.

    PostgreSQL -> API -> (dashboard; frontend/e2e/ repeats this in a browser)

One test per §27 question, in the order an analyst asks them, then the
re-score check that the dashboard's "Re-score this day" control runs (N64,
N69), then the login audit trail (N65).
"""
from __future__ import annotations

from datetime import date

import pandas as pd
import pytest

from ch15_stack import rows

pytestmark = pytest.mark.e2e


def _alert_id(stack) -> int:
    r = rows(stack.db.url, "SELECT id FROM alerts WHERE alert_run_id = :r AND alert_key = :k",
             r=stack.alert_run_id, k=stack.trace["alert_key"])
    assert len(r) == 1
    return r[0]["id"]


def test_health_says_everything_the_dashboard_needs_is_ready(stack, api):
    async def scenario(client, headers, engine):
        return (await client.get("/api/v1/health")).json()

    h = api(scenario, login=False)
    assert h["status"] == "healthy" and h["database"]["status"] == "reachable" and h["auth"]["status"] == "configured"
    assert {k: v["ready"] for k, v in h["routes"].items()} == {k: True for k in h["routes"]}, h["routes"]
    assert h["routes"]["alerts_risk_investigations"]["alert_run_id"] == stack.alert_run_id
    assert h["database"]["alert_runs_loaded"] == 1          # the two failed loads claimed nothing (N58)


def test_who_is_risky_overview_ranks_the_traced_user(stack, api):
    """§27 Q1. The traced user is ranked at the top score. Users tied on that score are ordered by id (risk.overview)."""
    async def scenario(client, headers, engine):
        return (await client.get("/api/v1/risk/overview", headers=headers)).json()

    ov = api(scenario)
    top_score = ov["top_users"][0]["max_queue_score"]
    assert top_score == pytest.approx(stack.trace["queue_score"], abs=1e-12)
    tied = [u["user_id"] for u in ov["top_users"] if u["max_queue_score"] == top_score]
    assert stack.trace["user_id"] in tied and tied == sorted(tied)
    db_open = rows(stack.db.url, "SELECT count(*) AS n FROM alerts WHERE alert_run_id = :r AND status = 'open'",
                   r=stack.alert_run_id)[0]["n"]
    assert ov["counts"]["open"] == db_open and ov["run"]["alert_run_id"] == stack.alert_run_id


def test_what_happened_the_queue_starts_with_the_traced_alert(stack, api):
    """§27 Q2. First row of the queue the Alerts view shows."""
    async def scenario(client, headers, engine):
        return (await client.get("/api/v1/alerts", params={"status": "open", "sort": "queue", "limit": 6},
                                 headers=headers)).json()

    q = api(scenario)
    first = q["items"][0]
    assert first["id"] == _alert_id(stack) and first["alert_key"] == stack.trace["alert_key"]
    assert first["peak_date"] == stack.trace["date"] and first["queue_score"] == pytest.approx(stack.trace["queue_score"])


def test_how_risky_alert_detail_matches_the_stored_rows(stack, api):
    """§27 Q3. Both scores of the peak member equal the database rows, and the CRI's points add up to it."""
    aid = _alert_id(stack)
    t = stack.trace

    async def scenario(client, headers, engine):
        d = (await client.get(f"/api/v1/alerts/{aid}", headers=headers)).json()
        r = (await client.get(f"/api/v1/risk/users/{t['user_id']}/days/{t['date']}", headers=headers)).json()
        a = (await client.get(f"/api/v1/anomaly/users/{t['user_id']}/days/{t['date']}", headers=headers)).json()
        return d, r, a

    d, risk, an = api(scenario)
    peak = next(m for m in d["members"] if m["is_peak"])
    db = rows(stack.db.url, "SELECT r.cri_score, r.severity, r.anomaly_score FROM risk_scores r JOIN alert_members m "
              "ON m.risk_score_id = r.id WHERE m.id = :m", m=peak["id"])[0]
    assert peak["activity_date"] == t["date"]
    assert (peak["anomaly_score"], peak["cri_score"], peak["severity"]) == (db["anomaly_score"], db["cri_score"],
                                                                              db["severity"])
    assert risk["cri_score"] == db["cri_score"] and an["anomaly_score"] == db["anomaly_score"]
    assert sum(v for v in risk["points"].values() if v is not None) == pytest.approx(risk["cri_score"], abs=1e-6)
    assert an["model_name"] == "gbdt" and an["role"] == "served" and an["batch_run_id"] == stack.world["batch"]["batch_run_id"]


def test_why_risky_explanation_is_the_stored_one(stack, api):
    """§27 Q4. The explanation sections equal the alert_reasons rows; the model factors are TreeSHAP of the served model."""
    aid = _alert_id(stack)

    async def scenario(client, headers, engine):
        return (await client.get(f"/api/v1/explanations/alerts/{aid}", headers=headers)).json()

    e = api(scenario)
    m = next(x for x in e["members"] if x["activity_date"] == stack.trace["date"])
    assert m["status"] == "complete" and m["headline"]["model_name"] == "gbdt"
    stored = {r["section"]: r["n"] for r in rows(
        stack.db.url, "SELECT section, count(*) AS n FROM alert_reasons WHERE member_id = :m GROUP BY section",
        m=m["member_id"])}
    assert m["reason_rows"] == stored
    attr = pd.read_parquet(stack.world["explain"]["outputs"]["attributions.parquet"])
    mine = attr[(attr["user_id"].astype(str) == stack.trace["user_id"]) & (attr["date"].astype(str) == stack.trace["date"])]
    col = next(c for c in ("feature", "column", "subject") if c in mine.columns)
    assert {f["feature"] for f in m["sections"]["model"]} <= set(mine[col])
    assert m["text"] and "probability" not in m["text"].replace("not a probability", "")


def test_contextual_evidence_mitre_rows_match_the_enrichment_run(stack, api):
    """§27 Q5. ATT&CK status of the traced day equals the Chapter 10 run; techniques equal the alert's."""
    aid = _alert_id(stack)

    async def scenario(client, headers, engine):
        return (await client.get(f"/api/v1/mitre/alerts/{aid}", headers=headers)).json()

    m = api(scenario)
    ctx = pd.read_parquet(stack.world["mitre"]["outputs"]["context"])
    ctx = ctx[(ctx["user_id"].astype(str) == stack.trace["user_id"]) & (ctx["date"].astype(str) == stack.trace["date"])]
    day = next(d for d in m["days"] if d["activity_date"] == stack.trace["date"])
    assert day["status"] == ctx.iloc[0]["mitre_status"]
    alert_tech = rows(stack.db.url, "SELECT techniques FROM alerts WHERE id = :i", i=aid)[0]["techniques"] or []
    assert {t["technique_id"] for t in m["techniques"]} == set(alert_tech)


def test_what_to_investigate_the_raw_event_is_in_the_users_timeline(stack, api):
    """§27 Q6. /events for the user and day returns the traced raw row, by its CERT id, linked to the feature vector."""
    t = stack.trace

    async def scenario(client, headers, engine):
        inv = (await client.get(f"/api/v1/investigations/{t['user_id']}", headers=headers)).json()
        hist = (await client.get(f"/api/v1/risk/users/{t['user_id']}/history", headers=headers)).json()
        ev = (await client.get("/api/v1/events", params={"user_id": t["user_id"], "date_from": t["date"],
                                                         "date_to": t["date"], "limit": 200}, headers=headers)).json()
        fv = (await client.get(f"/api/v1/features/users/{t['user_id']}/days/{t['date']}", headers=headers)).json()
        return inv, hist, ev, fv

    inv, hist, ev, fv = api(scenario)
    assert any(a["alert_key"] == t["alert_key"] for a in inv["alerts"])
    assert t["date"] in [b["start"] for b in hist["buckets"]]
    hit = [e for e in ev["items"] if e["event_id"] == t["raw_id"]]
    assert len(hit) == 1, f"{t['raw_id']} not among {ev['page']['total']} events of {t['user_id']} on {t['date']}"
    e = hit[0]
    assert e["source_type"] == t["domain"] and e["feature_vector_id"] == fv["id"]
    assert e["event_time"].startswith(pd.to_datetime(t["raw_row"]["date"], format="%m/%d/%Y %H:%M:%S")
                                      .strftime("%Y-%m-%dT%H:%M:%S"))
    raw_count = rows(stack.db.url, "SELECT count(*) AS n FROM event_logs WHERE user_id = :u AND activity_date = :d",
                     u=t["user_id"], d=date.fromisoformat(t["date"]))[0]["n"]
    assert ev["page"]["total"] == raw_count


def test_rescoring_from_the_dashboards_inputs_reproduces_the_decision(stack, api):
    """N64/N69: the "Re-score this day" request, built from /features and /risk like the dashboard builds it."""
    t = stack.trace

    async def scenario(client, headers, engine):
        fv = (await client.get(f"/api/v1/features/users/{t['user_id']}/days/{t['date']}", headers=headers)).json()
        risk = (await client.get(f"/api/v1/risk/users/{t['user_id']}/days/{t['date']}", headers=headers)).json()
        from sqlalchemy import text

        counts = {}
        async with engine.connect() as c:
            for tb in ("anomaly_scores", "risk_scores", "alerts", "alert_reasons", "mitre_mappings"):
                counts[tb] = (await c.execute(text(f"SELECT count(*) FROM {tb}"))).scalar()
        body = {"user_id": fv["user_id"], "date": fv["activity_date"],
                "features": {v["column"]: v["value"] for v in fv["values"]}, "role": risk["ldap_role"], "explain": False}
        out = (await client.post("/api/v1/risk/score", json=body, headers=headers))
        after = {}
        async with engine.connect() as c:
            for tb in counts:
                after[tb] = (await c.execute(text(f"SELECT count(*) FROM {tb}"))).scalar()
        return risk, out, counts, after

    risk, out, before, after = api(scenario)
    assert out.status_code == 200, out.text
    o = out.json()
    assert o["persisted"] is False and before == after
    assert abs(o["anomaly"]["anomaly_score"] - risk["anomaly_score"]) == 0.0
    assert o["risk"]["cri_score"] == pytest.approx(risk["cri_score"], abs=1e-9)
    assert o["risk"]["severity"] == risk["severity"] and o["alert_trigger"]["by_top_k"] is None


def test_every_login_of_the_journey_was_audited(stack, api):
    """N65: each sign-in above wrote an analyst_login row; none of them counts as a load (N58)."""
    async def scenario(client, headers, engine):
        bad = await client.post("/api/v1/auth/token", data={"username": stack.username, "password": "x" * 14})
        return bad.status_code

    assert api(scenario) == 401
    audit = {r["action"]: r["n"] for r in rows(
        stack.db.url, "SELECT action, count(*) AS n FROM audit_logs WHERE actor = :u GROUP BY action", u=stack.username)}
    assert audit.get("analyst_login", 0) >= 1 and audit.get("analyst_login_failed", 0) >= 1
    assert rows(stack.db.url, "SELECT count(*) AS n FROM audit_logs WHERE action = 'alert_run_loaded'")[0]["n"] == 1
