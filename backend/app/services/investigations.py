"""Monitored users an analyst can investigate, and one user's investigation view (Bible Ch14 §27 Q6).

A subject is a monitored CERT user with persisted rows in the served run:
the users of alert member days and the demo sample (HCEA D-6, N59). The demo
sample was drawn from validation and test users only, and every alert row
carries its split, so an in-sample user is never shown as an example
without saying so (N31).
"""
from __future__ import annotations

from collections import Counter, defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Alert, AnomalyScore, RiskScore

from .alerts import with_suppressed
from .common import clamp_page, in_sample, max_severity, page_info, user_variants
from .errors import BadRequest, NotFound
from .risk import coverage, persisted_users, user_rows
from .runs import CurrentRun

SCOPES = ("all", "alerting", "demo")


def _demo_users(run: CurrentRun) -> set[str]:
    return {str(u) for u in (run.demo_sample or {}).get("users") or []}


async def _subjects(session: AsyncSession, run: CurrentRun) -> list[dict]:
    rows = await persisted_users(session, run)
    alerts = (await session.execute(select(Alert.user_id, Alert.status, Alert.queue_score)
                                    .where(Alert.alert_run_id == run.alert_run_id))).all()
    open_n, sup_n, best = Counter(), Counter(), {}
    for u, st, q in alerts:
        (open_n if st == "open" else sup_n)[u] += 1
        if st == "open":
            best[u] = max(best.get(u, q), q)
    sev = defaultdict(list)
    roles = {}
    for u, s, r in (await session.execute(
            select(RiskScore.user_id, RiskScore.severity, RiskScore.ldap_role)
            .join(AnomalyScore, AnomalyScore.id == RiskScore.anomaly_score_id)
            .where(RiskScore.cri_run_id == run.cri_run_id, AnomalyScore.batch_run_id == run.batch_run_id)
            .order_by(RiskScore.activity_date))).all():
        sev[u].append(s)
        if r:
            roles[u] = r
    demo = _demo_users(run)
    merged: dict[str, dict] = {}
    for u, split, n, lo, hi in rows:
        m = merged.get(u)
        if m is None:
            merged[u] = {"user_id": u, "model_split": split, "in_sample": in_sample(split), "persisted_days": int(n),
                         "first_date": lo, "last_date": hi, "open_alerts": int(open_n.get(u, 0)),
                         "suppressed_alerts": int(sup_n.get(u, 0)), "max_queue_score": best.get(u),
                         "max_severity": max_severity(sev.get(u, [])), "in_demo_sample": u in demo,
                         "ldap_role": roles.get(u)}
        else:                       # one user has one split; two would be a lineage fault, shown, not hidden
            m["model_split"] = f"{m['model_split']},{split}"
            m["persisted_days"] += int(n)
            m["first_date"], m["last_date"] = min(m["first_date"], lo), max(m["last_date"], hi)
    return list(merged.values())


async def list_subjects(session: AsyncSession, run: CurrentRun, *, scope: str = "all", limit: int | None = None,
                        offset: int | None = None) -> dict:
    if scope not in SCOPES:
        raise BadRequest(f"scope must be one of {SCOPES}")
    limit, offset = clamp_page(limit, offset)
    subjects = await _subjects(session, run)
    if scope == "alerting":
        subjects = [s for s in subjects if s["open_alerts"] or s["suppressed_alerts"]]
    elif scope == "demo":
        subjects = [s for s in subjects if s["in_demo_sample"]]
    subjects.sort(key=lambda s: (-(s["max_queue_score"] if s["max_queue_score"] is not None else -1.0), s["user_id"]))
    window = (run.demo_sample or {}).get("window")
    return {"items": subjects[offset:offset + limit], "page": page_info(len(subjects), limit, offset),
            "demo_window": None if window is None else {**window, "rule": (run.demo_sample or {}).get("rule")},
            "run": run.lineage()}


async def investigation(session: AsyncSession, run: CurrentRun, user_id: str) -> dict:
    variants = set(user_variants(user_id))
    subject = next((s for s in await _subjects(session, run) if s["user_id"] in variants), None)
    if subject is None:
        raise NotFound(f"{user_id} has no persisted rows in the served run (alert member days and the demo sample, "
                       "HCEA D-6)")
    alerts = (await session.execute(select(Alert).where(Alert.alert_run_id == run.alert_run_id,
                                                        Alert.user_id == subject["user_id"])
                                    .order_by(Alert.first_date, Alert.id))).scalars().all()
    days = [r.activity_date for r, _ in await user_rows(session, run, subject["user_id"])]
    return {"subject": subject, "alerts": await with_suppressed(session, run, list(alerts)),
            "coverage": coverage(days), "run": run.lineage()}
