"""Stored analyst explanations of alert member days (N47, N48, N50; Architecture §18).

Every member day of a loaded alert run already has the full Chapter 11
explanation, built by ``build_explanation`` from TreeSHAP that adds up to the
served margin (N47). This module returns it with its sections kept apart:
raising model factors, lowering model factors, CRI points and ATT&CK
context (N50). CRI points and techniques are never returned as model
factors (N34, N45). KernelSHAP, where Chapter 11 ran it, is returned only as
the corroboration statistic (N48).

A user-day that is not an alert member has no stored explanation. One can be
built from a feature vector through ``POST /api/v1/risk/score``.
"""
from __future__ import annotations

from collections import Counter
from datetime import date

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Alert, AlertMember, AlertReason

from .alerts import get_alert_row
from .common import user_variants
from .errors import NotFound
from .runs import CurrentRun


def _sections(e: dict) -> dict:
    return {"model": list(e.get("model_factors") or []), "model_lowering": list(e.get("model_factors_lowering") or []),
            "cri": list(e.get("context_factors") or []), "mitre": e.get("attack_context")}


async def _reason_counts(session: AsyncSession, member_ids: list[int]) -> dict[int, dict[str, int]]:
    if not member_ids:
        return {}
    rows = (await session.execute(select(AlertReason.member_id, AlertReason.section)
                                  .where(AlertReason.member_id.in_(member_ids)))).all()
    out: dict[int, Counter] = {m: Counter() for m in member_ids}
    for mid, sec in rows:
        out[mid][sec] += 1
    return {m: dict(c) for m, c in out.items()}


def member_explanation(m: AlertMember, counts: dict[str, int]) -> dict:
    e = dict(m.explanation or {})
    return {"member_id": m.id, "alert_id": m.alert_id, "user_id": m.user_id, "activity_date": m.activity_date,
            "status": m.explanation_status, "model_unavailable_reason": m.explanation_reason,
            "headline": e.get("headline") or {}, "sections": _sections(e), "unavailable": e.get("unavailable") or {},
            "corroboration": e.get("corroboration"), "text": m.explanation_text, "reason_rows": counts,
            "explain_run_id": m.explain_run_id}


async def for_alert(session: AsyncSession, run: CurrentRun, alert_id: int) -> dict:
    a = await get_alert_row(session, run, alert_id)
    members = (await session.execute(select(AlertMember).where(AlertMember.alert_id == a.id)
                                     .order_by(AlertMember.activity_date))).scalars().all()
    counts = await _reason_counts(session, [m.id for m in members])
    return {"alert_id": a.id, "members": [member_explanation(m, counts.get(m.id, {})) for m in members],
            "run": run.lineage()}


async def for_user_day(session: AsyncSession, run: CurrentRun, user_id: str, day: date) -> dict:
    m = (await session.execute(select(AlertMember).join(Alert, Alert.id == AlertMember.alert_id)
                               .where(Alert.alert_run_id == run.alert_run_id,
                                      AlertMember.user_id.in_(user_variants(user_id)),
                                      AlertMember.activity_date == day)
                               .order_by(AlertMember.id).limit(1))).scalars().first()
    if m is None:
        raise NotFound(f"{user_id} on {day} is not a member day of alert run {run.alert_run_id}, so no explanation is "
                       "stored; POST /api/v1/risk/score with its feature vector builds one on demand")
    counts = await _reason_counts(session, [m.id])
    return member_explanation(m, counts.get(m.id, {}))
