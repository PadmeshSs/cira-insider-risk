"""Alert queue and alert detail, read from PostgreSQL (Bible Ch13; N55, N57, N58, N60).

The queue is the open alerts of the served run, ordered by ``queue_score``,
the value the alert policy ordered by (the served anomaly score under
``c12-alert-policy-v1``). The CRI and its band are returned on every row as
context and never used to re-sort (N55). Suppressed alerts are counted next
to open ones, attached to the open alert they repeat, and never presented as
resolved (N57, N60). Nothing is recomputed: every value is the stored one
(N34). Read only (N58).
"""
from __future__ import annotations

from sqlalchemy import Select, and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Alert, AlertMember, AnomalyScore, RiskScore

from .common import clamp_page, in_sample, page_info, user_variants
from .errors import BadRequest, NotFound
from .runs import CurrentRun

STATUSES = ("open", "suppressed")
SORTS = ("queue", "recent")


def queue_info(run: CurrentRun, sort: str = "queue") -> dict:
    return {"ordered_by": run.ordering, "policy_version": run.policy_version, "policy_hash": run.policy_hash,
            "sort": {"queue": f"{run.ordering} (queue_score), highest first, as the policy ordered it",
                     "recent": "first_date, newest first"}.get(sort, sort)}


def alert_dict(a: Alert, suppressed: dict | None = None) -> dict:
    return {"id": a.id, "alert_key": a.alert_key, "user_id": a.user_id, "status": a.status,
            "duplicate_of_id": a.duplicate_of_id, "first_date": a.first_date, "last_date": a.last_date,
            "peak_date": a.peak_date, "n_days": a.n_days, "queue_score": a.queue_score, "ordering": a.ordering,
            "peak_anomaly_score": a.peak_anomaly_score, "peak_cri_score": a.peak_cri_score,
            "max_cri_score": a.max_cri_score, "max_severity": a.max_severity, "triggers": list(a.triggers or []),
            "techniques": list(a.techniques or []), "top_feature": a.top_feature, "model_split": a.model_split,
            "in_sample": in_sample(a.model_split), "explanation_status": a.explanation_status,
            "suppressed": suppressed if a.status == "open" else None}


async def suppressed_by_original(session: AsyncSession, run: CurrentRun, ids: list[int]) -> dict[int, dict]:
    """count and date span of the suppressed alerts pointing at each open alert (N60)."""
    if not ids:
        return {}
    rows = (await session.execute(
        select(Alert.duplicate_of_id, func.count(Alert.id), func.min(Alert.first_date), func.max(Alert.last_date))
        .where(Alert.alert_run_id == run.alert_run_id, Alert.status == "suppressed", Alert.duplicate_of_id.in_(ids))
        .group_by(Alert.duplicate_of_id))).all()
    out = {i: {"count": 0, "first_date": None, "last_date": None} for i in ids}
    for orig, n, lo, hi in rows:
        out[orig] = {"count": int(n), "first_date": lo, "last_date": hi}
    return out


async def counts(session: AsyncSession, run: CurrentRun) -> dict:
    rows = (await session.execute(select(Alert.status, func.count(Alert.id))
                                  .where(Alert.alert_run_id == run.alert_run_id).group_by(Alert.status))).all()
    c = {s: 0 for s in STATUSES}
    c.update({s: int(n) for s, n in rows})
    return c


async def with_suppressed(session: AsyncSession, run: CurrentRun, alerts: list[Alert]) -> list[dict]:
    sup = await suppressed_by_original(session, run, [a.id for a in alerts if a.status == "open"])
    return [alert_dict(a, sup.get(a.id)) for a in alerts]


async def list_alerts(session: AsyncSession, run: CurrentRun, *, status: str = "open", severity: str | None = None,
                      user_id: str | None = None, sort: str = "queue", limit: int | None = None,
                      offset: int | None = None) -> dict:
    if status not in (*STATUSES, "all"):
        raise BadRequest(f"status must be one of {(*STATUSES, 'all')}")
    if sort not in SORTS:
        raise BadRequest(f"sort must be one of {SORTS}")
    limit, offset = clamp_page(limit, offset)
    cond = [Alert.alert_run_id == run.alert_run_id]
    if status != "all":
        cond.append(Alert.status == status)
    if severity:
        cond.append(Alert.max_severity == severity.upper())
    if user_id:
        cond.append(Alert.user_id.in_(user_variants(user_id)))
    total = (await session.execute(select(func.count(Alert.id)).where(and_(*cond)))).scalar_one()
    q: Select = select(Alert).where(and_(*cond))
    q = q.order_by(Alert.queue_score.desc(), Alert.peak_date, Alert.id) if sort == "queue" else \
        q.order_by(Alert.first_date.desc(), Alert.queue_score.desc(), Alert.id)
    alerts = (await session.execute(q.limit(limit).offset(offset))).scalars().all()
    return {"items": await with_suppressed(session, run, list(alerts)), "page": page_info(total, limit, offset),
            "counts": await counts(session, run), "queue": queue_info(run, sort), "run": run.lineage()}


async def get_alert_row(session: AsyncSession, run: CurrentRun, alert_id: int) -> Alert:
    a = (await session.execute(select(Alert).where(Alert.id == alert_id, Alert.alert_run_id == run.alert_run_id)
                               )).scalars().first()
    if a is None:
        raise NotFound(f"alert {alert_id} is not in the served alert run {run.alert_run_id}")
    return a


async def members_of(session: AsyncSession, alert_id: int) -> list[dict]:
    rows = (await session.execute(
        select(AlertMember, RiskScore, AnomalyScore)
        .join(RiskScore, RiskScore.id == AlertMember.risk_score_id)
        .join(AnomalyScore, AnomalyScore.id == RiskScore.anomaly_score_id)
        .where(AlertMember.alert_id == alert_id).order_by(AlertMember.activity_date))).all()
    return [{"id": m.id, "user_id": m.user_id, "activity_date": m.activity_date, "is_peak": m.is_peak,
             "by_band": m.by_band, "by_top_k": m.by_top_k, "anomaly_score": r.anomaly_score, "cri_score": r.cri_score,
             "severity": r.severity, "model_split": an.model_split, "in_sample": in_sample(an.model_split),
             "explanation_status": m.explanation_status, "explanation_reason": m.explanation_reason,
             "risk_score_id": r.id, "anomaly_score_id": an.id, "feature_vector_id": an.feature_vector_id}
            for m, r, an in rows]


async def get_alert(session: AsyncSession, run: CurrentRun, alert_id: int) -> dict:
    a = await get_alert_row(session, run, alert_id)
    alert = (await with_suppressed(session, run, [a]))[0]
    original = None
    if a.duplicate_of_id is not None:
        o = await get_alert_row(session, run, a.duplicate_of_id)
        original = (await with_suppressed(session, run, [o]))[0]
    children = (await session.execute(select(Alert).where(Alert.alert_run_id == run.alert_run_id,
                                                          Alert.duplicate_of_id == a.id)
                                      .order_by(Alert.first_date, Alert.id))).scalars().all()
    return {"alert": alert, "members": await members_of(session, a.id), "duplicate_of": original,
            "suppressed_alerts": [alert_dict(c) for c in children], "queue": queue_info(run), "run": run.lineage()}
