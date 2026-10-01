"""Stored risk rows, risk history and the overview (Bible Ch13; HCEA §13; N34, N52, N55, N60).

Every number is read from the served run's persisted rows: the CRI run the
alert run names and the anomaly scores of its batch. The two scores travel as
two fields; history buckets aggregate each one separately (N34). Aggregation
happens here, on the server, over the bounded persisted rows (HCEA §13), so
the dashboard receives a short series, not raw rows.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Alert, AlertMember, AnomalyScore, RiskScore

from .alerts import counts as alert_counts
from .alerts import queue_info
from .common import SEVERITY_ORDER, in_sample, max_severity, user_variants, week_start
from .errors import BadRequest, NotFound
from .runs import CurrentRun

BUCKETS = ("day", "week")
TOP_USERS = 10
TOP_FEATURES = 8
N52_FEATURE = "usb_disconnect_count"


def _split(s: str | None) -> list[str]:
    return [x for x in str(s or "").split(",") if x]


def risk_dict(r: RiskScore, an: AnomalyScore, alert_ids: list[int]) -> dict:
    return {"risk_score_id": r.id, "anomaly_score_id": an.id, "user_id": r.user_id, "activity_date": r.activity_date,
            "anomaly_score": r.anomaly_score, "cri_score": r.cri_score, "severity": r.severity,
            "components": dict(r.components or {}), "points": dict(r.points or {}),
            "missing_components": _split(r.missing_components), "historical_top_feature": r.historical_top_feature,
            "peer_top_feature": r.peer_top_feature, "ldap_role": r.ldap_role, "model_split": an.model_split,
            "in_sample": in_sample(an.model_split), "model_version": r.model_version, "cri_version": r.cri_version,
            "cri_config_hash": r.cri_config_hash, "cri_variant": r.cri_variant, "calibration_id": r.calibration_id,
            "cri_run_id": r.cri_run_id, "mitre_run_id": r.mitre_run_id, "alert_ids": alert_ids}


def _risk_query(run: CurrentRun):
    return (select(RiskScore, AnomalyScore).join(AnomalyScore, AnomalyScore.id == RiskScore.anomaly_score_id)
            .where(RiskScore.cri_run_id == run.cri_run_id, AnomalyScore.batch_run_id == run.batch_run_id,
                   AnomalyScore.role == "served"))


async def _member_alerts(session: AsyncSession, run: CurrentRun, risk_ids: list[int]) -> dict[int, list[int]]:
    if not risk_ids:
        return {}
    rows = (await session.execute(select(AlertMember.risk_score_id, AlertMember.alert_id)
                                  .join(Alert, Alert.id == AlertMember.alert_id)
                                  .where(Alert.alert_run_id == run.alert_run_id,
                                         AlertMember.risk_score_id.in_(risk_ids)))).all()
    out: dict[int, list[int]] = defaultdict(list)
    for rid, aid in rows:
        out[rid].append(aid)
    return {k: sorted(v) for k, v in out.items()}


async def user_rows(session: AsyncSession, run: CurrentRun, user_id: str) -> list[tuple[RiskScore, AnomalyScore]]:
    return list((await session.execute(_risk_query(run).where(RiskScore.user_id.in_(user_variants(user_id)))
                                       .order_by(RiskScore.activity_date))).all())


async def risk_for_day(session: AsyncSession, run: CurrentRun, user_id: str, day: date) -> dict:
    row = (await session.execute(_risk_query(run).where(RiskScore.user_id.in_(user_variants(user_id)),
                                                        RiskScore.activity_date == day))).first()
    if row is None:
        raise NotFound(f"no persisted risk row for {user_id} on {day} in CRI run {run.cri_run_id}; the database holds "
                       "alert member days and the demo sample only (HCEA D-6)")
    r, an = row
    return risk_dict(r, an, (await _member_alerts(session, run, [r.id])).get(r.id, []))


def coverage(days: list[date]) -> dict:
    return {"persisted_days": len(days), "first_date": min(days) if days else None,
            "last_date": max(days) if days else None}


async def history(session: AsyncSession, run: CurrentRun, user_id: str, bucket: str = "day") -> dict:
    if bucket not in BUCKETS:
        raise BadRequest(f"bucket must be one of {BUCKETS}")
    rows = await user_rows(session, run, user_id)
    if not rows:
        raise NotFound(f"no persisted risk rows for {user_id} in CRI run {run.cri_run_id}")
    members = await _member_alerts(session, run, [r.id for r, _ in rows])
    groups: dict[date, list] = defaultdict(list)
    for r, _an in rows:
        key = r.activity_date if bucket == "day" else week_start(r.activity_date)
        groups[key].append(r)
    out = []
    for start in sorted(groups):
        g = groups[start]
        cri = [x.cri_score for x in g]
        an = [x.anomaly_score for x in g]
        out.append({"start": start, "end": start if bucket == "day" else start + timedelta(days=6), "days": len(g),
                    "max_cri_score": max(cri), "mean_cri_score": sum(cri) / len(cri),
                    "max_anomaly_score": max(an), "mean_anomaly_score": sum(an) / len(an),
                    "max_severity": max_severity(x.severity for x in g),
                    "alert_member_days": sum(1 for x in g if x.id in members)})
    return {"user_id": rows[0][0].user_id, "bucket": bucket, "coverage": coverage([r.activity_date for r, _ in rows]),
            "buckets": out, "run": run.lineage()}


async def overview(session: AsyncSession, run: CurrentRun) -> dict:
    alerts = (await session.execute(select(Alert).where(Alert.alert_run_id == run.alert_run_id))).scalars().all()
    open_ = [a for a in alerts if a.status == "open"]
    sup = Counter(a.user_id for a in alerts if a.status == "suppressed")
    by_sev = Counter(a.max_severity for a in open_)
    feats = Counter(a.top_feature for a in open_ if a.top_feature)
    weekly = Counter(week_start(a.first_date) for a in open_)
    users: dict[str, list[Alert]] = defaultdict(list)
    for a in open_:
        users[a.user_id].append(a)
    ranked = sorted(users.items(), key=lambda kv: (-max(x.queue_score for x in kv[1]), kv[0]))[:TOP_USERS]
    return {
        "counts": await alert_counts(session, run),
        "open_by_severity": {s: int(by_sev.get(s, 0)) for s in SEVERITY_ORDER},
        "open_by_split": dict(sorted(Counter(a.model_split for a in open_).items())),
        "open_never_above_low": int(by_sev.get("LOW", 0)),
        "top_features": [{"feature": f, "open_alerts": int(n)} for f, n in feats.most_common(TOP_FEATURES)],
        "open_led_by_usb_disconnect_count": int(feats.get(N52_FEATURE, 0)),
        "new_open_alerts": [{"start": s, "end": s + timedelta(days=6), "count": int(weekly[s])} for s in sorted(weekly)],
        "top_users": [{"user_id": u, "open_alerts": len(g), "suppressed_alerts": int(sup.get(u, 0)),
                       "max_queue_score": max(x.queue_score for x in g),
                       "max_severity": max_severity(x.max_severity for x in g), "model_split": g[0].model_split,
                       "in_sample": in_sample(g[0].model_split)} for u, g in ranked],
        "queue": queue_info(run), "run": run.lineage(),
    }


async def persisted_users(session: AsyncSession, run: CurrentRun):
    """Per user: split, persisted days, span, highest band and latest LDAP role."""
    rows = (await session.execute(
        select(RiskScore.user_id, AnomalyScore.model_split, func.count(RiskScore.id), func.min(RiskScore.activity_date),
               func.max(RiskScore.activity_date))
        .join(AnomalyScore, AnomalyScore.id == RiskScore.anomaly_score_id)
        .where(RiskScore.cri_run_id == run.cri_run_id, AnomalyScore.batch_run_id == run.batch_run_id)
        .group_by(RiskScore.user_id, AnomalyScore.model_split).order_by(RiskScore.user_id))).all()
    return rows
