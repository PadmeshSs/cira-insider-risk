"""Stored events, feature vectors and anomaly scores of one user-day (Architecture §37).

Feature vectors and events are reached the way the lineage chain links them:
the served batch's AnomalyScore row for the user-day points at its
FeatureVector, and events point at that feature vector. No label is stored
in any of these tables, and none is read (N5).
"""
from __future__ import annotations

from datetime import date

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import AnomalyScore, EventLog, FeatureVector
from app.explainability.features import describe, value_text

from .common import clamp_page, in_sample, page_info, user_variants
from .errors import BadRequest, NotFound
from .runs import CurrentRun, Runtimes

SOURCE_TYPES = ("logon", "device", "file", "email", "http")


async def anomaly_row(session: AsyncSession, run: CurrentRun, user_id: str, day: date) -> AnomalyScore:
    a = (await session.execute(select(AnomalyScore).where(AnomalyScore.batch_run_id == run.batch_run_id,
                                                          AnomalyScore.role == "served",
                                                          AnomalyScore.user_id.in_(user_variants(user_id)),
                                                          AnomalyScore.activity_date == day))).scalars().first()
    if a is None:
        raise NotFound(f"no persisted served score for {user_id} on {day} in batch {run.batch_run_id}; the database "
                       "holds alert member days and the demo sample only (HCEA D-6)")
    return a


async def stored_anomaly(session: AsyncSession, run: CurrentRun, user_id: str, day: date) -> dict:
    a = await anomaly_row(session, run, user_id, day)
    return {"id": a.id, "user_id": a.user_id, "activity_date": a.activity_date, "anomaly_score": a.anomaly_score,
            "raw_score": a.raw_score, "model_name": a.model_name, "model_version": a.model_version,
            "registry_version": a.registry_version, "role": a.role, "model_split": a.model_split,
            "in_sample": in_sample(a.model_split), "batch_run_id": a.batch_run_id,
            "feature_vector_id": a.feature_vector_id, "model_version_id": a.model_version_id}


async def feature_vector_row(session: AsyncSession, run: CurrentRun, user_id: str, day: date) -> FeatureVector:
    a = await anomaly_row(session, run, user_id, day)
    fv = await session.get(FeatureVector, a.feature_vector_id)
    if fv is None:                                  # a foreign key makes this a database fault, not a user error
        raise NotFound(f"feature vector {a.feature_vector_id} of {user_id} {day} is missing")
    return fv


async def feature_vector(session: AsyncSession, run: CurrentRun, runtimes: Runtimes, user_id: str, day: date) -> dict:
    fv = await feature_vector_row(session, run, user_id, day)
    served = runtimes.served
    inputs = set(served.input_columns) if served is not None else set()
    values = []
    for col, v in (fv.values or {}).items():
        ft = describe(col)
        values.append({"column": col, "value": v, "value_text": value_text(col, v), "label": ft.label,
                       "domain": ft.domain, "kind": ft.kind, "described": ft.described, "static": ft.static,
                       "model_input": col in inputs})
    return {"id": fv.id, "user_id": fv.user_id, "activity_date": fv.activity_date, "profile": fv.profile,
            "features_fingerprint": fv.features_fingerprint, "pipeline_version": fv.pipeline_version,
            "source_path": fv.source_path, "loaded_for": fv.loaded_for,
            "model_inputs": sum(1 for x in values if x["model_input"]), "values": values}


async def list_events(session: AsyncSession, *, user_id: str, date_from: date | None = None,
                      date_to: date | None = None, source_type: str | None = None, limit: int | None = None,
                      offset: int | None = None) -> dict:
    """Persisted events of one monitored user, oldest first. ``user_id`` is required: no corpus-wide listing."""
    if source_type is not None and source_type not in SOURCE_TYPES:
        raise BadRequest(f"source_type must be one of {SOURCE_TYPES}")
    if date_from and date_to and date_from > date_to:
        raise BadRequest("date_from is after date_to")
    limit, offset = clamp_page(limit, offset)
    cond = [EventLog.user_id.in_(user_variants(user_id))]
    if date_from:
        cond.append(EventLog.activity_date >= date_from)
    if date_to:
        cond.append(EventLog.activity_date <= date_to)
    if source_type:
        cond.append(EventLog.source_type == source_type)
    total = (await session.execute(select(func.count(EventLog.id)).where(and_(*cond)))).scalar_one()
    rows = (await session.execute(select(EventLog).where(and_(*cond)).order_by(EventLog.event_time, EventLog.id)
                                  .limit(limit).offset(offset))).scalars().all()
    items = [{"id": e.id, "source_type": e.source_type, "event_type": e.event_type, "event_id": e.event_id,
              "user_id": e.user_id, "device_id": e.device_id, "event_time": e.event_time,
              "activity_date": e.activity_date, "details": e.details, "feature_vector_id": e.feature_vector_id,
              "source_path": e.source_path} for e in rows]
    return {"items": items, "page": page_info(total, limit, offset)}
