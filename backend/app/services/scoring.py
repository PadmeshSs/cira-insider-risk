"""Scoring one user-day on demand (Bible Ch8 outcome, Ch13; HCEA §8).

    anomaly(runtimes, features)            served model only -> anomaly score with its model version
    risk(session, runtimes, request)       anomaly score -> ATT&CK context -> CRI -> band trigger -> explanation

Nothing computed here is stored: HCEA §8 keeps persistence to the batch and
the bounded load, never row-by-row inserts over HTTP, and N58 keeps alert
rows to that one path. Each step that cannot run says why and the rest still
answers (Architecture §36); no step is filled with a default (N35).

The band trigger uses ``app.alerts.policy`` with the served alert run's
recorded policy (N56). A daily top-k needs that day's whole population, so a
single user-day cannot be ranked; ``by_top_k`` is always null here and the
response says so. The activity rule of N56 is applied through the same module.
"""
from __future__ import annotations

import math
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.alerts.policy import ACTIVITY_COLUMN, band_trigger, top_k_eligible
from app.scoring.contracts import (
    ScoringFailedError,
    ScoringInputError,
    ScoringUnavailableError,
)

from .errors import BadRequest, ServiceError, Unavailable
from .runs import Runtimes, current_run

TOP_K_NOTE = ("by_band uses the served alert run's policy through app.alerts.policy (N56). by_top_k is not evaluated: "
              "a daily top-k ranks a whole day's population, which only the batch has. Nothing here is stored.")


def _clean(v: Any) -> Any:
    from app.explainability.reason_builder import jsonable

    return jsonable(v)


def anomaly(runtimes: Runtimes, features: dict, *, user_id: str | None = None, day: str | None = None) -> dict:
    runtimes.require_served()
    try:
        res = runtimes.scoring.score_event(features, user_id=user_id, date=day)
    except ScoringInputError as exc:
        raise BadRequest(str(exc), code="invalid_feature_vector") from exc
    except ScoringUnavailableError as exc:
        raise Unavailable(str(exc), component="anomaly_model") from exc
    except ScoringFailedError as exc:
        raise Unavailable(str(exc), component="anomaly_model", code="scoring_failed") from exc
    return {**res.to_dict(), "persisted": False}


def _mitre(runtimes: Runtimes, features: dict, user_id: str, day: str) -> tuple[dict | None, str | None]:
    from app.mitre.enrich import MitreInputError, MitreUnavailableError

    if runtimes.mitre is None:
        return None, "MITRE runtime not started"
    try:
        ctx = runtimes.mitre.enricher().enrich_event(features, user_id=user_id, date=day)
    except MitreUnavailableError as exc:
        return None, str(exc)
    except (MitreInputError, KeyError, ValueError) as exc:
        return None, f"ATT&CK rules not evaluated: {exc}"
    return _clean(ctx), None


def _number(v) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(f) else f


async def _trigger(session: AsyncSession, runtimes: Runtimes, risk_row: dict | None, features: dict) -> dict:
    out = {"policy_version": None, "policy_hash": None, "by_band": None, "by_top_k": None,
           "eligible_for_top_k": None, "note": TOP_K_NOTE, "reason": None}
    try:
        run = await current_run(session, runtimes)
    except ServiceError as exc:
        return {**out, "reason": f"no alert policy to apply: {exc.message}"}
    except (SQLAlchemyError, OSError) as exc:
        return {**out, "reason": f"no alert policy to apply: database unavailable ({type(exc).__name__})"}
    policy = run.alert_policy
    out.update(policy_version=run.policy_version, policy_hash=run.policy_hash)
    reasons = []
    if risk_row is not None:
        out["by_band"] = bool(band_trigger([risk_row["severity"]], policy)[0])
    else:
        reasons.append("by_band needs the CRI severity, which is unavailable")
    if not policy.require_activity:
        out["eligible_for_top_k"] = True
    elif ACTIVITY_COLUMN in features:
        out["eligible_for_top_k"] = bool(top_k_eligible([features.get(ACTIVITY_COLUMN)], policy, 1)[0])
    else:
        reasons.append(f"eligible_for_top_k needs {ACTIVITY_COLUMN} in the feature vector")
    out["reason"] = "; ".join(reasons) or None
    return out


async def risk(session: AsyncSession, runtimes: Runtimes, *, user_id: str, day: str, features: dict,
               role: str | None = None, explain: bool = True) -> dict:
    from app.cri.engine import CRIInputError, CRIModelMismatchError, CRIUnavailableError

    score = anomaly(runtimes, features, user_id=user_id, day=day)
    mitre, mitre_reason = _mitre(runtimes, features, user_id, day)
    mitre_context = None if mitre is None else _number(mitre.get("mitre_context"))

    risk_row, risk_reason, unavailable = None, None, {}
    if runtimes.cri is None:
        risk_reason = "CRI runtime not started"
    else:
        try:
            detail = runtimes.cri.engine().compute_event_detail(score, features, role, mitre_context=mitre_context)
            risk_row, unavailable = _clean(detail["risk"]), dict(detail["unavailable_components"])
        except CRIInputError as exc:
            raise BadRequest(str(exc), code="invalid_feature_vector") from exc
        except (CRIUnavailableError, CRIModelMismatchError) as exc:
            risk_reason = str(exc)
    if mitre is not None and mitre_context is None and "mitre_context" in unavailable:
        unavailable["mitre_context"] = f"ATT&CK rules not evaluated for this day ({mitre.get('mitre_status')})"
    elif mitre_reason:
        unavailable.setdefault("mitre_context", mitre_reason)

    explanation, explanation_reason = None, None
    if explain:
        if runtimes.explain is None:
            explanation_reason = "explainability runtime not started"
        else:
            from app.explainability.reason_builder import ExplanationInputError

            shown = {k: v for k, v in unavailable.items() if k != "mitre_context"}   # ATT&CK section says it
            try:
                explanation = runtimes.explain.explain_event(features, user_id=user_id, date=day, risk=risk_row,
                                                             mitre=mitre, unavailable_components=shown)
            except ExplanationInputError as exc:
                explanation_reason = f"refused: {exc}"
    return {"anomaly": score, "risk": risk_row, "risk_unavailable_reason": risk_reason,
            "unavailable_components": unavailable, "mitre": mitre, "mitre_unavailable_reason": mitre_reason,
            "alert_trigger": await _trigger(session, runtimes, risk_row, features), "explanation": explanation,
            "explanation_unavailable_reason": explanation_reason, "persisted": False}
