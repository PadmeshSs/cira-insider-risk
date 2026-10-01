from datetime import date
from typing import Literal

from fastapi import APIRouter

from app.api.deps import Run, RuntimesDep, Session
from app.schemas.risk import (
    Overview,
    RiskHistory,
    RiskRow,
    RiskScoreOut,
    RiskScoreRequest,
)
from app.services import risk, scoring

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/overview", response_model=Overview, summary="Who is risky: counts, bands and ranked users (aggregated)")
async def overview(session: Session, run: Run):
    return await risk.overview(session, run)


@router.get("/users/{user_id}/history", response_model=RiskHistory, summary="Risk history of one user, bucketed")
async def history(user_id: str, session: Session, run: Run, bucket: Literal["day", "week"] = "day"):
    return await risk.history(session, run, user_id, bucket)


@router.get("/users/{user_id}/days/{day}", response_model=RiskRow, summary="The stored risk row of one user-day")
async def risk_day(user_id: str, day: date, session: Session, run: Run):
    return await risk.risk_for_day(session, run, user_id, day)


@router.post("/score", response_model=RiskScoreOut,
             summary="Score one user-day on demand: anomaly, ATT&CK, CRI, band trigger, explanation (not stored)")
async def score(body: RiskScoreRequest, session: Session, runtimes: RuntimesDep):
    return await scoring.risk(session, runtimes, user_id=body.user_id, day=body.date.isoformat(),
                              features=body.features, role=body.role, explain=body.explain)
