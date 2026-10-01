from datetime import date

from fastapi import APIRouter

from app.api.deps import Run, RuntimesDep, Session
from app.schemas.anomaly import StoredAnomalyScore
from app.schemas.risk import AnomalyScoreOut, ScoreRequest
from app.services import lineage, scoring

router = APIRouter(prefix="/anomaly", tags=["anomaly"])


@router.post("/score", response_model=AnomalyScoreOut, summary="Served model's anomaly score for one feature vector")
async def score(body: ScoreRequest, runtimes: RuntimesDep):
    return scoring.anomaly(runtimes, body.features, user_id=body.user_id,
                           day=None if body.date is None else body.date.isoformat())


@router.get("/users/{user_id}/days/{day}", response_model=StoredAnomalyScore,
            summary="The stored served score of one user-day")
async def stored(user_id: str, day: date, session: Session, run: Run):
    return await lineage.stored_anomaly(session, run, user_id, day)
