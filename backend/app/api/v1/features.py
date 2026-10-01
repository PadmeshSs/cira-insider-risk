from datetime import date

from fastapi import APIRouter

from app.api.deps import Run, RuntimesDep, Session
from app.schemas.features import FeatureVector
from app.services import lineage

router = APIRouter(prefix="/features", tags=["features"])


@router.get("/users/{user_id}/days/{day}", response_model=FeatureVector,
            summary="The stored Chapter 5 feature vector of one user-day, described")
async def feature_vector(user_id: str, day: date, session: Session, run: Run, runtimes: RuntimesDep):
    return await lineage.feature_vector(session, run, runtimes, user_id, day)
