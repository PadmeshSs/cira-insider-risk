from datetime import date

from fastapi import APIRouter

from app.api.deps import Run, Session
from app.schemas.explanations import AlertExplanations, MemberExplanation
from app.services import explanations

router = APIRouter(prefix="/explanations", tags=["explanations"])


@router.get("/alerts/{alert_id}", response_model=AlertExplanations, summary="Stored explanations of an alert's days")
async def for_alert(alert_id: int, session: Session, run: Run):
    return await explanations.for_alert(session, run, alert_id)


@router.get("/users/{user_id}/days/{day}", response_model=MemberExplanation,
            summary="Stored explanation of one alert member day")
async def for_user_day(user_id: str, day: date, session: Session, run: Run):
    return await explanations.for_user_day(session, run, user_id, day)
