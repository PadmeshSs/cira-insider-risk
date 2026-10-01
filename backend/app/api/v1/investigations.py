from typing import Literal

from fastapi import APIRouter

from app.api.deps import DEFAULT, Limit, Offset, Run, Session
from app.schemas.investigations import Investigation, SubjectPage
from app.services import investigations

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.get("", response_model=SubjectPage, summary="Monitored users with persisted rows in the served run")
async def subjects(session: Session, run: Run, scope: Literal["all", "alerting", "demo"] = "all",
                   limit: Limit = DEFAULT, offset: Offset = 0):
    return await investigations.list_subjects(session, run, scope=scope, limit=limit, offset=offset)


@router.get("/{user_id}", response_model=Investigation, summary="One user's alerts and persisted coverage")
async def investigation(user_id: str, session: Session, run: Run):
    return await investigations.investigation(session, run, user_id)
