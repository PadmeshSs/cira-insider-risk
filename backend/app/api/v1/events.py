from datetime import date
from typing import Literal

from fastapi import APIRouter, Query

from app.api.deps import DEFAULT, Limit, Offset, Session
from app.schemas.events import EventPage
from app.services import lineage

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=EventPage, summary="Persisted CERT events of one monitored user, oldest first")
async def list_events(session: Session, user_id: str = Query(min_length=1, max_length=64),
                      date_from: date | None = None, date_to: date | None = None,
                      source_type: Literal["logon", "device", "file", "email", "http"] | None = None,
                      limit: Limit = DEFAULT, offset: Offset = 0):
    return await lineage.list_events(session, user_id=user_id, date_from=date_from, date_to=date_to,
                                     source_type=source_type, limit=limit, offset=offset)
