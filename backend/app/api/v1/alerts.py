from typing import Literal

from fastapi import APIRouter

from app.api.deps import DEFAULT, Limit, Offset, Run, Session
from app.schemas.alerts import AlertDetail, AlertQueue
from app.services import alerts

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertQueue, summary="The analyst queue: alerts of the served run, paginated")
async def list_alerts(session: Session, run: Run, status: Literal["open", "suppressed", "all"] = "open",
                      severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None, user_id: str | None = None,
                      sort: Literal["queue", "recent"] = "queue", limit: Limit = DEFAULT, offset: Offset = 0):
    return await alerts.list_alerts(session, run, status=status, severity=severity, user_id=user_id, sort=sort,
                                    limit=limit, offset=offset)


@router.get("/{alert_id}", response_model=AlertDetail, summary="One alert, its member days and its suppressed repeats")
async def get_alert(alert_id: int, session: Session, run: Run):
    return await alerts.get_alert(session, run, alert_id)
