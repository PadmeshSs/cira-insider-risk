from fastapi import APIRouter

from app.api.deps import Run, RuntimesDep, Session
from app.schemas.mitre import AlertMitre, Technique
from app.services import mitre

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/alerts/{alert_id}", response_model=AlertMitre, summary="ATT&CK context of an alert's member days")
async def for_alert(alert_id: int, session: Session, run: Run):
    return await mitre.for_alert(session, run, alert_id)


@router.get("/techniques/{technique_id}", response_model=Technique, summary="One technique from the pinned ATT&CK table")
async def technique(technique_id: str, runtimes: RuntimesDep):
    return mitre.technique(runtimes, technique_id)
