from fastapi import APIRouter

from app.api.deps import RuntimesDep, Session
from app.schemas.models import ModelsOut
from app.services import models

router = APIRouter(prefix="/models", tags=["models"])


@router.get("", response_model=ModelsOut, summary="Served and shadow models, and model versions in the database")
async def list_models(session: Session, runtimes: RuntimesDep):
    return await models.models(session, runtimes)
