from fastapi import APIRouter, Depends

from app.api.deps import RuntimesDep, get_app_settings, get_engine
from app.services import health as health_service

router = APIRouter(tags=["health"])


@router.get("/health", summary="Every component's real status and which route groups can answer")
async def health(runtimes: RuntimesDep, engine=Depends(get_engine), settings=Depends(get_app_settings)) -> dict:
    return await health_service.health(runtimes, engine=engine, secret=settings.secret_key)
