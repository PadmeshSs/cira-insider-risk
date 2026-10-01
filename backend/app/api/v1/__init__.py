"""/api/v1. Every group except auth and health requires a signed-in analyst."""
from fastapi import APIRouter, Depends

from app.api.deps import current_analyst

from . import (
    alerts,
    anomaly,
    auth,
    events,
    explanations,
    features,
    health,
    investigations,
    mitre,
    models,
    risk,
    users,
)

PROTECTED = (users, events, features, anomaly, risk, alerts, investigations, mitre, explanations, models)

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(health.router)
for _m in PROTECTED:
    api_router.include_router(_m.router, dependencies=[Depends(current_analyst)])
