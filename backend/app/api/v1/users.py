from fastapi import APIRouter

from app.api.deps import Analyst
from app.schemas.auth import Analyst as AnalystOut

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=AnalystOut, summary="The signed-in analyst account")
async def me(analyst: Analyst):
    return analyst
