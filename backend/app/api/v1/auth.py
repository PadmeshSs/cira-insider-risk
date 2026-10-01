from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm

from app.api.deps import Session, get_app_settings
from app.schemas.auth import Token
from app.services import accounts

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/token", response_model=Token, summary="Sign in with username and password (OAuth2 password flow)")
async def token(form: Annotated[OAuth2PasswordRequestForm, Depends()], session: Session,
                settings=Depends(get_app_settings)):
    return await accounts.login(session, form.username, form.password, secret=settings.secret_key,
                                minutes=settings.access_token_minutes)
