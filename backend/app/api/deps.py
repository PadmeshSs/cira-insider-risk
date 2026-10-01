"""FastAPI dependencies: database session and engine, runtimes, the signed-in analyst, the served run.

Tests override ``get_session``, ``get_engine`` and ``get_app_settings`` with
``app.dependency_overrides`` to point the API at a test database.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Query, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_session
from app.services import accounts
from app.services.common import DEFAULT_LIMIT, MAX_LIMIT
from app.services.runs import CurrentRun, Runtimes, current_run

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)


def get_engine():
    from app.database.session import engine

    return engine


def get_app_settings():
    from app.core.config import settings

    return settings


def get_runtimes(request: Request) -> Runtimes:
    s = request.app.state
    return Runtimes(scoring=getattr(s, "scoring", None), cri=getattr(s, "cri", None), mitre=getattr(s, "mitre", None),
                    explain=getattr(s, "explain", None), alerts=getattr(s, "alerts", None))


Session = Annotated[AsyncSession, Depends(get_session)]
RuntimesDep = Annotated[Runtimes, Depends(get_runtimes)]


async def current_analyst(session: Session, token: Annotated[str | None, Depends(oauth2_scheme)],
                          settings=Depends(get_app_settings)) -> dict:
    return await accounts.analyst_from_token(session, token, secret=settings.secret_key)


Analyst = Annotated[dict, Depends(current_analyst)]


async def served_run(session: Session, runtimes: RuntimesDep,
                     alert_run_id: Annotated[str | None, Query(max_length=64, description=(
                         "A loaded alert run of the served model; default the newest one (N28, N58)"))] = None
                     ) -> CurrentRun:
    return await current_run(session, runtimes, alert_run_id)


Run = Annotated[CurrentRun, Depends(served_run)]
Limit = Annotated[int, Query(ge=1, le=MAX_LIMIT, description=f"Page size; hard cap {MAX_LIMIT} (HCEA §13)")]
Offset = Annotated[int, Query(ge=0)]
DEFAULT = DEFAULT_LIMIT
