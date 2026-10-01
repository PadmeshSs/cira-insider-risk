from __future__ import annotations

from datetime import datetime

from pydantic import Field

from .common import Out


class Token(Out):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


class Analyst(Out):
    """An analyst account (the ``users`` table). Not a monitored CERT user."""

    id: int
    username: str
    email: str
    role: str
    department: str | None = None
    is_active: bool
    created_at: datetime | None = None
    token_expires_at: datetime | None = Field(default=None, description="Expiry of the token used for this request")
