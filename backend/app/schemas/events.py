from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import Field

from .common import Out, PageInfo


class Event(Out):
    id: int
    source_type: str
    event_type: str
    event_id: str = Field(description="CERT's own record id")
    user_id: str
    device_id: str | None = None
    event_time: datetime
    activity_date: date
    details: dict[str, Any] | None = Field(default=None, description="Only what CERT records for the domain (N9, D-8)")
    feature_vector_id: int | None = None
    source_path: str


class EventPage(Out):
    items: list[Event]
    page: PageInfo
    note: str = ("Events are persisted for alert member days and the demo sample only (HCEA D-6); "
                 "a user-day without events here may still have events in the Stage 0 Parquet.")
