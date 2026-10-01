from __future__ import annotations

from datetime import date

from pydantic import Field

from .alerts import AlertSummary
from .common import IN_SAMPLE_NOTE, Coverage, Out, PageInfo, RunLineage, Severity


class Subject(Out):
    """A monitored user with persisted rows in the served run."""

    user_id: str
    model_split: str
    in_sample: bool = Field(description=IN_SAMPLE_NOTE)
    persisted_days: int
    first_date: date
    last_date: date
    open_alerts: int
    suppressed_alerts: int
    max_queue_score: float | None = None
    max_severity: Severity | None = Field(default=None, description="Highest CRI band over the persisted days")
    in_demo_sample: bool
    ldap_role: str | None = None


class SubjectPage(Out):
    items: list[Subject]
    page: PageInfo
    demo_window: dict | None = Field(default=None, description="The c12-demo-sample-v1 window (N59)")
    run: RunLineage


class Investigation(Out):
    subject: Subject
    alerts: list[AlertSummary] = Field(description="Every alert of this user in the served run, open and suppressed")
    coverage: Coverage
    run: RunLineage
