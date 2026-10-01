from __future__ import annotations

from datetime import date

from pydantic import Field

from .common import (
    ANOMALY_SCORE_NOTE,
    CRI_SCORE_NOTE,
    IN_SAMPLE_NOTE,
    Out,
    PageInfo,
    QueueInfo,
    RunLineage,
    Severity,
)


class SuppressedSummary(Out):
    """Suppressed repeats of an open alert (N57, N60). Suppressed is not resolved and not benign."""

    count: int
    first_date: date | None = None
    last_date: date | None = None


class AlertSummary(Out):
    id: int
    alert_key: str
    user_id: str = Field(description="Monitored CERT user id")
    status: str = Field(description="open, or suppressed (a kept repeat of an open alert; not resolved, N57)")
    duplicate_of_id: int | None = None
    first_date: date
    last_date: date
    peak_date: date
    n_days: int
    queue_score: float = Field(description="The value that ordered the queue; `ordering` names it (N55)")
    ordering: str
    peak_anomaly_score: float = Field(description=ANOMALY_SCORE_NOTE)
    peak_cri_score: float = Field(description=CRI_SCORE_NOTE)
    max_cri_score: float = Field(description=CRI_SCORE_NOTE)
    max_severity: Severity
    triggers: list[str] = Field(description="band (CRI HIGH/CRITICAL) and/or top_k (daily budget), N39")
    techniques: list[str] = Field(description="ATT&CK techniques on member days: context, not model reasons (N45)")
    top_feature: str | None = Field(default=None, description="Top raising model factor on the peak day")
    model_split: str
    in_sample: bool = Field(description=IN_SAMPLE_NOTE)
    explanation_status: str
    suppressed: SuppressedSummary | None = Field(default=None, description="For an open alert: its suppressed repeats")


class AlertCounts(Out):
    open: int
    suppressed: int = Field(description="Always reported next to the open count (N57)")


class AlertQueue(Out):
    items: list[AlertSummary]
    page: PageInfo
    counts: AlertCounts
    queue: QueueInfo
    run: RunLineage


class AlertMember(Out):
    id: int
    user_id: str
    activity_date: date
    is_peak: bool
    by_band: bool
    by_top_k: bool
    anomaly_score: float = Field(description=ANOMALY_SCORE_NOTE)
    cri_score: float = Field(description=CRI_SCORE_NOTE)
    severity: Severity
    model_split: str
    in_sample: bool = Field(description=IN_SAMPLE_NOTE)
    explanation_status: str
    explanation_reason: str | None = None
    risk_score_id: int
    anomaly_score_id: int
    feature_vector_id: int


class AlertDetail(Out):
    alert: AlertSummary
    members: list[AlertMember]
    duplicate_of: AlertSummary | None = Field(default=None, description="For a suppressed alert: the open alert it repeats")
    suppressed_alerts: list[AlertSummary] = Field(description="Suppressed alerts that point at this one (N57)")
    queue: QueueInfo
    run: RunLineage
