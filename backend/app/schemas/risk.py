from __future__ import annotations

import datetime as _dt
from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from .common import (
    ANOMALY_SCORE_NOTE,
    CRI_SCORE_NOTE,
    IN_SAMPLE_NOTE,
    Coverage,
    Out,
    QueueInfo,
    RunLineage,
    Severity,
)


class RiskRow(Out):
    """One persisted risk row of the served CRI run, with its anomaly score beside it (N34)."""

    risk_score_id: int
    anomaly_score_id: int
    user_id: str
    activity_date: date
    anomaly_score: float = Field(description=ANOMALY_SCORE_NOTE)
    cri_score: float = Field(description=CRI_SCORE_NOTE)
    severity: Severity
    components: dict[str, float | None] = Field(description="Each CRI component in [0, 1]; null = no value on this day")
    points: dict[str, float | None] = Field(description="CRI points per component: context, not model reasons (N34)")
    missing_components: list[str]
    historical_top_feature: str | None = None
    peer_top_feature: str | None = None
    ldap_role: str | None = None
    model_split: str
    in_sample: bool = Field(description=IN_SAMPLE_NOTE)
    model_version: str
    cri_version: str
    cri_config_hash: str
    cri_variant: str
    calibration_id: str
    cri_run_id: str
    mitre_run_id: str | None = None
    alert_ids: list[int] = Field(description="Alerts of the served run that have this user-day as a member")


class HistoryBucket(Out):
    start: date
    end: date
    days: int = Field(description="Persisted user-days in the bucket")
    max_cri_score: float = Field(description=CRI_SCORE_NOTE)
    mean_cri_score: float
    max_anomaly_score: float = Field(description=ANOMALY_SCORE_NOTE)
    mean_anomaly_score: float
    max_severity: Severity
    alert_member_days: int


class RiskHistory(Out):
    user_id: str
    bucket: Literal["day", "week"]
    coverage: Coverage
    buckets: list[HistoryBucket] = Field(description="Aggregated on the server (HCEA §13); both scores kept apart")
    run: RunLineage


class FeatureCount(Out):
    feature: str
    open_alerts: int


class DateCount(Out):
    start: date
    end: date
    count: int


class RiskyUser(Out):
    user_id: str
    open_alerts: int
    suppressed_alerts: int
    max_queue_score: float
    max_severity: Severity
    model_split: str
    in_sample: bool = Field(description=IN_SAMPLE_NOTE)


class Overview(Out):
    counts: dict[str, int] = Field(description="open and suppressed alerts, always together (N57)")
    open_by_severity: dict[str, int] = Field(description="Highest CRI band reached in each open alert")
    open_by_split: dict[str, int]
    open_never_above_low: int = Field(description="Open alerts that are in the queue on the anomaly score alone (N60)")
    top_features: list[FeatureCount] = Field(description="Top raising model factor of open alerts (N52)")
    open_led_by_usb_disconnect_count: int = Field(description="Shown because it leads most false alarms on validation (N52)")
    new_open_alerts: list[DateCount] = Field(description="New open alerts per week, by first day")
    top_users: list[RiskyUser] = Field(description="Ranked by their highest queue score among open alerts")
    queue: QueueInfo
    run: RunLineage


class ScoreRequest(BaseModel):
    user_id: str | None = Field(default=None, max_length=64)
    date: _dt.date | None = None
    features: dict[str, float | None] = Field(description="Chapter 5 columns by name; null is a deliberate null (N4)",
                                              max_length=2000)


class RiskScoreRequest(ScoreRequest):
    user_id: str = Field(max_length=64)
    date: _dt.date
    role: str | None = Field(default=None, max_length=128,
                             description="LDAP role for user_context; without it the component has no value (N35)")
    explain: bool = True


class AnomalyScoreOut(Out):
    anomaly_score: float = Field(description=ANOMALY_SCORE_NOTE)
    raw_score: float = Field(description="The served model's margin (log-odds)")
    model_name: str
    model_version: str
    registry_version: str
    role: Literal["served"]
    scored_at: datetime
    user_id: str | None = None
    date: _dt.date | None = None
    persisted: bool = Field(default=False, description="Scores computed over HTTP are never stored (HCEA §8)")


class AlertTrigger(Out):
    policy_version: str | None = None
    policy_hash: str | None = None
    by_band: bool | None = Field(default=None, description="CRI severity in the policy's bands (app.alerts.policy, N56)")
    by_top_k: None = Field(default=None, description="Not evaluated: a daily top-k needs that day's whole population")
    eligible_for_top_k: bool | None = Field(default=None, description="The N56 activity rule, applied to this day")
    note: str
    reason: str | None = None


class RiskScoreOut(Out):
    anomaly: AnomalyScoreOut
    risk: dict[str, Any] | None = Field(default=None, description="CRI row; anomaly_score inside it is the same value")
    risk_unavailable_reason: str | None = None
    unavailable_components: dict[str, str] = Field(default_factory=dict)
    mitre: dict[str, Any] | None = None
    mitre_unavailable_reason: str | None = None
    alert_trigger: AlertTrigger
    explanation: dict[str, Any] | None = None
    explanation_unavailable_reason: str | None = None
    persisted: bool = False
