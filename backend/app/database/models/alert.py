"""Alert and AlertMember entities (Bible Ch12, Architecture §17, §20, §37).

Alert: one correlated incident (``app.alerts.correlation``) of one monitored
user, with the policy that produced it and the runs it was built from. A
suppressed alert (``app.alerts.deduplication``) is kept for audit and must
name the open alert it repeats (check constraint). ``queue_score`` is what
orders the analyst queue (the served anomaly score under the default
policy, N40); ``max_cri_score`` and ``max_severity`` are context.

AlertMember: the link from an alert to each of its user-days, i.e. the
"child links" of Bible Ch12. It points at the RiskScore of that day (and
through it the AnomalyScore, FeatureVector and EventLog rows, §37), says
which trigger fired, and holds the full Chapter 11 explanation of the day
(``explanation`` and ``explanation_text``). §20 has no membership entity;
correlation needs one (deviation C12-3).

``user_id`` is a monitored subject's id (a CERT user id), not a row of
``users``, which holds analyst accounts.
"""
from datetime import date, datetime

from sqlalchemy import Boolean, CheckConstraint, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.database.models._types import JSONType

ALERT_STATUSES = ("open", "suppressed")
EXPLANATION_STATUSES = ("complete", "model_explanation_deferred")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    alert_key: Mapped[str] = mapped_column(String(32), nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    duplicate_of_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    first_date: Mapped[date] = mapped_column(Date, nullable=False)
    last_date: Mapped[date] = mapped_column(Date, nullable=False)
    peak_date: Mapped[date] = mapped_column(Date, nullable=False)
    n_days: Mapped[int] = mapped_column(Integer, nullable=False)
    peak_anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    peak_cri_score: Mapped[float] = mapped_column(Float, nullable=False)
    max_cri_score: Mapped[float] = mapped_column(Float, nullable=False)
    max_severity: Mapped[str] = mapped_column(String(16), nullable=False)
    queue_score: Mapped[float] = mapped_column(Float, nullable=False)
    ordering: Mapped[str] = mapped_column(String(32), nullable=False)
    triggers: Mapped[list | None] = mapped_column(JSONType, nullable=True)
    techniques: Mapped[list | None] = mapped_column(JSONType, nullable=True)
    signature: Mapped[list | None] = mapped_column(JSONType, nullable=True)
    top_feature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model_split: Mapped[str] = mapped_column(String(16), nullable=False)
    explanation_status: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(16), nullable=False)
    model_version_id: Mapped[int] = mapped_column(ForeignKey("model_versions.id"), nullable=False)
    model_version: Mapped[str] = mapped_column(String(128), nullable=False)
    batch_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    cri_run_id: Mapped[str] = mapped_column(String(96), nullable=False)
    explain_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    mitre_run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("status IN ('open', 'suppressed')", name="status_value"),
        CheckConstraint("status <> 'suppressed' OR duplicate_of_id IS NOT NULL", name="suppressed_names_original"),
        CheckConstraint("status <> 'open' OR duplicate_of_id IS NULL", name="open_is_not_a_duplicate"),
        CheckConstraint("first_date <= peak_date AND peak_date <= last_date", name="peak_inside_span"),
        CheckConstraint("n_days >= 1", name="has_members"),
        CheckConstraint("max_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="severity_value"),
        CheckConstraint("explanation_status IN ('complete', 'model_explanation_deferred')", name="explanation_status_value"),
        Index("uq_alerts_run_key", "alert_run_id", "alert_key", unique=True),
        Index("ix_alerts_user_first_date", "user_id", "first_date"),
        Index("ix_alerts_run_status_queue", "alert_run_id", "status", "queue_score"),
    )


class AlertMember(Base):
    __tablename__ = "alert_members"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), nullable=False)
    risk_score_id: Mapped[int] = mapped_column(ForeignKey("risk_scores.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    activity_date: Mapped[date] = mapped_column(Date, nullable=False)
    is_peak: Mapped[bool] = mapped_column(Boolean, nullable=False)
    by_band: Mapped[bool] = mapped_column(Boolean, nullable=False)
    by_top_k: Mapped[bool] = mapped_column(Boolean, nullable=False)
    explanation_status: Mapped[str] = mapped_column(String(32), nullable=False)
    explanation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation_text: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[dict] = mapped_column(JSONType, nullable=False)
    kernel_top5_overlap: Mapped[float | None] = mapped_column(Float, nullable=True)
    kernel_deletion_beats_random: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    explain_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("by_band OR by_top_k", name="triggered"),
        CheckConstraint("explanation_status IN ('complete', 'model_explanation_deferred')", name="explanation_status_value"),
        CheckConstraint("explanation_status <> 'model_explanation_deferred' OR explanation_reason IS NOT NULL",
                        name="deferred_has_reason"),
        Index("uq_alert_members_alert_day", "alert_id", "activity_date", unique=True),
        Index("ix_alert_members_risk_score_id", "risk_score_id"),
        Index("ix_alert_members_user_day", "user_id", "activity_date"),
    )
