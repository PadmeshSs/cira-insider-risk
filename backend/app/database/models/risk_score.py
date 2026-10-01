"""RiskScore entity (Bible Ch12 step 3, Architecture §14, §15, §20, §37; N33, N34, N35).

The CRI for one user-day from one Chapter 9 risk run. It points at the
AnomalyScore it was computed from and also keeps that score's value in
``anomaly_score``, unchanged, next to ``cri_score``: two values, never merged
and never derived from each other here (N34). The verifier checks that the
copy equals the referenced row. Components and points are stored as the run
wrote them; an unavailable component is absent from ``points`` and named in
the run's meta, never filled in (N35).
"""
from datetime import date, datetime

from sqlalchemy import CheckConstraint, Date, DateTime, Float, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.database.models._types import JSONType

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id: Mapped[int] = mapped_column(primary_key=True)
    anomaly_score_id: Mapped[int] = mapped_column(ForeignKey("anomaly_scores.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    activity_date: Mapped[date] = mapped_column(Date, nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    cri_score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    components: Mapped[dict | None] = mapped_column(JSONType, nullable=True)
    points: Mapped[dict | None] = mapped_column(JSONType, nullable=True)
    missing_components: Mapped[str | None] = mapped_column(Text, nullable=True)
    historical_top_feature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    peer_top_feature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ldap_role: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model_version: Mapped[str] = mapped_column(String(128), nullable=False)
    cri_version: Mapped[str] = mapped_column(String(32), nullable=False)
    cri_config_hash: Mapped[str] = mapped_column(String(32), nullable=False)
    cri_variant: Mapped[str] = mapped_column(String(32), nullable=False)
    calibration_id: Mapped[str] = mapped_column(String(64), nullable=False)
    formula_hash: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cri_run_id: Mapped[str] = mapped_column(String(96), nullable=False)
    mitre_run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="severity_value"),
        CheckConstraint("cri_score >= 0 AND cri_score <= 100", name="cri_range"),
        CheckConstraint("anomaly_score >= 0 AND anomaly_score <= 1", name="anomaly_range"),
        Index("uq_risk_scores_run_user_day", "cri_run_id", "user_id", "activity_date", unique=True),
        Index("ix_risk_scores_anomaly_score_id", "anomaly_score_id"),
        Index("ix_risk_scores_user_day", "user_id", "activity_date"),
    )
