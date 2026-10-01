"""AnomalyScore entity (Bible Ch12 step 3, Architecture §14, §20, §37; N10, N20, N31, N32).

The served model's score for one user-day, exactly as the Chapter 8 batch
wrote it: ``raw_score`` (the margin) and ``anomaly_score`` in [0, 1], a
ranking score and not a probability (N20). ``role`` can only be 'served'
(check constraint): a shadow score has no place in the alert path (N32).
``model_split`` keeps the served model's own split tag, so an in-sample row
can never be mistaken for a detection (N31).
"""
from datetime import date, datetime

from sqlalchemy import CheckConstraint, Date, DateTime, Float, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class AnomalyScore(Base):
    __tablename__ = "anomaly_scores"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    activity_date: Mapped[date] = mapped_column(Date, nullable=False)
    feature_vector_id: Mapped[int] = mapped_column(ForeignKey("feature_vectors.id"), nullable=False)
    model_version_id: Mapped[int] = mapped_column(ForeignKey("model_versions.id"), nullable=False)
    model_name: Mapped[str] = mapped_column(String(32), nullable=False)
    model_version: Mapped[str] = mapped_column(String(128), nullable=False)
    registry_version: Mapped[str] = mapped_column(String(16), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    model_split: Mapped[str] = mapped_column(String(16), nullable=False)
    raw_score: Mapped[float] = mapped_column(Float, nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    batch_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("role = 'served'", name="served_only"),
        CheckConstraint("anomaly_score >= 0 AND anomaly_score <= 1", name="score_range"),
        Index("uq_anomaly_scores_batch_user_day", "batch_run_id", "user_id", "activity_date", unique=True),
        Index("ix_anomaly_scores_user_day", "user_id", "activity_date"),
    )
