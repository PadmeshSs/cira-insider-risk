"""FeatureVector entity (Bible Ch12 step 3, Architecture §20, §37; HCEA D-6).

One Chapter 5 user-day row, as the model read it: every feature column in
``values`` (a null stays null, N4), with the matrix fingerprint and file it
came from. Only alert member days and the demo sample are persisted (D-6);
the full matrix stays in Parquet, referenced by ``source_path`` and the
(user_id, activity_date) key. No label is ever stored here (N5).
"""
from datetime import date, datetime

from sqlalchemy import Date, DateTime, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.database.models._types import JSONType


class FeatureVector(Base):
    __tablename__ = "feature_vectors"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    activity_date: Mapped[date] = mapped_column(Date, nullable=False)
    profile: Mapped[str] = mapped_column(String(16), nullable=False)
    features_fingerprint: Mapped[str] = mapped_column(String(32), nullable=False)
    pipeline_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    values: Mapped[dict] = mapped_column(JSONType, nullable=False)
    loaded_for: Mapped[str] = mapped_column(String(16), nullable=False)
    first_alert_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        Index("uq_feature_vectors_fp_user_day", "features_fingerprint", "user_id", "activity_date", unique=True),
        Index("ix_feature_vectors_user_day", "user_id", "activity_date"),
    )
