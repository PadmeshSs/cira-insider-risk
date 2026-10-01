"""EventLog entity (Bible Ch12 step 3, Architecture §8, §20, §37; HCEA D-6, R12).

One normalized CERT event (the Chapter 5 Stage 0 Parquet row) that belongs to
an alert member day or to the demo sample. PostgreSQL stores decisions and
lineage, not the corpus (R12): the other ~32.8M events stay in Parquet.

Traceability: ``event_id`` is CERT's own record id, ``source_path`` the
Stage 0 part file it was read from, and ``feature_vector_id`` the user-day
row it was aggregated into. ``details`` holds only what CERT records for
that domain (activity, file extension, email addresses and size, http host).
There is no URL (D-8), and no signal CERT lacks (N9).
"""
from datetime import date, datetime

from sqlalchemy import CheckConstraint, Date, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.database.models._types import JSONType

SOURCE_TYPES = ("logon", "device", "file", "email", "http")


class EventLog(Base):
    __tablename__ = "event_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_type: Mapped[str] = mapped_column(String(16), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    device_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    activity_date: Mapped[date] = mapped_column(Date, nullable=False)
    details: Mapped[dict | None] = mapped_column(JSONType, nullable=True)
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    feature_vector_id: Mapped[int | None] = mapped_column(ForeignKey("feature_vectors.id"), nullable=True)
    loaded_for: Mapped[str] = mapped_column(String(16), nullable=False)
    first_alert_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("source_type IN ('logon', 'device', 'file', 'email', 'http')", name="source_type_value"),
        Index("uq_event_logs_source_event", "source_type", "event_id", unique=True),
        Index("ix_event_logs_user_day", "user_id", "activity_date"),
        Index("ix_event_logs_feature_vector_id", "feature_vector_id"),
    )
