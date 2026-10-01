"""AuditLog entity (Architecture §20, §36, §37).

What happened to the stored decision record, and by whom. The Chapter 12
load writes one ``alert_run_loaded`` row inside the same transaction as the
rows it describes, so the audit row exists if and only if the load
committed: the database never claims an alert was stored when it was not
(§36). Later chapters add analyst actions (Chapter 13/14).
"""
from datetime import datetime

from sqlalchemy import DateTime, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.database.models._types import JSONType


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSONType, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        Index("ix_audit_logs_action_target", "action", "target_id"),
    )
