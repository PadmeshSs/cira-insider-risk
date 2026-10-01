"""AlertReason entity (Bible Ch12, Architecture §18, §20, §37; HCEA D-5; N45, N48, N50).

One item of a member day's explanation, built by the Chapter 11 reason
builder and never written by hand. ``section`` keeps the three kinds apart:

    model            a raising model factor (TreeSHAP on the served model):
                     ``subject`` is the feature, ``weight`` its log-odds
                     contribution, ``value`` the raw Chapter 5 value
    model_lowering   a factor that lowered the score, same fields
    cri              a CRI point (context, not a model reason, N34):
                     ``subject`` is the component, ``weight`` its points
    mitre            an ATT&CK match (context, not a model reason, N45):
                     ``subject`` is the technique, ``rule_id`` the rule,
                     ``value`` the triggering column's value

``source`` is the builder's source record, so every row traces back to the
attribution, CRI run or enrichment run it came from (N50). KernelSHAP values
are never stored here: they corroborate, they do not explain (N48).
"""
from datetime import date, datetime

from sqlalchemy import CheckConstraint, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.database.models._types import JSONType

REASON_SECTIONS = ("model", "model_lowering", "cri", "mitre")


class AlertReason(Base):
    __tablename__ = "alert_reasons"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), nullable=False)
    member_id: Mapped[int] = mapped_column(ForeignKey("alert_members.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    activity_date: Mapped[date] = mapped_column(Date, nullable=False)
    section: Mapped[str] = mapped_column(String(16), nullable=False)
    rank: Mapped[int] = mapped_column(Integer, nullable=False)
    subject: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    value: Mapped[float | None] = mapped_column(Float, nullable=True)
    weight: Mapped[float | None] = mapped_column(Float, nullable=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[dict] = mapped_column(JSONType, nullable=False)
    model_version: Mapped[str] = mapped_column(String(128), nullable=False)
    explain_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("section IN ('model', 'model_lowering', 'cri', 'mitre')", name="section_value"),
        CheckConstraint("section NOT IN ('model', 'model_lowering') OR weight IS NOT NULL", name="model_has_contribution"),
        CheckConstraint("section <> 'cri' OR weight IS NOT NULL", name="cri_has_points"),
        CheckConstraint("section <> 'mitre' OR rule_id IS NOT NULL", name="mitre_names_rule"),
        Index("ix_alert_reasons_alert_id", "alert_id"),
        Index("ix_alert_reasons_member_id", "member_id"),
    )
