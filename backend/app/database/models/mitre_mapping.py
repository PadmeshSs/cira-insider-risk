"""MITREMapping entity (Bible Ch10 step 4, Architecture §16, §20, §37).

Created in Chapter 10 because this is the chapter that produces mappings.
One row is either one mapped technique for a user-day (``status =
'mapped'``: technique, tactic, the rule and Chapter 5 column that triggered
it, its value and strength) or the explicit record that a user-day was
evaluated and nothing mapped (``status = 'unmapped'``: no technique). The
check constraints make a forced mapping impossible to store: a mapped row
must name its rule, technique, tactic and triggering column; an unmapped
row must not name a technique.

Lineage (§37): ``mitre_run_id`` -> the enrichment run's meta ->
``ruleset_version``/``ruleset_hash``, ``attack_version`` and
``reference_id``. Rows are persisted in Chapter 12 for alert-linked
user-days and the demo sample only (HCEA D-6); the full set stays in
Parquet. The link to an alert (``alert_id``) is added with the Alert entity
in Chapter 12. ``user_id`` is a monitored subject's id (a CERT user id),
not a row of ``users``.
"""
from datetime import date, datetime

from sqlalchemy import JSON, CheckConstraint, Date, DateTime, Float, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base

MAPPING_STATUSES = ("mapped", "unmapped")
EVIDENCE_GRADES = ("observed", "indicated")


class MITREMapping(Base):
    __tablename__ = "mitre_mappings"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    activity_date: Mapped[date] = mapped_column(Date, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)

    technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    technique_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    trigger_column: Mapped[str | None] = mapped_column(String(128), nullable=True)
    trigger_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    strength: Mapped[float | None] = mapped_column(Float, nullable=True)
    mitre_context: Mapped[float | None] = mapped_column(Float, nullable=True)
    unmapped_behaviours: Mapped[list | None] = mapped_column(JSON().with_variant(JSONB(), "postgresql"), nullable=True)

    ruleset_version: Mapped[str] = mapped_column(String(32), nullable=False)
    ruleset_hash: Mapped[str] = mapped_column(String(16), nullable=False)
    attack_version: Mapped[str] = mapped_column(String(16), nullable=False)
    reference_id: Mapped[str] = mapped_column(String(64), nullable=False)
    mitre_run_id: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("status IN ('mapped', 'unmapped')", name="status_value"),
        CheckConstraint(
            "status <> 'mapped' OR (technique_id IS NOT NULL AND tactic IS NOT NULL AND rule_id IS NOT NULL "
            "AND trigger_column IS NOT NULL AND evidence IS NOT NULL)",
            name="mapped_is_traceable",
        ),
        CheckConstraint("status <> 'unmapped' OR (technique_id IS NULL AND rule_id IS NULL)", name="unmapped_has_no_technique"),
        CheckConstraint("evidence IS NULL OR evidence IN ('observed', 'indicated')", name="evidence_grade"),
        CheckConstraint("mitre_context IS NULL OR (mitre_context >= 0 AND mitre_context <= 1)", name="context_range"),
        Index("ix_mitre_mappings_user_day", "user_id", "activity_date"),
        Index("ix_mitre_mappings_technique_id", "technique_id"),
    )
