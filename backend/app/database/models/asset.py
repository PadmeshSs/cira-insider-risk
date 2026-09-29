"""Asset entity (Bible Ch9 step 3, Architecture §20).

Created in Chapter 9 because the CRI's asset-criticality lookup reads it
(``app.cri.assets``). CERT r4.2 names PCs but says nothing about how critical
they are, so ``criticality`` is nullable and nothing fills it from CERT (N9).
``owner_user_id`` is a monitored subject's id (a CERT user id such as
``ACM2278``), not a row of ``users``, which holds analyst accounts.
"""
from datetime import date, datetime

from sqlalchemy import CheckConstraint, Date, DateTime, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base

CRITICALITY_VALUES = ("low", "medium", "high", "critical")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)

    asset_key: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
    )

    asset_type: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )

    criticality: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
    )

    criticality_source: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    owner_user_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    first_seen: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )

    last_seen: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (
        CheckConstraint(
            "criticality IS NULL OR criticality IN ('low', 'medium', 'high', 'critical')",
            name="criticality_level",
        ),
        CheckConstraint(
            "criticality IS NULL OR criticality_source IS NOT NULL",
            name="criticality_has_source",
        ),
        Index("ix_assets_owner_user_id", "owner_user_id"),
    )
