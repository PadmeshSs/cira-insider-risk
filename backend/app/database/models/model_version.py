"""ModelVersion entity (Bible Ch12 step 3, Architecture §20, §37, N21).

One row per registered model version that produced a persisted score. It
mirrors the registry entry (``models/saved_models/<model>/registry.jsonl``),
including the sha256 of every artifact file, so an alert traces back to the
exact files: alert -> model_version -> registry entry -> files. The registry
stays the source of the artifacts; this row is the lineage record the
database can join on. Only the served model is written by the Chapter 12 load
(N32: shadow scores never reach an alert).
"""
from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.database.models._types import JSONType


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[int] = mapped_column(primary_key=True)
    model_name: Mapped[str] = mapped_column(String(32), nullable=False)
    registry_version: Mapped[str] = mapped_column(String(16), nullable=False)
    model_version: Mapped[str] = mapped_column(String(128), nullable=False)
    run_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    profile: Mapped[str | None] = mapped_column(String(16), nullable=True)
    trained_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    split_mode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    n_input_columns: Mapped[int | None] = mapped_column(Integer, nullable=True)
    artifact_dir: Mapped[str | None] = mapped_column(Text, nullable=True)
    files: Mapped[dict | None] = mapped_column(JSONType, nullable=True)
    details: Mapped[dict | None] = mapped_column(JSONType, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        Index("uq_model_versions_model_version", "model_version", unique=True),
        Index("ix_model_versions_name_registry", "model_name", "registry_version"),
    )
