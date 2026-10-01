from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from .common import Out


class RegisteredModel(Out):
    id: int
    model_name: str
    registry_version: str
    model_version: str
    run_id: str | None = None
    profile: str | None = None
    trained_at: str | None = None
    split_mode: str | None = None
    n_input_columns: int | None = None
    files: dict[str, Any] | None = Field(default=None, description="sha256 of every artifact file (N21)")
    created_at: datetime | None = None


class ModelsOut(Out):
    status: str
    served: dict[str, Any] | None = None
    serving_source: str | None = None
    decision_rule: str | None = None
    reason: str | None = None
    shadow: list[dict[str, Any]] = Field(description="Kept for comparison only; never feeds CRI, alerts or explanations (N32)")
    score_convention: str | None = None
    in_database: list[RegisteredModel] = Field(description="Model versions that produced persisted scores (lineage)")
