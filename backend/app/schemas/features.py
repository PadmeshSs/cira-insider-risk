from __future__ import annotations

from datetime import date

from pydantic import Field

from .common import Out


class FeatureValue(Out):
    column: str
    value: float | None
    value_text: str
    label: str
    domain: str
    kind: str
    described: bool
    static: bool = Field(description="A per-user trait (psychometrics, department size), not behaviour (N22, N25)")
    model_input: bool = Field(description="Whether the served model reads this column")


class FeatureVector(Out):
    id: int
    user_id: str
    activity_date: date
    profile: str
    features_fingerprint: str
    pipeline_version: str | None = None
    source_path: str
    loaded_for: str
    model_inputs: int
    values: list[FeatureValue]
