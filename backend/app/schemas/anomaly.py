from __future__ import annotations

from datetime import date

from pydantic import Field

from .common import ANOMALY_SCORE_NOTE, IN_SAMPLE_NOTE, Out


class StoredAnomalyScore(Out):
    id: int
    user_id: str
    activity_date: date
    anomaly_score: float = Field(description=ANOMALY_SCORE_NOTE)
    raw_score: float
    model_name: str
    model_version: str
    registry_version: str
    role: str = Field(description="Always served: shadow scores are never stored (N32)")
    model_split: str
    in_sample: bool = Field(description=IN_SAMPLE_NOTE)
    batch_run_id: str
    feature_vector_id: int
    model_version_id: int
