"""Shared response pieces."""
from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

ANOMALY_SCORE_NOTE = ("Served model's anomaly score in [0, 1], higher = more anomalous. A ranking score from a "
                      "class-weighted model, not a probability (N20).")
CRI_SCORE_NOTE = ("Contextual risk score, 0-100 (Chapter 9). A separate value from the anomaly score, stored next "
                  "to it and never derived from it here (N34).")
IN_SAMPLE_NOTE = ("True when the served model saw this user's labels in training (model_split = train). Such a "
                  "score is in-sample and is not a detection (N31).")


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class PageInfo(Out):
    total: int = Field(description="Rows matching the filters")
    limit: int
    offset: int
    max_limit: int = Field(description="Server-side cap on limit (HCEA §13)")


class RunLineage(Out):
    """The runs every number in a response was read from (Architecture §37)."""

    alert_run_id: str
    policy_version: str
    policy_hash: str
    model_version: str
    registry_version: str
    batch_run_id: str
    cri_run_id: str
    explain_run_id: str
    mitre_run_id: str | None = None


class QueueInfo(Out):
    ordered_by: str = Field(description="The score that ordered the analyst queue under the alert policy (N55)")
    policy_version: str
    policy_hash: str
    sort: str = Field(description="How this response is sorted")
    context: str = Field(default="The CRI score and band are shown beside every alert as context; the queue is "
                                 "not re-sorted by them (N55).")


class Coverage(Out):
    persisted_days: int
    first_date: date | None = None
    last_date: date | None = None
    note: str = Field(default="PostgreSQL holds alert member days and the demo sample only (HCEA D-6); other "
                              "user-days stay in the Parquet runs and are not served by the API.")
