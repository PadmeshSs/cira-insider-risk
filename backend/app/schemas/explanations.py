from __future__ import annotations

from datetime import date
from typing import Any

from pydantic import Field

from .common import Out, RunLineage


class ExplanationSections(Out):
    model: list[dict[str, Any]] = Field(description="Factors that raised the served model's score (TreeSHAP, log-odds)")
    model_lowering: list[dict[str, Any]] = Field(description="Factors that lowered it")
    cri: list[dict[str, Any]] = Field(description="CRI points: context, not model reasons (N34)")
    mitre: dict[str, Any] | None = Field(default=None,
                                         description="What ATT&CK calls the behaviour; not a reason the model scored it (N45)")


class MemberExplanation(Out):
    member_id: int
    alert_id: int
    user_id: str
    activity_date: date
    status: str
    model_unavailable_reason: str | None = None
    headline: dict[str, Any]
    sections: ExplanationSections
    unavailable: dict[str, str] = Field(default_factory=dict, description="Components excluded, never imputed (N35)")
    corroboration: dict[str, Any] | None = Field(default=None,
                                                 description="KernelSHAP agreement statistic; never a reason (N48)")
    text: str
    reason_rows: dict[str, int] = Field(description="alert_reasons rows per section, for cross-checking (N50)")
    explain_run_id: str


class AlertExplanations(Out):
    alert_id: int
    members: list[MemberExplanation]
    run: RunLineage
