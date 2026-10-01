from __future__ import annotations

from datetime import date

from pydantic import Field

from .common import Out, RunLineage

TECHNIQUE_NOTE = ("A technique says what ATT&CK calls the observed behaviour. It is context, not a reason the model "
                  "scored the day, and most mapped days are ordinary (N43, N45).")


class Mapping(Out):
    id: int
    user_id: str
    activity_date: date
    status: str = Field(description="mapped, or unmapped (evaluated, nothing mapped)")
    technique_id: str | None = None
    technique_name: str | None = None
    tactic: str | None = None
    rule_id: str | None = None
    evidence: str | None = Field(default=None, description="observed, or indicated (CERT records a visit, not a transfer)")
    trigger_column: str | None = None
    trigger_value: float | None = None
    strength: float | None = None
    mitre_context: float | None = None
    unmapped_behaviours: list[str] | None = None
    ruleset_version: str
    ruleset_hash: str
    attack_version: str
    mitre_run_id: str


class MitreDay(Out):
    activity_date: date
    status: str = Field(description="mapped, unmapped, or not_evaluated (no row for the day)")
    mappings: list[Mapping]


class TechniqueCount(Out):
    technique_id: str
    technique_name: str | None = None
    tactic: str | None = None
    days: int


class AlertMitre(Out):
    alert_id: int
    days: list[MitreDay]
    techniques: list[TechniqueCount]
    note: str = TECHNIQUE_NOTE
    run: RunLineage


class RuleOut(Out):
    rule_id: str
    pattern: str
    trigger_column: str
    evidence: str
    reasoning: str
    not_observable: str


class Technique(Out):
    technique_id: str
    name: str
    full_name: str
    tactics: list[str]
    is_subtechnique: bool
    parent_id: str | None = None
    short_description: str
    url: str
    attack_version: str
    rules: list[RuleOut] = Field(description="CIRA rules that can map a user-day to this technique")
    note: str = TECHNIQUE_NOTE
