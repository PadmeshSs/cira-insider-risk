"""MitreEnricher: user-day behaviour -> candidate techniques and mitre_context (Bible Ch10 step 3).

    enricher = MitreEnricher.load()                        # table + pinned reference, both sha256-checked
    out = enricher.enrich(frame)                           # vectorised; frame has user_id, date + rule columns
    out.context   one row per user-day (the CRI reads ``mitre_context``)
    out.matches   one row per (user-day, rule) that fired: the traceable mappings
    row = enricher.enrich_event(feature_vector)            # one user-day, for the API (Chapter 13)

Per user-day status (Architecture §16: unmapped is explicit)
    mapped          at least one rule fired; ``mitre_context`` in (0, 1]
    unmapped        rules evaluated, none fired; ``mitre_context`` = 0.
                    ``mitre_unmapped_behaviours`` lists deliberately
                    unmapped behaviours seen that day (job search, a
                    first-seen PC, archive copies), so the analyst can see
                    they were considered and have no technique.
    not_evaluated   every rule column was null; ``mitre_context`` null

Traceability (Bible Ch10 acceptance)
    Every match names the rule, the technique and tactic from the pinned
    table, the evidence grade, the Chapter 5 column that triggered it and
    its value that day, and its stage-1 strength. Every context row names
    the ruleset version, the ATT&CK version and the reference id.

Model-free and label-free: reads behaviour columns only (N5, N42).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

import numpy as np
import pandas as pd

from . import MITRE_VERSION
from .mapping_rules import NOT_MAPPED, RULES, RULESET_VERSION, flag_columns, required_columns, ruleset_hash
from .reference import LoadedReference, MitreReferenceUnavailableError, load_reference
from .techniques import TechniqueTable, TechniqueTableError, load_technique_table

STATUSES = ("mapped", "unmapped", "not_evaluated")
CONTEXT_COLUMNS = (
    "user_id", "date", "mitre_status", "mitre_context", "mitre_strength_max",
    "mitre_top_rule", "mitre_top_technique", "mitre_top_technique_name", "mitre_top_tactic",
    "mitre_techniques", "mitre_rules", "mitre_match_count", "mitre_unmapped_behaviours",
    "mitre_version", "ruleset_version", "ruleset_hash", "attack_version", "mitre_reference_id",
)
MATCH_COLUMNS = (
    "user_id", "date", "rule_id", "technique_id", "technique_name", "tactic", "tactic_name", "evidence",
    "trigger_column", "trigger_value", "strength", "technique_url",
    "ruleset_version", "attack_version", "mitre_reference_id",
)


class MitreUnavailableError(RuntimeError):
    """The enrichment cannot run (no table, no reference, rules invalid)."""


class MitreInputError(ValueError):
    """The rows cannot be enriched as given."""


@dataclass
class Enrichment:
    context: pd.DataFrame
    matches: pd.DataFrame


def _join(acc: np.ndarray, add: np.ndarray, value: str) -> np.ndarray:
    return np.where(add, np.where(acc == "", value, acc + "," + value), acc)


class MitreEnricher:
    def __init__(self, table: TechniqueTable, reference: LoadedReference) -> None:
        from .mapping_rules import validate_rules

        problems = validate_rules(table)
        if problems:
            raise MitreUnavailableError("rules do not match the technique table: " + "; ".join(problems))
        if reference.meta.get("table_sha256") != table.table_sha256:
            raise MitreUnavailableError(
                f"reference {reference.reference_id} was fitted with another technique table")
        self.table = table
        self.reference = reference

    @classmethod
    def load(cls, *, table_path=None, pin_path=None, models_root=None) -> "MitreEnricher":
        try:
            table = load_technique_table(table_path)
            ref = load_reference(pin_path, models_root, table=table)
        except (TechniqueTableError, MitreReferenceUnavailableError) as exc:
            raise MitreUnavailableError(str(exc)) from exc
        return cls(table, ref)

    def status(self) -> dict:
        return {"status": "loaded", "mitre_version": MITRE_VERSION, "ruleset_version": RULESET_VERSION,
                "ruleset_hash": ruleset_hash(), "rules": [r.rule_id for r in RULES],
                "table": self.table.describe(), "reference": self.reference.describe()}

    # --- vectorised ---------------------------------------------------------
    def enrich(self, frame: pd.DataFrame) -> Enrichment:
        missing = [c for c in ("user_id", "date", *required_columns()) if c not in frame.columns]
        if missing:
            raise MitreInputError(f"rows lack {missing}; the rules read these Chapter 5 columns")
        n = len(frame)
        maps = self.reference.maps
        block = maps.strengths(frame)                             # [n x R], NaN = not evaluable
        stat, top_idx = maps.max_strength(block)
        context_value = maps.context(stat)

        trig = np.column_stack([frame[r.trigger_column].to_numpy(dtype="float64", na_value=np.nan) for r in RULES])
        fired = np.isfinite(trig) & (trig > 0)
        any_fired = fired.any(axis=1)
        evaluable = np.isfinite(trig).any(axis=1)
        status = np.where(any_fired, "mapped", np.where(evaluable, "unmapped", "not_evaluated")).astype(object)
        context_value = np.where(status == "unmapped", 0.0, context_value)

        # the top rule is the strongest *fired* rule
        strength_fired = np.where(fired, np.nan_to_num(block, nan=0.0), -1.0)
        top_fired = strength_fired.argmax(axis=1)
        tech_ids = np.asarray([r.technique_id for r in RULES], dtype=object)
        rule_ids = np.asarray([r.rule_id for r in RULES], dtype=object)
        tactics = np.asarray([r.tactic for r in RULES], dtype=object)
        names = np.asarray([self.table.full_name(r.technique_id) for r in RULES], dtype=object)
        top_rule = np.where(any_fired, rule_ids[top_fired], None)
        top_tech = np.where(any_fired, tech_ids[top_fired], None)
        top_name = np.where(any_fired, names[top_fired], None)
        top_tactic = np.where(any_fired, tactics[top_fired], None)

        techs = np.full(n, "", dtype=object)
        rules = np.full(n, "", dtype=object)
        for j, r in enumerate(RULES):
            techs = _join(techs, fired[:, j], r.technique_id)
            rules = _join(rules, fired[:, j], r.rule_id)
        unmapped = np.full(n, "", dtype=object)
        for nm in NOT_MAPPED:
            if nm.flag_column and nm.flag_column in frame.columns:
                v = frame[nm.flag_column].to_numpy(dtype="float64", na_value=np.nan)
                unmapped = _join(unmapped, np.isfinite(v) & (v > 0), nm.behaviour)

        ref_id = self.reference.reference_id
        context = pd.DataFrame({
            "user_id": frame["user_id"].astype("string").str.strip().str.casefold().to_numpy(),
            "date": frame["date"].astype("string").to_numpy(),
            "mitre_status": status,
            "mitre_context": context_value.astype("float64"),
            "mitre_strength_max": np.where(status == "not_evaluated", np.nan, stat),
            "mitre_top_rule": top_rule,
            "mitre_top_technique": top_tech,
            "mitre_top_technique_name": top_name,
            "mitre_top_tactic": top_tactic,
            "mitre_techniques": np.where(techs == "", None, techs),
            "mitre_rules": np.where(rules == "", None, rules),
            "mitre_match_count": fired.sum(axis=1).astype("int16"),
            "mitre_unmapped_behaviours": np.where(unmapped == "", None, unmapped),
            "mitre_version": MITRE_VERSION,
            "ruleset_version": RULESET_VERSION,
            "ruleset_hash": ruleset_hash(),
            "attack_version": self.table.attack_version,
            "mitre_reference_id": ref_id,
        }, columns=list(CONTEXT_COLUMNS))

        parts = []
        for j, r in enumerate(RULES):
            m = fired[:, j]
            if not m.any():
                continue
            t = self.table.get(r.technique_id)
            parts.append(pd.DataFrame({
                "user_id": context["user_id"].to_numpy()[m],
                "date": context["date"].to_numpy()[m],
                "rule_id": r.rule_id,
                "technique_id": r.technique_id,
                "technique_name": names[j],
                "tactic": r.tactic,
                "tactic_name": (self.table.tactics.get(r.tactic) or {}).get("name", r.tactic),
                "evidence": r.evidence,
                "trigger_column": r.trigger_column,
                "trigger_value": trig[m, j],
                "strength": block[m, j],
                "technique_url": t.url,
                "ruleset_version": RULESET_VERSION,
                "attack_version": self.table.attack_version,
                "mitre_reference_id": ref_id,
            }))
        matches = (pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=list(MATCH_COLUMNS)))
        matches = matches.sort_values(["user_id", "date", "rule_id"], kind="mergesort").reset_index(drop=True)
        return Enrichment(context=context, matches=matches[list(MATCH_COLUMNS)])

    # --- one user-day (Chapter 13) ------------------------------------------
    def enrich_event(self, feature_vector: Mapping[str, Any], *, user_id: str | None = None,
                     date: str | None = None) -> dict:
        row = {"user_id": user_id or feature_vector.get("user_id") or "",
               "date": date or feature_vector.get("date") or ""}
        for c in (*required_columns(), *flag_columns()):
            v = feature_vector.get(c)
            row[c] = np.nan if v is None else float(v)
        out = self.enrich(pd.DataFrame([row]))
        ctx = out.context.iloc[0].to_dict()
        ctx["matches"] = out.matches.to_dict(orient="records")
        return ctx
