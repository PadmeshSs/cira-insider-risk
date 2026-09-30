"""The analyst explanation for one user-day (Bible Ch11 step 3, Architecture §18).

    expl = build_explanation(user_id, date, model=..., risk=..., mitre=..., features_row=...)
    expl["text"]        the §18 layout, plain text
    expl["model_factors"], expl["context_factors"], expl["attack_context"]   the same, structured

Three sections, never mixed (N30, N34, N45)
    Model factors      why the served model scored the day: its own
                       attributions (TreeSHAP for XGBoost, masks for TabNet),
                       strongest raising factors first. Only the served model
                       (``role="served"``); a shadow explanation is refused (N32).
    Contextual factors the CRI points that are not the anomaly score's own
                       rarity: historical deviation, peer deviation, user
                       context, ATT&CK. A CRI point is context, not a model
                       reason (N34).
    ATT&CK context     each mapped technique with its rule, triggering column,
                       value and evidence grade; ``indicated`` shown as a
                       visit, never as data leaving (N9, N45); an unmapped day
                       says so, with the behaviours considered and left
                       without a technique.

Traceability (§18 non-negotiable, Bible acceptance)
    Every listed factor carries a ``source`` naming exactly what produced it:
    the attribution (method, model_version, feature, value), the CRI
    component (points, calibration, run), or the ATT&CK match (rule,
    technique, column, value). ``validate_explanation`` re-checks every factor
    against the inputs and the builder refuses to return an explanation that
    fails, that contains a generic statement ("model predicted high risk"), or
    that claims a signal CERT does not record (N9).

Static traits (N22)
    A psychometric score or department size is never listed as a model
    factor. If one appears among the served model's attributions it goes to
    ``suppressed`` with the reason, and the verifier reports it.

Degradation (Architecture §36)
    Without model attributions (the explainer failed, or has not run yet) the
    explanation is still built from the score and the context, with status
    ``model_explanation_deferred`` and the reason. Without a CRI row the
    header says the score was not contextualised. Nothing is filled in.

Label-free (N5).
"""
from __future__ import annotations

import math
from typing import Any, Iterable, Mapping

from app.cri.config import COMPONENTS
from app.mitre.mapping_rules import NOT_MAPPED

from . import EXPLAIN_VERSION
from .attributions import UNITS, ExplanationFailedError, is_static
from .features import BASE, describe, describe_value, forbidden_in, value_text

GENERIC_PHRASES = (
    "model predicted high risk", "predicted high risk", "high risk detected", "suspicious activity detected",
    "anomalous behaviour detected", "anomalous behavior detected", "the model flagged", "risky behaviour",
)
DEFAULT_MAX_FACTORS = 5
DEFAULT_MAX_LOWERING = 2
TOL = 1e-9
STATUSES = ("complete", "model_explanation_deferred")
_NOT_MAPPED_REASON = {nm.behaviour: nm.reason for nm in NOT_MAPPED}


class ExplanationInputError(ValueError):
    """The inputs cannot be combined into one explanation (wrong role, mismatched score)."""


def _f(v) -> float | None:
    if v is None:
        return None
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(v) else v


def _same(a, b) -> bool:
    a, b = _f(a), _f(b)
    if a is None or b is None:
        return a is None and b is None
    return abs(a - b) <= TOL * max(1.0, abs(a), abs(b))


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:]


def _model_label(model: Mapping) -> str:
    return f"{model.get('model_name')} {model.get('registry_version')}"


# ---------------------------------------------------------------------------
# sections
# ---------------------------------------------------------------------------

def _model_section(model: Mapping, max_factors: int, max_lowering: int) -> tuple[list, list, list]:
    method, signed = model["method"], model["method"] in ("treeshap", "kernelshap")
    raising, lowering, suppressed = [], [], []
    for a in model.get("factors", []):
        feat, c, val = str(a["feature"]), _f(a["contribution"]), a.get("feature_value")
        if c is None or c == 0:
            continue
        if is_static(feat):
            suppressed.append({"feature": feat, "contribution": c,
                               "reason": "static per-user trait; never a behavioural reason (N22)"})
            continue
        ft = describe(feat)
        if signed:
            effect = f"raised the score by {c:+.2f} log-odds" if c > 0 else f"lowered the score by {c:+.2f} log-odds"
        else:
            effect = f"{c:.0%} of the model's attention (TabNet mask: importance, not direction)"
        factor = {
            "feature": feat, "label": ft.label, "domain": ft.domain, "value": _f(val),
            "value_text": value_text(feat, _f(val)), "contribution": c, "effect_text": effect,
            "calendar": ft.calendar,
            "text": _cap(f"{describe_value(feat, _f(val))} ({effect})"),
            "source": {"kind": "model", "method": method, "model_name": model["model_name"],
                       "model_version": model["model_version"], "registry_version": model["registry_version"],
                       "feature": feat, "contribution": c, "feature_value": _f(val)},
        }
        if c > 0 and len(raising) < max_factors:
            raising.append(factor)
        elif c < 0 and signed and len(lowering) < max_lowering:
            lowering.append(factor)
    for i, f in enumerate(raising, 1):
        f["rank"] = i
    return raising, lowering, suppressed


def _context_section(risk: Mapping, features_row: Mapping) -> list[dict]:
    out = []
    base_src = {"kind": "cri", "cri_run_id": risk.get("cri_run_id"), "calibration_id": risk.get("calibration_id"),
                "cri_config_hash": risk.get("cri_config_hash")}
    for c in COMPONENTS:
        pts = _f(risk.get(f"points_{c}"))
        if c == "anomaly" or pts is None or pts <= 0:
            continue
        detail = None
        if c == "historical_deviation":
            feat = risk.get("historical_top_feature")
            if feat:
                col = f"hist_z_{feat}"
                detail = col
                label = BASE.get(str(feat), (str(feat),))[0]
                text = (f"Largest rise above the user's own previous 30 days: {label}, "
                        f"{value_text(col, _f(features_row.get(col)))}")
            else:
                text = "Rise above the user's own previous 30 days"
        elif c == "peer_deviation":
            feat = risk.get("peer_top_feature")
            if feat:
                col = f"peer_dev_{feat}"
                detail = col
                label = BASE.get(str(feat), (str(feat),))[0]
                text = f"Largest deviation above peers: {label}, {value_text(col, _f(features_row.get(col)))}"
            else:
                text = "Deviation above peers"
        elif c == "user_context":
            text = (f"Role {risk.get('role')} is on the configured privileged list (CRI_PRIVILEGED_ROLES); "
                    "a policy prior, not observed behaviour")
        elif c == "mitre_context":
            text = "ATT&CK context, listed below"
        else:
            text = c.replace("_", " ")
        out.append({"component": c, "points": pts, "text": f"{text}: {pts:.1f} points",
                    "source": {**base_src, "component": c, "points": pts, "detail_column": detail}})
    return out


def _attack_section(mitre: Mapping | None, unavailable_reason: str | None) -> dict:
    if mitre is None:
        return {"status": "not_joined", "matches": [], "unmapped_behaviours": [],
                "text": [f"ATT&CK context not available: {unavailable_reason or 'no enrichment run joined'}"]}
    status = str(mitre.get("mitre_status"))
    lines, matches = [], []
    for m in mitre.get("matches") or []:
        trig, val = str(m["trigger_column"]), _f(m.get("trigger_value"))
        what = _cap(describe_value(trig, val))
        if m.get("evidence") == "indicated":
            caveat = "indicated: CERT records the visit, not what was sent or received"
        else:
            caveat = "observed: CERT records this action"
        text = (f"{m['technique_id']} {m.get('technique_name')} [{m.get('tactic_name') or m.get('tactic')}]: "
                f"{what}; {caveat} (rule {m['rule_id']})")
        matches.append({"rule_id": m["rule_id"], "technique_id": m["technique_id"],
                        "technique_name": m.get("technique_name"), "tactic": m.get("tactic"),
                        "evidence": m.get("evidence"), "trigger_column": trig, "trigger_value": val,
                        "strength": _f(m.get("strength")), "text": text,
                        "source": {"kind": "mitre", "rule_id": m["rule_id"], "technique_id": m["technique_id"],
                                   "trigger_column": trig, "trigger_value": val,
                                   "ruleset_version": m.get("ruleset_version"),
                                   "mitre_reference_id": m.get("mitre_reference_id")}})
        lines.append(text)
    raw_tags = mitre.get("mitre_unmapped_behaviours")
    tags = [t for t in raw_tags.split(",") if t] if isinstance(raw_tags, str) else []
    unmapped = [{"behaviour": t, "technique": None, "reason": _NOT_MAPPED_REASON.get(t)} for t in tags]
    if status == "unmapped":
        lines.append("No ATT&CK technique mapped for this day")
    elif status == "not_evaluated":
        lines.append("ATT&CK rules could not be evaluated for this day (their columns are null)")
    for u in unmapped:
        lines.append(f"{u['behaviour']}: considered, no ATT&CK technique")
    return {"status": status, "mitre_context": _f(mitre.get("mitre_context")), "matches": matches,
            "unmapped_behaviours": unmapped, "text": lines}


# ---------------------------------------------------------------------------
# assembly
# ---------------------------------------------------------------------------

def build_explanation(user_id: str, date: str, *, model: Mapping | None, risk: Mapping | None,
                      mitre: Mapping | None = None, features_row: Mapping | None = None,
                      model_unavailable_reason: str | None = None, risk_unavailable_reason: str | None = None,
                      mitre_unavailable_reason: str | None = None,
                      unavailable_components: Mapping[str, str] | None = None,
                      max_factors: int = DEFAULT_MAX_FACTORS, max_lowering: int = DEFAULT_MAX_LOWERING) -> dict:
    """One user-day's explanation. See the module docstring for the rules."""
    features_row = features_row or {}
    if model is not None:
        if model.get("role", "served") != "served":
            raise ExplanationInputError("only the served model's attributions explain an alert (N30, N32)")
        if model.get("method") not in UNITS:
            raise ExplanationInputError(f"unknown attribution method {model.get('method')!r}")
    if model is not None and risk is not None:
        if risk.get("model_version") is not None and risk.get("model_version") != model.get("model_version"):
            raise ExplanationInputError(f"risk row was computed from {risk.get('model_version')}, the attributions "
                                        f"from {model.get('model_version')}; one explanation, one score")
        if not _same(risk.get("anomaly_score"), model.get("anomaly_score")):
            raise ExplanationInputError("risk row and attributions disagree on the anomaly score")

    raising, lowering, suppressed = ([], [], []) if model is None else _model_section(model, max_factors, max_lowering)
    context = [] if risk is None else _context_section(risk, features_row)
    attack = _attack_section(mitre, mitre_unavailable_reason)
    unavailable = dict(unavailable_components or {})
    if risk is None:
        unavailable["cri"] = risk_unavailable_reason or "no risk row for this user-day"
    status = "complete" if model is not None else "model_explanation_deferred"

    anomaly = _f((risk or {}).get("anomaly_score")) if model is None else _f(model.get("anomaly_score"))
    src_model = model if model is not None else (risk or {})
    headline = {
        "severity": None if risk is None else risk.get("severity"),
        "cri_score": None if risk is None else _f(risk.get("cri_score")),
        "anomaly_score": anomaly,
        "model_name": src_model.get("model_name"), "model_version": src_model.get("model_version"),
        "registry_version": src_model.get("registry_version"),
    }

    lines = []
    if risk is not None:
        lines.append(f"{risk.get('severity')} RISK")
        lines.append(f"CRI {headline['cri_score']:.1f} of 100; anomaly score {anomaly:.5f} from "
                     f"{_model_label(src_model)} (a ranking score, not a probability)")
    else:
        lines.append("RISK NOT CONTEXTUALISED")
        if anomaly is not None:
            lines.append(f"Anomaly score {anomaly:.5f} from {_model_label(src_model)} "
                         f"(a ranking score, not a probability); CRI unavailable: {unavailable['cri']}")
    if model is None:
        lines.append(f"Model explanation not available: {model_unavailable_reason or 'not computed'}. "
                     "The score and its context stand; the explanation is retried later (Architecture §36).")
    else:
        what = {"treeshap": "TreeSHAP", "tabnet_mask": "TabNet attention mask", "kernelshap": "KernelSHAP"}[model["method"]]
        lines.append(f"Primary contributing factors (served model {_model_label(model)}, {what}):")
        if raising:
            lines += [f"{f['rank']}. {f['text']}" for f in raising]
        elif model["method"] == "treeshap":
            ev = _f(model.get("expected_value"))
            lines.append(f"No input raised the score above the model's expected value "
                         f"({ev:+.2f} log-odds); nothing in this day's behaviour pushed it up")
        else:
            lines.append("The mask attended to no behavioural input for this day")
        if lowering:
            lines.append("Lowered the score most: " + "; ".join(
                f"{f['label']}, {f['value_text']} ({f['contribution']:+.2f} log-odds)" for f in lowering))
        for s in suppressed:
            lines.append(f"Not shown as a reason: {describe(s['feature']).label} ({s['reason']})")
    if context:
        lines.append("Contextual factors (CRI points, not model reasons):")
        lines += [f"- {c['text']}" for c in context]
    lines.append("ATT&CK context (what ATT&CK calls the observed behaviour; not a reason the model scored this day):")
    lines += [f"- {t}" for t in attack["text"]]
    for name, reason in unavailable.items():
        lines.append(f"Not available: {name.replace('_', ' ')} ({reason})")

    expl = {
        "explain_version": EXPLAIN_VERSION, "user_id": str(user_id), "date": str(date), "status": status,
        "headline": headline,
        "model": None if model is None else {k: model.get(k) for k in (
            "method", "model_name", "model_version", "registry_version", "raw_score", "expected_value")},
        "units": None if model is None else UNITS[model["method"]],
        "model_unavailable_reason": None if model is not None else (model_unavailable_reason or "not computed"),
        "model_factors": raising, "model_factors_lowering": lowering, "suppressed": suppressed,
        "context_factors": context, "attack_context": attack, "unavailable": unavailable,
        "text": "\n".join(lines),
    }
    problems = validate_explanation(expl, model=model, risk=risk, mitre=mitre)
    if problems:
        raise ExplanationFailedError("explanation failed its own traceability check: " + "; ".join(problems[:5]))
    return expl


# ---------------------------------------------------------------------------
# traceability
# ---------------------------------------------------------------------------

def validate_explanation(expl: Mapping, *, model: Mapping | None, risk: Mapping | None,
                         mitre: Mapping | None) -> list[str]:
    """Every factor traced to its input; no generic or unsupported statement. Empty list = valid."""
    problems: list[str] = []
    attrs = {str(a["feature"]): a for a in (model or {}).get("factors", [])}
    for f in [*expl.get("model_factors", []), *expl.get("model_factors_lowering", [])]:
        src = f.get("source") or {}
        a = attrs.get(f.get("feature"))
        if src.get("kind") != "model" or a is None:
            problems.append(f"model factor {f.get('feature')} has no attribution behind it")
            continue
        if not _same(a["contribution"], f["contribution"]) or not _same(a.get("feature_value"), f.get("value")):
            problems.append(f"model factor {f['feature']} differs from its attribution")
        if src.get("model_version") != (model or {}).get("model_version"):
            problems.append(f"model factor {f['feature']} names another model_version")
        if is_static(f["feature"]):
            problems.append(f"static trait {f['feature']} presented as a reason (N22)")
    for c in expl.get("context_factors", []):
        if risk is None or (c.get("source") or {}).get("kind") != "cri":
            problems.append(f"context factor {c.get('component')} has no risk row behind it")
        elif not _same(risk.get(f"points_{c['component']}"), c["points"]):
            problems.append(f"context factor {c['component']} points differ from the risk row")
    known = {(m["rule_id"], m["technique_id"]): m for m in (mitre or {}).get("matches") or []}
    for m in (expl.get("attack_context") or {}).get("matches", []):
        k = known.get((m["rule_id"], m["technique_id"]))
        if k is None or not _same(k.get("trigger_value"), m.get("trigger_value")):
            problems.append(f"ATT&CK match {m['rule_id']} is not in the enrichment run")
    text = str(expl.get("text", ""))
    low = text.lower()
    problems += [f"generic statement: {p!r}" for p in GENERIC_PHRASES if p in low]
    claim_lines = [f["text"] for f in expl.get("model_factors", [])] + [c["text"] for c in expl.get("context_factors", [])]
    for line in claim_lines:
        bad = forbidden_in(line)
        if bad:
            problems.append(f"claims a signal CERT does not record {bad} (N9): {line[:80]}")
    for f in expl.get("model_factors", []):
        if (f.get("source") or {}).get("kind") in ("cri", "mitre"):
            problems.append("a CRI or ATT&CK item is listed as a model factor (N34, N45)")
    return problems


def model_evidence(summary: Mapping, factors: Iterable[Mapping], *, method: str, model_name: str,
                   model_version: str, registry_version: str, anomaly_score: float, role: str = "served") -> dict:
    """The ``model`` argument of ``build_explanation`` from a batch summary row and its top-k rows."""
    return {"method": method, "model_name": model_name, "model_version": model_version,
            "registry_version": registry_version, "role": role, "anomaly_score": _f(anomaly_score),
            "raw_score": _f(summary.get("raw_score")), "expected_value": _f(summary.get("expected_value")),
            "factors": [{"feature": str(a["feature"]), "contribution": _f(a["contribution"]),
                         "feature_value": _f(a.get("feature_value"))} for a in factors]}


def jsonable(obj: Any) -> Any:
    """NaN -> None, numpy scalars -> Python, recursively (for reasons.jsonl and the API)."""
    if isinstance(obj, dict):
        return {str(k): jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [jsonable(v) for v in obj]
    if hasattr(obj, "item") and not isinstance(obj, (str, bytes)):
        try:
            obj = obj.item()
        except (ValueError, AttributeError):
            pass
    if isinstance(obj, float) and math.isnan(obj):
        return None
    return obj
