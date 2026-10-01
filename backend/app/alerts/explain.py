"""Member-day explanations through the Chapter 11 builder (N47, N48, N50).

Every member day of every alert gets the full analyst explanation from
``app.explainability.reason_builder.build_explanation``, the same code that
wrote Chapter 11's ``reasons.jsonl``. The model side is read from the explain
run's stored TreeSHAP attributions (every scored user-day is in it, and each
already adds up to the served margin, N47), so nothing is recomputed and no
model is loaded here. Days outside Chapter 11's bounded set are explained this
way "on demand" (N50).

One explanation, one score (N50)
    The risk row comes from the CRI run the explain run names, and the
    attributions from that explain run. The builder refuses a model_version
    or anomaly-score mismatch. That refusal is not worked around: the day is
    written with status ``model_explanation_deferred`` and the reason, and the
    alert still exists with its score and context (Architecture §36).

KernelSHAP (N48)
    Where Chapter 11 corroborated a member day, its top-5 overlap and deletion
    result are attached as statistics next to the explanation. They are never
    a reason and never appear in ``alert_reasons``.

``reason_rows`` flattens one explanation into AlertReason rows: one per model
factor (``model``), per lowering factor (``model_lowering``), per CRI point
(``cri``) and per ATT&CK match (``mitre``), each with its ``source``.
Label-free (N5).
"""
from __future__ import annotations

import json
from typing import Any

import numpy as np
import pandas as pd

from app.explainability.attributions import ExplanationFailedError
from app.explainability.reason_builder import ExplanationInputError, build_explanation, jsonable, model_evidence

SECTIONS = ("model", "model_lowering", "cri", "mitre")
REASON_COLUMNS = ("alert_key", "user_id", "date", "section", "rank", "subject", "rule_id", "value", "weight", "text",
                  "source", "model_version", "explain_run_id")


def _key(u, d) -> tuple[str, str]:
    return str(u), str(d)


def explain_members(members: pd.DataFrame, *, summary: pd.DataFrame, attributions: pd.DataFrame, served: dict,
                    method: str, explain_run_id: str, risk: pd.DataFrame, detail: pd.DataFrame,
                    mitre_ctx: pd.DataFrame | None, mitre_matches: pd.DataFrame | None, mitre_reason: str | None,
                    unavailable: dict[str, str], kernel: pd.DataFrame | None = None) -> list[dict]:
    """``risk`` and ``detail`` (hist_z_* / peer_dev_* columns) and ``mitre_ctx`` are aligned 1:1 with ``members``."""
    summ = {_key(u, d): r for (u, d), r in zip(zip(summary["user_id"], summary["date"]), summary.to_dict("records"))}
    attr = {k: g.sort_values("rank").to_dict("records")
            for k, g in attributions.groupby(["user_id", "date"], sort=False)}
    kern = {}
    if kernel is not None and len(kernel):
        for r in kernel.to_dict("records"):
            kern[_key(r["user_id"], r["date"])] = r
    matches_by = {}
    if mitre_matches is not None and len(mitre_matches):
        for k, g in mitre_matches.groupby(["user_id", "date"], sort=False):
            matches_by[_key(*k)] = g.sort_values("rule_id").to_dict("records")
    out = []
    for i in range(len(members)):
        uid, day = _key(members["user_id"].iloc[i], members["date"].iloc[i])
        rrow = risk.iloc[i].to_dict()
        mitre = None
        if mitre_ctx is not None:
            mitre = mitre_ctx.iloc[i].to_dict()
            mitre["matches"] = matches_by.get((uid, day), [])
        feats = detail.iloc[i].to_dict() if len(detail.columns) else {}
        model, reason = None, None
        s = summ.get((uid, day))
        if s is None:
            reason = f"no attribution for this user-day in explain run {explain_run_id}"
        else:
            model = model_evidence(s, attr.get((uid, day), []), method=method, model_name=served["model_name"],
                                   model_version=served["model_version"], registry_version=served["registry_version"],
                                   anomaly_score=float(s["anomaly_score"]))
        try:
            expl = build_explanation(uid, day, model=model, risk=rrow, mitre=mitre, features_row=feats,
                                     model_unavailable_reason=reason, mitre_unavailable_reason=mitre_reason,
                                     unavailable_components=unavailable)
        except (ExplanationInputError, ExplanationFailedError) as exc:
            # §36: the alert keeps its score and context; the model side is deferred with the reason.
            expl = build_explanation(uid, day, model=None, risk=rrow, mitre=mitre, features_row=feats,
                                     model_unavailable_reason=f"refused: {exc}", mitre_unavailable_reason=mitre_reason,
                                     unavailable_components=unavailable)
        k = kern.get((uid, day))
        expl["corroboration"] = None if k is None else {
            "method": "kernelshap", "top5_overlap": k.get("top5_overlap"),
            "deletion_top_beats_random": k.get("deletion_top_beats_random"),
            "note": "agreement statistic between two SHAP estimators; never a reason (N48)"}
        expl["alert_key"] = str(members["alert_key"].iloc[i])
        expl["explain_run_id"] = explain_run_id
        out.append(jsonable(expl))
    return out


def _num(v) -> float | None:
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    return None if np.isnan(v) else v


def reason_rows(expl: dict) -> list[dict[str, Any]]:
    """One explanation -> AlertReason rows, section and source kept (N50)."""
    base = {"alert_key": expl["alert_key"], "user_id": expl["user_id"], "date": expl["date"],
            "model_version": (expl.get("headline") or {}).get("model_version"), "explain_run_id": expl["explain_run_id"]}
    rows = []
    for section, items in (("model", expl.get("model_factors") or []), ("model_lowering", expl.get("model_factors_lowering") or [])):
        for i, f in enumerate(items, 1):
            rows.append({**base, "section": section, "rank": int(f.get("rank") or i), "subject": f["feature"],
                         "rule_id": None, "value": _num(f.get("value")), "weight": _num(f["contribution"]),
                         "text": f["text"] if section == "model" else
                         (f"{f['label']}, {f['value_text']} ({f['effect_text']})"[:1].upper()
                          + f"{f['label']}, {f['value_text']} ({f['effect_text']})"[1:]),
                         "source": json.dumps(f["source"], sort_keys=True)})
    for i, c in enumerate(expl.get("context_factors") or [], 1):
        rows.append({**base, "section": "cri", "rank": i, "subject": c["component"], "rule_id": None, "value": None,
                     "weight": _num(c["points"]), "text": c["text"], "source": json.dumps(c["source"], sort_keys=True)})
    for i, m in enumerate((expl.get("attack_context") or {}).get("matches") or [], 1):
        rows.append({**base, "section": "mitre", "rank": i, "subject": m["technique_id"], "rule_id": m["rule_id"],
                     "value": _num(m.get("trigger_value")), "weight": _num(m.get("strength")), "text": m["text"],
                     "source": json.dumps(m["source"], sort_keys=True)})
    return rows


def reasons_frame(explanations: list[dict]) -> pd.DataFrame:
    rows = [r for e in explanations for r in reason_rows(e)]
    return pd.DataFrame(rows, columns=list(REASON_COLUMNS))
