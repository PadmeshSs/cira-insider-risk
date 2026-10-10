"""Experiment E2: the Chapter 11 explanation readout, repeated on test (N48, N52, N53, N51).

Chapter 11 read the explanations of malicious validation days and left the test read to this chapter. Same
questions, same code, other part:

    * per scenario: the most frequent top raising factors on malicious days, the calendar-led share, the
      domain split of the top three factors (N53: the same days are explained differently by the two models)
    * the benign days in the served model's daily top-1: which factor leads them (N52: USB disconnects)
    * the shadow TabNet's mask view on the same days, mean top-5 Jaccard with TreeSHAP (N51: a readout,
      labelled as the second model's view, never shown to an analyst)
    * integrity numbers over every explained row of the part: additivity error, rows with a static trait in
      the top five (N22)

The helpers are Chapter 11's own (``app.explainability.evaluate``), so a Chapter 11 number and a Chapter 16
number are produced by the same lines of code. KernelSHAP agreement is not recomputed: it is a bounded,
label-free statistic of the explain run (N48) and is read from the run's meta.

Nothing here changes an explainer, a model or a description (N48: a weak statistic is a WARN, never a reason).
Offline; reads labels in memory (N5).
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from app.evaluation.labels import attach_labels, load_label_views
from app.evaluation.metrics import daily_top_k
from app.explainability.evaluate import SCENARIOS, _describe_days, _shadow_view, top_raising
from app.explainability.features import CALENDAR_COLUMNS
from app.explainability.sources import ATTRIBUTIONS_OUTPUT, SUMMARY_OUTPUT, explain_run_dir, read_meta
from app.tabnet.dataset import load_feature_matrix


def explanation_view(processed: str | Path, profile: str, part: str, *, explain_run_id: str | None = None,
                     seed: int = 42, include_shadow: bool = True) -> dict:
    processed = Path(processed)
    run_dir = explain_run_dir(processed, explain_run_id, profile)
    meta = read_meta(run_dir)
    summary = pd.read_parquet(run_dir / SUMMARY_OUTPUT)
    rows = summary[summary["model_split"].astype(str) == part].sort_values(["user_id", "date"], kind="mergesort")
    rows = rows.reset_index(drop=True)
    if rows.empty:
        raise RuntimeError(f"explain run {run_dir.name} has no {part} rows")
    attr = pd.read_parquet(run_dir / ATTRIBUTIONS_OUTPUT).merge(rows[["user_id", "date"]], on=["user_id", "date"])
    labels = attach_labels(rows[["user_id", "date"]], load_label_views(processed))
    y = labels["y_primary"].to_numpy()
    scen = labels["scenario_primary"].to_numpy()
    excl = labels["exclude_primary"].to_numpy().astype(bool)
    tops = top_raising(attr, 5)

    by_scenario, keys_by_scenario = {}, {}
    for s in SCENARIOS:
        keys = rows.loc[(y == 1) & (scen == s), ["user_id", "date"]].reset_index(drop=True)
        keys_by_scenario[s] = keys
        by_scenario[str(s)] = _describe_days(keys, tops)

    top1 = daily_top_k(rows["date"], rows["anomaly_score"].to_numpy(dtype="float64"), 1, seed=seed)
    fa_keys = rows.loc[top1 & (y == 0) & ~excl, ["user_id", "date"]]
    false_alarms = _describe_days(fa_keys, tops)

    shadow = {"available": False, "reason": "not requested"}
    if include_shadow:
        try:
            shadow = _shadow_view(processed, load_feature_matrix(processed, profile), keys_by_scenario, tops)
        except Exception as exc:                      # a missing shadow is a stated absence, not a crash (N32)
            shadow = {"available": False, "reason": f"{type(exc).__name__}: {exc}"}

    err = rows["additivity_error"].to_numpy(dtype="float64")
    integrity = {
        "rows": int(len(rows)),
        "max_additivity_error": float(np.nanmax(np.abs(err))) if np.isfinite(err).any() else None,
        "rows_with_static_trait_in_top5": int(rows["static_in_top5"].sum()),
        "rows_without_a_raising_factor": int((rows["n_raising"] == 0).sum()),
    }
    warnings = []
    if integrity["rows_with_static_trait_in_top5"]:
        warnings.append(f"{integrity['rows_with_static_trait_in_top5']} served explanations have a static trait in "
                        "their top 5 (N22)")
    for s, block in by_scenario.items():
        counts = block["top_factor_counts"]
        if counts and next(iter(counts)) in CALENDAR_COLUMNS:
            warnings.append(f"scenario {s}: the most frequent top factor on malicious test days is {next(iter(counts))}")
    kernel = (meta.get("kernel_corroboration") or meta.get("corroboration") or {})
    return {
        "explain_run_id": run_dir.name, "part": part, "served": meta.get("served"),
        "method": (meta.get("explainer") or {}).get("method"),
        "malicious_days_by_scenario": by_scenario,
        "false_alarms_at_top1": {"definition": f"benign {part} days in the served model's daily top-1 (seeded tie-break)",
                                 **false_alarms},
        "second_model_view": shadow,
        "integrity": integrity,
        "kernel_shap_agreement_from_run_meta": kernel or None,
        "warnings": warnings,
        "caveats": ["a factor that matches a public scenario description is partly by construction (N41)",
                    "a mask is attention, not direction (N51); the two models explaining days differently does not say "
                    "either is right",
                    "six scenario-1 insiders at most cannot settle a scenario claim (N15)"],
    }
