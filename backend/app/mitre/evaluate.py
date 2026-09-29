"""Validation readout of MITRE context in the CRI (Chapter 10, N41, N43).

Offline module: joins labels in memory through app.evaluation, like
app.cri.evaluate. Never imported by a serving module (N5).

What is compared, on the served model's validation user-days only
    anomaly_score            the served model's score (Chapter 8)
    cri:anomaly_only         must rank like the anomaly score (harness)
    cri:no_mitre_context     the Chapter 9 formula; must reproduce the Chapter 9
                             readout's cri:default PR-AUC on the same rows (harness)
    cri:default              the CRI with mitre_context (ablation D on validation)
    mitre_context            the MITRE component alone, as a ranking. It is not
                             a detector; the row shows how much ranking it holds
                             by itself (not_evaluated rows ranked as 0)

The XGBoost / TabNet disagreement view (why this chapter exists in this form)
    The served XGBoost and the shadow TabNet catch different insiders: on full
    validation XGBoost has 7/19 scenario-1 days at top-1 and TabNet 14/19,
    while XGBoost leads on scenario 2 (125/179 against 97/179). For every
    scenario the malicious days are split into four cells by daily top-1:
    caught by both, served only, shadow only, neither. Each cell reports how
    many days carry a mapped technique and how many the CRI with and without
    MITRE puts at top-1. The ``shadow_only`` cell is the question: does the
    MITRE term recover days TabNet finds and the served model misses?

    Shadow scores are read here for that comparison only (N32: monitoring of
    disagreement). They never enter a CRI, a threshold or an alert, and
    nothing is ensembled.

Also reported: the share of benign validation user-days that carry a mapped
technique (the analyst-facing cost), and per rule how often it fires on
malicious days per scenario against benign days.

Rules
    * Validation only; ``--part test`` is refused. The test readout is
      Chapter 16's ablation D (N11, N33).
    * The rules and the weight were fixed before this readout existed. Guard
      c10-mitre-guard-v1 produces WARNs for the audit; it never changes a rule
      or a weight (N37, N43).
    * Written once; ``--supersede "<reason>"`` keeps the old readout inside.

Usage, from backend/:

    python -m app.mitre.evaluate --profile full
"""
from __future__ import annotations

from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.cri.config import COMPONENTS  # noqa: E402
from app.cri.engine import combine  # noqa: E402
from app.cri.evaluate import READOUT_FILE as CH9_READOUT_FILE  # noqa: E402
from app.cri.evaluate import chapter8_reference, config_from_meta, guard, summary_row  # noqa: E402
from app.cri.sources import RISK_META, RISK_OUTPUT, SourceError, chapter8_batch  # noqa: E402
from app.evaluation.labels import attach_labels, load_label_views  # noqa: E402
from app.evaluation.metrics import DEFAULT_BUDGETS, daily_top_k, evaluate_scores  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, repo_root  # noqa: E402
from app.scoring.serving_config import DECISION_FILE  # noqa: E402

from .mapping_rules import RULES  # noqa: E402
from .sources import MitreSourceError, mitre_run_dir, read_context  # noqa: E402

READOUT_FILE = "chapter10_validation_readout.json"
VARIANTS = ("anomaly_only", "no_mitre_context", "default")
GUARD = {
    "version": "c10-mitre-guard-v1",
    "compares": "cri:default (with mitre_context) against cri:no_mitre_context, validation, primary view",
    "warn_if": ["PR-AUC lower", "fewer insiders caught at top-1", "fewer insiders caught at top-5",
                "fewer malicious days at top-1 in any scenario"],
    "margin": 0.0,
    "effect": "WARN to be explained in docs/audits/chapter_10_audit.md; never a reason to change a rule or weight",
}
CELLS = ("both", "served_only", "shadow_only", "neither")
TOL = 1e-9


class ReadoutRefused(RuntimeError):
    """Nothing was written."""


def newest_mitre_risk_run(processed: Path, profile: str) -> Path:
    root = processed / "risk" / "chapter9"
    runs = []
    for d in sorted(root.iterdir()) if root.exists() else []:
        m = d / RISK_META
        if not m.exists():
            continue
        meta = json.loads(m.read_text(encoding="utf-8"))
        if meta.get("profile") == profile and meta.get("mitre") and meta.get("variant") == "default" \
                and not meta.get("config", {}).get("disabled"):
            runs.append(d)
    if not runs:
        raise ReadoutRefused(f"no default CRI run with MITRE for profile={profile}; run "
                             "`python -m app.cri.batch --profile <p> --with-mitre` first")
    return runs[-1]


def _shadow_scores(processed: Path, meta: dict, keys: pd.DataFrame) -> tuple[np.ndarray | None, dict | None]:
    try:
        batch = chapter8_batch(processed, meta["source_batch"]["batch_run_id"], None)
        sh = batch.read(role="shadow", columns=["user_id", "date", "model_name", "registry_version", "anomaly_score"])
    except (SourceError, KeyError, FileNotFoundError):
        return None, None
    if sh.empty:
        return None, None
    j = keys.assign(_pos=np.arange(len(keys))).merge(sh, on=["user_id", "date"], how="left", validate="one_to_one")
    if j["anomaly_score"].isna().any():
        return None, None
    j = j.sort_values("_pos")
    return j["anomaly_score"].to_numpy(dtype="float64"), {
        "model": f"{sh['model_name'].iloc[0]}:{sh['registry_version'].iloc[0]}"}


def disagreement_view(keys, labels, masks: dict[str, np.ndarray], mapped: np.ndarray) -> dict:
    y = labels["y_primary"].to_numpy().astype(bool)
    keep = ~labels["exclude_primary"].to_numpy().astype(bool)
    scen = labels["scenario_primary"].to_numpy()
    s, h = masks["served"], masks["shadow"]
    cell = np.where(s & h, "both", np.where(s, "served_only", np.where(h, "shadow_only", "neither")))
    out = {}
    for sc in sorted(set(scen[y & keep].tolist())):
        m = y & keep & (scen == sc)
        out[str(int(sc))] = {
            c: {"days": int((m & (cell == c)).sum()),
                "mitre_mapped": int((m & (cell == c) & mapped).sum()),
                "cri_default_at_1": int((m & (cell == c) & masks["cri_default"]).sum()),
                "cri_no_mitre_at_1": int((m & (cell == c) & masks["cri_no_mitre"]).sum())}
            for c in CELLS}
    return out


def rule_rates(labels, rules_col: pd.Series, mapped: np.ndarray) -> dict:
    y = labels["y_primary"].to_numpy().astype(bool)
    keep = ~labels["exclude_primary"].to_numpy().astype(bool)
    scen = labels["scenario_primary"].to_numpy()
    benign = ~y & keep
    rules = rules_col.fillna("").astype(str)
    out = {"benign_mapped_share": float(mapped[benign].mean()) if benign.any() else None,
           "benign_user_days": int(benign.sum()), "rules": {}}
    for r in RULES:
        fired = rules.str.contains(r.rule_id, regex=False).to_numpy()
        row = {"technique_id": r.technique_id, "benign_share": float(fired[benign].mean()) if benign.any() else None}
        for sc in sorted(set(scen[y & keep].tolist())):
            m = y & keep & (scen == sc)
            row[f"scenario_{int(sc)}"] = f"{int((fired & m).sum())}/{int(m.sum())}"
        out["rules"][r.rule_id] = row
    return out


def _parse_args(argv):
    root = repo_root()
    p = argparse.ArgumentParser(description="CIRA Chapter 10 MITRE validation readout (reads labels)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"))
    p.add_argument("--cri-run-id", default=None, help="a default CRI run made with --with-mitre (default: newest)")
    p.add_argument("--part", default="validation")
    p.add_argument("--decision-path", default=os.getenv("CIRA_SERVING_DECISION") or str(root / "experiments" / DECISION_FILE))
    p.add_argument("--chapter9-readout", default=str(root / "experiments" / CH9_READOUT_FILE))
    p.add_argument("--readout-path", default=str(root / "experiments" / READOUT_FILE))
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter10"))
    p.add_argument("--supersede", default=None, metavar="REASON")
    p.add_argument("--seed", type=int, default=int(os.getenv("CIRA_SEED", "42")))
    return p.parse_args(argv)


def run(args) -> dict:
    if args.part != "validation":
        raise ReadoutRefused("MITRE context is read on validation only in Chapter 10; its test readout is "
                             "Chapter 16's ablation D (N11, N33)")
    readout_path = Path(args.readout_path)
    previous = None
    if readout_path.exists():
        previous = json.loads(readout_path.read_text(encoding="utf-8"))
        if not args.supersede:
            raise ReadoutRefused(f"{readout_path} exists; the readout is written once. Pass --supersede \"<reason>\"")
    processed = Path(args.processed_dir)
    run_dir = (processed / "risk" / "chapter9" / args.cri_run_id) if args.cri_run_id else newest_mitre_risk_run(processed, args.profile)
    meta = json.loads((run_dir / RISK_META).read_text(encoding="utf-8"))
    if not meta.get("mitre"):
        raise ReadoutRefused(f"risk run {run_dir.name} was made without MITRE; use --with-mitre")
    if meta.get("variant") != "default" or meta.get("config", {}).get("disabled"):
        raise ReadoutRefused(f"risk run {run_dir.name} is not the default variant")
    risk = pd.read_parquet(run_dir / RISK_OUTPUT)
    risk = risk[risk["model_split"] == "validation"].sort_values(["user_id", "date"], kind="mergesort").reset_index(drop=True)
    if risk.empty:
        raise ReadoutRefused(f"risk run {run_dir.name} has no validation rows")
    keys = risk[["user_id", "date"]].copy()
    keys["user_id"] = keys["user_id"].astype("string")
    keys["date"] = keys["date"].astype("string")
    try:
        mctx = read_context(mitre_run_dir(processed, meta["mitre"]["mitre_run_id"]), keys,
                            ["mitre_status", "mitre_context", "mitre_rules"])
    except MitreSourceError as exc:
        raise ReadoutRefused(str(exc)) from exc
    labels = attach_labels(keys, load_label_views(processed))
    config = config_from_meta(meta)
    available = {c for c in COMPONENTS if c not in meta.get("unavailable_components", {})}
    if "mitre_context" not in available:
        raise ReadoutRefused("the risk run lists mitre_context as unavailable")
    comps = {c: risk[f"component_{c}"].to_numpy(dtype="float64", na_value=np.nan) for c in COMPONENTS}
    budgets = DEFAULT_BUDGETS

    full, models, cri_values = {}, {}, {}
    anomaly = risk["anomaly_score"].to_numpy(dtype="float64")
    full["anomaly_score"] = evaluate_scores(keys, anomaly, labels, budgets=budgets, seed=args.seed)
    models["anomaly_score"] = summary_row(full["anomaly_score"])
    for v in VARIANTS:
        out = combine(comps, available, config.variant(v))
        name = f"cri:{v}"
        cri_values[v] = out["cri"]
        full[name] = evaluate_scores(keys, out["cri"], labels, budgets=budgets, seed=args.seed)
        models[name] = summary_row(full[name])
        models[name]["effective_weights"] = out["weights"]
    mitre_only = np.nan_to_num(mctx["mitre_context"].to_numpy(dtype="float64", na_value=np.nan), nan=0.0)
    full["mitre_context"] = evaluate_scores(keys, mitre_only, labels, budgets=budgets, seed=args.seed)
    models["mitre_context"] = summary_row(full["mitre_context"])

    harness = []
    stored = risk["cri_score"].to_numpy(dtype="float64")
    d0 = float(np.abs(stored - cri_values["default"]).max())
    harness.append({"check": "recombining stored components reproduces the stored cri_score", "ok": d0 <= TOL,
                    "detail": f"max diff {d0:.2e}"})
    d1 = abs((models["cri:anomaly_only"]["pr_auc"] or 0) - (models["anomaly_score"]["pr_auc"] or 0))
    harness.append({"check": "cri:anomaly_only ranks like the anomaly score", "ok": d1 <= 1e-12, "detail": f"{d1:.2e}"})
    ch9 = Path(args.chapter9_readout)
    c9 = json.loads(ch9.read_text(encoding="utf-8")) if ch9.exists() else None
    if c9 and c9.get("rows") == len(risk) and c9.get("calibration_id") == meta["calibration"]["calibration_id"]:
        want = c9["models"]["cri:default"]["pr_auc"]
        got = models["cri:no_mitre_context"]["pr_auc"]
        harness.append({"check": "cri:no_mitre_context equals the Chapter 9 readout's cri:default",
                        "ok": abs(want - got) <= TOL, "detail": f"Chapter 9 {want:.6f}, here {got:.6f}"})
    else:
        harness.append({"check": "cri:no_mitre_context equals the Chapter 9 readout's cri:default", "ok": None,
                        "detail": "no Chapter 9 readout for the same calibration and rows"})

    mapped = (mctx["mitre_status"].astype(str) == "mapped").to_numpy()
    dates = keys["date"]
    shadow, shadow_info = _shadow_scores(processed, meta, keys)
    view = None
    if shadow is not None:
        masks = {"served": daily_top_k(dates, anomaly, 1, seed=args.seed),
                 "shadow": daily_top_k(dates, shadow, 1, seed=args.seed),
                 "cri_default": daily_top_k(dates, cri_values["default"], 1, seed=args.seed),
                 "cri_no_mitre": daily_top_k(dates, cri_values["no_mitre_context"], 1, seed=args.seed)}
        view = {"shadow_model": shadow_info["model"], "budget": "daily top-1", "seed": args.seed,
                "by_scenario": disagreement_view(keys, labels, masks, mapped),
                "note": "shadow scores read for disagreement monitoring only (N32); never in a CRI or an alert"}

    warnings = [w.replace("anomaly score", "cri:no_mitre_context")
                for w in guard(models["cri:no_mitre_context"], models["cri:default"])]
    ref = chapter8_reference(Path(args.decision_path), args.profile, meta, len(risk), models["anomaly_score"]["positives"])
    readout = {
        "chapter": 10,
        "part": "validation",
        "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile": args.profile,
        "reportable": args.profile != "dev",
        "cri_run_id": run_dir.name,
        "formula_hash": meta.get("formula_hash"),
        "mitre": meta["mitre"],
        "calibration_id": meta["calibration"]["calibration_id"],
        "served": meta["served"],
        "rows": int(len(risk)),
        "positives": models["anomaly_score"]["positives"],
        "chance_pr_auc": float(labels["y_primary"][~labels["exclude_primary"]].mean()),
        "models": models,
        "disagreement_view": view,
        "rule_rates": rule_rates(labels, mctx["mitre_rules"], mapped),
        "chapter8_reference_rows": None if not ref else {
            k: {"pr_auc": v.get("pr_auc"), "insiders_caught_at_1": v.get("insiders_caught_at_1"),
                "recall_by_scenario_at_1": v.get("recall_by_scenario_at_1")} for k, v in ref["others"].items()},
        "harness": harness,
        "guard": {**GUARD, "warnings": warnings},
        "disclosure": ("Rules were written from ATT&CK definitions and Chapter 5 columns, label-blind, but the public "
                       "r4.2 scenario descriptions are known; any scenario gain is partly by construction (N41)."),
        "superseded": ([] if previous is None else [*previous.get("superseded", []),
                                                     {**{k: v for k, v in previous.items() if k != "superseded"},
                                                      "superseded_because": args.supersede}]),
    }
    results = Path(args.results_dir) / run_dir.name
    results.mkdir(parents=True, exist_ok=True)
    (results / "validation_metrics_full.json").write_text(json.dumps(full, indent=2, default=str), encoding="utf-8")
    readout_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = readout_path.with_name(readout_path.name + ".tmp")
    tmp.write_text(json.dumps(readout, indent=2, default=str), encoding="utf-8")
    tmp.replace(readout_path)
    append_experiment_runlog({
        "stage": "chapter10_validation_readout", "cri_run_id": run_dir.name, "profile": args.profile,
        "reportable": readout["reportable"], "mitre_run_id": meta["mitre"]["mitre_run_id"],
        "validation_pr_auc": {k: v["pr_auc"] for k, v in models.items()}, "guard_warnings": len(warnings),
        "harness_ok": all(h["ok"] is not False for h in harness), "superseded": bool(args.supersede),
    })
    print_table(readout)
    return readout


def _f(v, nd=3) -> str:
    return "-" if v is None else f"{v:.{nd}f}"


def print_table(r: dict) -> None:
    print(f"\n[readout] {r['cri_run_id']} validation: {r['rows']} rows, {r['positives']} malicious user-days", flush=True)
    for name, m in r["models"].items():
        scen = ", ".join(f"s{k} {v}" for k, v in m["days_by_scenario_at_1"].items())
        print(f"  {name:<24} PR-AUC {_f(m['pr_auc'])}  caught@1 {m['insiders_caught_at_1']:>6}  "
              f"caught@5 {m['insiders_caught_at_5']:>6}  days@1 {scen}", flush=True)
    v = r.get("disagreement_view")
    if v:
        print(f"[readout] served vs {v['shadow_model']} at daily top-1, malicious days per cell "
              "(days / MITRE-mapped / CRI+MITRE@1 / CRI-no-MITRE@1):", flush=True)
        for sc, cells in v["by_scenario"].items():
            print(f"  scenario {sc}: " + "; ".join(
                f"{c} {x['days']}/{x['mitre_mapped']}/{x['cri_default_at_1']}/{x['cri_no_mitre_at_1']}"
                for c, x in cells.items()), flush=True)
    print(f"[readout] benign user-days with a mapped technique: {_f(r['rule_rates']['benign_mapped_share'], 4)}", flush=True)
    for h in r["harness"]:
        status = "PASS" if h["ok"] else ("n/a" if h["ok"] is None else "FAIL")
        print(f"[readout] harness {status}: {h['check']} ({h['detail']})", flush=True)
    for w in r["guard"]["warnings"]:
        print(f"[readout] WARN {r['guard']['version']}: {w}", flush=True)


def main(argv=None) -> int:
    args = _parse_args(argv)
    try:
        run(args)
    except (ReadoutRefused, SourceError) as exc:
        print(f"chapter10 readout refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
