"""Validation readout of the CRI and its ablation variants (Chapter 9, N37).

Offline module: joins labels in memory through app.evaluation, like
app.scoring.select. Never imported by a serving module (N5).

What is compared, on the served model's validation user-days only
    anomaly_score            the served model's raw score (Chapter 8)
    cri:anomaly_only         must rank exactly like the anomaly score (harness check)
    cri:default              the configured CRI
    cri:no_historical_deviation, cri:no_peer_deviation, cri:no_user_context
                             leave-one-out ablations, recombined from the
                             stored components (HCEA §9: no recomputation)

For each: PR-AUC (primary view, N1/N2), ROC-AUC as a secondary number,
recall and insiders caught at daily top-k, per scenario (N15), and the
band view (HIGH or above, CRITICAL): alerts, precision, recall, insiders
caught, alerts per day. The shadow TabNet appears only as a reference row
copied from the Chapter 8 decision evidence (same rows, same harness); it is
never turned into a CRI (N32).

Rules
    * Validation only. The CRI's test readout is Chapter 16's ablation C;
      ``--part test`` is refused here (N11).
    * The weights were fixed before this readout existed and are not tuned
      on it (N37). The guard below produces WARNs, which the audit must
      explain; it never changes a weight.
    * Written once. ``experiments/chapter9_validation_readout.json`` is
      replaced only with ``--supersede "<reason>"``, keeping the old one.

Guard c9-cri-guard-v1 (do-no-harm check, default CRI vs the anomaly score)
    WARN if validation PR-AUC is lower, if fewer insiders are caught at
    top-1 or top-5, or if any scenario has fewer malicious days at top-1.
    No margin: every decrease is stated and explained, none is tuned away.

Usage, from backend/:

    python -m app.cri.evaluate --profile full
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

from app.evaluation.labels import attach_labels, load_label_views  # noqa: E402
from app.evaluation.metrics import (  # noqa: E402
    DEFAULT_BUDGETS,
    budget_counts,
    evaluate_scores,
    headline,
    per_scenario_recall,
    per_user_detection,
)
from app.feature_engineering.common import append_experiment_runlog, repo_root  # noqa: E402
from app.scoring.serving_config import DECISION_FILE  # noqa: E402

from .batch import daily_volume  # noqa: E402
from .config import COMPONENTS, SEVERITIES, CRIConfig  # noqa: E402
from .engine import combine  # noqa: E402
from .sources import RISK_META, RISK_OUTPUT, SourceError, risk_run_dir  # noqa: E402

READOUT_FILE = "chapter9_validation_readout.json"
VARIANTS = ("anomaly_only", "default", "no_historical_deviation", "no_peer_deviation", "no_user_context")
GUARD = {
    "version": "c9-cri-guard-v1",
    "compares": "cri:default against the served anomaly score, validation, primary view",
    "warn_if": ["PR-AUC lower", "fewer insiders caught at top-1", "fewer insiders caught at top-5",
                "fewer malicious days at top-1 in any scenario"],
    "margin": 0.0,
    "effect": "WARN to be explained in docs/audits/chapter_9_audit.md; never a reason to retune weights (N37)",
}
HARNESS_TOL = 1e-9


class ReadoutRefused(RuntimeError):
    """Nothing was written."""


def config_from_meta(meta: dict) -> CRIConfig:
    c = meta["config"]
    sev = c["severity_maxima"]
    return CRIConfig(weights=tuple((k, float(c["weights"][k])) for k in COMPONENTS),
                     bands=(int(sev["LOW"]), int(sev["MEDIUM"]), int(sev["HIGH"])),
                     privileged_roles=tuple(c["privileged_roles"]), rarity_decades=float(c["rarity_decades"]),
                     disabled=frozenset(c["disabled"]), variant_name=c.get("variant", "default"))


def band_metrics(keys: pd.DataFrame, labels: pd.DataFrame, severity: np.ndarray, bands: tuple[str, ...]) -> dict:
    alerted = np.isin(severity, bands)
    y = labels["y_primary"].to_numpy()
    excl = labels["exclude_primary"].to_numpy()
    scen = labels["scenario_primary"].to_numpy()
    return {
        **budget_counts(y, alerted, excl),
        "recall_by_scenario": per_scenario_recall(y, alerted, scen, excl),
        "per_user": per_user_detection(keys["user_id"].to_numpy(), keys["date"].to_numpy(), y, alerted, scen, excl),
        "alerts_per_day": daily_volume(keys, alerted),
    }


def summary_row(metrics: dict) -> dict:
    p = metrics["primary"]
    out = headline(metrics)
    for k in ("1", "5"):
        b = p["budgets"][k]
        out[f"days_by_scenario_at_{k}"] = {s: f'{v["alerted"]}/{v["positives"]}' for s, v in b["recall_by_scenario"].items()}
        out[f"caught_by_scenario_at_{k}"] = {s: f'{v["caught"]}/{v["insiders"]}' for s, v in b["per_user"]["by_scenario"].items()}
    return out


def guard(anomaly: dict, cri: dict) -> list[str]:
    warns = []
    if cri["pr_auc"] is not None and anomaly["pr_auc"] is not None and cri["pr_auc"] < anomaly["pr_auc"]:
        warns.append(f"PR-AUC {cri['pr_auc']:.4f} < anomaly score {anomaly['pr_auc']:.4f}")
    for k in ("1", "5"):
        a, c = anomaly[f"insiders_caught_at_{k}"], cri[f"insiders_caught_at_{k}"]
        if int(c.split("/")[0]) < int(a.split("/")[0]):
            warns.append(f"insiders caught at top-{k}: {c} < anomaly score {a}")
    for s, a in anomaly["days_by_scenario_at_1"].items():
        c = cri["days_by_scenario_at_1"].get(s, "0/0")
        if int(c.split("/")[0]) < int(a.split("/")[0]):
            warns.append(f"scenario {s} malicious days at top-1: {c} < anomaly score {a}")
    return warns


def chapter8_reference(decision_path: Path, profile: str, meta: dict, rows: int, positives: int) -> dict | None:
    """The Chapter 8 evidence for the same rows, if they are the same rows."""
    if not decision_path.exists() or profile != "full":
        return None
    d = json.loads(decision_path.read_text(encoding="utf-8"))
    ev = (d.get("evidence") or {}).get("full/user")
    if not ev or ev.get("rows") != rows or ev.get("positives") != positives:
        return None
    served_name = meta["served"]["model_name"]
    out = {"served": ev["models"].get(served_name), "others": {k: v for k, v in ev["models"].items() if k != served_name}}
    return out


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    root = repo_root()
    p = argparse.ArgumentParser(description="CIRA Chapter 9 CRI validation readout (reads labels)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"))
    p.add_argument("--cri-run-id", default=None, help="Chapter 9 risk run (default: newest for the profile)")
    p.add_argument("--part", default="validation")
    p.add_argument("--decision-path", default=os.getenv("CIRA_SERVING_DECISION") or str(root / "experiments" / DECISION_FILE))
    p.add_argument("--readout-path", default=str(root / "experiments" / READOUT_FILE))
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter9"))
    p.add_argument("--supersede", default=None, metavar="REASON")
    p.add_argument("--seed", type=int, default=int(os.getenv("CIRA_SEED", "42")))
    return p.parse_args(argv)


def run(args: argparse.Namespace) -> dict:
    if args.part != "validation":
        raise ReadoutRefused("the CRI is read on validation only in Chapter 9; its test readout is Chapter 16's "
                             "ablation C (N11, N37)")
    readout_path = Path(args.readout_path)
    previous = None
    if readout_path.exists():
        previous = json.loads(readout_path.read_text(encoding="utf-8"))
        if not args.supersede:
            raise ReadoutRefused(f"{readout_path} exists; the readout is written once. Pass --supersede \"<reason>\" "
                                 "to replace it (the old one is kept inside the new file)")

    run_dir = risk_run_dir(args.processed_dir, args.cri_run_id, args.profile)
    meta = json.loads((run_dir / RISK_META).read_text(encoding="utf-8"))
    if meta.get("variant") != "default" or meta.get("config", {}).get("disabled"):
        raise ReadoutRefused(f"risk run {run_dir.name} is variant {meta.get('variant')!r}; evaluate the default run, "
                             "the variants are recombined from its components")
    risk = pd.read_parquet(run_dir / RISK_OUTPUT)
    risk = risk[risk["model_split"] == "validation"].sort_values(["user_id", "date"], kind="mergesort").reset_index(drop=True)
    if risk.empty:
        raise ReadoutRefused(f"risk run {run_dir.name} has no validation rows")

    keys = risk[["user_id", "date"]].copy()
    labels = attach_labels(keys, load_label_views(args.processed_dir))
    config = config_from_meta(meta)
    available = {c for c in COMPONENTS if c not in meta.get("unavailable_components", {})}
    comps = {c: risk[f"component_{c}"].to_numpy(dtype="float64", na_value=np.nan) for c in COMPONENTS}
    budgets = DEFAULT_BUDGETS

    models: dict[str, dict] = {}
    full_metrics: dict[str, dict] = {}
    anomaly = risk["anomaly_score"].to_numpy(dtype="float64")
    full_metrics["anomaly_score"] = evaluate_scores(keys, anomaly, labels, budgets=budgets, seed=args.seed)
    models["anomaly_score"] = summary_row(full_metrics["anomaly_score"])
    bands_by_variant = {}
    for v in VARIANTS:
        out = combine(comps, available, config.variant(v))
        name = f"cri:{v}"
        full_metrics[name] = evaluate_scores(keys, out["cri"], labels, budgets=budgets, seed=args.seed)
        models[name] = summary_row(full_metrics[name])
        models[name]["effective_weights"] = out["weights"]
        bands_by_variant[name] = {
            "HIGH_or_above": band_metrics(keys, labels, out["severity"], ("HIGH", "CRITICAL")),
            "CRITICAL": band_metrics(keys, labels, out["severity"], ("CRITICAL",)),
            "severity_counts": {s: int((out["severity"] == s).sum()) for s in SEVERITIES},
        }
        if v == "default":
            stored = risk["cri_score"].to_numpy(dtype="float64")
            if np.abs(stored - out["cri"]).max() > 1e-9:
                raise ReadoutRefused("recombining the stored components does not reproduce the stored cri_score; "
                                     "the risk run and this code disagree")

    positives = models["anomaly_score"]["positives"]
    harness = []
    d = abs((models["cri:anomaly_only"]["pr_auc"] or 0) - (models["anomaly_score"]["pr_auc"] or 0))
    harness.append({"check": "cri:anomaly_only ranks like the anomaly score (same PR-AUC)", "ok": d <= 1e-12,
                    "detail": f"difference {d:.2e}"})
    ref = chapter8_reference(Path(args.decision_path), args.profile, meta, len(risk), positives)
    if ref and ref.get("served"):
        d8 = abs(ref["served"]["pr_auc"] - models["anomaly_score"]["pr_auc"])
        harness.append({"check": "anomaly score PR-AUC equals the Chapter 8 decision evidence", "ok": d8 <= HARNESS_TOL,
                        "detail": f"Chapter 8 {ref['served']['pr_auc']:.6f}, here {models['anomaly_score']['pr_auc']:.6f}"})
    else:
        harness.append({"check": "anomaly score PR-AUC equals the Chapter 8 decision evidence", "ok": None,
                        "detail": "not comparable (profile is not full, or the rows differ from the decision evidence)"})

    warnings = guard(models["anomaly_score"], models["cri:default"])
    readout = {
        "chapter": 9,
        "part": "validation",
        "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile": args.profile,
        "reportable": args.profile != "dev",
        "cri_run_id": run_dir.name,
        "calibration_id": meta["calibration"]["calibration_id"],
        "config_hash": meta["config_hash"],
        "is_calibrated_default": meta.get("is_calibrated_default"),
        "config_overrides": meta.get("config_overrides", {}),
        "served": meta["served"],
        "rows": int(len(risk)),
        "positives": positives,
        "chance_pr_auc": float(labels["y_primary"][~labels["exclude_primary"]].mean()),
        "budgets": list(budgets),
        "models": models,
        "bands": bands_by_variant,
        "chapter8_reference_rows": None if not ref else {
            k: {"pr_auc": v.get("pr_auc"), "insiders_caught_at_1": v.get("insiders_caught_at_1"),
                "recall_by_scenario_at_1": v.get("recall_by_scenario_at_1"),
                "caught_by_scenario_at_1": v.get("caught_by_scenario_at_1")}
            for k, v in ref["others"].items()},
        "harness": harness,
        "guard": {**GUARD, "warnings": warnings},
        "superseded": ([] if previous is None else [*previous.get("superseded", []),
                                                     {**{k: v for k, v in previous.items() if k != "superseded"},
                                                      "superseded_because": args.supersede}]),
    }
    results = Path(args.results_dir) / run_dir.name
    results.mkdir(parents=True, exist_ok=True)
    (results / "validation_metrics_full.json").write_text(json.dumps(full_metrics, indent=2, default=str), encoding="utf-8")
    readout_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = readout_path.with_name(readout_path.name + ".tmp")
    tmp.write_text(json.dumps(readout, indent=2, default=str), encoding="utf-8")
    tmp.replace(readout_path)
    append_experiment_runlog({
        "stage": "chapter9_validation_readout", "cri_run_id": run_dir.name, "profile": args.profile,
        "reportable": readout["reportable"], "config_hash": meta["config_hash"],
        "validation_pr_auc": {k: v["pr_auc"] for k, v in models.items()},
        "guard_warnings": len(warnings), "harness_ok": all(h["ok"] is not False for h in harness),
        "superseded": bool(args.supersede),
    })
    print_table(readout)
    return readout


def _f(v, nd=3) -> str:
    return "-" if v is None else f"{v:.{nd}f}"


def print_table(r: dict) -> None:
    print(f"\n[readout] {r['cri_run_id']} validation: {r['rows']} rows, {r['positives']} malicious user-days, "
          f"chance {r['chance_pr_auc']:.4f}", flush=True)
    print(f"{'model':<30} {'PR-AUC':>7} {'ROC':>6} {'R@1':>6} {'caught@1':>9} {'caught@5':>9}  days@1 by scenario", flush=True)
    for name, m in r["models"].items():
        scen = ", ".join(f"s{k} {v}" for k, v in m["days_by_scenario_at_1"].items())
        print(f"{name:<30} {_f(m['pr_auc']):>7} {_f(m['roc_auc_secondary']):>6} {_f(m['recall_at_1']):>6} "
              f"{m['insiders_caught_at_1']:>9} {m['insiders_caught_at_5']:>9}  {scen}", flush=True)
    for name, ref in (r.get("chapter8_reference_rows") or {}).items():
        print(f"{name + ' (Ch8 evidence)':<30} {_f(ref['pr_auc']):>7} {'':>6} {'':>6} {ref['insiders_caught_at_1']:>9} "
              f"{'':>9}  " + ", ".join(f"s{k} {v}" for k, v in (ref.get('recall_by_scenario_at_1') or {}).items()), flush=True)
    b = r["bands"]["cri:default"]
    for band in ("HIGH_or_above", "CRITICAL"):
        x = b[band]
        print(f"[readout] default CRI {band}: {x['alerts']} alerts, precision {_f(x['precision'])}, recall {_f(x['recall'])}, "
              f"caught {x['per_user']['caught']}/{x['per_user']['insiders']}, per day median "
              f"{x['alerts_per_day'].get('median')} max {x['alerts_per_day'].get('max')}", flush=True)
    for h in r["harness"]:
        status = "PASS" if h["ok"] else ("n/a" if h["ok"] is None else "FAIL")
        print(f"[readout] harness {status}: {h['check']} ({h['detail']})", flush=True)
    for w in r["guard"]["warnings"]:
        print(f"[readout] WARN {r['guard']['version']}: {w}", flush=True)
    if not r["guard"]["warnings"]:
        print(f"[readout] {r['guard']['version']}: no warning", flush=True)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        run(args)
    except (ReadoutRefused, SourceError) as exc:
        print(f"chapter9 readout refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
