"""Chapter 16 readout: comparison chain and ablation experiments A-E, from stored runs only.

Nothing is trained here. Every number comes from score files, risk runs, alert runs and explain runs that
earlier chapters (and ``app.evaluation.seeds``) wrote, joined to labels in memory (N5).

Experiments
    chain  baselines -> TabNet (shadow) -> XGBoost (served) -> + CRI -> + CRI + MITRE      (deviation C16-1)
    A      behaviour-only models over seeds (TabNet, XGBoost)
    B      the same models with the static / contextual columns, over seeds; paired A vs B
    C      anomaly score vs the Chapter 9 CRI and its leave-one-out variants, top-k and band views (N39, N40)
    D      anomaly score, CRI with and without MITRE, MITRE alone, per scenario, with the benign mapped
           share and the served/shadow disagreement cells (N43, N46)
    E1     alert queue: with / without deduplication, both orderings, the activity rule (N55-N57, N60, N61)
    E2     explanations on test (N52, N53), integrity numbers
    E3     cost of the interpretability constraint: behaviour-only vs all features (B - A)

Rules
    * Part ``test`` writes the pinned readout ``experiments/chapter16_test_readout.json`` ONCE. A second
      write needs ``--supersede "<reason>"``; the old readout is kept inside the new file (N11, N37, N43).
    * Part ``validation`` is a rehearsal: it writes under ``experiments/results/chapter16/<run_id>/`` only.
      Nothing about design may change after test is read.
    * The best baseline is chosen on VALIDATION before test is read (``baseline_choice_on_validation``).
    * Deviations and disclosures are written into the readout, not only into the docs.
    * Guard c16-evaluation-guard-v1 produces WARNs for the audit. It never changes a model, a weight or a policy.

Usage, from backend/:

    python -m app.evaluation.seeds --profile full                  # once, about two hours
    python -m app.evaluation.ablation --profile full --part validation      # rehearsal
    python -m app.evaluation.ablation --profile full --part test            # the readout, once
    python -m app.evaluation.report                                  # experiments/chapter16_evaluation_report.md
"""
from __future__ import annotations

from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.core.run_stamp import utc_run_stamp  # noqa: E402
from app.cri.engine import combine  # noqa: E402
from app.cri.evaluate import band_metrics, summary_row  # noqa: E402
from app.cri.sources import SourceError, chapter8_batch  # noqa: E402
from app.evaluation import compare  # noqa: E402
from app.evaluation.alert_views import operational_views  # noqa: E402
from app.evaluation.bootstrap import DEFAULT_BOOT, cluster_bootstrap, paired_wilcoxon, seed_summary  # noqa: E402
from app.evaluation.explain_view import explanation_view  # noqa: E402
from app.evaluation.metrics import DEFAULT_BUDGETS, daily_top_k, evaluate_scores, per_user_detection, pr_auc  # noqa: E402
from app.evaluation.operating import operating_point, risk_coverage  # noqa: E402
from app.evaluation.rankings import (  # noqa: E402
    BAND_VARIANTS, BASELINE_LABEL, CHAIN, SERVED, SHADOW, VALIDATION_INFORMED, Population, RankingError,
    baseline_choice_on_validation, build_rankings, cri_variant_outputs, load_population, mapped_mask,
)
from app.evaluation.seeds import CONFIGS, MANIFEST_FILE, read_manifest  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, repo_root  # noqa: E402
from app.mitre.evaluate import disagreement_view, rule_rates  # noqa: E402
from app.tabnet.dataset import file_sha256  # noqa: E402

READOUT_FILE = "chapter16_test_readout.json"
READOUT_VERSION = "c16-readout-v1"
TIE_SEEDS = (42, 43, 44, 45, 46)
GUARD = {
    "version": "c16-evaluation-guard-v1",
    "warn_if": ["the default CRI is below the anomaly score on test (PR-AUC, insiders caught at top-1)",
                "a scenario has fewer than 10 test days: no claim is made about it (N15)",
                "seed runs are missing, so experiments A, B and E3 are not computed",
                "a paired Wilcoxon test cannot reach p < 0.05 at the number of seeds available"],
    "effect": "WARN to be explained in docs/audits/chapter_16_audit.md; never changes a model, a weight or a policy (N37)",
}
DEVIATIONS = {
    "C16-1": "The Bible's chain ends 'TabNet + CRI + MITRE'. The served model is XGBoost (C8-1) and the CRI is calibrated "
             "to it (N33); shadow scores never feed a CRI (N32). The chain therefore ends in XGBoost + CRI + MITRE, and "
             "TabNet is compared as the supervised alternative (N23).",
    "C16-2": "Experiments C and D run on the one served model_version, because the CRI calibration is pinned to it (N33). "
             "Their 'seeds' are tie-break seeds for the daily top-k plus a user-clustered bootstrap. Training seeds belong "
             "to experiments A and B.",
    "C16-3": "Risk coverage is defined in app/evaluation/operating.py; the Architecture text that names it was not "
             "available. It is always printed with the review load.",
}
DISCLOSURES = [
    "Test was read once per model in Chapter 8 (experiments/chapter8_test_readout.json). This is the designated "
    "Chapter 16 readout; nothing about design may change after it.",
    "The mid all-features TabNet test PR-AUC was seen during tuning (C7-9, N26). Experiment B uses new seeds on full.",
    "The variant 'cri:no_peer_deviation+no_user_context' was found by looking at validation (N40). It is reported, "
    "not adopted.",
    "The alert queue ordering and the MITRE / user_context rules touch behaviour the public scenarios describe (N41, N36). "
    "A scenario gain from them is partly by construction.",
    "The headline is mostly scenario 2 (N15). Scenario 3 has too few test days for any claim.",
]
PAIRS = (
    (SHADOW, "{best}"), (SERVED, "{best}"), (SHADOW, SERVED),
    ("cri:no_mitre_context", SERVED), ("cri:default", "cri:no_mitre_context"), ("cri:default", SERVED),
    ("cri:no_historical_deviation", "cri:no_mitre_context"), ("cri:no_peer_deviation", "cri:no_mitre_context"),
    ("cri:no_user_context", "cri:no_mitre_context"),
    ("cri:no_peer_deviation+no_user_context", "cri:no_mitre_context"),
)


class ReadoutRefused(RuntimeError):
    """Nothing was written."""


def _top_masks(pop: Population, scores: dict, k: int, seed: int) -> dict:
    return {n: daily_top_k(pop.dates, s, k, seed=seed) for n, s in scores.items()}


def ranking_block(pop: Population, scores: np.ndarray, budgets, seed: int) -> tuple[dict, dict]:
    full = evaluate_scores(pop.keys, scores, pop.labels, budgets=budgets, seed=seed)
    op = {}
    for k in budgets:
        m = daily_top_k(pop.dates, scores, k, seed=seed)
        op[str(k)] = {**operating_point(pop.y, m, pop.exclude), "coverage": risk_coverage(pop.y, m, pop.exclude)}
    return full, {"summary": summary_row(full), "operating_by_budget": op}


def band_block(pop: Population, severity: np.ndarray) -> dict:
    out = {}
    for label, bands in (("HIGH_or_above", ("HIGH", "CRITICAL")), ("CRITICAL", ("CRITICAL",))):
        alerted = np.isin(severity, bands)
        out[label] = {**band_metrics(pop.keys, pop.labels, severity, bands),
                      "operating": operating_point(pop.y, alerted, pop.exclude),
                      "coverage": risk_coverage(pop.y, alerted, pop.exclude)}
    return out


def tie_break_sensitivity(pop: Population, scores: dict, seeds=TIE_SEEDS) -> dict:
    out = {}
    for name, s in scores.items():
        rec, prec, caught = [], [], []
        for sd in seeds:
            m = daily_top_k(pop.dates, s, 1, seed=sd)
            op = operating_point(pop.y, m, pop.exclude)
            ud = per_user_detection(pop.users, pop.keys["date"].to_numpy(), pop.y, m, pop.scenario, pop.exclude)
            rec.append(op["recall"]); prec.append(op["precision"]); caught.append(ud["caught"])
        out[name] = {"seeds": list(seeds), "recall_at_1": seed_summary(rec), "precision_at_1": seed_summary(prec),
                     "insiders_caught_at_1": seed_summary(caught)}
    return out


def cell_scores_path(processed: Path, key: str, rec: dict) -> Path:
    if rec.get("scores_path"):
        return Path(rec["scores_path"])
    model = key.split("/")[0]
    config = key.split("/")[1]
    sub, name = ("chapter7", "tabnet") if model == "tabnet" else (("chapter8" if config == "behaviour" else "chapter6"), "gbdt")
    return processed / "scores" / sub / rec["run_id"] / f"{name}.parquet"


def seed_experiments(pop: Population, manifest: dict | None, budgets, seed: int) -> dict:
    """Experiments A, B, E3 and the seed-level paired tests, from the seed manifest's score files."""
    if not manifest or not manifest.get("runs"):
        return {"available": False, "reason": "no seed manifest; run `python -m app.evaluation.seeds` first"}
    cells: dict[str, dict] = {}
    for key, rec in manifest["runs"].items():
        model, config, sd = key.split("/")
        src = compare.ScoreSource(key, 7 if model == "tabnet" else 8, rec["run_id"], model,
                                  cell_scores_path(pop.processed, key, rec))
        if not src.path.exists():
            cells[key] = {"error": f"score file missing: {src.path}"}
            continue
        frame = compare._load_part(src, pop.part)
        same = len(frame) == len(pop.keys) and (frame["user_id"].to_numpy() == pop.keys["user_id"].astype(str).to_numpy()).all() \
            and (frame["date"].to_numpy() == pop.keys["date"].astype(str).to_numpy()).all()
        if not same:
            cells[key] = {"error": "rows differ from the served model's population (split or matrix mismatch)"}
            continue
        full = evaluate_scores(pop.keys, frame["anomaly_score"].to_numpy(dtype="float64"), pop.labels, budgets=budgets, seed=seed)
        row = summary_row(full)
        cells[key] = {"seed": int(sd), "run_id": rec["run_id"], "reference": bool(rec.get("reference")),
                      "model_version": rec.get("model_version"), "pr_auc": row["pr_auc"],
                      "recall_at_1": row["recall_at_1"], "insiders_caught_at_1": row["insiders_caught_at_1"],
                      "caught_by_scenario_at_1": row["caught_by_scenario_at_1"]}
    errors = {k: v["error"] for k, v in cells.items() if "error" in v}
    ok = {k: v for k, v in cells.items() if "error" not in v}

    def series(model, config):
        return {c["seed"]: c["pr_auc"] for k, c in ok.items() if k.startswith(f"{model}/{config}/") and c["pr_auc"] is not None}

    per = {f"{m}/{c}": series(m, c) for m in ("tabnet", "gbdt") for c in CONFIGS}
    summary = {k: seed_summary(list(v.values())) for k, v in per.items()}

    def paired(a: dict, b: dict) -> dict:
        common = sorted(set(a) & set(b))
        return {"seeds": common, **paired_wilcoxon([a[s] for s in common], [b[s] for s in common])}

    tests = {
        "A_tabnet_vs_xgboost_behaviour_n23": paired(per["tabnet/behaviour"], per["gbdt/behaviour"]),
        "B_tabnet_all_features_minus_behaviour": paired(per["tabnet/all_features"], per["tabnet/behaviour"]),
        "B_xgboost_all_features_minus_behaviour": paired(per["gbdt/all_features"], per["gbdt/behaviour"]),
        "headline_tabnet_vs_xgboost_all_features": {
            **paired(per["tabnet/behaviour"], per["gbdt/all_features"]),
            "note": "XGBoost on all features is the closest seeded reproduction of the Chapter 6 XGBoost baseline; "
                    "it is not that baseline's own run"},
    }
    return {"available": True, "manifest_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
            "split_seed": manifest.get("split_seed"), "cells": cells, "errors": errors,
            "per_seed_pr_auc": {k: {str(s): v for s, v in d.items()} for k, d in per.items()},
            "seed_summary_pr_auc": summary, "paired_tests": tests,
            "E3_interpretability_cost": {
                "definition": "all-features minus behaviour-only PR-AUC, mean over seeds; behaviour-only is the adopted, "
                              "explainable configuration (N25)",
                "tabnet": tests["B_tabnet_all_features_minus_behaviour"].get("mean_difference"),
                "xgboost": tests["B_xgboost_all_features_minus_behaviour"].get("mean_difference")}}


def harness_checks(pop: Population, scores: dict, full: dict, prov: dict, args, experiments: Path) -> list[dict]:
    checks = [{"check": "every ranking covers exactly the served model's rows", "ok": True,
               "detail": f"{len(pop.keys)} {pop.part} rows, {len(scores)} rankings"},
              {"check": "recombining the stored components reproduces the stored cri_score", "ok": True,
               "detail": "cri_variant_outputs raises otherwise"}]
    cfg = pop.config
    ao = combine(pop.components, pop.available, cfg.variant("anomaly_only"))["cri"]
    keep = ~pop.exclude
    d = abs((pr_auc(pop.y[keep], ao[keep]) or 0) - (full[SERVED]["primary"]["pr_auc"] or 0))
    # The anomaly component is a rarity against the validation reference (N33): non-strictly monotone, so scores that
    # fall between the same two reference points tie. The check is order preservation; ties and the PR-AUC shift are
    # reported, not failed (found on the CERT test readout: 63,824 distinct scores became 32,866, shift 3.28e-03).
    a = scores[SERVED]
    o = np.argsort(a, kind="stable")
    monotone = bool(np.all(np.diff(ao[o]) >= 0))
    checks.append({"check": "cri:anomaly_only never reverses the anomaly score's order (ties allowed)", "ok": monotone,
                   "detail": f"distinct values {len(np.unique(a))} -> {len(np.unique(ao))}; PR-AUC shift from ties {d:.2e}"})
    try:
        b = chapter8_batch(pop.processed, pop.risk_meta["source_batch"]["batch_run_id"], None).read(role="served")
        j = pop.keys.merge(b[["user_id", "date", "anomaly_score"]], on=["user_id", "date"], how="left")
        diff = float(np.abs(j["anomaly_score"].to_numpy(dtype="float64") - scores[SERVED]).max())
        checks.append({"check": "the risk run's anomaly score equals the Chapter 8 batch's served score",
                       "ok": bool(np.isfinite(diff) and diff <= 1e-12), "detail": f"max difference {diff:.2e}"})
    except (SourceError, KeyError, FileNotFoundError) as exc:
        checks.append({"check": "the risk run's anomaly score equals the Chapter 8 batch's served score", "ok": None,
                       "detail": f"batch not readable: {exc}"})
    if pop.part == "test":
        log = compare._runlog_lines()
        for name, p in prov.items():
            if not name.startswith("baseline:") or p.get("chapter") != 6:
                continue
            model = next((m for m in BASELINE_LABEL if f"baseline:{BASELINE_LABEL[m]}" == name), name.split(":", 1)[1])
            line = next((r for r in log if r.get("stage") == "chapter6_baseline" and r.get("run_id") == p["run_id"]
                         and r.get("model") == model), None)
            now = full[name]["primary"]["pr_auc"]
            logged = None if line is None else line.get("test_pr_auc")
            checks.append({"check": f"{name}: recomputed test PR-AUC equals the one its Chapter 6 run logged",
                           "ok": None if logged is None else abs(now - logged) <= compare.HARNESS_TOLERANCE,
                           "detail": f"logged {logged}, recomputed {now}"})
        f8 = experiments / "chapter8_test_readout.json"
        ev = json.loads(f8.read_text(encoding="utf-8"))["evidence"].get(f"{pop.profile}/user") if f8.exists() else None
        if ev and ev.get("rows") == len(pop.keys):
            for ours, theirs in ((SERVED, "gbdt"), (SHADOW, "tabnet"), ("baseline:gbdt_all_features", "gbdt_ch6_all_feat")):
                want = (ev["models"].get(theirs) or {}).get("pr_auc")
                have = full[ours]["primary"]["pr_auc"]
                checks.append({"check": f"{ours} test PR-AUC equals the Chapter 8 test readout ({theirs})",
                               "ok": None if want is None else abs(want - have) <= 1e-9, "detail": f"Chapter 8 {want}, here {have}"})
        else:
            checks.append({"check": "test PR-AUCs equal the Chapter 8 test readout", "ok": None,
                           "detail": "no comparable Chapter 8 evidence (different rows or no file)"})
    return checks


def secondary_comparisons(processed: Path, splits: list[str], experiments: Path, part: str) -> dict:
    """mid/user and mid/time through the Chapter 7 harness, with the seen/new breakdown on the time split (N16, N17)."""
    out = {}
    f8 = experiments / "chapter8_reference_runs.json"
    cands = (json.loads(f8.read_text(encoding="utf-8")).get("gbdt_candidates") or {}) if f8.exists() else {}
    for key in splits:
        profile, split = key.split("/")
        try:
            sources = compare_sources_for(processed, profile, split, experiments, cands)
            info = {"mode": split}
            if split == "time":
                info.update({"validation_start": "2011-01-01", "test_start": "2011-02-01"})
            res = compare.compare_sources(processed, sources, part=part, split_info=info)
            res["harness_check"] = compare.harness_check(res, sources, compare._runlog_lines())
            out[key] = res
        except Exception as exc:
            out[key] = {"available": False, "reason": f"{type(exc).__name__}: {exc}"}
    return out


def compare_sources_for(processed, profile, split, experiments, cands):
    from app.evaluation.rankings import reference_sources

    sources = reference_sources(processed, profile, split, experiments)
    c = cands.get(f"{profile}/{split}")
    if c:
        sources.append(compare.ScoreSource("xgboost_behaviour", 8, c["run_id"], "gbdt",
                                           processed / "scores" / "chapter8" / c["run_id"] / "gbdt.parquet"))
    return sources


def guard(rankings: dict, seeds: dict, scen_days: dict) -> list[str]:
    w = []
    a, c = rankings[SERVED]["summary"], rankings["cri:default"]["summary"]
    if c["pr_auc"] is not None and a["pr_auc"] is not None and c["pr_auc"] < a["pr_auc"]:
        w.append(f"cri:default PR-AUC {c['pr_auc']:.4f} < anomaly score {a['pr_auc']:.4f}")
    if int(c["insiders_caught_at_1"].split("/")[0]) < int(a["insiders_caught_at_1"].split("/")[0]):
        w.append(f"cri:default insiders caught at top-1 {c['insiders_caught_at_1']} < anomaly score {a['insiders_caught_at_1']}")
    for s, n in scen_days.items():
        if n < 10:
            w.append(f"scenario {s} has {n} test days: no claim is made about it (N15)")
    if not seeds.get("available"):
        w.append("seed runs missing: experiments A, B and E3 not computed")
    else:
        for name, t in seeds["paired_tests"].items():
            if t.get("note", "").startswith("with "):
                w.append(f"{name}: {t['note']}")
    return w


def run(args: argparse.Namespace) -> dict:
    if args.part not in ("validation", "test"):
        raise ReadoutRefused("part must be validation or test")
    experiments = Path(args.experiments_dir)
    readout_path = Path(args.readout_path)
    previous = None
    if args.part == "test" and readout_path.exists():
        if not args.supersede:
            raise ReadoutRefused(f"{readout_path} exists; the test readout is written once. Pass --supersede \"<reason>\"")
        previous = json.loads(readout_path.read_text(encoding="utf-8"))
    processed = Path(args.processed_dir)
    budgets = tuple(int(k) for k in args.budgets.split(","))
    tie_seeds = tuple(int(s) for s in args.tie_seeds.split(","))
    run_id = f"{utc_run_stamp()}-{args.profile}-{args.part}-c16"

    try:
        pop = load_population(processed, args.profile, args.part, cri_run_id=args.cri_run_id)
        choice = baseline_choice_on_validation(processed, args.profile, "user", experiments)
        scores, prov = build_rankings(pop, experiments=experiments)
    except RankingError as exc:
        raise ReadoutRefused(str(exc)) from exc
    best = f"baseline:{BASELINE_LABEL.get(choice['best'], choice['best'])}"
    print(f"[c16] {args.part}: {len(pop.keys)} rows, {int(pop.y[~pop.exclude].sum())} malicious user-days; "
          f"best baseline on validation: {choice['best']}", flush=True)

    full, rankings = {}, {}
    for name, s in scores.items():
        full[name], rankings[name] = ranking_block(pop, s, budgets, args.seed)
        rankings[name]["provenance"] = prov[name]
    variants = cri_variant_outputs(pop)
    for name in BAND_VARIANTS:
        rankings[name]["bands"] = band_block(pop, variants[name]["severity"])
        rankings[name]["validation_informed"] = name in VALIDATION_INFORMED

    top1 = _top_masks(pop, scores, 1, args.seed)
    masks = dict(top1)
    for name in ("cri:default", "cri:no_mitre_context"):
        masks[f"band:{name}"] = np.isin(variants[name]["severity"], ("HIGH", "CRITICAL"))
    pairs = [tuple(x.format(best=best) for x in p) for p in PAIRS]
    boot = cluster_bootstrap(pop.users, pop.y, pop.exclude, scores, masks, pairs=pairs, n_boot=args.n_boot, seed=args.seed)

    sens = tie_break_sensitivity(pop, {n: scores[n] for n in (best, SHADOW, SERVED, "cri:no_mitre_context", "cri:default")}, tie_seeds)
    seeds_block = seed_experiments(pop, read_manifest(Path(args.seed_manifest)), budgets, args.seed)

    mapped = mapped_mask(pop)
    shadow_top1 = top1[SHADOW]
    cells = disagreement_view(pop.keys, pop.labels, {"served": top1[SERVED], "shadow": shadow_top1,
                                                     "cri_default": top1["cri:default"],
                                                     "cri_no_mitre": top1["cri:no_mitre_context"]}, mapped)
    exp_D = {"rankings": ["anomaly: " + SERVED, "cri:no_mitre_context", "cri:default", "mitre_context"],
             "benign_and_rules": rule_rates(pop.labels, pop.mitre["mitre_rules"], mapped),
             "served_shadow_disagreement_at_top1": cells,
             "disclosure": "a scenario gain from MITRE is partly by construction (N41); read it beside cri:no_mitre_context "
                           "and the benign mapped share (N43)"}

    views = operational_views(processed, args.profile, args.part, alert_run_id=args.alert_run_id)
    explain = {"available": False, "reason": "--no-explain"} if args.no_explain else \
        explanation_view(processed, args.profile, args.part, explain_run_id=args.explain_run_id, seed=args.seed,
                         include_shadow=not args.no_shadow_view)
    secondary = {}
    if args.secondary and args.secondary != "none":
        secondary = secondary_comparisons(processed, args.secondary.split(","), experiments, args.part)

    harness = harness_checks(pop, scores, full, prov, args, experiments)
    # reproducibility from stored scores: a fresh load must give the same headline numbers (Architecture §45 item 16)
    again_pop = load_population(processed, args.profile, args.part, cri_run_id=args.cri_run_id)
    again, _ = build_rankings(again_pop, experiments=experiments)
    repro = {n: bool(np.array_equal(scores[n], again[n])) for n in scores}
    harness.append({"check": "a fresh load of every stored ranking is identical (metrics are reproducible)",
                    "ok": all(repro.values()), "detail": f"{sum(repro.values())}/{len(repro)} rankings identical"})

    scen_days = {str(s): int(((pop.scenario == s) & (pop.y == 1) & ~pop.exclude).sum()) for s in (1, 2, 3)}
    warnings = guard(rankings, seeds_block, scen_days)
    keep = ~pop.exclude
    chain = [{"stage": label, "ranking": name.format(best_baseline=best)} for label, name in CHAIN]
    for row in chain:
        s = rankings[row["ranking"]]["summary"]
        row.update({"pr_auc": s["pr_auc"], "recall_at_1": s["recall_at_1"], "insiders_caught_at_1": s["insiders_caught_at_1"],
                    "pr_auc_ci": boot["scores"][row["ranking"]]["pr_auc"]})

    readout = {
        "chapter": 16, "version": READOUT_VERSION, "run_id": run_id, "part": args.part, "profile": args.profile,
        "reportable": args.profile == "full", "split": "user (saved split file, N11)",
        "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "view": "primary (N1); masquerade account-days neither hit nor false alarm; secondary account view in the full blocks",
        "deviations": DEVIATIONS, "disclosures": DISCLOSURES,
        "lineage": {**pop.provenance, "alert_run_id": views["alert_run_id"], "alert_policy_hash": views["policy_hash"],
                    "explain_run_id": explain.get("explain_run_id"), "bootstrap_seed": args.seed,
                    "tie_break_seeds": list(tie_seeds), "label_files_sha256": _label_hashes(processed)},
        "population": {"rows": int(len(pop.keys)), "users": int(pd.Series(pop.users).nunique()),
                       "positives": int(pop.y[keep].sum()), "scenario_days": scen_days,
                       "chance_pr_auc": float(pop.y[keep].mean()),
                       "precision_ceiling": compare._precision_ceiling(pop.keys["date"], pop.y, keep, budgets),
                       "budgets": list(budgets),
                       "note": "daily top-k here ranks this part's users only; the alert queue ranks validation and test "
                               "users together (N61)"},
        "baseline_choice": choice, "chain": chain, "rankings": rankings,
        "bootstrap": boot, "tie_break_sensitivity": sens,
        "experiments": {
            "A_B_E3_seeds": seeds_block,
            "C": {"definition": "anomaly score vs the Chapter 9 CRI (MITRE off) and leave-one-out variants; top-k and band views (N39, N40)",
                  "rankings": [SERVED, "cri:no_mitre_context", "cri:no_historical_deviation", "cri:no_peer_deviation",
                               "cri:no_user_context", "cri:no_peer_deviation+no_user_context"]},
            "D": exp_D,
            "E1_alert_queue": views, "E2_explanations": explain,
        },
        "secondary_splits": secondary, "harness": harness,
        "guard": {**GUARD, "warnings": warnings}, "reproducibility": repro,
        "caveats": ["one trained model per ranking except experiments A and B (seeds, N26)",
                    "a bootstrap interval is about which users the test set holds, not about training noise",
                    "scenario 2 supplies most positives (N15); six scenario-1 insiders cannot settle a scenario claim",
                    "nothing here is a probability of malice (N20)"],
    }
    if previous is not None:
        readout["supersedes"] = {"reason": args.supersede, "previous": previous}

    results = Path(args.results_dir) / run_id
    results.mkdir(parents=True, exist_ok=True)
    (results / "metrics_full.json").write_text(json.dumps(full, indent=2, default=str), encoding="utf-8")
    (results / f"readout_{args.part}.json").write_text(json.dumps(readout, indent=2, default=str), encoding="utf-8")
    if args.part == "test":
        readout_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = readout_path.with_name(readout_path.name + ".tmp")
        tmp.write_text(json.dumps(readout, indent=2, default=str), encoding="utf-8")
        tmp.replace(readout_path)
    append_experiment_runlog({
        "stage": "chapter16_readout", "run_id": run_id, "part": args.part, "profile": args.profile,
        "reportable": readout["reportable"], "pinned": args.part == "test", "risk_run_id": pop.provenance["risk_run_id"],
        "alert_run_id": views["alert_run_id"], "guard_warnings": len(warnings),
        "harness_ok": all(h["ok"] is not False for h in harness),
        "pr_auc": {n: r["summary"]["pr_auc"] for n, r in rankings.items()}, "superseded": bool(args.supersede)})
    print_table(readout)
    return readout


def _label_hashes(processed: Path) -> dict:
    root = processed / "labels"
    return {p.name: file_sha256(p) for p in sorted(root.glob("*.parquet"))} if root.exists() else {}


def _f(v, nd=3) -> str:
    return "-" if v is None else f"{v:.{nd}f}"


def print_table(r: dict) -> None:
    p = r["population"]
    print(f"\n[c16] {r['part']} readout {r['run_id']}: {p['rows']} rows, {p['positives']} malicious user-days, chance {p['chance_pr_auc']:.4f}")
    print(f"{'ranking':<40} {'PR-AUC':>7} {'95% CI':>17} {'R@1':>6} {'caught@1':>9}")
    for n, x in r["rankings"].items():
        s, ci = x["summary"], r["bootstrap"]["scores"][n]["pr_auc"]
        rng = f"{_f(ci['lo'])}-{_f(ci['hi'])}"
        print(f"{n:<40} {_f(s['pr_auc']):>7} {rng:>17} {_f(s['recall_at_1']):>6} {s['insiders_caught_at_1']:>9}")
    for h in r["harness"]:
        st = "PASS" if h["ok"] else ("n/a" if h["ok"] is None else "FAIL")
        print(f"[c16] harness {st}: {h['check']} ({h['detail']})")
    for w in r["guard"]["warnings"]:
        print(f"[c16] WARN {r['guard']['version']}: {w}")


def _parse_args(argv):
    root = repo_root()
    p = argparse.ArgumentParser(description="CIRA Chapter 16 evaluation readout (reads labels)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=("mid", "full"))
    p.add_argument("--part", default="validation", choices=("validation", "test"))
    p.add_argument("--cri-run-id", default=None)
    p.add_argument("--alert-run-id", default=None)
    p.add_argument("--explain-run-id", default=None)
    p.add_argument("--seed-manifest", default=str(root / "experiments" / MANIFEST_FILE))
    p.add_argument("--experiments-dir", default=str(root / "experiments"))
    p.add_argument("--readout-path", default=str(root / "experiments" / READOUT_FILE))
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter16"))
    p.add_argument("--budgets", default=",".join(str(k) for k in DEFAULT_BUDGETS))
    p.add_argument("--n-boot", type=int, default=DEFAULT_BOOT)
    p.add_argument("--tie-seeds", default=",".join(str(s) for s in TIE_SEEDS))
    p.add_argument("--seed", type=int, default=int(os.getenv("CIRA_SEED", "42")))
    p.add_argument("--secondary", default="none", help="comma list such as mid/user,mid/time (Chapter 7 harness)")
    p.add_argument("--no-explain", action="store_true")
    p.add_argument("--no-shadow-view", action="store_true")
    p.add_argument("--supersede", default=None, metavar="REASON")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    try:
        run(args)
    except ReadoutRefused as exc:
        print(f"chapter16 readout refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
