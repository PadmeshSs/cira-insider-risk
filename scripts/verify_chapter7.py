"""Verify a Chapter 7 TabNet run before any number from it is used.

Reads the outputs of ``python -m app.tabnet.train`` (metrics.json, the split
file, the score Parquet, the registry entry and artifacts, runlog lines) and
checks them against the Bible Ch7 acceptance list, HCEA §7 and
CARRY_FORWARD N1-N18. Every check prints PASS, WARN or FAIL; exit code 1 on
any FAIL.

Usage, from backend/ (same env vars as the runner):

    python ../scripts/verify_chapter7.py --profile mid
    python ../scripts/verify_chapter7.py --profile mid --reload-models --permutation-test --baselines
    python ../scripts/verify_chapter7.py --profile mid --split time --baselines
    python ../scripts/verify_chapter7.py --profile mid --compare-run-id <earlier --fresh run with the same config>

Defaults to the newest run for the profile/split. Writes
``experiments/results/chapter7/<run_id>/verification.json`` and one
``chapter7_verification`` line in the runlog.

``--baselines`` checks comparability with the reference Chapter 6 runs (N18):
same (user, date) rows in validation and test, same feature matrix, and the
harness reproduces every logged baseline test PR-AUC. It does not print any
TabNet test number.

This is evaluation code: it reads labels, in memory, like the runner.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.runtime import apply_thread_caps  # noqa: E402

apply_thread_caps()

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.evaluation.compare import (  # noqa: E402
    ComparisonError,
    chapter6_sources,
    chapter7_source,
    compare_sources,
    fingerprint_check,
    harness_check,
    load_reference_runs,
    reference_runs_for,
)
from app.evaluation.labels import attach_labels, insider_scenarios, load_label_views  # noqa: E402
from app.evaluation.metrics import pr_auc  # noqa: E402
from app.evaluation.splitting import SPLITS, _allocate, assign_user_splits, load_split, rows_for_split, time_split  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, repo_root  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, feature_fingerprint, file_sha256  # noqa: E402
from app.tabnet.infer import load_model, sigmoid  # noqa: E402
from app.tabnet.model_registry import ModelRegistry  # noqa: E402

PUBLISHED = {"malicious_user_days": 966, "insiders": 70}
SCORE_COLUMNS = {"user_id", "date", "split", "raw_score", "anomaly_score", "model_name", "model_version"}
LABEL_WORDS = ("malicious", "insider", "scenario", "label", "y_primary", "y_account", "is_masquerade", "target")
RSS_TARGET_MB, RSS_CEILING_MB = 10 * 1024, 20 * 1024     # HCEA §7.6 target, §1.2 ceiling
VRAM_TARGET_MB = 3 * 1024                                 # HCEA §7.6
HYPERPARAMETER_BUDGET = 12                                # HCEA §7.6
ENTRY_FIELDS = ("model_name", "model_version", "registry_version", "run_id", "profile", "reportable", "trained_at",
                "registered_at", "training_data", "feature_schema", "config", "imbalance", "metrics", "split", "files")


class Checks:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, section: str, name: str, status: str, detail: str = "") -> None:
        self.rows.append({"section": section, "check": name, "status": status, "detail": detail})
        print(f"  {status:<4} {section:<12} {name}" + (f"  -- {detail}" if detail else ""), flush=True)

    def ok(self, section, name, cond, detail="", warn_only=False) -> bool:
        self.add(section, name, "PASS" if cond else ("WARN" if warn_only else "FAIL"), detail)
        return bool(cond)

    def counts(self) -> dict:
        return {s: sum(r["status"] == s for r in self.rows) for s in ("PASS", "WARN", "FAIL")}


def _latest_run(results: Path, profile: str, split: str) -> str:
    runs = sorted(p.name for p in results.iterdir() if p.is_dir() and f"-{profile}-{split}-" in p.name
                  and (p / "metrics.json").exists()) if results.exists() else []
    if not runs:
        raise SystemExit(f"No Chapter 7 run under {results} for profile={profile} split={split}")
    return runs[-1]


def _keys(frame: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({"user_id": frame["user_id"].astype("string").str.strip().str.casefold(),
                         "date": frame["date"].astype("string")})


def main(argv=None) -> int:
    root = repo_root()
    p = argparse.ArgumentParser(description="Verify a Chapter 7 TabNet run")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "mid"), choices=("dev", "mid", "full"))
    p.add_argument("--split", default=None, choices=("user", "time"), help="picks the newest run of this mode")
    p.add_argument("--run-id", default=None)
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter7"))
    p.add_argument("--splits-dir", default=str(root / "experiments" / "splits"))
    p.add_argument("--references", default=str(root / "experiments" / "chapter6_reference_runs.json"))
    p.add_argument("--runlog", default=os.getenv("CIRA_RUNLOG", str(root / "experiments" / "runlog.jsonl")))
    p.add_argument("--reload-models", action="store_true", help="load the registered artifact and re-score test")
    p.add_argument("--permutation-test", action="store_true", help="TabNet on shuffled training labels must stay near chance")
    p.add_argument("--permutation-epochs", type=int, default=10,
                   help="epochs per shuffled-label model; three shuffles plus one untrained control are fitted")
    p.add_argument("--compare-run-id", default=None, help="earlier --fresh run with the same config, for determinism")
    p.add_argument("--baselines", action="store_true", help="comparability with the reference Chapter 6 runs (N18)")
    args = p.parse_args(argv)

    results = Path(args.results_dir)
    run_id = args.run_id or _latest_run(results, args.profile, args.split or "user")
    report = json.loads((results / run_id / "metrics.json").read_text(encoding="utf-8"))
    split_mode = report["split"]["mode"]
    block = report["models"]["tabnet"]
    md = block["metadata"]
    c = Checks()
    print(f"\nVerifying Chapter 7 run {run_id}  (split mode from the run: {split_mode})\n")

    # ------------------------------------------------------------------ run
    S = "run"
    c.ok(S, "chapter 7 run", report.get("chapter") == 7)
    c.ok(S, "profile matches", report["profile"] == args.profile, report["profile"])
    if args.split and args.split != split_mode:
        c.add(S, "split mode", "WARN", f"--split {args.split} given, run is {split_mode}; verified as {split_mode}")
    c.ok(S, "reportable flag follows N6", report["reportable"] == (args.profile != "dev"))
    if args.profile == "dev":
        c.add(S, "dev numbers are for debugging only", "WARN", "never report them (HCEA R10)")
    c.ok(S, "no accuracy anywhere (N2)", "accuracy" not in json.dumps(report).lower())

    # ------------------------------------------------------------------ features
    S = "features"
    processed = Path(args.processed_dir)
    fpath = processed / "features" / PROFILE_OUTPUT[args.profile]
    matrix = pd.read_parquet(fpath)
    keys = _keys(matrix)
    c.ok(S, "row count unchanged since the run", len(matrix) == report["features"]["rows"], f"{len(matrix)} rows")
    c.ok(S, "feature file unchanged since the run", feature_fingerprint(fpath) == report["features"]["fingerprint"],
         report["features"]["fingerprint"], warn_only=True)
    leaky = [col for col in matrix.columns if any(w in col.lower() for w in LABEL_WORDS)]
    c.ok(S, "no label-like feature columns (N5)", not leaky, ", ".join(leaky))

    # ------------------------------------------------------------------ labels
    S = "labels"
    views = load_label_views(processed)
    cov = report["label_coverage"]
    for view in ("primary", "account"):
        c.ok(S, f"{view}: every label day in the window has a feature row", cov[view]["unmatched"] == 0)
        if args.profile != "dev":
            c.ok(S, f"{view}: no label day outside the window", cov[view].get("outside_feature_window", 0) == 0)
    c.ok(S, "label table matches published r4.2 counts",
         (len(views.primary), views.primary["user_id"].nunique()) == (PUBLISHED["malicious_user_days"], PUBLISHED["insiders"]),
         f"{len(views.primary)} user-days, {views.primary['user_id'].nunique()} insiders", warn_only=True)
    labels = attach_labels(keys, views)
    scen = insider_scenarios(views, set(keys["user_id"]))

    # ------------------------------------------------------------------ split
    S = "split"
    assignment = None
    if split_mode == "user":
        spath = Path(report["split"]["file"])
        if not spath.exists():
            spath = Path(args.splits_dir) / spath.name
        if c.ok(S, "split file exists", spath.exists(), str(spath)):
            c.ok(S, "split file unchanged since the run (N11)", file_sha256(spath) == report["split"]["file_sha256"])
            created = bool(report["split"].get("created_now"))
            c.ok(S, "split loaded, not created by this run (N11)", not created,
                 "created now: Chapter 6 comparisons hold only if the baselines used this file" if created else "", warn_only=True)
            assignment, meta = load_split(spath)
            again = assign_user_splits(set(keys["user_id"]), scen, seed=meta["seed"], fractions=tuple(meta["fractions"].values()))
            c.ok(S, "assignment reproduces from seed", again == {u: assignment[u] for u in again})
            fr = tuple(meta["fractions"].values())
            for s in sorted(set(scen.values())):
                members = [u for u, v in scen.items() if v == s]
                want = dict(zip(SPLITS, _allocate(len(members), fr)))
                got = {sp: sum(assignment[u] == sp for u in members) for sp in SPLITS}
                c.ok(S, f"scenario {s} insiders stratified", got == want, f"{got['train']}/{got['validation']}/{got['test']}")
        split_rows = rows_for_split(keys["user_id"], assignment) if assignment else None
    else:
        split_rows = time_split(keys["date"], validation_start=report["split"]["validation_start"], test_start=report["split"]["test_start"])
    if split_rows is None:
        c.add(S, "split rows", "FAIL", "cannot rebuild the split")
        return _finish(c, results, run_id, args)
    per = {s: int((split_rows == s).sum()) for s in SPLITS}
    c.ok(S, "row counts per split match the run", per == report["split"]["rows"], str(per))
    if split_mode == "user":
        c.ok(S, "no user in two splits (N3)",
             pd.DataFrame({"u": keys["user_id"], "s": split_rows}).groupby("u")["s"].nunique().max() == 1)

    # ------------------------------------------------------------------ N13 / N2
    S = "training"
    tr_rows = report["training_rows"]
    excl = report["split"]["masquerade_rows_excluded"]
    c.ok(S, "masquerade rows dropped from training (N13)", tr_rows["train_masquerade_dropped"] == excl["train"], f"{excl['train']}")
    c.ok(S, "masquerade rows dropped from validation (N13)", tr_rows["validation_masquerade_dropped"] == excl["validation"],
         f"{excl['validation']}")
    imb = md["imbalance"]
    pos, neg = imb["train_positives"], imb["train_negatives"]
    c.ok(S, "train positives = split train positives", pos == report["split"]["positives_primary"]["train"], str(pos))
    c.ok(S, "training rows = train rows minus masquerade", pos + neg == tr_rows["train_used"], str(pos + neg))
    c.ok(S, "imbalance method recorded (HCEA D-7)", imb["method"] in ("class_weighted_loss", "balanced_sampler"), imb["method"])
    c.ok(S, "effective weight = negatives/positives from train (N2)",
         pos > 0 and abs(imb["effective_positive_weight"] - neg / pos) < 1e-9, f"{imb['effective_positive_weight']:.3f}")
    c.ok(S, "early stopping on validation PR-AUC (C7-1)", str(md.get("early_stopping", "")).startswith("validation pr_auc"),
         md.get("early_stopping", ""), warn_only=True)
    c.ok(S, "at least one epoch trained", (md.get("epochs_run") or 0) >= 1, f"{md.get('epochs_run')} epochs, device {md.get('device_used')}")
    if md.get("best_epoch") is not None:
        c.ok(S, "best epoch inside the run", 0 <= md["best_epoch"] < md["epochs_run"], str(md["best_epoch"]))
    ck = md.get("checkpoint_dir")
    c.ok(S, "per-epoch checkpoints exist (R7)", bool(ck) and Path(ck).exists() and any(Path(ck).glob("epoch_*.pt")), str(ck), warn_only=True)
    c.ok(S, "drop_last kept False (HCEA §7.2)", not md.get("drop_last"), md.get("drop_last_reason") or "", warn_only=True)
    c.ok(S, "no static per-user trait in mask top 10", not md.get("static_traits_in_top10"),
         str(md.get("static_traits_in_top10")), warn_only=True)

    # ------------------------------------------------------------------ scores
    S = "scores"
    sp = Path(md["scores_path"])
    if not sp.exists():
        sp = processed / "scores" / "chapter7" / run_id / "tabnet.parquet"
    sc = None
    if c.ok(S, "score file exists", sp.exists(), str(sp)):
        sc = pd.read_parquet(sp)
        c.ok(S, "score columns exact, no labels (N5)", set(sc.columns) == SCORE_COLUMNS, str(sorted(set(sc.columns) ^ SCORE_COLUMNS)))
        c.ok(S, "anomaly_score finite and in [0, 1] (N10)", np.isfinite(sc["anomaly_score"]).all() and sc["anomaly_score"].between(0, 1).all())
        c.ok(S, "anomaly_score = sigmoid(raw_score)",
             np.allclose(sc["anomaly_score"].to_numpy(), sigmoid(sc["raw_score"].to_numpy()), rtol=0, atol=1e-12))
        c.ok(S, "one model_version, matches metadata", sc["model_version"].nunique() == 1 and sc["model_version"].iloc[0] == md["model_version"])
        c.ok(S, "rows = validation + test", len(sc) == per["validation"] + per["test"], str(len(sc)))
        c.ok(S, "no duplicate (user, date, split)", not sc.duplicated(["user_id", "date", "split"]).any())
        sat = int((sc.loc[sc["split"] == "test", "anomaly_score"] >= 1.0).sum())
        c.ok(S, "no saturated test scores", sat == 0, f"{sat} rows at exactly 1.0; ties broken by the seeded key", warn_only=True)

    S = "metrics"
    for part in ("validation", "test"):
        pm = block[part]["primary"]
        c.ok(S, f"{part} PR-AUC computed", pm["pr_auc"] is not None)
        c.ok(S, f"{part} budgets present", set(pm["budgets"]) == {str(k) for k in report["budgets"]})
        c.ok(S, f"{part} per-scenario recall present (N15)", all("recall_by_scenario" in b for b in pm["budgets"].values()))
    c.ok(S, "account view reported once (N1)", "secondary_account_view" in block["test"])
    t = block["test"]["primary"]
    if t["pr_auc"] is not None and t["positive_rate"]:
        c.ok(S, "test PR-AUC above chance", t["pr_auc"] > t["positive_rate"], f"chance {t['positive_rate']:.4f}", warn_only=True)
        c.ok(S, "test PR-AUC not suspiciously perfect", t["pr_auc"] < 0.99, "if ~1.0 look for leakage", warn_only=True)

    # ------------------------------------------------------------------ registry
    S = "registry"
    entry = None
    if report.get("registry") is None:
        c.add(S, "model registered", "WARN", "run used --no-register; nothing to serve or report from it")
    else:
        reg_root = Path(report["registry"]["artifact_dir"]).parent.parent
        reg = ModelRegistry(reg_root)
        try:
            entry = reg.resolve(report["registry"]["registry_version"])
        except Exception as exc:
            c.add(S, "registry entry found", "FAIL", str(exc))
        if entry is not None:
            c.ok(S, "registry entry found", True, entry["registry_version"])
            c.ok(S, "entry belongs to this run", entry["run_id"] == run_id)
            missing = [f for f in ENTRY_FIELDS if f not in entry]
            c.ok(S, "entry has every Bible Ch7 field", not missing, ", ".join(missing))
            c.ok(S, "entry model_version = score file", sc is None or entry["model_version"] == sc["model_version"].iloc[0])
            c.ok(S, "entry has feature-schema version", bool(entry.get("feature_schema", {}).get("pipeline_version")))
            c.ok(S, "entry has evaluation metrics", {"validation", "test"} <= set(entry.get("metrics", {})))
            problems = reg.verify(entry)
            c.ok(S, "artifact files match recorded sha256", not problems, "; ".join(problems))

    # ------------------------------------------------------------------ resources / log
    S = "resources"
    runlog = [json.loads(x) for x in Path(args.runlog).read_text(encoding="utf-8").splitlines() if x.strip()]
    line = next((r for r in runlog if r.get("stage") == "chapter7_tabnet" and r.get("run_id") == run_id), None)
    if c.ok(S, "runlog line exists (R8)", line is not None):
        rss = line.get("peak_rss_mb", 0)
        if rss > RSS_CEILING_MB:
            c.add(S, "peak RSS within HCEA ceiling (20 GB)", "FAIL", f"{rss:.0f} MB")
        else:
            c.ok(S, "peak RSS within HCEA §7.6 target (10 GB)", rss <= RSS_TARGET_MB, f"{rss:.0f} MB", warn_only=True)
        if line.get("peak_vram_mb") is not None:
            c.ok(S, "peak VRAM within HCEA §7.6 (3 GB)", line["peak_vram_mb"] <= VRAM_TARGET_MB, f"{line['peak_vram_mb']:.0f} MB", warn_only=True)
        configs = {r["config_hash"] for r in runlog if r.get("stage") == "chapter7_tabnet" and r.get("profile") == args.profile and r.get("config_hash")}
        c.ok(S, f"hyperparameter configurations <= {HYPERPARAMETER_BUDGET} (HCEA §7.6)", len(configs) <= HYPERPARAMETER_BUDGET,
             f"{len(configs)} at {args.profile}", warn_only=True)
    for key in ("seed", "config", "model_version", "fit_wall_seconds", "process_peak_rss_mb", "profile", "device_used"):
        c.ok(S, f"metadata has {key}", key in md)

    # ------------------------------------------------------------------ optional
    frames = {s: matrix.iloc[np.flatnonzero(split_rows == s)].assign(
        user_id=lambda f: f["user_id"].astype("string").str.strip().str.casefold(), date=lambda f: f["date"].astype("string")
    ).reset_index(drop=True) for s in SPLITS}

    if args.reload_models and sc is not None and entry is not None:
        S = "reload"
        dev = md.get("device_used", "cpu")
        try:
            import torch

            dev = dev if dev == "cpu" or torch.cuda.is_available() else "cpu"
        except Exception:
            dev = "cpu"
        scorer = load_model(entry["registry_version"], registry_root=Path(entry["artifact_dir"]).parent.parent, device=dev)
        test = frames["test"]
        stored = sc[sc["split"] == "test"].merge(test[["user_id", "date"]], on=["user_id", "date"], how="right")
        diff = float(np.max(np.abs(scorer.score(test) - stored["anomaly_score"].to_numpy())))
        c.ok(S, "registered artifact reproduces stored test scores", diff < 1e-6, f"max |diff| {diff:.2e} on {len(test)} rows, {dev}")
        if dev != md.get("device_used"):
            c.add(S, "reload device", "WARN", f"trained on {md.get('device_used')}, reloaded on {dev}")

    if args.compare_run_id and sc is not None:
        S = "determinism"
        other = json.loads((results / args.compare_run_id / "metrics.json").read_text(encoding="utf-8"))
        b = pd.read_parquet(other["models"]["tabnet"]["metadata"]["scores_path"])
        j = sc.merge(b, on=["user_id", "date", "split"], suffixes=("_a", "_b"))
        diff = float((j["anomaly_score_a"] - j["anomaly_score_b"]).abs().max()) if len(j) else float("nan")
        c.ok(S, f"same scores as {args.compare_run_id}", len(j) == len(sc) and diff < 1e-6, f"max |diff| {diff:.2e}", warn_only=True)
        if other["models"]["tabnet"]["metadata"].get("resumed_from_epoch") is not None or md.get("resumed_from_epoch") is not None:
            c.add(S, "both runs trained from scratch", "WARN", "one run resumed from a checkpoint; use --fresh for a real determinism check")

    if args.permutation_test:
        _permutation(c, args, md, matrix, labels, split_rows, split_mode)

    if args.baselines:
        S = "baselines"
        refs = reference_runs_for(load_reference_runs(args.references), args.profile, split_mode)
        if not refs:
            c.add(S, "reference Chapter 6 runs exist", "WARN", f"none recorded for {args.profile}/{split_mode}; no comparison possible")
        else:
            srcs = chapter6_sources(processed, refs) + [chapter7_source(processed, run_id)]
            try:
                for part in ("validation", "test"):
                    res = compare_sources(processed, srcs if part == "validation" else srcs[:-1], part=part,
                                          budgets=tuple(report["budgets"]), seed=report["seed"], split_info=report["split"])
                    if part == "test":
                        tab = sc[sc["split"] == "test"] if sc is not None else None
                        base = pd.read_parquet(srcs[0].path, columns=["user_id", "date", "split"])
                        base = base[base["split"] == "test"]
                        same = tab is not None and len(tab) == len(base) and set(zip(tab["user_id"], tab["date"])) == set(zip(base["user_id"], base["date"]))
                        c.ok(S, "same test rows as the baselines", same)
                        for row in harness_check(res, srcs, runlog):
                            c.ok(S, f"harness reproduces logged test PR-AUC: {row['model']}", row["match"],
                                 f"logged {row['logged_test_pr_auc']}, recomputed {row['recomputed_test_pr_auc']}")
                    else:
                        c.ok(S, "same validation rows as the baselines", True, f"{res['rows']} rows")
                for row in fingerprint_check(runlog, srcs, report["features"]["fingerprint"]):
                    c.ok(S, f"same feature matrix as {row['model']}", row["match"],
                         f"{row['baseline_fingerprint']} vs {row['chapter7_fingerprint']}")
            except ComparisonError as exc:
                c.add(S, "runs are comparable", "FAIL", str(exc))

    return _finish(c, results, run_id, args)


PERMUTATION_SEEDS = (12345, 12346, 12347)
LABEL_FREE_BASELINES = ("rule_based", "isolation_forest", "lof", "lstm_autoencoder")


def _label_free_reference(args, split_mode: str) -> tuple[str, float] | None:
    """Best test PR-AUC any label-free Chapter 6 baseline reached on these rows."""
    try:
        refs = reference_runs_for(load_reference_runs(args.references), args.profile, split_mode)
    except FileNotFoundError:
        return None
    runlog = [json.loads(x) for x in Path(args.runlog).read_text(encoding="utf-8").splitlines() if x.strip()]
    best = None
    for model in LABEL_FREE_BASELINES:
        rid = refs.get(model)
        line = next((r for r in runlog if r.get("stage") == "chapter6_baseline" and r.get("run_id") == rid
                     and r.get("model") == model), None)
        if line and line.get("test_pr_auc") is not None and (best is None or line["test_pr_auc"] > best[1]):
            best = (model, float(line["test_pr_auc"]))
    return best


def _permutation(c: "Checks", args, md: dict, matrix: pd.DataFrame, labels: pd.DataFrame, split_rows, split_mode: str) -> None:
    """Label-permutation test with controls (deviation C7-8).

    A model trained on shuffled labels has learned nothing about who is an
    insider. It can still rank above chance if its output follows how
    unusual a row is, because malicious days are unusual days: the
    label-free Chapter 6 baselines do exactly that. So the test compares the
    shuffled-label model with two label-free references on the same rows:

      * an untrained TabNet (0 epochs; no label has touched its weights), and
      * the best label-free Chapter 6 baseline (rule-based, Isolation
        Forest, LOF, LSTM autoencoder) from the reference runs.

    PASS  worst shuffled PR-AUC <= max(3 x chance, chance + 0.02), the
          Chapter 6 rule;
    WARN  above that, but not above the best label-free baseline: explain it
          in the audit with the diagnostics printed here;
    FAIL  above every label-free reference: a model with no label
          information outranks methods that never see labels. Investigate.
    """
    from app.tabnet.train import TabNetDetector

    S = "leakage"
    keep = ~labels["exclude_primary"].to_numpy()
    tr = np.flatnonzero((split_rows == "train") & keep)
    te = np.flatnonzero((split_rows == "test") & keep)
    y_tr = labels["y_primary"].to_numpy()[tr]
    y_te = labels["y_primary"].to_numpy()[te]
    excluded = list(md["config"].get("excluded_features", []))
    f_tr = frames_all(matrix, tr).drop(columns=excluded)
    f_te = frames_all(matrix, te).drop(columns=excluded)
    active = matrix["is_active_day"].fillna(0).to_numpy()[te] > 0 if "is_active_day" in matrix else np.ones(len(te), bool)
    chance = float(y_te.mean())
    chance_act = float(y_te[active].mean()) if active.any() else float("nan")
    cfg = {k: v for k, v in md["config"].items() if k not in ("checkpoint_dir", "max_epochs", "pretrain")}

    def fit_score(y_fit: np.ndarray, epochs: int, seed: int) -> tuple[float, float]:
        det = TabNetDetector(seed=seed, max_epochs=epochs, pretrain=False, checkpoint_dir=None, **cfg).fit(f_tr, y_fit)
        s = det.score(f_te)
        return pr_auc(y_te, s), pr_auc(y_te[active], s[active])

    shuffled = []
    for i, seed in enumerate(PERMUTATION_SEEDS):
        y_perm = np.random.default_rng(seed).permutation(y_tr)
        ap, ap_act = fit_score(y_perm, args.permutation_epochs, i)
        shuffled.append(ap)
        c.add(S, f"shuffled labels (seed {seed})", "INFO",
              f"PR-AUC {ap:.4f}; active days only {ap_act:.4f} (chance {chance_act:.4f})")
    ap0, ap0_act = fit_score(np.random.default_rng(PERMUTATION_SEEDS[0]).permutation(y_tr), 0, 0)
    c.add(S, "untrained TabNet (0 epochs, no label information)", "INFO",
          f"PR-AUC {ap0:.4f}; active days only {ap0_act:.4f}")
    ref = _label_free_reference(args, split_mode)
    if ref:
        c.add(S, "best label-free Chapter 6 baseline on these rows", "INFO", f"{ref[0]} {ref[1]:.4f}")

    status, detail = permutation_verdict(max(shuffled), chance, ref)
    c.add(S, "TabNet on shuffled labels stays near chance", status, detail)


def permutation_verdict(worst: float, chance: float, ref: tuple[str, float] | None) -> tuple[str, str]:
    """PASS / WARN / FAIL for the worst shuffled-label PR-AUC (see _permutation)."""
    strict = max(3 * chance, chance + 0.02)
    detail = f"worst shuffled PR-AUC {worst:.4f}; chance {chance:.4f}; 3x-chance bar {strict:.4f}"
    if worst <= strict:
        return "PASS", detail
    if ref is not None and worst <= ref[1]:
        return "WARN", detail + f"; not above the label-free {ref[0]} ({ref[1]:.4f}). Explain in the audit with the lines above"
    return "FAIL", detail + ("; above every label-free reference" if ref else "; no label-free reference available")


def frames_all(matrix: pd.DataFrame, idx: np.ndarray) -> pd.DataFrame:
    f = matrix.iloc[idx].reset_index(drop=True)
    f["user_id"] = f["user_id"].astype("string").str.strip().str.casefold()
    f["date"] = f["date"].astype("string")
    return f


def _finish(c: Checks, results: Path, run_id: str, args) -> int:
    counts = c.counts()
    out = results / run_id / "verification.json"
    out.write_text(json.dumps({"run_id": run_id, "counts": counts, "checks": c.rows}, indent=2), encoding="utf-8")
    append_experiment_runlog({"stage": "chapter7_verification", "run_id": run_id, "profile": args.profile,
                              "reload_models": args.reload_models, "permutation_test": args.permutation_test,
                              "baselines": args.baselines, "compared_with": args.compare_run_id,
                              **{k.lower(): v for k, v in counts.items()}})
    print(f"\n{counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL  ->  {out}")
    if counts["FAIL"]:
        print("NOT READY: fix every FAIL, then re-run the runner and this script.")
    elif counts["WARN"]:
        print("No FAILs. Read every WARN and note in the write-up why it is acceptable.")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
