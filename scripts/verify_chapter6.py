"""Verify a Chapter 6 baseline run before it is greenlit.

Reads the outputs of ``python -m app.baselines.run`` (metrics.json, the split
file, score Parquet files, runlog lines, saved models) and checks them
against the Bible Ch6 acceptance list, HCEA §6 and CARRY_FORWARD N1-N9.
Every check prints PASS, WARN or FAIL. Exit code 1 if anything FAILs.

Usage, from backend/ (same env vars as the runner):

    python ../scripts/verify_chapter6.py --profile mid
    python ../scripts/verify_chapter6.py --profile mid --split time
    python ../scripts/verify_chapter6.py --profile mid --reload-models --permutation-test
    python ../scripts/verify_chapter6.py --profile mid --compare-run-id <earlier run id>

Defaults to the newest run for the profile/split. The result is written to
``experiments/results/chapter6/<run_id>/verification.json`` and one summary
line is appended to ``experiments/runlog.jsonl``.

This is evaluation code: it reads labels, in memory, like the runner does.
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

from app.baselines import DETECTORS  # noqa: E402
from app.evaluation.labels import attach_labels, insider_scenarios, load_label_views  # noqa: E402
from app.evaluation.metrics import pr_auc  # noqa: E402
from app.evaluation.splitting import SPLITS, _allocate, assign_user_splits, load_split, rows_for_split, time_split  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, repo_root  # noqa: E402

PUBLISHED = {"malicious_user_days": 966, "insiders": 70, "masquerade_account_days": 20}
SCORE_COLUMNS = {"user_id", "date", "split", "raw_score", "anomaly_score", "model_name", "model_version"}
LABEL_WORDS = ("malicious", "insider", "scenario", "label", "y_primary", "y_account", "is_masquerade", "target")
RSS_TARGET_MB, RSS_CEILING_MB = 12 * 1024, 20 * 1024
PROFILE_OUTPUT = {"dev": "user_day_dev.parquet", "mid": "user_day_mid.parquet", "full": "user_day_full.parquet"}


class Checks:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, section: str, name: str, status: str, detail: str = "") -> None:
        self.rows.append({"section": section, "check": name, "status": status, "detail": detail})
        print(f"  {status:<4} {section:<11} {name}" + (f"  -- {detail}" if detail else ""), flush=True)

    def ok(self, section, name, cond, detail="", warn_only=False) -> bool:
        self.add(section, name, "PASS" if cond else ("WARN" if warn_only else "FAIL"), detail)
        return bool(cond)

    def counts(self) -> dict:
        return {s: sum(r["status"] == s for r in self.rows) for s in ("PASS", "WARN", "FAIL")}


def _latest_run(results: Path, profile: str, split: str) -> str:
    runs = sorted(p.name for p in results.iterdir() if p.is_dir() and f"-{profile}-{split}-" in p.name and (p / "metrics.json").exists())
    if not runs:
        raise SystemExit(f"No Chapter 6 run found under {results} for profile={profile} split={split}")
    return runs[-1]


def _keys(frame: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({
        "user_id": frame["user_id"].astype("string").str.strip().str.casefold(),
        "date": frame["date"].astype("string"),
    })


def _split_rows(report: dict, keys: pd.DataFrame, assignment: dict | None) -> np.ndarray:
    if report["split"]["mode"] == "user":
        return rows_for_split(keys["user_id"], assignment)
    return time_split(keys["date"], validation_start=report["split"]["validation_start"], test_start=report["split"]["test_start"])


def main(argv=None) -> int:
    root = repo_root()
    p = argparse.ArgumentParser(description="Verify a Chapter 6 run")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "mid"), choices=("dev", "mid", "full"))
    p.add_argument("--split", default=None, choices=("user", "time"),
                   help="picks the newest run of this mode; ignored when --run-id is given (the run's own mode is used)")
    p.add_argument("--run-id", default=None, help="defaults to the newest run for profile/split")
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter6"))
    p.add_argument("--splits-dir", default=str(root / "experiments" / "splits"))
    p.add_argument("--runlog", default=os.getenv("CIRA_RUNLOG", str(root / "experiments" / "runlog.jsonl")))
    p.add_argument("--reload-models", action="store_true", help="load saved models and re-score a few test users")
    p.add_argument("--permutation-test", action="store_true", help="GBDT on shuffled training labels must be near chance")
    p.add_argument("--compare-run-id", default=None, help="earlier run with the same profile/split, for determinism")
    args = p.parse_args(argv)

    results = Path(args.results_dir)
    run_id = args.run_id or _latest_run(results, args.profile, args.split or "user")
    report = json.loads((results / run_id / "metrics.json").read_text(encoding="utf-8"))
    requested_split = args.split
    args.split = report["split"]["mode"]          # the run decides; a flag cannot contradict it
    c = Checks()
    print(f"\nVerifying Chapter 6 run {run_id}  (split mode from the run: {args.split})\n")

    # ------------------------------------------------------------------ A
    S = "run"
    c.ok(S, "profile matches", report["profile"] == args.profile, report["profile"])
    if requested_split and requested_split != args.split:
        c.add(S, "split mode", "WARN", f"--split {requested_split} given, but this run is {args.split}; verified as {args.split}")
    c.ok(S, "reportable flag follows N6", report["reportable"] == (args.profile != "dev"), f"reportable={report['reportable']}")
    if args.profile == "dev":
        c.add(S, "dev numbers are for debugging only", "WARN", "never report them (HCEA R10)")
    c.ok(S, "no accuracy anywhere (N2)", "accuracy" not in json.dumps(report).lower())

    # ------------------------------------------------------------------ B
    S = "features"
    processed = Path(args.processed_dir)
    fpath = processed / "features" / PROFILE_OUTPUT[args.profile]
    matrix = pd.read_parquet(fpath)
    keys = _keys(matrix)
    c.ok(S, "feature file is the one the run used", str(fpath) == report["features"]["path"] or fpath.name == Path(report["features"]["path"]).name, str(fpath))
    c.ok(S, "row count unchanged since the run", len(matrix) == report["features"]["rows"], f"{len(matrix)} rows")
    leaky = [col for col in matrix.columns if any(w in col.lower() for w in LABEL_WORDS)]
    c.ok(S, "no label-like feature columns (N5)", not leaky, ", ".join(leaky))
    c.ok(S, "(user_id, date) unique", not keys.duplicated().any())

    # ------------------------------------------------------------------ C
    S = "labels"
    views = load_label_views(processed)
    cov = report["label_coverage"]
    for view in ("primary", "account"):
        c.ok(S, f"{view}: every label day inside the window has a feature row", cov[view]["unmatched"] == 0, f"unmatched={cov[view]['unmatched']}")
        if args.profile != "dev":
            c.ok(S, f"{view}: no label day outside the window (mid/full)", cov[view].get("outside_feature_window", 0) == 0,
                 f"outside={cov[view].get('outside_feature_window')}")
    total_days, total_ins = len(views.primary), views.primary["user_id"].nunique()
    c.ok(S, "label table matches published r4.2 counts", (total_days, total_ins) == (PUBLISHED["malicious_user_days"], PUBLISHED["insiders"]),
         f"{total_days} malicious user-days, {total_ins} insiders (published 966 / 70)", warn_only=True)
    if args.profile in ("mid", "full"):
        c.ok(S, "all insiders are in the profile", cov["primary"]["insiders_in_profile"] == total_ins,
             f"{cov['primary']['insiders_in_profile']}/{total_ins}")
        c.ok(S, "all malicious user-days matched", cov["primary"]["matched_to_feature_rows"] == total_days,
             f"{cov['primary']['matched_to_feature_rows']}/{total_days}")
    labels = attach_labels(keys, views)
    users = set(keys["user_id"])
    scen = insider_scenarios(views, users)

    # ------------------------------------------------------------------ D
    S = "split"
    assignment = None
    split_rows = None
    if args.split == "user":
        spath = Path(report["split"]["file"])
        if not spath.exists():
            spath = Path(args.splits_dir) / spath.name
        c.ok(S, "split file exists", spath.exists(), str(spath))
        assignment, meta = load_split(spath)
        c.ok(S, "split values are split names only (no labels in file)", set(assignment.values()) <= set(SPLITS))
        c.ok(S, "every matrix user is assigned", users <= set(assignment), f"{len(users)} users")
        again = assign_user_splits(users, scen, seed=meta["seed"], fractions=tuple(meta["fractions"].values()))
        c.ok(S, "assignment reproduces from seed (determinism)", again == {u: assignment[u] for u in again})
        fr = tuple(meta["fractions"].values())
        for s in sorted(set(scen.values())):
            members = [u for u, v in scen.items() if v == s]
            want = dict(zip(SPLITS, _allocate(len(members), fr)))
            got = {sp: sum(assignment[u] == sp for u in members) for sp in SPLITS}
            c.ok(S, f"scenario {s} insiders stratified", got == want, f"{got['train']}/{got['validation']}/{got['test']}")
        other = "full" if args.profile == "mid" else "mid" if args.profile == "full" else None
        if other:
            opath = spath.with_name(spath.name.replace(f"_{args.profile}_", f"_{other}_"))
            if opath.exists():
                oa, _ = load_split(opath)
                shared = set(oa) & set(assignment)
                moved = [u for u in shared if oa[u] != assignment[u]]
                c.ok(S, f"same split as {other} for shared users", not moved, f"{len(shared)} shared, {len(moved)} moved")
            else:
                c.add(S, f"cross-profile check vs {other}", "WARN", f"{opath.name} not found yet; re-run this after the {other} run")
    split_rows = _split_rows(report, keys, assignment)
    per = {s: int((split_rows == s).sum()) for s in SPLITS}
    c.ok(S, "row counts per split match the run", per == report["split"]["rows"], str(per))
    if args.split == "user":
        leaked = pd.DataFrame({"u": keys["user_id"], "s": split_rows}).groupby("u")["s"].nunique().gt(1).sum()
        c.ok(S, "no user in two splits (N3)", leaked == 0)
    for s in ("validation", "test"):
        c.ok(S, f"{s} has positives", report["split"]["positives_primary"][s] > 0, str(report["split"]["positives_primary"][s]))

    # ------------------------------------------------------------------ E
    S = "masquerade"
    acct = views.account[views.account["is_masquerade"] == 1]
    lo = keys.groupby("user_id")["date"].min()
    hi = keys.groupby("user_id")["date"].max()
    in_frame = acct[acct["user_id"].isin(users)]
    in_frame = in_frame[(in_frame["date"] >= in_frame["user_id"].map(lo)) & (in_frame["date"] <= in_frame["user_id"].map(hi))]
    excluded = sum(report["split"]["masquerade_rows_excluded"].values())
    c.ok(S, "excluded rows = masquerade account-days in this matrix (N1)", excluded == len(in_frame),
         f"{excluded} excluded; supervisors present: {sorted(set(in_frame['user_id']))}")
    c.ok(S, "exclusion flags agree with a fresh label join", int(labels["exclude_primary"].sum()) == excluded)

    # ------------------------------------------------------------------ F
    runlog = [json.loads(x) for x in Path(args.runlog).read_text(encoding="utf-8").splitlines() if x.strip()]
    mine = {r["model"]: r for r in runlog if r.get("stage") == "chapter6_baseline" and r.get("run_id") == run_id}
    models = report["models"]
    S = "models"
    c.ok(S, "all five detectors ran", set(models) == set(DETECTORS), ", ".join(sorted(models)), warn_only=set(models) < set(DETECTORS))
    for name, block in models.items():
        md = block["metadata"]
        S = name
        for s in ("validation", "test"):
            pm = block[s]["primary"]
            c.ok(S, f"{s} PR-AUC computed", pm["pr_auc"] is not None, f"{pm['pr_auc']}")
            c.ok(S, f"{s} budgets present", set(pm["budgets"]) == {str(k) for k in report["budgets"]})
        t = block["test"]["primary"]
        c.ok(S, "account view reported once (N1)", "secondary_account_view" in block["test"])
        if t["pr_auc"] is not None and t["positive_rate"]:
            c.ok(S, "test PR-AUC above chance", t["pr_auc"] > t["positive_rate"], f"{t['pr_auc']:.4f} vs chance {t['positive_rate']:.4f}", warn_only=True)
            if name != "gbdt":
                c.ok(S, "unsupervised PR-AUC not suspiciously high", t["pr_auc"] < 0.9, f"{t['pr_auc']:.4f}; if >= 0.9 look for leakage", warn_only=True)
            else:
                c.ok(S, "supervised PR-AUC not suspiciously perfect", t["pr_auc"] < 0.99, f"{t['pr_auc']:.4f}; if ~1.0 look for leakage", warn_only=True)

        sp = Path(md["scores_path"])
        if not sp.exists():
            sp = processed / "scores" / "chapter6" / run_id / f"{name}.parquet"
        if c.ok(S, "score file exists", sp.exists(), str(sp)):
            sc = pd.read_parquet(sp)
            c.ok(S, "score columns exact, no labels (N5)", set(sc.columns) == SCORE_COLUMNS, str(sorted(set(sc.columns) - SCORE_COLUMNS)))
            c.ok(S, "anomaly_score finite and in [0, 1]", np.isfinite(sc["anomaly_score"]).all() and sc["anomaly_score"].between(0, 1).all())
            c.ok(S, "raw_score finite", np.isfinite(sc["raw_score"]).all())
            c.ok(S, "one model_version, matches metadata", sc["model_version"].nunique() == 1 and sc["model_version"].iloc[0] == md["model_version"])
            c.ok(S, "rows = validation + test", len(sc) == per["validation"] + per["test"], f"{len(sc)}")
            c.ok(S, "no duplicate (user, date, split)", not sc.duplicated(["user_id", "date", "split"]).any())

        r = mine.get(name)
        if c.ok(S, "runlog line exists (R8)", r is not None):
            rss = r.get("peak_rss_mb", 0)
            if rss > RSS_CEILING_MB:
                c.add(S, "peak RSS within HCEA ceiling (20 GB)", "FAIL", f"{rss:.0f} MB")
            else:
                c.ok(S, "peak RSS within HCEA target (12 GB)", rss <= RSS_TARGET_MB, f"{rss:.0f} MB", warn_only=True)
            c.ok(S, "runlog reportable flag", r.get("reportable") == (args.profile != "dev"))
        for key in ("seed", "config", "model_version", "fit_wall_seconds", "process_peak_rss_mb", "profile"):
            c.ok(S, f"metadata has {key} (HCEA §6.3)", key in md)

        if name == "lof":
            c.ok(S, "LOF fit rows <= 50,000 (D-2)", md.get("lof_fit_rows", 10**9) <= 50_000, str(md.get("lof_fit_rows")))
            c.ok(S, "PCA dims and retained variance recorded", "pca_components" in md and "pca_retained_variance" in md,
                 f"{md.get('pca_components')} comps, {md.get('pca_retained_variance', 0):.3f} variance")
        if name == "lstm_autoencoder":
            c.ok(S, "LSTM trained at least one epoch", md.get("epochs_run", 0) >= 1, f"epochs={md.get('epochs_run')} device={md.get('device_used')}")
            c.ok(S, "no date gaps in training sequences", md.get("train_date_gaps", 1) == 0, str(md.get("train_date_gaps")), warn_only=True)
            if "resumed_from_epoch" in md:
                c.add(S, "resumed from checkpoint (R7)", "PASS", f"after epoch {md['resumed_from_epoch'] + 1}")
        if name == "gbdt":
            pos, neg = md.get("train_positives", 0), md.get("train_negatives", 0)
            c.ok(S, "train positives = split train positives", pos == report["split"]["positives_primary"]["train"], f"{pos}")
            c.ok(S, "masquerade rows removed from GBDT training (N13)",
                 pos + neg == report["split"]["rows"]["train"] - report["split"]["masquerade_rows_excluded"]["train"], f"{pos + neg} rows")
            c.ok(S, "scale_pos_weight = neg/pos from train (N2)", pos > 0 and abs(md.get("scale_pos_weight", 0) - neg / pos) < 1e-6,
                 f"{md.get('scale_pos_weight')}")
            c.ok(S, "early stopping on validation", str(md.get("early_stopping", "")).startswith("validation"), md.get("early_stopping", ""), warn_only=True)

    # ------------------------------------------------------------------ G  optional
    frames = {s: matrix.iloc[np.flatnonzero(split_rows == s)].assign(
        user_id=lambda f: f["user_id"].astype("string").str.strip().str.casefold(), date=lambda f: f["date"].astype("string")
    ).reset_index(drop=True) for s in SPLITS}

    if args.reload_models:
        S = "reload"
        for name, block in models.items():
            mdir = block["metadata"].get("model_dir")
            if not mdir or not Path(mdir).exists():
                c.add(S, f"{name}: saved model", "WARN", "no model_dir (run used --no-save-models?)")
                continue
            model = _detector_class(name).load(mdir)
            test = frames["test"]
            kwargs = {}
            if name == "lstm_autoencoder" and args.split == "time":
                kwargs["history"] = pd.concat([frames["train"], frames["validation"]], ignore_index=True)
            stored = pd.read_parquet(block["metadata"]["scores_path"])
            stored = stored[stored["split"] == "test"].merge(test[["user_id", "date"]], on=["user_id", "date"], how="right")
            # Same rows, same batch as the runner: persistence must be exact.
            fresh = model.score(test, **kwargs)
            diff = float(np.max(np.abs(fresh - stored["anomaly_score"].to_numpy())))
            c.ok(S, f"{name}: reloaded model reproduces stored test scores", diff < 1e-6, f"max |diff| {diff:.2e} on {len(test)} rows")
            # Informational: does a smaller batch give the same numbers? kNN
            # and BLAS results can shift in the last bits with batch size on
            # some machines; that is numerics, not a persistence fault.
            pick = np.flatnonzero(test["user_id"].isin(sorted(test["user_id"].unique())[:5]).to_numpy())
            sub_kwargs = kwargs if name != "lstm_autoencoder" else {"history": pd.concat([kwargs.get("history", test.iloc[:0]), test], ignore_index=True)}
            part = model.score(test.iloc[pick].reset_index(drop=True), **sub_kwargs)
            bdiff = float(np.max(np.abs(part - fresh[pick]))) if len(pick) else 0.0
            c.ok(S, f"{name}: batch-size invariance (5-user subset)", bdiff < 1e-6, f"max |diff| {bdiff:.2e} on {len(pick)} rows", warn_only=True)

    if args.compare_run_id:
        S = "determinism"
        other = json.loads((results / args.compare_run_id / "metrics.json").read_text(encoding="utf-8"))
        for name in sorted(set(models) & set(other["models"])):
            a = pd.read_parquet(models[name]["metadata"]["scores_path"])
            b = pd.read_parquet(other["models"][name]["metadata"]["scores_path"])
            j = a.merge(b, on=["user_id", "date", "split"], suffixes=("_a", "_b"))
            diff = float((j["anomaly_score_a"] - j["anomaly_score_b"]).abs().max()) if len(j) else float("nan")
            strict = name in ("rule_based", "isolation_forest", "lof")
            c.ok(S, f"{name}: same scores as {args.compare_run_id}", len(j) == len(a) and diff < 1e-9,
                 f"max |diff| {diff:.2e}", warn_only=not strict)

    if args.permutation_test:
        S = "leakage"
        from app.baselines.gbdt import GBDTDetector

        lab = attach_labels(_keys(matrix), views)
        tr = np.flatnonzero((split_rows == "train") & ~lab["exclude_primary"].to_numpy())
        te = np.flatnonzero((split_rows == "test") & ~lab["exclude_primary"].to_numpy())
        y_tr = np.random.default_rng(12345).permutation(lab["y_primary"].to_numpy()[tr])
        y_te = lab["y_primary"].to_numpy()[te]
        det = GBDTDetector(seed=0, n_estimators=300).fit(matrix.iloc[tr].reset_index(drop=True), y_tr)
        ap = pr_auc(y_te, det.score(matrix.iloc[te].reset_index(drop=True)))
        chance = float(y_te.mean())
        c.ok(S, "GBDT on shuffled labels stays near chance", ap is not None and ap <= max(3 * chance, chance + 0.02),
             f"PR-AUC {ap:.4f} vs chance {chance:.4f}; well above chance means labels leak through features or the split")

    counts = c.counts()
    out = results / run_id / "verification.json"
    out.write_text(json.dumps({"run_id": run_id, "counts": counts, "checks": c.rows}, indent=2), encoding="utf-8")
    append_experiment_runlog({"stage": "chapter6_verification", "run_id": run_id, "profile": args.profile, "split_mode": args.split,
                              "reload_models": args.reload_models, "permutation_test": args.permutation_test,
                              "compared_with": args.compare_run_id, **{k.lower(): v for k, v in counts.items()}})
    print(f"\n{counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL  ->  {out}")
    if counts["FAIL"]:
        print("NOT READY: fix every FAIL, then re-run the runner and this script.")
    elif counts["WARN"]:
        print("No FAILs. Read every WARN and note in the write-up why it is acceptable.")
    return 1 if counts["FAIL"] else 0


def _detector_class(name: str):
    from app.baselines.gbdt import GBDTDetector
    from app.baselines.isolation_forest import IsolationForestDetector
    from app.baselines.lof import LOFDetector
    from app.baselines.lstm_autoencoder import LSTMAutoencoderDetector
    from app.baselines.rule_based import RuleBasedDetector

    return {"rule_based": RuleBasedDetector, "isolation_forest": IsolationForestDetector, "lof": LOFDetector,
            "lstm_autoencoder": LSTMAutoencoderDetector, "gbdt": GBDTDetector}[name]


if __name__ == "__main__":
    raise SystemExit(main())
