"""Chapter 6 runner: fit every baseline on one split and evaluate it.

Usage (from backend/, with .env loaded):

    python -m app.baselines.run --profile mid
    python -m app.baselines.run --profile mid --split time
    python -m app.baselines.run --profile full --models isolation_forest,lof

What it does, in order:

1. Thread caps before numpy/torch are imported (N8, HCEA R6).
2. Load ``features/user_day_<profile>.parquet`` and its schema.
3. Load the label views and join them to the feature keys in memory (N5).
   Labels are kept in a separate frame; unsupervised detectors never get it.
4. Load or create the user split under ``experiments/splits/`` (N3) and
   check that every positive label row has a feature row.
5. For each detector: fit on train, score validation and test, compute the
   N1/N2 metric block, save the model and metadata, write scores to Parquet
   under ``<processed>/scores/chapter6/<run_id>/`` (no labels in that file),
   and append one line per detector to ``experiments/runlog.jsonl`` (R8).
6. Write ``experiments/results/chapter6/<run_id>/metrics.json``.

dev-profile runs are marked ``reportable: false`` (N6, HCEA R10).
"""
from __future__ import annotations

from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.evaluation.labels import (  # noqa: E402
    attach_labels,
    insider_scenarios,
    label_coverage,
    load_label_views,
)
from app.evaluation.metrics import (  # noqa: E402
    DEFAULT_BUDGETS,
    evaluate_scores,
    headline,
)
from app.evaluation.splitting import (  # noqa: E402
    DEFAULT_FRACTIONS,
    SPLITS,
    assert_user_disjoint,
    load_or_create_split,
    rows_for_split,
    split_summary,
    time_split,
)
from app.feature_engineering.common import (  # noqa: E402
    append_experiment_runlog,
    atomic_to_parquet,
    memory_rss_mb,
    repo_root,
)

from . import DETECTORS  # noqa: E402
from .base import CHAPTER6_VERSION, BaselineDetector  # noqa: E402
from .preprocess import load_schema, nullable_columns_from_schema  # noqa: E402

PROFILE_OUTPUT = {"dev": "user_day_dev.parquet", "mid": "user_day_mid.parquet", "full": "user_day_full.parquet"}


def build_detector(name: str, *, seed: int, nullable: list[str], args: argparse.Namespace, data_fingerprint: str = "") -> BaselineDetector:
    if name == "rule_based":
        from .rule_based import RuleBasedDetector

        return RuleBasedDetector(seed=seed)
    if name == "isolation_forest":
        from .isolation_forest import IsolationForestDetector

        return IsolationForestDetector(seed=seed, nullable_columns=nullable)
    if name == "lof":
        from .lof import LOFDetector

        return LOFDetector(seed=seed, nullable_columns=nullable, max_fit_rows=args.lof_max_fit_rows, n_components=args.lof_components)
    if name == "lstm_autoencoder":
        from .lstm_autoencoder import LSTMAutoencoderDetector

        return LSTMAutoencoderDetector(
            seed=seed, max_epochs=args.lstm_max_epochs, device=args.device, data_fingerprint=data_fingerprint,
            checkpoint_dir=str(Path(args.checkpoint_dir) / "chapter6" / args.profile / args.split),
        )
    if name == "gbdt":
        from .gbdt import GBDTDetector

        return GBDTDetector(seed=seed, device=args.device)
    raise ValueError(f"unknown detector {name!r}; choose from {DETECTORS}")


def _feature_fingerprint(path: Path) -> str:
    st = path.stat()
    return hashlib.sha256(f"{path.name}|{st.st_size}|{int(st.st_mtime)}".encode()).hexdigest()[:12]


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    root = repo_root()
    p = argparse.ArgumentParser(description="CIRA Chapter 6 baselines")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "dev"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--split", default="user", choices=("user", "time"))
    p.add_argument("--models", default=",".join(DETECTORS), help=f"comma list from {DETECTORS}")
    p.add_argument("--seed", type=int, default=int(os.getenv("CIRA_SEED", "42")))
    p.add_argument("--budgets", default=",".join(str(k) for k in DEFAULT_BUDGETS), help="daily top-k alert budgets")
    p.add_argument("--fractions", default=",".join(str(f) for f in DEFAULT_FRACTIONS), help="train,validation,test user fractions")
    p.add_argument("--rebuild-split", action="store_true", help="overwrite a saved split that no longer matches")
    p.add_argument("--time-validation-start", default="2011-01-01")
    p.add_argument("--time-test-start", default="2011-02-01")
    p.add_argument("--lstm-max-epochs", type=int, default=20)
    p.add_argument("--lof-max-fit-rows", type=int, default=50_000)
    p.add_argument("--lof-components", type=int, default=20)
    p.add_argument("--device", default=os.getenv("CIRA_DEVICE", "auto"), choices=("auto", "cpu", "cuda"))
    p.add_argument("--splits-dir", default=str(root / "experiments" / "splits"))
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter6"))
    p.add_argument("--models-dir", default=os.getenv("MODEL_PATH", str(root / "models" / "saved_models")))
    p.add_argument("--checkpoint-dir", default=str(root / "models" / "checkpoints"))
    p.add_argument("--no-save-models", action="store_true")
    return p.parse_args(argv)


def run(args: argparse.Namespace) -> dict:
    started = time.perf_counter()
    processed = Path(args.processed_dir)
    features_path = processed / "features" / PROFILE_OUTPUT[args.profile]
    schema_path = processed / "features" / f"feature_schema_{args.profile}.json"
    if not schema_path.exists():
        schema_path = processed / "features" / "feature_schema.json"
    if not features_path.exists():
        raise FileNotFoundError(f"{features_path} not found; run the Chapter 5 pipeline for profile={args.profile}")
    schema = load_schema(schema_path)
    if schema.get("profile") not in (None, args.profile):
        raise RuntimeError(f"{schema_path} describes profile {schema.get('profile')!r}, not {args.profile!r}")
    nullable = nullable_columns_from_schema(schema)
    budgets = tuple(int(k) for k in args.budgets.split(",") if k.strip())
    fractions = tuple(float(f) for f in args.fractions.split(","))
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    for m in models:
        if m not in DETECTORS:
            raise ValueError(f"unknown detector {m!r}; choose from {DETECTORS}")

    matrix = pd.read_parquet(features_path)
    matrix["user_id"] = matrix["user_id"].astype("string").str.strip().str.casefold()
    matrix["date"] = matrix["date"].astype("string")
    matrix = matrix.sort_values(["user_id", "date"], kind="mergesort").reset_index(drop=True)
    keys = matrix[["user_id", "date"]]

    # --- labels: evaluation-only, in memory -----------------------------
    views = load_label_views(processed)
    labels = attach_labels(keys, views)
    coverage = label_coverage(keys, views)
    for view in ("primary", "account"):
        if coverage[view]["unmatched"]:
            raise RuntimeError(f"{view} label days inside the feature window have no feature row: {coverage[view]}")
        if args.profile != "dev" and coverage[view]["outside_feature_window"]:
            # mid/full keep each user's whole active span, so this cannot
            # happen unless Chapter 5 dropped days. Stop rather than guess.
            raise RuntimeError(f"{view} label days outside the feature window under profile={args.profile}: {coverage[view]}")
    users = set(keys["user_id"].unique().tolist())
    scen = insider_scenarios(views, users)

    # --- split -----------------------------------------------------------
    split_info: dict = {"mode": args.split}
    if args.split == "user":
        split_path = Path(args.splits_dir) / f"user_split_{args.profile}_seed{args.seed}.json"
        assignment, meta, created = load_or_create_split(
            split_path, users, scen, seed=args.seed, fractions=fractions, profile=args.profile, rebuild=args.rebuild_split
        )
        split = rows_for_split(keys["user_id"], assignment)
        assert_user_disjoint(keys["user_id"], split)
        split_info.update({"file": str(split_path), "created_now": created, "counts": split_summary(assignment, scen)})
    else:
        split = time_split(keys["date"], validation_start=args.time_validation_start, test_start=args.time_test_start)
        split_info.update({"validation_start": args.time_validation_start, "test_start": args.time_test_start})
    part = {s: np.flatnonzero(split == s) for s in SPLITS}
    split_info["rows"] = {s: int(len(ix)) for s, ix in part.items()}
    split_info["positives_primary"] = {s: int(labels["y_primary"].to_numpy()[ix].sum()) for s, ix in part.items()}
    split_info["masquerade_rows_excluded"] = {s: int(labels["exclude_primary"].to_numpy()[ix].sum()) for s, ix in part.items()}
    for s in SPLITS:
        if len(part[s]) == 0:
            raise RuntimeError(f"split {s!r} is empty under mode={args.split}")

    reportable = args.profile != "dev"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{args.profile}-{args.split}-s{args.seed}"
    feature_fp = _feature_fingerprint(features_path)
    score_dir = processed / "scores" / "chapter6" / run_id
    results_dir = Path(args.results_dir) / run_id
    results_dir.mkdir(parents=True, exist_ok=True)

    # Identifies the exact training data, so a resumed checkpoint can never
    # belong to an older feature matrix or a different split.
    data_fp = hashlib.sha256(
        json.dumps({"features": feature_fp, "split": split_info.get("file") or [args.time_validation_start, args.time_test_start],
                    "rows": split_info["rows"]}, sort_keys=True, default=str).encode()
    ).hexdigest()[:12]
    split_info["data_fingerprint"] = data_fp
    frames = {s: matrix.iloc[ix].reset_index(drop=True) for s, ix in part.items()}
    label_parts = {s: labels.iloc[ix].reset_index(drop=True) for s, ix in part.items()}

    report = {
        "chapter": 6,
        "version": CHAPTER6_VERSION,
        "run_id": run_id,
        "profile": args.profile,
        "reportable": reportable,
        "reportable_note": None if reportable else "dev profile: debugging only, never report these numbers (N6, HCEA R10)",
        "seed": args.seed,
        "budgets": list(budgets),
        "features": {"path": str(features_path), "fingerprint": feature_fp, "schema": str(schema_path),
                     "pipeline_version": schema.get("pipeline_version"), "n_features": int(matrix.shape[1] - 2), "rows": int(len(matrix))},
        "label_coverage": coverage,
        "split": split_info,
        "models": {},
    }

    for name in models:
        detector = build_detector(name, seed=args.seed, nullable=nullable, args=args, data_fingerprint=data_fp)
        t0 = time.perf_counter()
        if detector.supervised:
            keep_tr = ~label_parts["train"]["exclude_primary"].to_numpy()
            keep_va = ~label_parts["validation"]["exclude_primary"].to_numpy()
            detector.fit(
                frames["train"][keep_tr].reset_index(drop=True), label_parts["train"]["y_primary"].to_numpy()[keep_tr],
                validation=frames["validation"][keep_va].reset_index(drop=True),
                y_validation=label_parts["validation"]["y_primary"].to_numpy()[keep_va],
            )
        elif name == "lstm_autoencoder":
            detector.fit(frames["train"], validation=frames["validation"])
        else:
            detector.fit(frames["train"])
        fit_seconds = time.perf_counter() - t0

        block: dict = {"metadata": None}
        score_rows = []
        t1 = time.perf_counter()
        for s in ("validation", "test"):
            kwargs = {}
            if name == "lstm_autoencoder" and args.split == "time":
                # Causal history: the earlier date ranges only. Windows look
                # back from the scored day, so later rows would never be used
                # anyway, but passing them would invite that mistake later.
                kwargs["history"] = matrix.iloc[np.flatnonzero(np.isin(split, SPLITS[: SPLITS.index(s)]))]
            raw, calibrated = detector.scores(frames[s], **kwargs)
            block[s] = evaluate_scores(frames[s][["user_id", "date"]], calibrated, label_parts[s], budgets=budgets, seed=args.seed)
            score_rows.append(
                pd.DataFrame({
                    "user_id": frames[s]["user_id"].to_numpy(), "date": frames[s]["date"].to_numpy(), "split": s,
                    "raw_score": raw, "anomaly_score": calibrated, "model_name": name, "model_version": detector.model_version,
                })
            )
        score_seconds = time.perf_counter() - t1

        scores_path = score_dir / f"{name}.parquet"
        atomic_to_parquet(pd.concat(score_rows, ignore_index=True), scores_path)
        meta = detector.metadata()
        provenance = {"profile": args.profile, "split_mode": args.split, "run_id": run_id, "feature_fingerprint": feature_fp,
                      "wall_clock_fit_seconds": round(fit_seconds, 2), "wall_clock_score_seconds": round(score_seconds, 2)}
        if not args.no_save_models:
            model_dir = detector.save(Path(args.models_dir) / "baselines" / run_id / name, extra=provenance)
            provenance["model_dir"] = str(model_dir)
        block["metadata"] = {**meta, **provenance, "scores_path": str(scores_path)}
        report["models"][name] = block

        head = headline(block["test"], budgets)
        append_experiment_runlog({
            "stage": "chapter6_baseline", "run_id": run_id, "model": name, "model_version": detector.model_version,
            "profile": args.profile, "reportable": reportable, "split_mode": args.split, "seed": args.seed,
            "rows_train": int(len(frames["train"])), "rows_test": int(len(frames["test"])),
            "wall_seconds_fit": round(fit_seconds, 2), "wall_seconds_score": round(score_seconds, 2),
            "peak_rss_mb": round(memory_rss_mb(), 1), "feature_fingerprint": feature_fp,
            **{f"test_{k}": v for k, v in head.items()},
        })
        print(f"[{name}] fit {fit_seconds:.1f}s score {score_seconds:.1f}s  test: {json.dumps(head)}", flush=True)

    report["wall_seconds"] = round(time.perf_counter() - started, 2)
    report["peak_rss_mb"] = round(memory_rss_mb(), 1)
    tmp = results_dir / "metrics.json.tmp"
    tmp.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    tmp.replace(results_dir / "metrics.json")
    report["results_path"] = str(results_dir / "metrics.json")
    _print_table(report, budgets)
    return report


def _fmt(v) -> str:
    return "n/a" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))


def _print_table(report: dict, budgets) -> None:
    k = budgets[len(budgets) // 2]
    print()
    if not report["reportable"]:
        print("!! dev profile: debugging numbers only, do not report (N6) !!")
    print(f"run {report['run_id']}  split={report['split']['mode']}  test positives={report['split']['positives_primary']['test']}")
    print(f"{'model':<18}{'PR-AUC':>8}{'ROC-AUC*':>10}{f'R@{k}':>8}{f'P@{k}':>8}{f'caught@{k}':>11}   recall@{k} by scenario")
    for name, block in report["models"].items():
        p = block["test"]["primary"]
        b = p["budgets"][str(k)]
        by_s = ", ".join(f"s{s}:{v['alerted']}/{v['positives']}" for s, v in b["recall_by_scenario"].items())
        print(f"{name:<18}{_fmt(p['pr_auc']):>8}{_fmt(p['roc_auc_secondary']):>10}{_fmt(b['recall']):>8}{_fmt(b['precision']):>8}"
              f"{b['per_user']['caught']:>6}/{b['per_user']['insiders']:<4}   {by_s}")
    print("* ROC-AUC is secondary (N2). Full metrics:", report.get("results_path", "(see results dir)"))


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    try:
        run(args)
    except Exception as exc:
        print(f"chapter6 run failed: {exc}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
