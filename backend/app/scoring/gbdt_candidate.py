"""Train and register the behaviour-only XGBoost serving candidate.

Chapter 8, deviation C8-2. Offline module: it joins labels in memory, like
``app.tabnet.train``. The serving modules never import it.

Why this exists
    Chapter 7 left the serving choice to Chapter 8 (N26) with XGBoost ahead
    of TabNet on every split. But the two reported models do not see the
    same inputs: the adopted TabNet is behaviour-only (N25), the Chapter 6
    XGBoost also sees the five psychometric scores and department size. And
    the Chapter 6 XGBoost is not in a registry, so it cannot be served under
    N21. This runner produces the XGBoost that can be compared with TabNet
    fairly and served if it wins:

    * same learner, defaults and imbalance correction as Chapter 6
      (``scale_pos_weight`` = negatives / positives on the training rows,
      early stopping on validation aucpr, native nulls);
    * the same excluded columns as the adopted TabNet
      (``--exclude-features psych_,peer_department_size``);
    * the saved Chapter 6 split (N11), masquerade days dropped from training
      and early-stopping rows (N13), scored on every validation and test row;
    * registered under ``<MODEL_PATH>/gbdt/`` with sha256 per file (N21).

    It does not replace the Chapter 6 reference run (N18). That run stays
    the baseline row in every comparison.

Usage, from backend/:

    python -m app.scoring.gbdt_candidate --profile mid
    python -m app.scoring.gbdt_candidate --profile mid --split time
    python -m app.scoring.gbdt_candidate --profile full

The console shows validation only (C7-9 practice). Test metrics go to
metrics.json, the registry entry and the runlog, and are read once through
``python -m app.scoring.select --report-test`` after the decision.

Outputs
    <processed>/scores/chapter8/<run_id>/gbdt.parquet   no labels (N5)
    experiments/results/chapter8/<run_id>/metrics.json
    <MODEL_PATH>/gbdt/vNNNN/                            registry artifact
    experiments/runlog.jsonl                            one chapter8_gbdt_candidate line
"""
from __future__ import annotations

from app.core.run_stamp import utc_run_stamp  # noqa: E402
from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import time  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import pandas as pd  # noqa: E402

from app.evaluation.labels import attach_labels, insider_scenarios, label_coverage, load_label_views  # noqa: E402
from app.evaluation.metrics import DEFAULT_BUDGETS, evaluate_scores, headline  # noqa: E402
from app.evaluation.splitting import DEFAULT_FRACTIONS, SPLITS  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, atomic_to_parquet, memory_rss_mb, repo_root  # noqa: E402
from app.tabnet.dataset import (  # noqa: E402
    data_fingerprint,
    feature_fingerprint,
    load_feature_matrix,
    make_split,
    supervised_rows,
)
from app.tabnet.model_registry import ModelRegistry  # noqa: E402

from . import SERVING_VERSION  # noqa: E402
from .contracts import STATIC_TRAIT_PREFIXES, static_inputs  # noqa: E402
from .gbdt_model import BehaviourGBDTDetector  # noqa: E402

MODEL_NAME = "gbdt"
SCORE_COLUMNS = ("user_id", "date", "split", "raw_score", "anomaly_score", "model_name", "model_version")
DEFAULT_EXCLUDE = ",".join(STATIC_TRAIT_PREFIXES)


def excluded_columns(matrix: pd.DataFrame, prefixes: str) -> list[str]:
    """Same rule as ``app.tabnet.train.excluded_columns`` (a unit test checks it)."""
    wanted = [p.strip() for p in (prefixes or "").split(",") if p.strip()]
    cols = [c for c in matrix.columns if c not in ("user_id", "date")]
    out = []
    for p in wanted:
        hit = [c for c in cols if c.startswith(p)]
        if not hit:
            raise SystemExit(f"--exclude-features: no feature column starts with {p!r}")
        out.extend(hit)
    return sorted(set(out))


def _scenario_summary(block: dict, budgets) -> dict:
    out = {}
    for k in budgets:
        b = block["primary"]["budgets"][str(k)]
        out[f"recall_by_scenario_at_{k}"] = {s: f"{v['alerted']}/{v['positives']}" for s, v in b["recall_by_scenario"].items()}
        out[f"caught_by_scenario_at_{k}"] = {s: f"{v['caught']}/{v['insiders']}" for s, v in b["per_user"]["by_scenario"].items()}
    return out


def split_seed(args) -> int:
    """The seed of the saved split to load: ``--split-seed`` if given, else ``--seed`` (unchanged behaviour)."""
    value = getattr(args, "split_seed", None)
    return int(args.seed if value is None else value)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    root = repo_root()
    p = argparse.ArgumentParser(description="CIRA Chapter 8: behaviour-only XGBoost serving candidate")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "dev"), choices=("dev", "mid", "full"))
    p.add_argument("--split", default="user", choices=("user", "time"))
    p.add_argument("--seed", type=int, default=int(os.getenv("CIRA_SEED", "42")))
    p.add_argument("--split-seed", type=int, default=None,
                   help="seed of the saved user split to load (default: --seed). Chapter 16 trains other model "
                        "seeds on the SAME split file by passing the split's seed here (N11, N78)")
    p.add_argument("--exclude-features", default=DEFAULT_EXCLUDE,
                   help="comma-separated column prefixes kept out of the model input (default: the static traits, N25)")
    p.add_argument("--budgets", default=",".join(str(k) for k in DEFAULT_BUDGETS))
    p.add_argument("--fractions", default=",".join(str(f) for f in DEFAULT_FRACTIONS))
    p.add_argument("--time-validation-start", default="2011-01-01")
    p.add_argument("--time-test-start", default="2011-02-01")
    # CPU by default: the model is served on CPU (HCEA §8), so the scores the serving
    # decision is made on are the scores that get served. XGBoost's full fit took
    # 47 s on CPU in Chapter 6; the GPU is optional everywhere but the LSTM (R11).
    p.add_argument("--device", default="cpu", choices=("auto", "cpu", "cuda"))
    p.add_argument("--tag", default=None)
    p.add_argument("--no-register", action="store_true")
    p.add_argument("--splits-dir", default=str(root / "experiments" / "splits"))
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter8"))
    p.add_argument("--models-dir", default=os.getenv("MODEL_PATH", str(root / "models" / "saved_models")))
    return p.parse_args(argv)


def run(args: argparse.Namespace) -> dict:
    started = time.perf_counter()
    processed = Path(args.processed_dir)
    budgets = tuple(int(k) for k in args.budgets.split(",") if k.strip())
    fractions = tuple(float(f) for f in args.fractions.split(","))
    fm = load_feature_matrix(processed, args.profile)
    matrix, keys = fm.matrix, fm.keys

    views = load_label_views(processed)
    labels = attach_labels(keys, views)
    coverage = label_coverage(keys, views)
    for view in ("primary", "account"):
        if coverage[view]["unmatched"]:
            raise RuntimeError(f"{view} label days inside the feature window have no feature row: {coverage[view]}")
        if args.profile != "dev" and coverage[view]["outside_feature_window"]:
            raise RuntimeError(f"{view} label days outside the feature window under profile={args.profile}: {coverage[view]}")
    scen = insider_scenarios(views, set(keys["user_id"].unique().tolist()))

    split = make_split(
        keys, mode=args.split, insider_scenarios=scen, seed=split_seed(args), profile=args.profile,
        splits_dir=args.splits_dir, fractions=fractions,
        time_validation_start=args.time_validation_start, time_test_start=args.time_test_start,
    )
    if split.info.get("created_now") and args.profile != "dev":
        print(f"NOTE: {split.info['file']} was created now; comparisons with Chapters 6 and 7 need the file they used (N11).", flush=True)
    lab = {s: labels.iloc[ix].reset_index(drop=True) for s, ix in split.parts.items()}
    split.info["positives_primary"] = {s: int(lab[s]["y_primary"].sum()) for s in SPLITS}
    split.info["masquerade_rows_excluded"] = {s: int(lab[s]["exclude_primary"].sum()) for s in SPLITS}

    reportable = args.profile != "dev"
    run_id = f"{utc_run_stamp()}-{args.profile}-{args.split}-s{args.seed}"
    feature_fp = feature_fingerprint(fm.features_path)
    data_fp = data_fingerprint(feature_fp, split)
    split.info["data_fingerprint"] = data_fp
    frames = {s: matrix.iloc[ix].reset_index(drop=True) for s, ix in split.parts.items()}

    excluded = excluded_columns(matrix, args.exclude_features)
    if not excluded:
        raise SystemExit("the serving candidate must be behaviour-only; --exclude-features cannot be empty (C8-2)")
    detector = BehaviourGBDTDetector(seed=args.seed, device=args.device, excluded_features=excluded)
    print(f"[gbdt] excluded from the model input: {', '.join(excluded)}", flush=True)

    keep_tr, keep_va = supervised_rows(lab["train"]), supervised_rows(lab["validation"])
    t0 = time.perf_counter()
    detector.fit(
        frames["train"][keep_tr].drop(columns=excluded).reset_index(drop=True),
        lab["train"]["y_primary"].to_numpy()[keep_tr],
        validation=frames["validation"][keep_va].drop(columns=excluded).reset_index(drop=True),
        y_validation=lab["validation"]["y_primary"].to_numpy()[keep_va],
    )
    fit_seconds = time.perf_counter() - t0
    left = static_inputs(detector.input_columns)
    if left:
        raise RuntimeError(f"static traits reached the model input: {left}")

    t1 = time.perf_counter()
    blocks, score_rows, saturated = {}, [], {}
    for s in ("validation", "test"):
        raw, cal = detector.scores(frames[s])     # full rows; the detector picks its columns by name
        blocks[s] = evaluate_scores(frames[s][["user_id", "date"]], cal, lab[s], budgets=budgets, seed=args.seed)
        saturated[s] = int((cal >= 1.0).sum())
        score_rows.append(pd.DataFrame({
            "user_id": frames[s]["user_id"].to_numpy(), "date": frames[s]["date"].to_numpy(), "split": s,
            "raw_score": raw, "anomaly_score": cal, "model_name": MODEL_NAME, "model_version": detector.model_version,
        }))
    score_seconds = time.perf_counter() - t1
    scores_path = processed / "scores" / "chapter8" / run_id / f"{MODEL_NAME}.parquet"
    atomic_to_parquet(pd.concat(score_rows, ignore_index=True)[list(SCORE_COLUMNS)], scores_path)

    meta = detector.metadata()
    imbalance = {
        "method": "scale_pos_weight", "resampling": "none",
        "effective_positive_weight": meta.get("scale_pos_weight"),
        "train_positives": meta.get("train_positives"), "train_negatives": meta.get("train_negatives"),
        "train_positive_rate": meta.get("train_positive_rate"),
    }
    provenance = {
        "profile": args.profile, "split_mode": args.split, "run_id": run_id, "feature_fingerprint": feature_fp,
        "data_fingerprint": data_fp, "wall_clock_fit_seconds": round(fit_seconds, 2),
        "wall_clock_score_seconds": round(score_seconds, 2), "saturated_scores": saturated, "tag": args.tag,
    }
    val_head, test_head = headline(blocks["validation"], budgets), headline(blocks["test"], budgets)

    entry = None
    if not args.no_register:
        registry = ModelRegistry(args.models_dir, MODEL_NAME)
        entry = registry.register(
            lambda d: detector.save(d, extra=provenance),
            {
                "model_version": detector.model_version,
                "run_id": run_id,
                "chapter": 8,
                "profile": args.profile,
                "reportable": reportable,
                "split": {k: split.info.get(k) for k in ("mode", "file", "file_sha256", "validation_start", "test_start", "rows")},
                "seed": args.seed,
                "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "training_data": {
                    "dataset": fm.schema.get("dataset", "CERT r4.2"), "features_path": str(fm.features_path),
                    "feature_fingerprint": feature_fp, "data_fingerprint": data_fp,
                    "rows_matrix": int(len(matrix)), "rows_train_used": int(keep_tr.sum()),
                    "rows_train_masquerade_dropped": int((~keep_tr).sum()), "n_features": int(matrix.shape[1] - 2),
                    "n_input_columns": len(detector.input_columns), "excluded_features": excluded,
                },
                "feature_schema": {
                    "path": str(fm.schema_path), "pipeline_version": fm.schema.get("pipeline_version"),
                    "host_categories_version": fm.schema.get("host_categories_version"),
                    "config_fingerprint": fm.schema.get("config_fingerprint"),
                },
                "config": detector.config,
                "imbalance": imbalance,
                "training": {"device_used": meta.get("device_used"), "best_iteration": meta.get("best_iteration"),
                             "early_stopping": meta.get("early_stopping"), "xgboost_version": meta.get("xgboost_version")},
                "metrics": {"validation": {**val_head, **_scenario_summary(blocks["validation"], budgets)},
                            "test": {**test_head, **_scenario_summary(blocks["test"], budgets)}},
                "score_convention": "anomaly_score = sigmoid(XGBoost margin) in [0, 1], higher = more anomalous (N10)",
                "scores_path": str(scores_path),
            },
        )
        provenance["registry_version"] = entry["registry_version"]
        provenance["model_dir"] = entry["artifact_dir"]

    report = {
        "chapter": 8,
        "version": SERVING_VERSION,
        "run_id": run_id,
        "profile": args.profile,
        "reportable": reportable,
        "reportable_note": None if reportable else "dev profile: debugging only, never report these numbers (N6, HCEA R10)",
        "seed": args.seed,
        "budgets": list(budgets),
        "features": {"path": str(fm.features_path), "fingerprint": feature_fp, "schema": str(fm.schema_path),
                     "pipeline_version": fm.schema.get("pipeline_version"), "n_features": int(matrix.shape[1] - 2),
                     "rows": int(len(matrix)), "excluded_from_model": excluded},
        "label_coverage": coverage,
        "split": split.info,
        "training_rows": {"train_used": int(keep_tr.sum()), "train_masquerade_dropped": int((~keep_tr).sum()),
                          "validation_used": int(keep_va.sum()), "validation_masquerade_dropped": int((~keep_va).sum())},
        "registry": None if entry is None else {k: entry[k] for k in ("registry_version", "artifact_dir", "files")},
        "models": {MODEL_NAME: {"metadata": {**meta, **provenance, "imbalance": imbalance, "scores_path": str(scores_path)}, **blocks}},
    }
    report["wall_seconds"] = round(time.perf_counter() - started, 2)
    report["peak_rss_mb"] = round(memory_rss_mb(), 1)
    results_dir = Path(args.results_dir) / run_id
    results_dir.mkdir(parents=True, exist_ok=True)
    tmp = results_dir / "metrics.json.tmp"
    tmp.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    tmp.replace(results_dir / "metrics.json")
    report["results_path"] = str(results_dir / "metrics.json")

    append_experiment_runlog({
        "stage": "chapter8_gbdt_candidate", "run_id": run_id, "model": MODEL_NAME, "model_version": detector.model_version,
        "registry_version": provenance.get("registry_version"), "profile": args.profile, "reportable": reportable,
        "split_mode": args.split, "seed": args.seed, "split_seed": split_seed(args), "tag": args.tag,
        "excluded_features": excluded,
        "imbalance": "scale_pos_weight", "effective_positive_weight": imbalance["effective_positive_weight"],
        "train_positive_rate": imbalance["train_positive_rate"], "device": meta.get("device_used"),
        "best_iteration": meta.get("best_iteration"), "valid_pr_auc": val_head["pr_auc"],
        "rows_train": int(keep_tr.sum()), "rows_test": int(len(frames["test"])),
        "wall_seconds_fit": round(fit_seconds, 2), "wall_seconds_score": round(score_seconds, 2),
        "peak_rss_mb": round(memory_rss_mb(), 1), "feature_fingerprint": feature_fp, "data_fingerprint": data_fp,
        "split_sha256": split.info.get("file_sha256"), "saturated_test_scores": saturated["test"],
        **{f"test_{k}": v for k, v in test_head.items()},
        **{f"test_{k}": v for k, v in _scenario_summary(blocks["test"], budgets).items()},
    })
    _print_summary(report, val_head, budgets)
    return report


def _f(v) -> str:
    return "n/a" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))


def _print_summary(report: dict, val_head: dict, budgets) -> None:
    md = report["models"][MODEL_NAME]["metadata"]
    print()
    if not report["reportable"]:
        print("!! dev profile: debugging numbers only, do not report (N6) !!")
    print(f"run {report['run_id']}  split={report['split']['mode']}  model_version={md['model_version']}  "
          f"registry={md.get('registry_version', 'not registered')}")
    print(f"inputs: {md['n_input_columns']} columns, static traits excluded: {', '.join(report['features']['excluded_from_model'])}")
    print(f"imbalance: scale_pos_weight {md['imbalance']['effective_positive_weight']:.3f} "
          f"(train positive rate {md['imbalance']['train_positive_rate']:.5f}); best iteration {md.get('best_iteration')}")
    row = f"validation  PR-AUC {_f(val_head['pr_auc'])}  ROC-AUC* {_f(val_head['roc_auc_secondary'])}"
    for k in budgets:
        row += f"  R@{k} {_f(val_head[f'recall_at_{k}'])} caught@{k} {val_head[f'insiders_caught_at_{k}']}"
    print(row)
    print("test: written to metrics.json, not shown. Read it once with `python -m app.scoring.select --report-test`.")
    print("* ROC-AUC is secondary (N2). Full metrics:", report.get("results_path"))


def main(argv: list[str] | None = None) -> None:
    run(_parse_args(argv))


if __name__ == "__main__":
    main()
