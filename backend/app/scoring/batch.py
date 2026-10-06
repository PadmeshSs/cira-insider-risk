"""Batch anomaly scoring to Parquet (Bible Ch8, HCEA §8).

Usage, from backend/ with .env loaded:

    python -m app.scoring.batch --profile full
    python -m app.scoring.batch --profile full --with-shadow
    python -m app.scoring.batch --profile full --rows evaluation   # validation + test users only

What it does
    1. Thread caps before numpy/torch (N8).
    2. Resolves the served model (decision file or env pin) and loads it
       once, on CPU. If it cannot be loaded the run stops with the reason and
       writes no score (Architecture §36).
    3. Reads ``features/user_day_<profile>.parquet``. Refuses a matrix whose
       Chapter 5 ``pipeline_version`` differs from the one the served model
       was trained on, unless ``--allow-schema-change`` is given and logged.
    4. Tags every row with ``model_split``: the split the served model put
       that user (or day, for a time-split model) in, read from the split
       file named in its registry entry after checking its sha256. ``train``
       rows are in-sample; their scores are not evidence of detection
       (N31). Users absent from that file are tagged ``unassigned``.
    5. Scores in chunks and writes
       ``<processed>/scores/chapter8/<batch_run_id>/anomaly_scores.parquet``
       atomically, plus ``batch_meta.json`` beside it.
    6. Appends one ``chapter8_batch_scoring`` line to the runlog (R8).

No label is read and no metric is computed here: this is the serving path
(N5). The bounded load into PostgreSQL is Chapter 12's job (HCEA §12,
D-6); this runner only produces the Parquet it will read.
"""
from __future__ import annotations

from app.core.run_stamp import utc_run_stamp  # noqa: E402
from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.evaluation.splitting import load_split, time_split  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, atomic_to_parquet, memory_rss_mb, repo_root  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, feature_fingerprint, file_sha256, load_feature_matrix  # noqa: E402

from . import SERVING_VERSION  # noqa: E402
from .contracts import ScoringUnavailableError  # noqa: E402
from .serving_config import resolve_serving_config  # noqa: E402
from .service import AnomalyScoringService  # noqa: E402

OUTPUT_FILE = "anomaly_scores.parquet"
META_FILE = "batch_meta.json"
BATCH_COLUMNS = ("user_id", "date", "model_split", "role", "model_name", "model_version", "registry_version",
                 "raw_score", "anomaly_score", "batch_run_id")
DEFAULT_CHUNK_ROWS = 100_000


class BatchRefused(RuntimeError):
    """The batch cannot run as configured; nothing was written."""


def model_split_tags(keys: pd.DataFrame, entry: dict, splits_dir: Path) -> tuple[np.ndarray, dict]:
    """Per row: the split the served model assigned it to, from its registry entry."""
    split = entry.get("split") or {}
    mode = split.get("mode")
    if mode == "user":
        recorded = Path(str(split.get("file") or ""))
        path = splits_dir / recorded.name
        if not path.exists():
            raise BatchRefused(f"split file {recorded.name} named by the served model's registry entry is not in {splits_dir}")
        digest = file_sha256(path)
        if split.get("file_sha256") and digest != split["file_sha256"]:
            raise BatchRefused(f"{path} sha256 {digest[:12]} differs from the one recorded at training "
                               f"({split['file_sha256'][:12]}); the in-sample tags would be wrong")
        assignment, _meta = load_split(path)
        tags = keys["user_id"].astype("string").map(assignment).fillna("unassigned").to_numpy(dtype=object)
        return tags, {"mode": "user", "file": str(path), "file_sha256": digest}
    if mode == "time":
        v, t = split.get("validation_start"), split.get("test_start")
        if not (v and t):
            raise BatchRefused("time-split registry entry lacks validation_start / test_start")
        return time_split(keys["date"], validation_start=v, test_start=t).astype(object), {"mode": "time", "validation_start": v, "test_start": t}
    raise BatchRefused(f"served model's registry entry has no usable split record (mode={mode!r})")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    root = repo_root()
    p = argparse.ArgumentParser(description="CIRA Chapter 8 batch anomaly scoring")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--rows", default="all", choices=("all", "evaluation"),
                   help="all rows, or only rows the served model did not train on (validation, test, unassigned)")
    p.add_argument("--with-shadow", action="store_true", help="also score the shadow model named in the decision")
    p.add_argument("--chunk-rows", type=int, default=DEFAULT_CHUNK_ROWS)
    p.add_argument("--splits-dir", default=str(root / "experiments" / "splits"))
    p.add_argument("--allow-schema-change", action="store_true",
                   help="score a matrix whose Chapter 5 pipeline_version differs from the training one (logged)")
    p.add_argument("--allow-unreportable", action="store_true", help=argparse.SUPPRESS)   # tests only
    return p.parse_args(argv)


def run(args: argparse.Namespace) -> dict:
    started = time.perf_counter()
    config = resolve_serving_config()
    service = AnomalyScoringService.load(config, allow_unreportable=args.allow_unreportable)
    if not service.available:
        raise ScoringUnavailableError(f"no score written: {service.unavailable_reason}")
    served = service.served
    entry = served.entry

    fm = load_feature_matrix(args.processed_dir, args.profile)
    matrix = fm.matrix
    trained_pipeline = (entry.get("feature_schema") or {}).get("pipeline_version")
    scored_pipeline = fm.schema.get("pipeline_version")
    schema_same = trained_pipeline == scored_pipeline
    if not schema_same and not args.allow_schema_change:
        raise BatchRefused(f"feature pipeline_version {scored_pipeline!r} differs from the served model's "
                           f"{trained_pipeline!r}; rebuild the model or pass --allow-schema-change")
    feature_fp = feature_fingerprint(fm.features_path)
    same_matrix = feature_fp == (entry.get("training_data") or {}).get("feature_fingerprint")

    tags, split_record = model_split_tags(matrix[["user_id", "date"]], entry, Path(args.splits_dir))
    if args.rows == "evaluation":
        keep = tags != "train"
        matrix, tags = matrix[keep].reset_index(drop=True), tags[keep]

    stamp = utc_run_stamp()
    batch_run_id = f"{stamp}-{args.profile}-batch"
    out_dir = Path(args.processed_dir) / "scores" / "chapter8" / batch_run_id
    chunk = max(1, int(args.chunk_rows))

    parts, t0 = [], time.perf_counter()
    for start in range(0, len(matrix), chunk):
        block = matrix.iloc[start:start + chunk]
        scored = service.score_frame(block, include_shadow=args.with_shadow)
        n_models = len(scored) // len(block)
        scored.insert(2, "model_split", np.tile(tags[start:start + chunk], n_models))
        parts.append(scored)
    score_seconds = time.perf_counter() - t0
    frame = pd.concat(parts, ignore_index=True)
    frame["batch_run_id"] = batch_run_id
    frame = frame[list(BATCH_COLUMNS)]
    atomic_to_parquet(frame, out_dir / OUTPUT_FILE)

    served_rows = frame[frame["role"] == "served"]
    s = served_rows["anomaly_score"].to_numpy()
    summary = {
        "rows_scored": int(len(served_rows)),
        "rows_by_model_split": {k: int(v) for k, v in served_rows["model_split"].value_counts().sort_index().items()},
        "shadow_rows": int((frame["role"] == "shadow").sum()),
        "shadow_score_failures": service.shadow_score_failures,
        "saturated_served_scores": int((s >= 1.0).sum()),
        "served_score_quantiles": {q: float(np.quantile(s, float(q))) for q in ("0.5", "0.9", "0.99", "0.999")},
        "served_score_min": float(s.min()), "served_score_max": float(s.max()),
    }
    meta = {
        "chapter": 8,
        "version": SERVING_VERSION,
        "batch_run_id": batch_run_id,
        "profile": args.profile,
        "rows_option": args.rows,
        "source": config.source,
        "decision_file": None if config.decision_path is None else str(config.decision_path),
        "decision_sha256": (hashlib.sha256(config.decision_path.read_bytes()).hexdigest()
                            if config.decision_path is not None and config.decision_path.exists() else None),
        "served": served.describe(),
        "shadow": [m.describe() for m in service.shadows] if args.with_shadow else [],
        "shadow_load_errors": service.shadow_load_errors,
        "features": {"path": str(fm.features_path), "fingerprint": feature_fp, "pipeline_version": scored_pipeline,
                     "same_matrix_as_training": same_matrix, "same_pipeline_as_training": schema_same},
        "model_split": split_record,
        "summary": summary,
        "chunk_rows": chunk,
        "output": str(out_dir / OUTPUT_FILE),
        "wall_seconds": round(time.perf_counter() - started, 2),
        "score_seconds": round(score_seconds, 2),
        "peak_rss_mb": round(memory_rss_mb(), 1),
    }
    tmp = out_dir / (META_FILE + ".tmp")
    tmp.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
    tmp.replace(out_dir / META_FILE)

    append_experiment_runlog({
        "stage": "chapter8_batch_scoring", "batch_run_id": batch_run_id, "profile": args.profile,
        "reportable": args.profile != "dev", "source": config.source,
        "served_model": served.model_name, "served_registry_version": served.registry_version,
        "served_model_version": served.model_version,
        "shadow": [f"{m.model_name}:{m.registry_version}" for m in service.shadows] if args.with_shadow else [],
        "rows_scored": summary["rows_scored"], "rows_by_model_split": summary["rows_by_model_split"],
        "saturated_served_scores": summary["saturated_served_scores"],
        "shadow_score_failures": summary["shadow_score_failures"],
        "same_matrix_as_training": same_matrix, "same_pipeline_as_training": schema_same,
        "feature_fingerprint": feature_fp, "wall_seconds": meta["wall_seconds"],
        "rows_per_second": round(summary["rows_scored"] / score_seconds, 1) if score_seconds > 0 else None,
        "peak_rss_mb": meta["peak_rss_mb"], "output": meta["output"],
    })
    print(f"[batch] {batch_run_id}: {summary['rows_scored']} rows scored by {served.model_name} {served.registry_version} "
          f"({served.model_version}) in {score_seconds:.1f}s; model_split {summary['rows_by_model_split']}", flush=True)
    if summary["rows_by_model_split"].get("train"):
        print("[batch] rows tagged model_split=train are in-sample: never quote detection from them (N31)", flush=True)
    if not same_matrix:
        print("[batch] note: this feature file is not the one the model was trained on (fingerprint differs)", flush=True)
    print(f"[batch] written: {meta['output']}", flush=True)
    return meta


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        run(args)
    except (ScoringUnavailableError, BatchRefused) as exc:
        print(f"chapter8 batch refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
