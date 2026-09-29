"""Batch CRI over a Chapter 8 batch, to Parquet (Bible Ch9, HCEA §9).

Usage, from backend/ with .env loaded:

    python -m app.cri.batch --profile full
    python -m app.cri.batch --profile full --variant anomaly_only      # ablation hook (Chapter 16)
    python -m app.cri.batch --profile full --rows evaluation           # validation + test rows only

What it does
    1. Thread caps before numpy (N8).
    2. Loads the pinned calibration (sha256-checked) and refuses to run if
       the model served now, the model that scored the Chapter 8 batch and the
       model the calibration was fitted for are not one and the same (N29).
    3. Reads the served rows of the Chapter 8 batch (never shadow rows, N32),
       the hist_z_* / peer_dev_* columns of the same Chapter 5 matrix
       (fingerprint checked) and the LDAP roles.
    4. Computes the CRI in one vectorised pass (HCEA §9: seconds at full).
    5. Writes ``<processed>/risk/chapter9/<cri_run_id>/risk_scores.parquet``
       and ``cri_meta.json`` atomically. Every row keeps its anomaly score,
       model_version and model_split next to the CRI (§14, §37). Rows tagged
       ``train`` are in-sample (N31).
    6. Appends one ``chapter9_cri_batch`` runlog line (R8).

Label-free: no label is read and no detection metric is computed (N5). The
validation readout is ``python -m app.cri.evaluate``. Loading risk scores
into PostgreSQL is Chapter 12's job (HCEA §12, D-6).
"""
from __future__ import annotations

from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.feature_engineering.common import append_experiment_runlog, atomic_to_parquet, memory_rss_mb  # noqa: E402
from app.scoring.serving_config import resolve_serving_config  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, feature_fingerprint  # noqa: E402

from . import CRI_VERSION  # noqa: E402
from .calibration import default_models_root, resolve_pin_path  # noqa: E402
from .config import ABLATIONS, COMPONENTS, SEVERITIES, CRIConfig, CRIConfigError  # noqa: E402
from .context import build_context, load_roles, read_feature_columns  # noqa: E402
from .engine import CRIEngine, CRIInputError, CRIModelMismatchError, CRIUnavailableError  # noqa: E402
from .sources import RISK_META, RISK_OUTPUT, SourceError, chapter8_batch  # noqa: E402

SCORE_READ = ["user_id", "date", "model_split", "role", "model_name", "model_version", "registry_version", "anomaly_score"]


class CRIBatchRefused(RuntimeError):
    """Nothing was written."""


def daily_volume(frame: pd.DataFrame, mask: np.ndarray) -> dict:
    """Alerts per calendar day for a band mask: what an analyst queue would receive."""
    per_day = pd.Series(mask.astype(int), index=frame["date"].to_numpy()).groupby(level=0).sum()
    if per_day.empty:
        return {"days": 0}
    return {"days": int(len(per_day)), "total": int(per_day.sum()), "mean": float(per_day.mean()),
            "median": float(per_day.median()), "p95": float(per_day.quantile(0.95)), "max": int(per_day.max()),
            "days_with_none": int((per_day == 0).sum())}


def summarise(risk: pd.DataFrame, engine: CRIEngine, parts_unavailable: dict[str, str]) -> dict:
    sev = risk["severity"].to_numpy()
    by_split = {}
    for split, g in risk.groupby("model_split", sort=True, dropna=False):
        by_split[str(split)] = {
            "rows": int(len(g)),
            "severity": {s: int((g["severity"] == s).sum()) for s in SEVERITIES},
            "anomaly_beyond_reference": int(g["anomaly_beyond_reference"].sum()),
            "cri_quantiles": {q: float(np.quantile(g["cri_score"], float(q))) for q in ("0.5", "0.99", "0.999")},
        }
    evaluation = risk[risk["model_split"].isin(["validation", "test"])]
    volume = {}
    for split in ("validation", "test"):
        g = risk[risk["model_split"] == split]
        if len(g):
            volume[split] = {
                "HIGH_or_above": daily_volume(g, g["severity"].isin(["HIGH", "CRITICAL"]).to_numpy()),
                "CRITICAL": daily_volume(g, (g["severity"] == "CRITICAL").to_numpy()),
            }
    active = [c for c in COMPONENTS if c not in parts_unavailable and c not in engine.config.disabled
              and engine.config.weight[c] > 0]
    return {
        "rows": int(len(risk)),
        "severity": {s: int((sev == s).sum()) for s in SEVERITIES},
        "by_model_split": by_split,
        "daily_volume_out_of_sample": volume,
        "missing_share_out_of_sample": {c: float(evaluation["missing_components"].str.contains(c, regex=False).mean())
                                        for c in active} if len(evaluation) else {},
        "cri_score_min": float(risk["cri_score"].min()),
        "cri_score_max": float(risk["cri_score"].max()),
        "note": "rows tagged model_split=train are in-sample (N31); quote nothing about detection from them",
    }


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CIRA Chapter 9 batch CRI (label-free)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--batch-run-id", default=None, help="Chapter 8 batch (default: newest for the profile)")
    p.add_argument("--variant", default="default", choices=tuple(ABLATIONS))
    p.add_argument("--rows", default="all", choices=("all", "evaluation"))
    p.add_argument("--models-dir", default=os.getenv("MODEL_PATH") or str(default_models_root()))
    p.add_argument("--pin-path", default=str(resolve_pin_path()))
    return p.parse_args(argv)


def run(args: argparse.Namespace) -> dict:
    started = time.perf_counter()
    base = CRIConfig.from_env()
    config = base if args.variant == "default" else base.variant(args.variant)
    engine = CRIEngine.load(config, pin_path=args.pin_path, models_root=args.models_dir)
    cal_model = engine.model

    serving = resolve_serving_config()
    if serving.served is None:
        raise CRIBatchRefused(f"no served model: {serving.problem}")
    if (serving.served.model_name, serving.served.registry_version) != (cal_model.get("model_name"), cal_model.get("registry_version")):
        raise CRIBatchRefused(
            f"the served model is {serving.served}, the calibration {engine.calibration.calibration_id} was fitted for "
            f"{cal_model.get('model_name')}:{cal_model.get('registry_version')}; recalibrate for the served model (N29)")

    processed = Path(args.processed_dir)
    batch = chapter8_batch(processed, args.batch_run_id, args.profile)
    served = batch.served
    if (served.get("model_name"), served.get("model_version")) != (cal_model.get("model_name"), cal_model.get("model_version")):
        raise CRIBatchRefused(f"batch {batch.batch_run_id} was scored by {served.get('model_name')} "
                              f"{served.get('model_version')}, not the calibrated model (N29)")
    scores = batch.read(role="served", columns=SCORE_READ)
    if args.rows == "evaluation":
        scores = scores[scores["model_split"] != "train"].reset_index(drop=True)

    features_path = processed / "features" / PROFILE_OUTPUT[args.profile]
    fp = feature_fingerprint(features_path)
    if fp != (batch.meta.get("features") or {}).get("fingerprint"):
        raise CRIBatchRefused(f"{features_path.name} is not the matrix batch {batch.batch_run_id} scored "
                              "(fingerprint differs); context and score must come from one matrix")

    t0 = time.perf_counter()
    feats = read_feature_columns(features_path, scores[["user_id", "date"]])
    ctx = build_context(scores[["user_id", "date"]], feats, load_roles(processed), config.privileged_roles)
    del feats
    parts = engine.components(scores, ctx)
    risk = engine.assemble(scores, ctx, parts, config)
    compute_seconds = time.perf_counter() - t0

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    cri_run_id = f"{stamp}-{args.profile}-cri-{config.variant_name}"
    out_dir = processed / "risk" / "chapter9" / cri_run_id
    risk.insert(len(risk.columns), "cri_run_id", cri_run_id)
    risk.insert(len(risk.columns), "source_batch_run_id", batch.batch_run_id)
    atomic_to_parquet(risk, out_dir / RISK_OUTPUT)

    summary = summarise(risk, engine, parts["unavailable"])
    cal_hash = (engine.calibration.meta.get("config_at_calibration") or {}).get("config_hash")
    meta = {
        "chapter": 9,
        "cri_version": CRI_VERSION,
        "cri_run_id": cri_run_id,
        "profile": args.profile,
        "reportable": args.profile != "dev",
        "rows_option": args.rows,
        "variant": config.variant_name,
        "config": config.to_dict(),
        "config_hash": config.config_hash,
        "config_overrides": dict(config.overrides),
        "is_calibrated_default": config.variant_name == "default" and config.config_hash == cal_hash,
        "effective_weights": config.effective_weights(parts["available"]),
        "unavailable_components": parts["unavailable"],
        "calibration": engine.calibration.describe(),
        "served": {k: served.get(k) for k in ("model_name", "model_version", "registry_version", "run_id")},
        "serving_source": serving.source,
        "source_batch": {"batch_run_id": batch.batch_run_id, "path": str(batch.path)},
        "features": {"path": str(features_path), "fingerprint": fp},
        "summary": summary,
        "output": str(out_dir / RISK_OUTPUT),
        "compute_seconds": round(compute_seconds, 2),
        "wall_seconds": round(time.perf_counter() - started, 2),
        "peak_rss_mb": round(memory_rss_mb(), 1),
    }
    tmp = out_dir / (RISK_META + ".tmp")
    tmp.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
    tmp.replace(out_dir / RISK_META)

    append_experiment_runlog({
        "stage": "chapter9_cri_batch", "cri_run_id": cri_run_id, "profile": args.profile,
        "reportable": meta["reportable"], "variant": config.variant_name, "config_hash": config.config_hash,
        "config_overrides": meta["config_overrides"], "is_calibrated_default": meta["is_calibrated_default"],
        "calibration_id": engine.calibration.calibration_id, "served_model": served.get("model_name"),
        "served_registry_version": served.get("registry_version"), "served_model_version": served.get("model_version"),
        "source_batch_run_id": batch.batch_run_id, "rows": summary["rows"], "severity": summary["severity"],
        "wall_seconds": meta["wall_seconds"], "compute_seconds": meta["compute_seconds"],
        "peak_rss_mb": meta["peak_rss_mb"], "output": meta["output"],
    })
    print(f"[cri] {cri_run_id}: {summary['rows']} user-days, variant {config.variant_name}, config {config.config_hash}, "
          f"calibration {engine.calibration.calibration_id}", flush=True)
    print("[cri] severity: " + ", ".join(f"{k} {v}" for k, v in summary["severity"].items()), flush=True)
    for split, vol in summary["daily_volume_out_of_sample"].items():
        h = vol["HIGH_or_above"]
        print(f"[cri] {split}: HIGH or above per day median {h.get('median')}, p95 {h.get('p95')}, max {h.get('max')}", flush=True)
    if config.overrides:
        print(f"[cri] note: configuration overridden by environment: {dict(config.overrides)}", flush=True)
    for name, reason in parts["unavailable"].items():
        print(f"[cri] {name} unavailable: {reason}", flush=True)
    print(f"[cri] written: {meta['output']}", flush=True)
    return meta


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        run(args)
    except (CRIBatchRefused, CRIUnavailableError, CRIModelMismatchError, CRIInputError, CRIConfigError, SourceError) as exc:
        print(f"chapter9 CRI batch refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
