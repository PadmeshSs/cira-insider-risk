"""Fit the CRI calibration for the served model (Chapter 9, N29, N33).

Usage, from backend/ with .env loaded:

    python -m app.cri.calibrate --profile full
    python -m app.cri.calibrate --profile full --supersede "served model changed to tabnet:v0005"

What it does
    1. Thread caps before numpy (N8).
    2. Resolves the served model (Chapter 8 decision file, or an env pin for a
       rollback) and the newest Chapter 8 batch for the profile. Refuses if
       that batch was scored by a different model than the one served now:
       a calibration belongs to one model_version (N29).
    3. Takes the served model's validation user-days from the batch, by the
       batch's own ``model_split`` tags. No label is read. Train rows are
       in-sample (N31); test rows stay unread (N11).
    4. Reads only the hist_z_* and peer_dev_* columns of the same Chapter 5
       matrix the batch scored (fingerprint checked) and the LDAP roles, and
       computes the reference statistics.
    5. Writes ``models/saved_models/cri/<calibration_id>/reference.parquet``
       and ``calibration.json``, then points
       ``experiments/chapter9_cri_calibration.json`` at them with sha256.
       An existing pin is replaced only with ``--supersede "<reason>"``.
    6. Writes a label-free report into ``calibration.json`` and prints it:
       served-score quantiles by model_split, what share of reference days
       each band would hold, and, when the batch has shadow rows, how the
       served and shadow models disagree on the same validation user-days.
       Shadow scores are read for that comparison only; they never enter the
       calibration or the CRI (N32).
    7. Appends one ``chapter9_cri_calibration`` runlog line (R8).
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

from app.feature_engineering.common import append_experiment_runlog, memory_rss_mb  # noqa: E402
from app.scoring.serving_config import resolve_serving_config  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, feature_fingerprint  # noqa: E402

from . import CRI_VERSION  # noqa: E402
from .calibration import (  # noqa: E402
    ANOMALY_STAT,
    DEFINITION_VERSION,
    HISTORICAL_STAT,
    LoadedCalibration,
    default_models_root,
    fit_maps,
    resolve_pin_path,
    save_calibration,
)
from .config import CRIConfig  # noqa: E402
from .context import build_context, historical_columns, load_roles, peer_columns, read_feature_columns  # noqa: E402
from .engine import CRIEngine  # noqa: E402
from .sources import Chapter8Batch, SourceError, chapter8_batch  # noqa: E402

QUANTILES = ("0.5", "0.9", "0.99", "0.999")
DEFAULT_MIN_REFERENCE_ROWS = 1000


class CalibrationRefused(RuntimeError):
    """Nothing was written."""


# ---------------------------------------------------------------------------
# Label-free report helpers
# ---------------------------------------------------------------------------

def _quantiles(x: np.ndarray) -> dict:
    x = np.asarray(x, dtype="float64")
    if len(x) == 0:
        return {}
    return {**{q: float(np.quantile(x, float(q))) for q in QUANTILES}, "max": float(x.max()), "rows": int(len(x))}


def _daily_top(frame: pd.DataFrame, k: int) -> dict[str, set]:
    ordered = frame.sort_values(["date", "score", "user_id"], ascending=[True, False, True], kind="mergesort")
    top = ordered.groupby("date", sort=False).head(k)
    return {d: set(g["user_id"]) for d, g in top.groupby("date", sort=False)}


def shadow_disagreement(frame: pd.DataFrame, part: str = "validation") -> dict | None:
    """How the served and shadow models rank the same user-days (N32 monitoring).

    Label-free. Explains why one raw threshold cannot serve both models and
    why the CRI calibration is per model_version.
    """
    s = frame[(frame["role"] == "served") & (frame["model_split"] == part)]
    h = frame[(frame["role"] == "shadow") & (frame["model_split"] == part)]
    if s.empty or h.empty:
        return None
    j = s[["user_id", "date", "anomaly_score"]].merge(
        h[["user_id", "date", "anomaly_score", "model_name", "registry_version"]], on=["user_id", "date"],
        suffixes=("_served", "_shadow"), validate="one_to_one")
    a, b = j["anomaly_score_served"].to_numpy(), j["anomaly_score_shadow"].to_numpy()
    spearman = float(pd.Series(a).rank().corr(pd.Series(b).rank()))
    q99_s, q99_h = float(np.quantile(a, 0.99)), float(np.quantile(b, 0.99))
    n_top = max(1, int(round(0.01 * len(j))))
    top_s = set(np.argsort(-a, kind="mergesort")[:n_top].tolist())
    top_h = set(np.argsort(-b, kind="mergesort")[:n_top].tolist())
    days = {}
    for k in (1, 5):
        ds = _daily_top(j.rename(columns={"anomaly_score_served": "score"})[["user_id", "date", "score"]], k)
        dh = _daily_top(j.rename(columns={"anomaly_score_shadow": "score"})[["user_id", "date", "score"]], k)
        jac = [len(ds[d] & dh[d]) / len(ds[d] | dh[d]) for d in ds if d in dh and (ds[d] | dh[d])]
        days[str(k)] = {"days": len(jac), "mean_jaccard": float(np.mean(jac)) if jac else None,
                        "identical_days": int(sum(x == 1.0 for x in jac))}
    return {
        "part": part,
        "rows": int(len(j)),
        "shadow_model": f"{j['model_name'].iloc[0]}:{j['registry_version'].iloc[0]}",
        "served_quantiles": _quantiles(a),
        "shadow_quantiles": _quantiles(b),
        "spearman_rank_correlation": spearman,
        "top_1pct_overlap": len(top_s & top_h) / n_top,
        "share_of_shadow_at_or_above_served_q99": float((b >= q99_s).mean()),
        "share_of_served_at_or_above_shadow_q99": float((a >= q99_h).mean()),
        "daily_top_k_agreement": days,
        "note": "label-free; shadow scores never enter the calibration or the CRI (N32)",
    }


def band_thresholds_anomaly_only(config: CRIConfig, available: set[str]) -> dict:
    """Exceedance probability the anomaly score alone needs to reach each band."""
    w = config.effective_weights(available)["anomaly"]
    out = {"anomaly_effective_weight": w, "anomaly_only_max_cri": 100.0 * w}
    for name, edge in zip(("MEDIUM", "HIGH", "CRITICAL"), config.band_edges()):
        r = edge / (100.0 * w)
        out[name] = {"rarity_needed": r, "exceedance_p_at_most": (10 ** (-config.rarity_decades * r)) if r <= 1 else None}
    return out


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CIRA Chapter 9 CRI calibration (label-free)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--batch-run-id", default=None, help="Chapter 8 batch (default: newest for the profile)")
    p.add_argument("--models-dir", default=os.getenv("MODEL_PATH") or str(default_models_root()))
    p.add_argument("--pin-path", default=str(resolve_pin_path()))
    p.add_argument("--supersede", default=None, metavar="REASON", help="replace the current calibration pin, keeping it on record")
    p.add_argument("--min-reference-rows", type=int, default=DEFAULT_MIN_REFERENCE_ROWS, help=argparse.SUPPRESS)  # tests only
    return p.parse_args(argv)


def _check_served(batch: Chapter8Batch) -> tuple[dict, str]:
    serving = resolve_serving_config()
    if serving.served is None:
        raise CalibrationRefused(f"no served model: {serving.problem}")
    got = batch.served
    if (got.get("model_name"), got.get("registry_version")) != (serving.served.model_name, serving.served.registry_version):
        raise CalibrationRefused(
            f"batch {batch.batch_run_id} was scored by {got.get('model_name')}:{got.get('registry_version')}, but the "
            f"served model is {serving.served}; re-run the Chapter 8 batch for the served model first (N29)")
    return got, serving.source


def run(args: argparse.Namespace) -> dict:
    started = time.perf_counter()
    config = CRIConfig.from_env()
    processed = Path(args.processed_dir)
    batch = chapter8_batch(processed, args.batch_run_id, args.profile)
    served, source = _check_served(batch)

    frame = batch.read(role=None, columns=["user_id", "date", "model_split", "role", "model_name", "model_version",
                                           "registry_version", "anomaly_score"])
    served_rows = frame[frame["role"] == "served"].reset_index(drop=True)
    ref_scores = served_rows[served_rows["model_split"] == "validation"].reset_index(drop=True)
    if len(ref_scores) < args.min_reference_rows:
        raise CalibrationRefused(f"only {len(ref_scores)} validation rows in batch {batch.batch_run_id}; "
                                 f"need at least {args.min_reference_rows}")

    features_path = processed / "features" / PROFILE_OUTPUT[args.profile]
    fp = feature_fingerprint(features_path)
    scored_fp = (batch.meta.get("features") or {}).get("fingerprint")
    if fp != scored_fp:
        raise CalibrationRefused(f"{features_path.name} fingerprint {fp} differs from the one batch "
                                 f"{batch.batch_run_id} scored ({scored_fp}); context and score must come from one matrix")
    feats = read_feature_columns(features_path, ref_scores[["user_id", "date"]])
    roles = load_roles(processed)
    ctx = build_context(ref_scores[["user_id", "date"]], feats, roles, config.privileged_roles)

    reference = pd.DataFrame({
        "user_id": ref_scores["user_id"].to_numpy(),
        "date": ref_scores["date"].to_numpy(),
        ANOMALY_STAT: ref_scores["anomaly_score"].to_numpy(dtype="float64"),
        HISTORICAL_STAT: ctx["historical_statistic"].to_numpy(dtype="float64"),
        **{c: ctx[c].to_numpy(dtype="float64") for c in ctx.columns if c.startswith("peer_pos__")},
    })
    maps = fit_maps(reference, config.rarity_decades)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    cal_id = f"{stamp}-{args.profile}-cri"
    model = {k: served.get(k) for k in ("model_name", "model_version", "registry_version", "run_id", "profile")}
    meta = {
        "chapter": 9,
        "cri_version": CRI_VERSION,
        "calibration_id": cal_id,
        "definition_version": DEFINITION_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile": args.profile,
        "reportable": args.profile != "dev",
        "model": model,
        "serving_source": source,
        "source_batch": {"batch_run_id": batch.batch_run_id, "path": str(batch.path),
                         "decision_sha256": batch.meta.get("decision_sha256")},
        "features": {"path": str(features_path), "fingerprint": fp,
                     "historical_columns": historical_columns(feats.columns), "peer_columns": peer_columns(feats.columns)},
        "reference": {
            "part": "validation",
            "rule": "served model's validation user-days by its own model_split tags; no labels read",
            "rows": int(len(reference)),
            "users": int(reference["user_id"].nunique()),
            "days": int(reference["date"].nunique()),
            "non_null": {k: int(len(v)) for k, v in maps.references.items()},
            "max_reachable_rarity": float(np.log10(len(reference) + 1) / config.rarity_decades),
        },
        "rarity_decades": config.rarity_decades,
        "config_at_calibration": {**config.to_dict(), "config_hash": config.config_hash,
                                  "overrides": dict(config.overrides)},
    }

    # --- label-free report ----------------------------------------------------
    cal = LoadedCalibration(meta=meta, maps=maps, pin={}, reference_path=Path())
    engine = CRIEngine(config, cal)
    available = engine.components(ref_scores, ctx)["available"]
    variants = engine.compute_variants(ref_scores, ctx, ["default", "anomaly_only"])
    risk, only = variants["default"], variants["anomaly_only"]
    priv = ctx["user_context_value"].to_numpy(dtype="float64")
    meta["report"] = {
        "served_score_quantiles_by_model_split": {
            k: _quantiles(g["anomaly_score"].to_numpy()) for k, g in served_rows.groupby("model_split", sort=True)},
        "band_share_on_reference": {
            "default": {s: float((risk["severity"] == s).mean()) for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")},
            "anomaly_only": {s: float((only["severity"] == s).mean()) for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")},
        },
        "anomaly_only_band_thresholds": band_thresholds_anomaly_only(config, available),
        "context_on_reference": {
            "historical_null_share": float(np.isnan(reference[HISTORICAL_STAT]).mean()),
            "peer_null_share": float(risk["component_peer_deviation"].isna().mean()),
            "user_context_null_share": float(np.isnan(priv).mean()),
            "privileged_user_day_share": float(np.nanmean(priv)) if np.isfinite(priv).any() else None,
            "privileged_users": int(ctx.loc[ctx["user_context_value"] == 1.0, "user_id"].nunique()),
        },
        "unavailable_components": {"asset_criticality": "no source in CERT r4.2 (N9)", "mitre_context": "Chapter 10"},
        "served_vs_shadow": shadow_disagreement(frame),
    }

    pin = save_calibration(meta, reference, models_root=Path(args.models_dir), pin_path=Path(args.pin_path),
                           supersede_reason=args.supersede)
    append_experiment_runlog({
        "stage": "chapter9_cri_calibration", "calibration_id": cal_id, "profile": args.profile,
        "reportable": meta["reportable"], "served_model": model["model_name"],
        "served_registry_version": model["registry_version"], "served_model_version": model["model_version"],
        "source_batch_run_id": batch.batch_run_id, "reference_rows": meta["reference"]["rows"],
        "config_hash": config.config_hash, "config_overrides": dict(config.overrides),
        "superseded": bool(args.supersede), "reference_sha256": pin["current"]["reference_sha256"],
        "wall_seconds": round(time.perf_counter() - started, 2), "peak_rss_mb": round(memory_rss_mb(), 1),
    })
    _print(meta, Path(args.pin_path))
    return meta


def _print(meta: dict, pin_path: Path) -> None:
    r, rep = meta["reference"], meta["report"]
    m = meta["model"]
    print(f"[calibrate] {meta['calibration_id']}: {m['model_name']} {m['registry_version']} ({m['model_version']}), "
          f"reference = {r['rows']} validation user-days, {r['users']} users, {r['days']} days", flush=True)
    print(f"[calibrate] max reachable rarity {r['max_reachable_rarity']:.3f} (D = {meta['rarity_decades']})", flush=True)
    for split, q in rep["served_score_quantiles_by_model_split"].items():
        print(f"[calibrate] served score quantiles, {split:<10} " + ", ".join(f"{k}={v:.3g}" for k, v in q.items() if k != "rows"), flush=True)
    for name, shares in rep["band_share_on_reference"].items():
        print(f"[calibrate] band share on reference, {name:<12} " + ", ".join(f"{k} {v:.4f}" for k, v in shares.items()), flush=True)
    sv = rep.get("served_vs_shadow")
    if sv:
        print(f"[calibrate] served vs shadow {sv['shadow_model']} on {sv['rows']} validation rows: spearman "
              f"{sv['spearman_rank_correlation']:.3f}, top-1% overlap {sv['top_1pct_overlap']:.3f}, shadow >= served q99 "
              f"{sv['share_of_shadow_at_or_above_served_q99']:.4f}", flush=True)
    print(f"[calibrate] pinned in {pin_path}", flush=True)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        run(args)
    except (CalibrationRefused, SourceError, FileExistsError) as exc:
        print(f"chapter9 calibration refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
