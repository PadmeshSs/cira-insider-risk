"""Batch explanations to Parquet (Bible Ch11, HCEA §11 / D-5).

Usage, from backend/ with .env loaded, after Chapters 8-10:

    python -m app.explainability.batch --profile full
    python -m app.explainability.batch --profile full --rows evaluation   # skip the served model's training users
    python -m app.explainability.batch --profile full --no-kernel         # TreeSHAP and reasons only

What it does
    1. Thread caps before numpy (N8).
    2. Loads the served model through the scoring service (pinned, sha256-
       checked, N21) and the explainer for that model (N30): TreeSHAP for
       XGBoost, masks for TabNet. Shadow models are not loaded for this (N32).
    3. Checks lineage before computing anything: the Chapter 8 batch was
       scored by the served model_version; the CRI run (default variant,
       with MITRE if there is one) was computed from that batch; both came
       from the matrix that exists now (fingerprint). Any mismatch refuses.
    4. Explains every scored user-day in 50,000-row chunks and keeps the
       top-k features per row (HCEA §11.1). Every row's contributions must add
       up to the margin the model produces now, and that margin must equal
       the batch's ``raw_score``; otherwise the run refuses.
    5. Selects the bounded set (``selection.py``, label-free) and for it runs
       KernelSHAP with the deletion check (D-5), and writes the full analyst
       explanation to ``reasons.jsonl``. A KernelSHAP failure is recorded and
       does not stop the run (Architecture §36: the explanation still stands
       on TreeSHAP, and the corroboration is retried later).
    6. Writes ``<processed>/explanations/chapter11/<explain_run_id>/`` and one
       ``chapter11_explain_batch`` runlog line (R8).

No label is read (N5). Rows tagged ``model_split=train`` are in-sample
(N31); they are explained, because the explanation of a score is valid for
any row, but they are never selected as examples. Persisting explanations to
``AlertReason`` is Chapter 12's job (C11-5).
"""
from __future__ import annotations

from app.core.run_stamp import utc_run_stamp  # noqa: E402
from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.baselines.base import user_stratified_sample  # noqa: E402
from app.cri.sources import SourceError, chapter8_batch  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, atomic_to_parquet, memory_rss_mb, repo_root  # noqa: E402
from app.scoring.contracts import ScoringUnavailableError  # noqa: E402
from app.scoring.serving_config import resolve_serving_config  # noqa: E402
from app.scoring.service import AnomalyScoringService  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, feature_fingerprint, load_feature_matrix  # noqa: E402

from . import EXPLAIN_VERSION  # noqa: E402
from .attributions import (  # noqa: E402
    ATTRIBUTION_COLUMNS,
    DEFAULT_TOP_K,
    ExplanationFailedError,
    ExplanationUnavailableError,
    explainer_for,
    row_summary,
    top_k_long,
)
from .features import undescribed  # noqa: E402
from .reason_builder import build_explanation, jsonable, model_evidence  # noqa: E402
from .selection import DEFAULT_MAX_ROWS, select_rows  # noqa: E402
from .shap_explainer import CORROBORATION_COLUMNS, N_BACKGROUND, KernelCorroborator  # noqa: E402
from .sources import (  # noqa: E402
    ATTRIBUTIONS_OUTPUT,
    EXPLAIN_META,
    KERNEL_OUTPUT,
    REASONS_OUTPUT,
    RISK_META,
    SELECTION_OUTPUT,
    SUMMARY_OUTPUT,
    ExplainSourceError,
    aligned,
    default_risk_run,
)

CHUNK_ROWS = 50_000
MARGIN_TOL = 1e-4          # the batch's raw_score and the margin now; TabNet float32 moves in the last bits
DEFAULT_POOL_ROWS = 5_000
RISK_READ = ("user_id", "date", "model_split", "model_version", "anomaly_score", "cri_score", "severity",
             "historical_top_feature", "peer_top_feature", "role", "calibration_id", "cri_config_hash", "cri_run_id")
MITRE_CONTEXT_READ = ["mitre_status", "mitre_context", "mitre_unmapped_behaviours"]
SUMMARY_COLUMNS = ("user_id", "date", "model_split", "model_name", "model_version", "registry_version", "method",
                   "raw_score", "anomaly_score", "expected_value", "attribution_sum", "additivity_error", "n_raising",
                   "top_feature", "top_contribution", "top_is_calendar", "static_in_top5", "explain_run_id")


class ExplainBatchRefused(RuntimeError):
    """Nothing was written."""


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CIRA Chapter 11 batch explanations (label-free)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--batch-run-id", default=None, help="Chapter 8 batch (default: newest for the profile)")
    p.add_argument("--cri-run-id", default=None, help="Chapter 9/10 risk run (default: newest default run of that batch, MITRE preferred)")
    p.add_argument("--rows", default="all", choices=("all", "evaluation"))
    p.add_argument("--top-k", type=int, default=DEFAULT_TOP_K, help="features kept per user-day")
    p.add_argument("--chunk-rows", type=int, default=CHUNK_ROWS)
    p.add_argument("--select-top-k-per-day", type=int, default=1)
    p.add_argument("--max-bounded-rows", type=int, default=DEFAULT_MAX_ROWS)
    p.add_argument("--no-kernel", action="store_true", help="skip KernelSHAP and the deletion check")
    p.add_argument("--kernel-nsamples", default="auto", help="'auto' = 2 * inputs + 2048; must exceed the input count")
    p.add_argument("--n-background", type=int, default=N_BACKGROUND)
    p.add_argument("--background-pool-rows", type=int, default=DEFAULT_POOL_ROWS)
    p.add_argument("--seed", type=int, default=int(os.getenv("CIRA_SEED", "42")))
    p.add_argument("--splits-dir", default=str(repo_root() / "experiments" / "splits"),
                   help="where the served model's split file lives (KernelSHAP background: its training users)")
    p.add_argument("--allow-unreportable", action="store_true", help=argparse.SUPPRESS)   # tests only
    return p.parse_args(argv)


def _risk_dir(processed: Path, args, batch_run_id: str) -> Path:
    if args.cri_run_id:
        d = processed / "risk" / "chapter9" / args.cri_run_id
        if not (d / RISK_META).exists():
            raise ExplainBatchRefused(f"CRI run {args.cri_run_id} not found")
        return d
    return default_risk_run(processed, args.profile, batch_run_id)


def _mitre_for(processed: Path, risk_meta: dict, keys: pd.DataFrame) -> tuple[pd.DataFrame | None, pd.DataFrame | None, str | None, dict | None]:
    block = risk_meta.get("mitre")
    if not block:
        reason = (risk_meta.get("unavailable_components") or {}).get("mitre_context") or "no enrichment run joined"
        return None, None, reason, None
    from app.mitre.sources import MATCHES_OUTPUT, MitreSourceError, mitre_run_dir, read_context

    try:
        mdir = mitre_run_dir(processed, block["mitre_run_id"])
        ctx = read_context(mdir, keys, MITRE_CONTEXT_READ)
    except MitreSourceError as exc:
        raise ExplainBatchRefused(f"the CRI run names enrichment run {block.get('mitre_run_id')}: {exc}") from exc
    matches = pd.read_parquet(mdir / MATCHES_OUTPUT)
    matches["user_id"] = matches["user_id"].astype("string").str.strip().str.casefold()
    matches["date"] = matches["date"].astype("string")
    want = set(zip(keys["user_id"].astype(str), keys["date"].astype(str)))
    matches = matches[[k in want for k in zip(matches["user_id"].astype(str), matches["date"].astype(str))]]
    return ctx, matches.reset_index(drop=True), None, {"mitre_run_id": mdir.name, **{k: block.get(k) for k in (
        "ruleset_version", "ruleset_hash", "attack_version", "reference_id")}}


def background_pool(matrix: pd.DataFrame, entry: dict, splits_dir: Path, pool_rows: int, seed: int) -> tuple[pd.DataFrame, dict]:
    """Training user-days of the served model, from its own split record, as a label-free pool.

    The split comes from the registry entry (sha256-checked by the Chapter 8
    helper), not from the Chapter 8 batch, which may have been run with
    ``--rows evaluation`` and hold no training rows. A user-stratified sample
    keeps one heavy user from filling the pool.
    """
    from app.scoring.batch import BatchRefused, model_split_tags

    try:
        tags, record = model_split_tags(matrix[["user_id", "date"]], entry, splits_dir)
    except BatchRefused as exc:
        raise ExplanationUnavailableError(f"cannot tell the served model's training rows: {exc}") from exc
    train = matrix[tags == "train"].reset_index(drop=True)
    if train.empty:
        raise ExplanationUnavailableError("the served model's split has no training rows in this matrix")
    pick = user_stratified_sample(train["user_id"], pool_rows, seed)
    return train.iloc[pick].reset_index(drop=True), record


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
    tmp.replace(path)


def _quant(x: np.ndarray) -> dict:
    x = np.asarray(x, dtype="float64")
    x = x[np.isfinite(x)]
    if x.size == 0:
        return {}
    return {"median": float(np.median(x)), "p10": float(np.quantile(x, 0.1)), "p90": float(np.quantile(x, 0.9)),
            "min": float(x.min()), "max": float(x.max())}


def run(args: argparse.Namespace) -> dict:
    started = time.perf_counter()
    serving = resolve_serving_config()
    service = AnomalyScoringService.load(serving, allow_unreportable=args.allow_unreportable)
    if not service.available:
        raise ScoringUnavailableError(f"no explanation written: {service.unavailable_reason}")
    served = service.served
    try:
        explainer = explainer_for(served, role="served", chunk_rows=args.chunk_rows)
    except ExplanationUnavailableError as exc:
        raise ExplainBatchRefused(str(exc)) from exc

    processed = Path(args.processed_dir)
    batch = chapter8_batch(processed, args.batch_run_id, args.profile)
    b = batch.served
    if (b.get("model_name"), b.get("model_version"), b.get("registry_version")) != \
            (served.model_name, served.model_version, served.registry_version):
        raise ExplainBatchRefused(f"batch {batch.batch_run_id} was scored by {b.get('model_name')} {b.get('registry_version')} "
                                  f"({b.get('model_version')}); the served model is {served.model_name} "
                                  f"{served.registry_version}. Explanations come from the model that scored (N30)")
    risk_dir = _risk_dir(processed, args, batch.batch_run_id)
    risk_meta = json.loads((risk_dir / RISK_META).read_text(encoding="utf-8"))
    if (risk_meta.get("source_batch") or {}).get("batch_run_id") != batch.batch_run_id:
        raise ExplainBatchRefused(f"CRI run {risk_dir.name} was computed from another batch; score and context must match")
    if (risk_meta.get("served") or {}).get("model_version") != served.model_version:
        raise ExplainBatchRefused(f"CRI run {risk_dir.name} belongs to another model_version (N29)")

    fm = load_feature_matrix(processed, args.profile)
    fp = feature_fingerprint(fm.features_path)
    for what, other in (("batch", (batch.meta.get("features") or {}).get("fingerprint")),
                        ("CRI run", (risk_meta.get("features") or {}).get("fingerprint"))):
        if other != fp:
            raise ExplainBatchRefused(f"the {what} was made from another matrix (fingerprint {other}, matrix now {fp})")
    missing_text = undescribed(explainer.features)
    if missing_text:
        raise ExplainBatchRefused(f"no plain-language description for model input(s) {missing_text[:5]}; "
                                  "add them to app/explainability/features.py")

    all_scores = batch.read(role="served", columns=["user_id", "date", "model_split", "raw_score", "anomaly_score"])
    scores = all_scores[all_scores["model_split"] != "train"].reset_index(drop=True) if args.rows == "evaluation" else all_scores
    frame = aligned(fm.matrix, scores[["user_id", "date"]], f"matrix {fm.features_path.name}")

    stamp = utc_run_stamp()
    run_id = f"{stamp}-{args.profile}-explain"
    out_dir = processed / "explanations" / "chapter11" / run_id

    # --- TreeSHAP (or masks) over every scored user-day ---------------------
    t0 = time.perf_counter()
    summaries, longs, worst_margin = [], [], 0.0
    for start in range(0, len(frame), max(1, args.chunk_rows)):
        chunk = frame.iloc[start:start + args.chunk_rows]
        attr = explainer.explain(chunk)
        batch_raw = scores["raw_score"].to_numpy(dtype="float64")[start:start + len(chunk)]
        worst_margin = max(worst_margin, float(np.abs(attr.raw_score - batch_raw).max()))
        s = row_summary(attr)
        s.insert(2, "model_split", scores["model_split"].to_numpy(dtype=object)[start:start + len(chunk)])
        s.insert(3, "model_name", served.model_name)
        s.insert(4, "model_version", served.model_version)
        s.insert(5, "registry_version", served.registry_version)
        s.insert(8, "anomaly_score", scores["anomaly_score"].to_numpy(dtype="float64")[start:start + len(chunk)])
        summaries.append(s)
        longs.append(top_k_long(attr, chunk, args.top_k))
    if worst_margin > MARGIN_TOL:
        raise ExplainBatchRefused(f"the served model's margin now differs from batch {batch.batch_run_id}'s raw_score by "
                                  f"{worst_margin:.3g}; the batch is not this model's output")
    summary = pd.concat(summaries, ignore_index=True).assign(explain_run_id=run_id)[list(SUMMARY_COLUMNS)]
    attributions = pd.concat(longs, ignore_index=True).assign(explain_run_id=run_id)
    explain_seconds = time.perf_counter() - t0

    # --- bounded set --------------------------------------------------------
    import pyarrow.parquet as pq

    risk_cols = [c for c in pq.read_schema(risk_dir / "risk_scores.parquet").names
                 if c in RISK_READ or c.startswith("points_") or c.startswith("component_")]
    risk = pd.read_parquet(risk_dir / "risk_scores.parquet", columns=risk_cols)
    risk["user_id"] = risk["user_id"].astype("string").str.strip().str.casefold()
    risk["date"] = risk["date"].astype("string")
    sel, sel_info = select_rows(risk, top_k_per_day=args.select_top_k_per_day, max_rows=args.max_bounded_rows)
    bounded = aligned(frame, sel[["user_id", "date"]], "the explained rows") if len(sel) else frame.iloc[:0]
    kernel = pd.DataFrame(columns=list(CORROBORATION_COLUMNS))
    kernel_info: dict = {"status": "skipped" if args.no_kernel else "not run"}
    reasons: list[dict] = []
    if len(bounded):
        attr_b = explainer.explain(bounded)
        long_b = top_k_long(attr_b, bounded, args.top_k)
        summ_b = row_summary(attr_b)
        if not args.no_kernel:
            t1 = time.perf_counter()
            try:
                pool, split_record = background_pool(fm.matrix, served.entry, Path(args.splits_dir),
                                                     args.background_pool_rows, args.seed)
                nsamples = "auto" if str(args.kernel_nsamples) == "auto" else int(args.kernel_nsamples)
                corr = KernelCorroborator(served, pool, n_background=args.n_background, nsamples=nsamples, seed=args.seed)
                kernel = corr.corroborate(bounded, attr_b)
                kernel_info = {"status": "done", **corr.describe(), "rows": int(len(kernel)),
                               "background_from": "training users of the served model's own split file (label-free)",
                               "background_split": split_record, "seconds": round(time.perf_counter() - t1, 2)}
            except Exception as exc:     # §36: any corroboration failure degrades, it never blocks the explanations
                kernel_info = {"status": "failed", "reason": str(exc)[:500],
                               "effect": "TreeSHAP explanations stand; corroboration to be retried (Architecture §36)"}
        mctx, mmatch, mitre_reason, mitre_block = _mitre_for(processed, risk_meta, sel[["user_id", "date"]])
        risk_b = aligned(risk, sel[["user_id", "date"]], f"CRI run {risk_dir.name}")
        extra = {"cri_run_id": risk_dir.name}
        unavailable = dict(risk_meta.get("unavailable_components") or {})
        unavailable.pop("mitre_context", None)            # reported in the ATT&CK section instead
        detail_cols = [c for c in bounded.columns if str(c).startswith(("hist_z_", "peer_dev_"))]
        by_key = {k: g for k, g in long_b.groupby(["user_id", "date"], sort=False)}
        for i in range(len(bounded)):
            uid, day = str(bounded["user_id"].iloc[i]), str(bounded["date"].iloc[i])
            factors = by_key.get((uid, day), long_b.iloc[:0]).sort_values("rank").to_dict("records")
            model = model_evidence(summ_b.iloc[i].to_dict(), factors, method=explainer.method,
                                   model_name=served.model_name, model_version=served.model_version,
                                   registry_version=served.registry_version,
                                   anomaly_score=float(risk_b["anomaly_score"].iloc[i]))
            rrow = {**risk_b.iloc[i].to_dict(), **extra}
            mitre = None
            if mctx is not None:
                mitre = mctx.iloc[i].to_dict()
                hit = mmatch[(mmatch["user_id"].astype(str) == uid) & (mmatch["date"].astype(str) == day)]
                mitre["matches"] = hit.sort_values("rule_id").to_dict("records")
            expl = build_explanation(uid, day, model=model, risk=rrow, mitre=mitre,
                                     features_row=bounded.iloc[i][detail_cols].to_dict(),
                                     mitre_unavailable_reason=mitre_reason, unavailable_components=unavailable)
            expl["model_split"] = str(sel["model_split"].iloc[i])
            expl["selected_by"] = [n for n, col in (("severity", "by_severity"), ("anomaly_top_k", "by_anomaly"),
                                                    ("cri_top_k", "by_cri")) if bool(sel[col].iloc[i])]
            expl["explain_run_id"] = run_id
            reasons.append(jsonable(expl))
    else:
        mitre_block = None

    # --- write --------------------------------------------------------------
    atomic_to_parquet(summary, out_dir / SUMMARY_OUTPUT)
    atomic_to_parquet(attributions[[*ATTRIBUTION_COLUMNS, "explain_run_id"]], out_dir / ATTRIBUTIONS_OUTPUT)
    atomic_to_parquet(sel.assign(explain_run_id=run_id), out_dir / SELECTION_OUTPUT)
    atomic_to_parquet(kernel.assign(explain_run_id=run_id), out_dir / KERNEL_OUTPUT)
    _write_jsonl(out_dir / REASONS_OUTPUT, reasons)

    ev = summary[summary["model_split"].isin(["validation", "test"])]
    top_counts = ev["top_feature"].dropna().value_counts().head(10)
    stats = {
        "rows_explained": int(len(summary)),
        "rows_by_model_split": {k: int(v) for k, v in summary["model_split"].astype(str).value_counts().sort_index().items()},
        "additivity_error": _quant(summary["additivity_error"].to_numpy()),
        "max_margin_difference_vs_batch": worst_margin,
        "rows_with_static_trait_in_top5": int(summary["static_in_top5"].sum()),
        "out_of_sample_rows_with_no_raising_factor": int((ev["n_raising"] == 0).sum()),
        "out_of_sample_top_feature_is_calendar_share": float(ev["top_is_calendar"].mean()) if len(ev) else None,
        "out_of_sample_most_frequent_top_features": {str(k): int(v) for k, v in top_counts.items()},
        "attribution_rows": int(len(attributions)),
        "bounded_rows": int(len(bounded)),
        "reasons_written": len(reasons),
        "reasons_deferred": sum(r["status"] != "complete" for r in reasons),
    }
    if len(kernel):
        beats = kernel["deletion_top_beats_random"].dropna().astype(bool)
        stats["kernel"] = {
            "top5_overlap": _quant(kernel["top5_overlap"].to_numpy()),
            "rank_correlation": _quant(kernel["rank_correlation"].to_numpy()),
            "sign_agreement": _quant(kernel["sign_agreement"].to_numpy()),
            "kernel_additivity_error": _quant(kernel["kernel_additivity_error"].to_numpy()),
            "deletion_top_beats_random_share": float(beats.mean()) if len(beats) else None,
            "deletion_drop_top": _quant(kernel["deletion_drop_top"].to_numpy()),
            "deletion_drop_random": _quant(kernel["deletion_drop_random"].to_numpy()),
        }
    meta = {
        "chapter": 11, "explain_version": EXPLAIN_VERSION, "explain_run_id": run_id, "profile": args.profile,
        "reportable": args.profile != "dev", "rows_option": args.rows, "top_k": int(args.top_k),
        "served": served.describe(), "serving_source": serving.source, "explainer": explainer.describe(),
        "source_batch": {"batch_run_id": batch.batch_run_id, "path": str(batch.path)},
        "risk_run": {"cri_run_id": risk_dir.name, "formula_hash": risk_meta.get("formula_hash"),
                     "config_hash": risk_meta.get("config_hash"),
                     "calibration_id": (risk_meta.get("calibration") or {}).get("calibration_id"),
                     "with_mitre": bool(risk_meta.get("mitre"))},
        "mitre": mitre_block,
        "features": {"path": str(fm.features_path), "fingerprint": fp},
        "selection": sel_info, "kernel": kernel_info, "summary": stats,
        "shadow": "not loaded: shadow output never feeds an analyst explanation (N32); see evaluate.py",
        "outputs": {n: str(out_dir / n) for n in (SUMMARY_OUTPUT, ATTRIBUTIONS_OUTPUT, SELECTION_OUTPUT, KERNEL_OUTPUT,
                                                  REASONS_OUTPUT)},
        "explain_seconds": round(explain_seconds, 2),
        "rows_per_second": round(len(summary) / explain_seconds, 1) if explain_seconds > 0 else None,
        "wall_seconds": round(time.perf_counter() - started, 2), "peak_rss_mb": round(memory_rss_mb(), 1),
    }
    tmp = out_dir / (EXPLAIN_META + ".tmp")
    tmp.write_text(json.dumps(jsonable(meta), indent=2, default=str), encoding="utf-8")
    tmp.replace(out_dir / EXPLAIN_META)
    append_experiment_runlog({
        "stage": "chapter11_explain_batch", "explain_run_id": run_id, "profile": args.profile,
        "reportable": meta["reportable"], "method": explainer.method, "served_model": served.model_name,
        "served_registry_version": served.registry_version, "served_model_version": served.model_version,
        "source_batch_run_id": batch.batch_run_id, "cri_run_id": risk_dir.name,
        "rows_explained": stats["rows_explained"], "bounded_rows": stats["bounded_rows"],
        "kernel_status": kernel_info.get("status"),
        "max_additivity_error": stats["additivity_error"].get("max"),
        "rows_with_static_trait_in_top5": stats["rows_with_static_trait_in_top5"],
        "features_fingerprint": fp, "wall_seconds": meta["wall_seconds"], "peak_rss_mb": meta["peak_rss_mb"],
    })
    print(f"[explain] {run_id}: {stats['rows_explained']} user-days explained by {explainer.method} on "
          f"{served.model_name} {served.registry_version} in {explain_seconds:.1f}s; max additivity error "
          f"{stats['additivity_error'].get('max', float('nan')):.2e}", flush=True)
    print(f"[explain] bounded set ({sel_info['rule']}): {stats['bounded_rows']} user-days "
          f"{sel_info.get('by_split', {})}, {sel_info.get('truncated', 0)} cut by --max-bounded-rows; "
          f"KernelSHAP {kernel_info.get('status')}", flush=True)
    if "kernel" in stats:
        k = stats["kernel"]
        print(f"[explain] KernelSHAP vs {explainer.method}: median top-5 overlap {k['top5_overlap'].get('median')}, "
              f"deletion beats random on {k['deletion_top_beats_random_share']} of rows", flush=True)
    if stats["rows_with_static_trait_in_top5"]:
        print(f"[explain] WARNING: {stats['rows_with_static_trait_in_top5']} rows have a static trait in their top 5 "
              "(N22); they are suppressed in reasons", flush=True)
    print(f"[explain] written: {out_dir}", flush=True)
    return meta


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        run(args)
    except (ScoringUnavailableError, ExplainBatchRefused, ExplainSourceError, SourceError, ExplanationFailedError) as exc:
        print(f"chapter11 explain batch refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
