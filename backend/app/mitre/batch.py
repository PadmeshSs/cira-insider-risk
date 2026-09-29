"""Batch MITRE enrichment over the Chapter 5 matrix, to Parquet (Bible Ch10 step 3, HCEA §10).

Usage, from backend/ with .env loaded:

    python -m app.mitre.batch --profile full

What it does
    1. Thread caps before numpy (N8).
    2. Loads the technique table and the pinned reference (both sha256-
       checked) and refuses if the matrix is not the one the reference was
       fitted on (fingerprint), or its host classes changed (N7).
    3. Reads user_id, date, the rule columns and the unmapped-tag columns of
       every user-day, and enriches them in one vectorised pass.
    4. Writes ``<processed>/mitre/chapter10/<mitre_run_id>/`` atomically:
       ``mitre_context.parquet`` (one row per user-day), ``mitre_matches.parquet``
       (one row per fired rule) and ``mitre_meta.json``.
    5. Appends one ``chapter10_mitre_batch`` runlog line (R8).

Model-free and label-free: no score, no model_version, no label is read
(N5, N42). The CRI joins ``mitre_context`` with
``python -m app.cri.batch --profile full --mitre-run-id <id>``.
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

from app.evaluation.splitting import load_split, rows_for_split  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, atomic_to_parquet, memory_rss_mb  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, feature_fingerprint  # noqa: E402

from . import MITRE_VERSION  # noqa: E402
from .calibrate import matrix_schema, read_rule_columns  # noqa: E402
from .enrich import STATUSES, MitreEnricher, MitreInputError, MitreUnavailableError  # noqa: E402
from .mapping_rules import RULES, RULESET_VERSION, ruleset_hash  # noqa: E402
from .reference import default_models_root, resolve_pin_path  # noqa: E402
from .sources import CONTEXT_OUTPUT, MATCHES_OUTPUT, MITRE_META  # noqa: E402


class MitreBatchRefused(RuntimeError):
    """Nothing was written."""


def summarise(ctx: pd.DataFrame, matches: pd.DataFrame, parts: np.ndarray | None) -> dict:
    out = {
        "rows": int(len(ctx)),
        "status": {s: int((ctx["mitre_status"] == s).sum()) for s in STATUSES},
        "matches": int(len(matches)),
        "by_rule": {r.rule_id: {"technique_id": r.technique_id, "user_days": int((matches["rule_id"] == r.rule_id).sum()),
                                "users": int(matches.loc[matches["rule_id"] == r.rule_id, "user_id"].nunique())}
                    for r in RULES},
        "mitre_context_quantiles": {q: float(np.nanquantile(ctx["mitre_context"], float(q)))
                                    for q in ("0.5", "0.99", "0.999")},
        "unmapped_tagged_user_days": int(ctx["mitre_unmapped_behaviours"].notna().sum()),
    }
    if parts is not None:
        out["mapped_share_by_split"] = {
            p: float((ctx.loc[parts == p, "mitre_status"] == "mapped").mean())
            for p in ("train", "validation", "test") if (parts == p).any()}
    return out


def _parse_args(argv):
    p = argparse.ArgumentParser(description="CIRA Chapter 10 batch MITRE enrichment (label-free, model-free)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--models-dir", default=os.getenv("MODEL_PATH") or str(default_models_root()))
    p.add_argument("--pin-path", default=str(resolve_pin_path()))
    return p.parse_args(argv)


def run(args) -> dict:
    started = time.perf_counter()
    try:
        enricher = MitreEnricher.load(pin_path=args.pin_path, models_root=args.models_dir)
    except MitreUnavailableError as exc:
        raise MitreBatchRefused(str(exc)) from exc
    ref = enricher.reference
    processed = Path(args.processed_dir)
    features_path = processed / "features" / PROFILE_OUTPUT[args.profile]
    if not features_path.exists():
        raise MitreBatchRefused(f"{features_path} not found")
    fp = feature_fingerprint(features_path)
    if fp != ref.meta["features"]["fingerprint"]:
        raise MitreBatchRefused(f"{features_path.name} is not the matrix reference {ref.reference_id} was fitted on "
                                "(fingerprint differs); refit with `python -m app.mitre.calibrate --supersede`")
    names, schema = matrix_schema(features_path)
    if schema.get("host_categories_version") != ref.meta["features"].get("host_categories_version"):
        raise MitreBatchRefused("host categories changed since the reference was fitted (N7); refit")

    t0 = time.perf_counter()
    frame = read_rule_columns(features_path, names)
    out = enricher.enrich(frame)
    compute_seconds = time.perf_counter() - t0
    parts = None
    split_file = Path(ref.meta.get("split", {}).get("path", ""))
    if split_file.exists():
        assignment, _ = load_split(split_file)
        parts = rows_for_split(out.context["user_id"], assignment)
    del frame

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{args.profile}-mitre"
    out_dir = processed / "mitre" / "chapter10" / run_id
    ctx = out.context.assign(mitre_run_id=run_id)
    matches = out.matches.assign(mitre_run_id=run_id)
    atomic_to_parquet(ctx, out_dir / CONTEXT_OUTPUT)
    atomic_to_parquet(matches, out_dir / MATCHES_OUTPUT)
    summary = summarise(ctx, matches, parts)
    meta = {
        "chapter": 10,
        "mitre_version": MITRE_VERSION,
        "mitre_run_id": run_id,
        "profile": args.profile,
        "reportable": args.profile != "dev",
        "ruleset_version": RULESET_VERSION,
        "ruleset_hash": ruleset_hash(),
        "table": enricher.table.describe(),
        "reference": ref.describe(),
        "features": {"path": str(features_path), "fingerprint": fp,
                     "host_categories_version": schema.get("host_categories_version")},
        "model_free": True,
        "summary": summary,
        "outputs": {"context": str(out_dir / CONTEXT_OUTPUT), "matches": str(out_dir / MATCHES_OUTPUT)},
        "compute_seconds": round(compute_seconds, 2),
        "wall_seconds": round(time.perf_counter() - started, 2),
        "peak_rss_mb": round(memory_rss_mb(), 1),
    }
    tmp = out_dir / (MITRE_META + ".tmp")
    tmp.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
    tmp.replace(out_dir / MITRE_META)
    append_experiment_runlog({
        "stage": "chapter10_mitre_batch", "mitre_run_id": run_id, "profile": args.profile,
        "reportable": meta["reportable"], "ruleset_version": RULESET_VERSION, "ruleset_hash": ruleset_hash(),
        "attack_version": enricher.table.attack_version, "reference_id": ref.reference_id,
        "rows": summary["rows"], "status": summary["status"], "matches": summary["matches"],
        "features_fingerprint": fp, "wall_seconds": meta["wall_seconds"], "peak_rss_mb": meta["peak_rss_mb"],
    })
    print(f"[mitre] {run_id}: {summary['rows']} user-days, " +
          ", ".join(f"{k} {v}" for k, v in summary["status"].items()) + f"; {summary['matches']} matches", flush=True)
    for rid, r in summary["by_rule"].items():
        print(f"[mitre]   {rid:<28} {r['technique_id']:<10} {r['user_days']} user-days, {r['users']} users", flush=True)
    return meta


def main(argv=None) -> int:
    args = _parse_args(argv)
    try:
        run(args)
    except (MitreBatchRefused, MitreInputError) as exc:
        print(f"chapter10 MITRE batch refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
