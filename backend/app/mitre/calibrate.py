"""Fit and pin the MITRE rarity reference (Chapter 10, N42).

Usage, from backend/ with .env loaded:

    python -m app.mitre.calibrate --profile full
    python -m app.mitre.calibrate --profile full --supersede "<reason>"

What it does
    1. Thread caps before numpy (N8).
    2. Loads the committed technique table (sha256 and version pin checked)
       and validates every rule against it and against the Chapter 5 matrix
       schema. Any problem stops the run before anything is fitted.
    3. Loads the shared user split (``experiments/splits/user_split_<profile>
       _seed<seed>.json``, N11) and keeps the validation users' rows. No
       model's batch is read: the reference is model-free.
    4. Reads only user_id, date and the rule columns (HCEA R3/R4), fits the
       stage-1 and stage-2 rarity maps on the scale of CRI_RARITY_DECADES.
    5. Writes ``models/saved_models/mitre/<reference_id>/`` and points
       ``experiments/chapter10_mitre_reference.json`` at it with sha256.
    6. Label-free report in ``reference.json``: how often each rule fires on
       the reference, the strength of a single triggering event per rule,
       the distribution of mitre_context, and the share of user-days mapped.
    7. Appends one ``chapter10_mitre_reference`` runlog line.
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
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.cri.calibration import file_sha256  # noqa: E402
from app.cri.config import CRIConfig  # noqa: E402
from app.evaluation.splitting import load_split, rows_for_split  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, memory_rss_mb, repo_root  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, feature_fingerprint  # noqa: E402

from . import MITRE_VERSION  # noqa: E402
from .mapping_rules import RULES, RULESET_VERSION, flag_columns, required_columns, ruleset_hash, validate_rules  # noqa: E402
from .reference import (  # noqa: E402
    DEFINITION_VERSION,
    MitreMaps,
    default_models_root,
    fit_maps,
    resolve_pin_path,
    save_reference,
)
from .techniques import TechniqueTableError, load_technique_table  # noqa: E402

DEFAULT_MIN_REFERENCE_ROWS = 1000
QUANTILES = ("0.5", "0.9", "0.99", "0.999")


class ReferenceRefused(RuntimeError):
    """Nothing was written."""


def split_path(splits_dir: str | Path, profile: str, seed: int) -> Path:
    return Path(splits_dir) / f"user_split_{profile}_seed{seed}.json"


def matrix_schema(features_path: Path) -> tuple[list[str], dict]:
    import pyarrow.parquet as pq

    names = pq.read_schema(features_path).names
    schema = {}
    for cand in (features_path.parent / f"feature_schema_{features_path.stem.split('_')[-1]}.json",
                 features_path.parent / "feature_schema.json"):
        if cand.exists():
            schema = json.loads(cand.read_text(encoding="utf-8"))
            break
    return names, schema


def read_rule_columns(features_path: Path, names: list[str]) -> pd.DataFrame:
    wanted = ["user_id", "date", *required_columns(), *[c for c in flag_columns() if c in names]]
    frame = pd.read_parquet(features_path, columns=list(dict.fromkeys(wanted)))
    frame["user_id"] = frame["user_id"].astype("string").str.strip().str.casefold()
    frame["date"] = frame["date"].astype("string")
    return frame


def report(reference: pd.DataFrame, maps: MitreMaps) -> dict:
    block = maps.strengths(reference)
    stat, _ = maps.max_strength(block)
    ctx = maps.context(stat)
    fired = {}
    for j, r in enumerate(RULES):
        v = reference[r.intensity_column].to_numpy(dtype="float64", na_value=np.nan)
        one = float(maps.rule_strength(r, np.array([1.0]))[0])
        fired[r.rule_id] = {
            "technique_id": r.technique_id,
            "fires_on_share_of_reference": float((v > 0).mean()),
            "users_with_any_firing": int(reference.loc[v > 0, "user_id"].nunique()),
            "strength_of_one_event": one,
            "strength_q99_when_fired": float(np.quantile(block[v > 0, j], 0.99)) if (v > 0).any() else None,
        }
    finite = ctx[np.isfinite(ctx)]
    return {
        "rules": fired,
        "mapped_share": float((stat > 0).mean()),
        "mitre_context_quantiles": {q: float(np.quantile(finite, float(q))) for q in QUANTILES} if len(finite) else {},
        "mitre_context_max": float(finite.max()) if len(finite) else None,
        "max_reachable": float(np.log10(len(reference) + 1) / maps.decades),
        "note": ("label-free; how often a rule fires on ordinary validation days is the cost side of each mapping "
                 "and is why rule strength is graded by rarity rather than set to 1"),
    }


def _parse_args(argv):
    root = repo_root()
    p = argparse.ArgumentParser(description="CIRA Chapter 10: fit and pin the MITRE rarity reference (label-free)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--splits-dir", default=str(root / "experiments" / "splits"))
    p.add_argument("--seed", type=int, default=int(os.getenv("CIRA_SEED", "42")))
    p.add_argument("--models-dir", default=os.getenv("MODEL_PATH") or str(default_models_root()))
    p.add_argument("--pin-path", default=str(resolve_pin_path()))
    p.add_argument("--supersede", default=None, metavar="REASON")
    p.add_argument("--min-reference-rows", type=int, default=DEFAULT_MIN_REFERENCE_ROWS)
    return p.parse_args(argv)


def run(args) -> dict:
    started = time.perf_counter()
    try:
        table = load_technique_table()
    except TechniqueTableError as exc:
        raise ReferenceRefused(str(exc)) from exc
    processed = Path(args.processed_dir)
    features_path = processed / "features" / PROFILE_OUTPUT[args.profile]
    if not features_path.exists():
        raise ReferenceRefused(f"{features_path} not found; run the Chapter 5 pipeline for profile={args.profile}")
    names, schema = matrix_schema(features_path)
    problems = validate_rules(table, names)
    if problems:
        raise ReferenceRefused("rules do not validate: " + "; ".join(problems))

    sp = split_path(args.splits_dir, args.profile, args.seed)
    if not sp.exists():
        raise ReferenceRefused(f"{sp} not found; the shared user split comes from Chapter 6 (N11)")
    assignment, split_meta = load_split(sp)
    frame = read_rule_columns(features_path, names)
    part = rows_for_split(frame["user_id"], assignment)
    reference = frame[part == "validation"].reset_index(drop=True)
    if len(reference) < args.min_reference_rows:
        raise ReferenceRefused(f"only {len(reference)} validation user-days; at least {args.min_reference_rows} "
                               "are needed for a usable rarity scale")
    decades = CRIConfig.from_env().rarity_decades
    maps = fit_maps(reference, decades)

    stamp = utc_run_stamp()
    ref_id = f"{stamp}-{args.profile}-mitre"
    meta = {
        "chapter": 10,
        "reference_id": ref_id,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mitre_version": MITRE_VERSION,
        "definition_version": DEFINITION_VERSION,
        "ruleset_version": RULESET_VERSION,
        "ruleset_hash": ruleset_hash(),
        "attack_version": table.attack_version,
        "table_sha256": table.table_sha256,
        "bundle_sha256": table.bundle_sha256,
        "rarity_decades": decades,
        "profile": args.profile,
        "reportable": args.profile != "dev",
        "reference": {"part": "validation", "rows": int(len(reference)), "users": int(reference["user_id"].nunique()),
                      "days": int(reference["date"].nunique()), "source": "shared user split (N11), not a model batch",
                      "columns": [c for c in reference.columns if c not in ("user_id", "date")]},
        "split": {"path": str(sp), "sha256": file_sha256(sp), "version": split_meta.get("version"),
                  "seed": split_meta.get("seed")},
        "features": {"path": str(features_path), "fingerprint": feature_fingerprint(features_path),
                     "host_categories_version": schema.get("host_categories_version"),
                     "pipeline_version": schema.get("pipeline_version")},
        "report": report(reference, maps),
    }
    pin = save_reference(meta, reference[["user_id", "date", *required_columns()]], models_root=Path(args.models_dir),
                         pin_path=Path(args.pin_path), supersede_reason=args.supersede)
    append_experiment_runlog({
        "stage": "chapter10_mitre_reference", "reference_id": ref_id, "profile": args.profile,
        "reportable": meta["reportable"], "ruleset_version": RULESET_VERSION, "ruleset_hash": ruleset_hash(),
        "attack_version": table.attack_version, "reference_rows": len(reference),
        "mapped_share": meta["report"]["mapped_share"], "superseded": bool(args.supersede),
        "wall_seconds": round(time.perf_counter() - started, 2), "peak_rss_mb": round(memory_rss_mb(), 1),
    })
    print(f"[mitre] reference {ref_id}: {len(reference)} validation user-days, ATT&CK {table.attack_version}, "
          f"ruleset {RULESET_VERSION} ({ruleset_hash()})", flush=True)
    for rid, r in meta["report"]["rules"].items():
        print(f"[mitre]   {rid:<28} {r['technique_id']:<10} fires on {r['fires_on_share_of_reference']:.4f} of "
              f"reference days; one event -> strength {r['strength_of_one_event']:.3f}", flush=True)
    print(f"[mitre] mapped share {meta['report']['mapped_share']:.4f}; pinned in {args.pin_path}", flush=True)
    return {"meta": meta, "pin": pin}


def main(argv=None) -> int:
    args = _parse_args(argv)
    try:
        run(args)
    except (ReferenceRefused, FileExistsError) as exc:
        print(f"chapter10 MITRE reference refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
