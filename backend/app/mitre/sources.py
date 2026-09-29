"""Where enrichment runs live, and reading them aligned to a set of user-days.

Label-free and model-free (N5, N42). Shared by batch.py, the CRI batch, the
readout and the verifiers so "the newest enrichment run for this profile"
means one thing.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

CONTEXT_OUTPUT = "mitre_context.parquet"
MATCHES_OUTPUT = "mitre_matches.parquet"
MITRE_META = "mitre_meta.json"


class MitreSourceError(RuntimeError):
    """A required enrichment run is missing or inconsistent."""


def runs_root(processed: str | Path) -> Path:
    return Path(processed) / "mitre" / "chapter10"


def mitre_run_dir(processed: str | Path, run_id: str | None, profile: str | None = None) -> Path:
    root = runs_root(processed)
    if run_id:
        path = root / run_id
    else:
        if not root.exists():
            raise MitreSourceError(f"no Chapter 10 enrichment run under {root}")
        runs = []
        for d in sorted(root.iterdir()):
            meta = d / MITRE_META
            if meta.exists() and (profile is None or json.loads(meta.read_text(encoding="utf-8")).get("profile") == profile):
                runs.append(d)
        if not runs:
            raise MitreSourceError(f"no Chapter 10 enrichment run for profile={profile!r} under {root}")
        path = runs[-1]                      # run ids start with a UTC timestamp
    for f in (CONTEXT_OUTPUT, MATCHES_OUTPUT, MITRE_META):
        if not (path / f).exists():
            raise MitreSourceError(f"enrichment run {path.name} is incomplete (missing {f})")
    return path


def read_meta(run_dir: Path) -> dict:
    return json.loads((run_dir / MITRE_META).read_text(encoding="utf-8"))


def read_context(run_dir: Path, keys: pd.DataFrame, columns: list[str] | None = None) -> pd.DataFrame:
    """Context rows aligned 1:1 with ``keys`` (user_id, date); refuses missing user-days."""
    cols = ["user_id", "date", *(columns or ["mitre_status", "mitre_context"])]
    ctx = pd.read_parquet(run_dir / CONTEXT_OUTPUT, columns=list(dict.fromkeys(cols)))
    ctx["user_id"] = ctx["user_id"].astype("string").str.strip().str.casefold()
    ctx["date"] = ctx["date"].astype("string")
    k = pd.DataFrame({
        "user_id": keys["user_id"].astype("string").str.strip().str.casefold().to_numpy(),
        "date": keys["date"].astype("string").to_numpy(),
        "_pos": np.arange(len(keys)),
    })
    j = k.merge(ctx, on=["user_id", "date"], how="left", validate="one_to_one", indicator=True)
    missing = int((j["_merge"] != "both").sum())
    if missing:
        raise MitreSourceError(f"{missing} user-days have no row in enrichment run {run_dir.name}; "
                               "enrich the same matrix the scores came from")
    return j.sort_values("_pos").drop(columns=["_pos", "_merge"]).reset_index(drop=True)
