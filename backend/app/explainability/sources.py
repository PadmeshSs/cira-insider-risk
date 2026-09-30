"""Where explain runs and their inputs live, and reading them aligned.

Label-free (N5). Shared by batch.py, runtime.py, evaluate.py and the verifier,
so "the newest explain run for this profile" and "the default risk run" mean
one thing.

Layout of one run: ``<processed>/explanations/chapter11/<explain_run_id>/``
    explanations.parquet          one row per user-day: method, margin,
                                  expected value, additivity error, top factor
    attributions.parquet          top-k features per user-day, long format
    kernel_corroboration.parquet  bounded rows: KernelSHAP agreement, deletion check
    selection.parquet             bounded rows and why each was selected
    reasons.jsonl                 bounded rows: the full analyst explanation
    explain_meta.json             lineage, settings, summary
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

SUMMARY_OUTPUT = "explanations.parquet"
ATTRIBUTIONS_OUTPUT = "attributions.parquet"
KERNEL_OUTPUT = "kernel_corroboration.parquet"
SELECTION_OUTPUT = "selection.parquet"
REASONS_OUTPUT = "reasons.jsonl"
EXPLAIN_META = "explain_meta.json"
REQUIRED = (SUMMARY_OUTPUT, ATTRIBUTIONS_OUTPUT, SELECTION_OUTPUT, REASONS_OUTPUT, EXPLAIN_META)
RISK_META = "cri_meta.json"


class ExplainSourceError(RuntimeError):
    """A required run is missing or inconsistent."""


def runs_root(processed: str | Path) -> Path:
    return Path(processed) / "explanations" / "chapter11"


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def explain_run_dir(processed: str | Path, run_id: str | None, profile: str | None = None) -> Path:
    root = runs_root(processed)
    if run_id:
        path = root / run_id
    else:
        runs = [d for d in sorted(root.iterdir()) if (d / EXPLAIN_META).exists()
                and (profile is None or _read(d / EXPLAIN_META).get("profile") == profile)] if root.exists() else []
        if not runs:
            raise ExplainSourceError(f"no Chapter 11 explain run for profile={profile!r} under {root}")
        path = runs[-1]                          # run ids start with a UTC timestamp
    for f in REQUIRED:
        if not (path / f).exists():
            raise ExplainSourceError(f"explain run {path.name} is incomplete (missing {f})")
    return path


def read_meta(run_dir: Path) -> dict:
    return _read(run_dir / EXPLAIN_META)


def read_reasons(run_dir: Path) -> list[dict]:
    text = (run_dir / REASONS_OUTPUT).read_text(encoding="utf-8")
    return [json.loads(x) for x in text.splitlines() if x.strip()]


def default_risk_run(processed: str | Path, profile: str, batch_run_id: str | None = None) -> Path:
    """The newest default-variant CRI run for the profile, with MITRE if one exists (Chapter 10 is the current formula).

    Ablation variants and runs with disabled components are never used to
    explain: the analyst sees the configured CRI.
    """
    root = Path(processed) / "risk" / "chapter9"
    with_mitre, without = [], []
    for d in sorted(root.iterdir()) if root.exists() else []:
        m = d / RISK_META
        if not m.exists():
            continue
        meta = _read(m)
        if meta.get("profile") != profile or meta.get("variant") != "default" or (meta.get("config") or {}).get("disabled"):
            continue
        if batch_run_id and (meta.get("source_batch") or {}).get("batch_run_id") != batch_run_id:
            continue
        (with_mitre if meta.get("mitre") else without).append(d)
    runs = with_mitre or without
    if not runs:
        raise ExplainSourceError(f"no default CRI run for profile={profile!r}"
                                 + (f" from batch {batch_run_id}" if batch_run_id else "")
                                 + "; run `python -m app.cri.batch --with-mitre` first")
    return runs[-1]


def aligned(frame: pd.DataFrame, keys: pd.DataFrame, what: str) -> pd.DataFrame:
    """Rows of ``frame`` aligned 1:1 with ``keys`` on (user_id, date); refuses missing keys."""
    f = frame.copy()
    f["user_id"] = f["user_id"].astype("string").str.strip().str.casefold()
    f["date"] = f["date"].astype("string")
    k = pd.DataFrame({"user_id": keys["user_id"].astype("string").str.strip().str.casefold().to_numpy(),
                      "date": keys["date"].astype("string").to_numpy(), "_pos": range(len(keys))})
    j = k.merge(f, on=["user_id", "date"], how="left", validate="one_to_one", indicator=True)
    missing = int((j["_merge"] != "both").sum())
    if missing:
        raise ExplainSourceError(f"{missing} user-days have no row in {what}")
    return j.sort_values("_pos").drop(columns=["_pos", "_merge"]).reset_index(drop=True)
