"""Where the CRI reads its inputs: Chapter 8 batches and Chapter 9 risk runs.

Label-free (N5). Shared by calibrate.py, batch.py, evaluate.py and the
verifier so that "the newest batch for this profile" means one thing.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

CH8_OUTPUT = "anomaly_scores.parquet"
CH8_META = "batch_meta.json"
RISK_OUTPUT = "risk_scores.parquet"
RISK_META = "cri_meta.json"


class SourceError(RuntimeError):
    """A required input is missing or inconsistent."""


@dataclass
class Chapter8Batch:
    batch_run_id: str
    path: Path
    meta: dict

    @property
    def served(self) -> dict:
        return self.meta.get("served") or {}

    def read(self, *, role: str | None = "served", columns: list[str] | None = None) -> pd.DataFrame:
        if columns is not None and role is not None and "role" not in columns:
            columns = [*columns, "role"]
        frame = pd.read_parquet(self.path / CH8_OUTPUT, columns=columns)
        if role is not None:
            frame = frame[frame["role"] == role].reset_index(drop=True)
        frame["user_id"] = frame["user_id"].astype("string").str.strip().str.casefold()
        frame["date"] = frame["date"].astype("string")
        return frame


def _newest(root: Path, meta_name: str, profile: str | None, what: str) -> Path:
    if not root.exists():
        raise SourceError(f"no {what} under {root}")
    runs = []
    for d in sorted(root.iterdir()):
        meta = d / meta_name
        if not meta.exists():
            continue
        m = json.loads(meta.read_text(encoding="utf-8"))
        if profile is None or m.get("profile") == profile:
            runs.append(d)
    if not runs:
        raise SourceError(f"no {what} for profile={profile!r} under {root}")
    return runs[-1]          # run ids start with a UTC timestamp, so the last is the newest


def chapter8_batch(processed: str | Path, batch_run_id: str | None, profile: str | None) -> Chapter8Batch:
    root = Path(processed) / "scores" / "chapter8"
    path = root / batch_run_id if batch_run_id else _newest(root, CH8_META, profile, "Chapter 8 batch")
    if not (path / CH8_OUTPUT).exists() or not (path / CH8_META).exists():
        raise SourceError(f"Chapter 8 batch {path.name} is incomplete (needs {CH8_OUTPUT} and {CH8_META})")
    meta = json.loads((path / CH8_META).read_text(encoding="utf-8"))
    if profile is not None and meta.get("profile") != profile:
        raise SourceError(f"batch {path.name} is profile {meta.get('profile')!r}, not {profile!r}")
    return Chapter8Batch(path.name, path, meta)


def risk_run_dir(processed: str | Path, cri_run_id: str | None, profile: str | None = None) -> Path:
    root = Path(processed) / "risk" / "chapter9"
    path = root / cri_run_id if cri_run_id else _newest(root, RISK_META, profile, "Chapter 9 risk run")
    if not (path / RISK_OUTPUT).exists() or not (path / RISK_META).exists():
        raise SourceError(f"Chapter 9 risk run {path.name} is incomplete")
    return path
