"""Shared utilities for CIRA Chapter 5 feature engineering.

No ground-truth data is imported here.  The feature path is deliberately
label-blind and operates only on processed CERT events/context.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
OFF_HOURS_START = 7
OFF_HOURS_END = 19  # 19:00 is outside the 07:00-18:59 work window.
BASELINE_WINDOW = 30
BASELINE_MIN_PERIODS = 7

# CERT r4.2 has exactly these six file extensions.  These are structural
# categories, not ground-truth-derived "sensitive" lists.
FILE_EXTENSIONS = ("doc", "pdf", "txt", "jpg", "zip", "exe")


def as_user_day_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Return a stable, typed user/day key frame."""
    out = df.copy()
    out["user_id"] = out["user_id"].astype("string")
    out["date"] = pd.to_datetime(out["date"], errors="raise").dt.normalize()
    return out


def day_and_hour_from_cert_date(series: pd.Series) -> tuple[pd.Series, pd.Series]:
    """Use CERT string slicing for hot paths; parse only when needed."""
    s = series.astype("string")
    day = pd.to_datetime(s.str.slice(0, 10), format="%m/%d/%Y", errors="raise")
    hour = pd.to_numeric(s.str.slice(11, 13), errors="raise").astype("int8")
    return day, hour


def normalize_user(series: pd.Series) -> pd.Series:
    return series.astype("string").str.strip().str.casefold()


def normalize_text(series: pd.Series) -> pd.Series:
    return series.astype("string").fillna("").str.strip().str.casefold()


def off_hours(hour: pd.Series) -> pd.Series:
    return ((hour < OFF_HOURS_START) | (hour >= OFF_HOURS_END)).astype("int8")


def ratio(num: pd.Series, den: pd.Series) -> pd.Series:
    return (num.astype("float32") / den.replace(0, np.nan)).astype("float32")


def to_float32(df: pd.DataFrame, exclude: Iterable[str] = ("user_id", "date")) -> pd.DataFrame:
    excluded = set(exclude)
    for col in df.columns:
        if col not in excluded and pd.api.types.is_numeric_dtype(df[col]):
            df[col] = df[col].astype("float32")
    return df


def atomic_to_parquet(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    df.to_parquet(tmp, engine="pyarrow", compression="zstd", index=False)
    os.replace(tmp, path)


def read_parquet_tree(root: Path, columns: list[str] | None = None) -> Iterable[pd.DataFrame]:
    """Yield parquet parts one at a time; never concatenate raw-scale data."""
    for path in sorted(root.rglob("*.parquet")):
        yield pd.read_parquet(path, columns=columns, engine="pyarrow")


def parse_host(url: pd.Series) -> pd.Series:
    # CERT r4.2 uses http URLs.  Avoid urllib object creation for 28M rows.
    host = (
        url.astype("string")
        .str.extract(r"^[A-Za-z]+://([^/:?#]+)", expand=False)
        .fillna("")
        .str.casefold()
        .str.rstrip(".")
    )
    return host.astype("string")


def extension(series: pd.Series) -> pd.Series:
    return (
        series.astype("string")
        .str.casefold()
        .str.extract(r"\.([a-z0-9]{1,8})$", expand=False)
        .fillna("other")
    )


def memory_rss_mb() -> float:
    """Best-effort current process RSS in MiB."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)

        handle = ctypes.windll.kernel32.GetCurrentProcess()
        get_info = ctypes.windll.psapi.GetProcessMemoryInfo

        get_info.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD,
        ]
        get_info.restype = wintypes.BOOL

        ok = get_info(
            handle,
            ctypes.byref(counters),
            counters.cb,
        )

        if ok:
            return counters.WorkingSetSize / (1024 ** 2)

        return float("nan")

    import resource

    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    if os.uname().sysname == "Linux":
        return float(value / 1024)

    return float(value / (1024 ** 2))

def timed_stage(name: str, runlog: Path, **extra):
    return _StageTimer(name, runlog, extra)


class _StageTimer:
    def __init__(self, name: str, runlog: Path, extra: dict | None = None):
        self.name = name
        self.runlog = runlog
        self.extra = dict(extra or {})
        self.started = 0.0
        self.peak = 0.0

    def __enter__(self):
        self.started = time.perf_counter()
        self.peak = memory_rss_mb()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.peak = max(self.peak, memory_rss_mb())
        record = {
            "stage": self.name,
            "wall_seconds": round(time.perf_counter() - self.started, 3),
            "peak_rss_mb": round(self.peak, 2),
            "status": "failed" if exc else "completed",
            **self.extra,
        }
        self.runlog.parent.mkdir(parents=True, exist_ok=True)
        with self.runlog.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        return False


def ensure_pyarrow() -> None:
    try:
        import pyarrow  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "Chapter 5 requires pyarrow for Parquet I/O. Add pyarrow to backend/requirements.txt."
        ) from exc


# ---------------------------------------------------------------------------
# Chunk-safe combination of per-part aggregates (HCEA §5.3)
# ---------------------------------------------------------------------------
# Per-part aggregates are combined with a per-column rule.  Only additive
# columns may be summed.  Distinct counts are NEVER combined here: they are
# recomputed exactly from deduplicated (user, day, item) triples.

def combine_rule(column: str) -> str:
    """Return the correct cross-part reducer for an aggregate column."""
    if column.endswith(("_first_hour",)) or column == "first_auth_hour":
        return "min"
    if column.endswith(("_last_hour",)) or column == "last_auth_hour":
        return "max"
    if column.endswith("_flag"):
        return "max"
    return "sum"


def is_distinct_column(column: str) -> bool:
    return "distinct" in column


def is_ratio_column(column: str) -> bool:
    return column.endswith(("_ratio", "_avg"))


# ---------------------------------------------------------------------------
# Host classification (vectorised over unique hosts, not 28M rows)
# ---------------------------------------------------------------------------

def host_matches(host: str, suffixes: tuple[str, ...]) -> bool:
    return any(host == s or host.endswith("." + s) for s in suffixes)


def categorize_hosts(
    host: pd.Series,
    categories: dict[str, tuple[str, ...]],
) -> pd.DataFrame:
    """Return one int8 indicator column per category, aligned to ``host``."""
    codes, uniques = pd.factorize(host.astype("string").fillna(""), sort=False)
    out = {}
    for name, suffixes in categories.items():
        lookup = np.fromiter(
            (host_matches(str(h), suffixes) for h in uniques),
            dtype=np.int8,
            count=len(uniques),
        )
        values = lookup[codes] if len(uniques) else np.zeros(len(host), dtype=np.int8)
        out[name] = values
    return pd.DataFrame(out, index=host.index)


# ---------------------------------------------------------------------------
# Evidence trail (HCEA R8)
# ---------------------------------------------------------------------------

def repo_root() -> Path:
    # backend/app/feature_engineering/common.py -> repo root
    return Path(__file__).resolve().parents[3]


def append_experiment_runlog(record: dict) -> Path:
    """Append one JSON line to experiments/runlog.jsonl in the repository."""
    path = Path(os.getenv("CIRA_RUNLOG", str(repo_root() / "experiments" / "runlog.jsonl")))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, default=str) + "\n")
    return path
