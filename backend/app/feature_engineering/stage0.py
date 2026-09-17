"""Chapter 5 Stage 0: streaming CERT r4.2 -> typed Parquet.

Raw CSV is never loaded wholesale.  Each domain is read exactly once by this
stage, in chunks, and written atomically as zstd Parquet parts partitioned by
month.  Ground truth is never read or referenced.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pandas as pd

from .common import DATE_FORMAT, atomic_to_parquet, ensure_pyarrow, memory_rss_mb, normalize_user, parse_host, extension, timed_stage

DOMAIN_COLUMNS: dict[str, list[str]] = {
    "logon": ["id", "date", "user", "pc", "activity"],
    "device": ["id", "date", "user", "pc", "activity"],
    "file": ["id", "date", "user", "pc", "filename", "content"],
    "email": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments"],
    "http": ["id", "date", "user", "pc", "url"],
}

CSV_NAMES = {name: f"{name}.csv" for name in DOMAIN_COLUMNS}
CHUNK_SIZES = {"http": 500_000, "email": 1_000_000, "logon": 1_000_000, "device": 1_000_000, "file": 1_000_000}


def _canonical_domain_chunk(domain: str, chunk: pd.DataFrame, timezone: str) -> pd.DataFrame:
    out = chunk.copy()
    out.columns = [str(c).strip().lower() for c in out.columns]
    out["user_id"] = normalize_user(out["user"])
    out["device_id"] = out["pc"].astype("string").str.strip().str.casefold()
    out["event_id"] = out["id"].astype("string").str.strip()
    # CERT's date has a fixed format.  Parse only once per retained row.
    ts = pd.to_datetime(out["date"].astype("string").str.strip(), format=DATE_FORMAT, errors="raise")
    out["timestamp"] = ts.dt.tz_localize(timezone)
    out["date_day"] = ts.dt.normalize()
    out["hour"] = ts.dt.hour.astype("int8")
    out["weekday"] = ts.dt.dayofweek.astype("int8")
    out["month"] = ts.dt.strftime("%Y-%m")

    if domain in {"logon", "device"}:
        out["activity"] = out["activity"].astype("string").str.strip().str.casefold()
    if domain == "file":
        out["filename"] = out["filename"].astype("string").fillna("")
        out["file_extension"] = extension(out["filename"])
    if domain == "email":
        for col in ("to", "cc", "bcc", "from"):
            out[col] = out[col].astype("string").fillna("").str.strip().str.casefold()
        out["size"] = pd.to_numeric(out["size"], errors="coerce").fillna(0).astype("int32")
        out["attachments"] = pd.to_numeric(out["attachments"], errors="coerce").fillna(0).astype("int16")
    if domain == "http":
        out["host"] = parse_host(out["url"])

    # Feature-safe processed representation: raw content/URLs are not carried forward.
    keep = ["event_id", "timestamp", "date_day", "hour", "weekday", "month", "user_id", "device_id"]
    if domain in {"logon", "device"}:
        keep += ["activity"]
    elif domain == "file":
        keep += ["file_extension"]
    elif domain == "email":
        keep += ["to", "cc", "bcc", "from", "size", "attachments"]
    elif domain == "http":
        keep += ["host"]

    out = out[keep]
    out["event_id"] = out["event_id"].astype("string")
    out["user_id"] = out["user_id"].astype("string")
    out["device_id"] = out["device_id"].astype("string")
    out["month"] = out["month"].astype("string")
    return out


def convert_domain(
    raw_dir: Path,
    processed_dir: Path,
    domain: str,
    *,
    profile: str,
    timezone: str = "UTC",
    users: set[str] | None = None,
    start: str | None = None,
    end: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    ensure_pyarrow()
    src = raw_dir / CSV_NAMES[domain]
    out_root = (
    processed_dir
    / "events"
    / f"profile={profile}"
    / f"source_type={domain}"
)
    if not src.exists():
        raise FileNotFoundError(src)
    if force and out_root.exists():
        for p in out_root.rglob("*.parquet"):
            p.unlink()
    out_root.mkdir(parents=True, exist_ok=True)
    rows = 0
    written = 0
    peak = memory_rss_mb()
    start_ts = pd.Timestamp(start) if start else None
    end_ts = pd.Timestamp(end) if end else None
    runlog = processed_dir / "_runlog" / "stages.jsonl"
    with timed_stage(f"stage0:{domain}", runlog):
        for part, chunk in enumerate(pd.read_csv(src, usecols=DOMAIN_COLUMNS[domain], chunksize=CHUNK_SIZES[domain], low_memory=False)):
            rows += len(chunk)
            normalized = _canonical_domain_chunk(domain, chunk, timezone)
            if users is not None:
                normalized = normalized[normalized["user_id"].isin(users)]
            if start_ts is not None:
                normalized = normalized[normalized["date_day"] >= start_ts]
            if end_ts is not None:
                normalized = normalized[normalized["date_day"] < end_ts]
            if normalized.empty:
                continue
            peak = max(peak, memory_rss_mb())
            month = str(normalized["month"].iloc[0])
            # Raw files are globally time-sorted, so a chunk can span at most a small
            # number of month partitions. Split by month without retaining prior chunks.
            for month_value, month_df in normalized.groupby("month", sort=False):
                target_dir = out_root / f"month={month_value}"
                target = target_dir / f"part-{part:06d}.parquet"
                atomic_to_parquet(month_df.drop(columns=["month"]), target)
                written += len(month_df)
    return {"domain": domain, "raw_rows_seen": rows, "rows_written": written, "peak_rss_mb": peak}


def run_stage0(
    raw_dir: str | Path,
    processed_dir: str | Path,
    *,
    profile: str,
    timezone: str = "UTC",
    users: set[str] | None = None,
    start: str | None = None,
    end: str | None = None,
    force: bool = False,
) -> list[dict[str, Any]]:
    raw_dir, processed_dir = Path(raw_dir), Path(processed_dir)

    results = []

    marker_root = (
        processed_dir
        / "_runlog"
        / "stage0_domains"
        / profile
    )
    marker_root.mkdir(parents=True, exist_ok=True)

    for domain in ("logon", "device", "file", "email", "http"):
        marker = marker_root / f"{domain}.json"

        if marker.exists() and not force:
            results.append(
                json.loads(marker.read_text(encoding="utf-8"))
            )
            continue

        result = convert_domain(
            raw_dir,
            processed_dir,
            domain,
            profile=profile,
            timezone=timezone,
            users=users,
            start=start,
            end=end,
            force=force,
        )

        marker.write_text(
            json.dumps(result, indent=2, default=str),
            encoding="utf-8",
        )

        results.append(result)

    return results


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--raw-dir", required=True)
    p.add_argument("--processed-dir", required=True)
    p.add_argument("--timezone", default="UTC")
    p.add_argument("--start")
    p.add_argument("--end")
    p.add_argument("--force", action="store_true")
    args = p.parse_args()
    results = run_stage0(args.raw_dir, args.processed_dir, timezone=args.timezone, start=args.start, end=args.end, force=args.force)
    print(json.dumps(results, indent=2, default=str))

if __name__ == "__main__":
    main()
