"""Chapter 5 Stage 0: streaming CERT r4.2 -> typed Parquet.

Raw CSV is never loaded wholesale (HCEA R1).  Each domain is read in chunks
and written atomically as zstd Parquet parts partitioned by month (R2).
Ground truth is never read or referenced here.

Chapter 4 policy, applied vectorised per chunk (the per-event Pydantic path
in app.preprocessing is kept for the canonical contract and tests; running it
on 3.2x10^7 rows is outside the HCEA time budget):
  * identifiers: strip + casefold (same result as normalize_identifier for
    CERT's ASCII ids);
  * timestamps: fixed CERT format, localised to the configured timezone;
  * malformed rows (unparseable date, missing id/user/pc) are written to a
    rejected sink with a reason code, never silently dropped;
  * duplicate source ids within a chunk are rejected as ``duplicate_event``.
    CERT ids are unique per domain; a global cross-chunk dedupe would need a
    multi-GB id set and is intentionally not done (documented deviation);
  * missing numeric values stay null (email size/attachments are not
    zero-filled).

Resumability (R7): every source chunk writes its outputs, then a ``.done``
marker.  A re-run skips chunks whose marker exists, so a crash at 80% costs
the remaining 20%.  A changed configuration (profile users, window, code
version) invalidates the domain's outputs and markers automatically.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pandas as pd

from .common import DATE_FORMAT, atomic_to_parquet, ensure_pyarrow, extension, memory_rss_mb, normalize_user, parse_host, timed_stage

STAGE0_VERSION = "stage0-v2"

DOMAIN_COLUMNS: dict[str, list[str]] = {
    "logon": ["id", "date", "user", "pc", "activity"],
    "device": ["id", "date", "user", "pc", "activity"],
    "file": ["id", "date", "user", "pc", "filename"],
    "email": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments"],
    "http": ["id", "date", "user", "pc", "url"],
}
DOMAINS = ("logon", "device", "file", "email", "http")
CSV_NAMES = {name: f"{name}.csv" for name in DOMAIN_COLUMNS}
# HCEA §5.2: 500k for http, 1M for the smaller domains. Halve if RSS > 8 GB.
CHUNK_SIZES = {"http": 500_000, "email": 1_000_000, "logon": 1_000_000, "device": 1_000_000, "file": 1_000_000}
_READ_DTYPES = {"id": "string", "date": "string", "user": "string", "pc": "string"}


def config_fingerprint(profile: str, users: set[str] | None, start: str | None, end: str | None, timezone: str) -> str:
    payload = json.dumps(
        {
            "version": STAGE0_VERSION,
            "profile": profile,
            "users": sorted(users) if users is not None else None,
            "start": start,
            "end": end,
            "timezone": timezone,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _split_valid(domain: str, chunk: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (valid rows with parsed timestamp, rejected rows with reason)."""
    raw_date = chunk["date"].astype("string").str.strip()
    ts = pd.to_datetime(raw_date, format=DATE_FORMAT, errors="coerce")
    reason = pd.Series(pd.NA, index=chunk.index, dtype="string")
    for col, code in (("id", "missing_event_id"), ("user", "missing_user_id"), ("pc", "missing_device_id")):
        blank = chunk[col].isna() | chunk[col].astype("string").str.strip().eq("")
        reason = reason.mask(reason.isna() & blank, code)
    reason = reason.mask(reason.isna() & ts.isna(), "unparseable_timestamp")
    ids = chunk["id"].astype("string").str.strip()
    dup = ids.duplicated(keep="first") & reason.isna()
    reason = reason.mask(dup, "duplicate_event")

    bad = reason.notna()
    rejected = chunk.loc[bad, ["id", "date", "user", "pc"]].astype("string").copy()
    rejected["reason_code"] = reason[bad]
    rejected["domain"] = domain
    valid = chunk.loc[~bad].copy()
    valid["_ts"] = ts[~bad]
    return valid, rejected


def _canonical_domain_chunk(domain: str, chunk: pd.DataFrame, timezone: str) -> pd.DataFrame:
    out = chunk
    out["user_id"] = normalize_user(out["user"])
    out["device_id"] = out["pc"].astype("string").str.strip().str.casefold()
    out["event_id"] = out["id"].astype("string").str.strip()
    ts = out.pop("_ts")
    out["timestamp"] = ts.dt.tz_localize(timezone)
    out["date_day"] = ts.dt.normalize()
    out["hour"] = ts.dt.hour.astype("int8")
    out["weekday"] = ts.dt.dayofweek.astype("int8")
    out["month"] = ts.dt.strftime("%Y-%m")

    keep = ["event_id", "timestamp", "date_day", "hour", "weekday", "month", "user_id", "device_id"]
    if domain in {"logon", "device"}:
        out["activity"] = out["activity"].astype("string").str.strip().str.casefold()
        keep += ["activity"]
    elif domain == "file":
        out["file_extension"] = extension(out["filename"].astype("string").fillna(""))
        keep += ["file_extension"]
    elif domain == "email":
        for col in ("to", "cc", "bcc", "from"):
            out[col] = out[col].astype("string").fillna("").str.strip().str.casefold()
        # Missing stays missing (Chapter 4 policy): no zero-fill.
        out["size"] = pd.to_numeric(out["size"], errors="coerce").astype("float32")
        out["attachments"] = pd.to_numeric(out["attachments"], errors="coerce").astype("float32")
        keep += ["to", "cc", "bcc", "from", "size", "attachments"]
    elif domain == "http":
        # D-8: raw URL dropped; host kept. Source id preserves traceability.
        out["host"] = parse_host(out["url"])
        keep += ["host"]

    out = out[keep].copy()
    for col in ("event_id", "user_id", "device_id", "month"):
        out[col] = out[col].astype("string")
    return out


def _domain_paths(processed_dir: Path, profile: str, domain: str) -> dict[str, Path]:
    return {
        "events": processed_dir / "events" / f"profile={profile}" / f"source_type={domain}",
        "rejected": processed_dir / "rejected" / f"profile={profile}" / f"source_type={domain}",
        "chunks": processed_dir / "_runlog" / "stage0_parts" / profile / domain,
        "marker": processed_dir / "_runlog" / "stage0_domains" / profile / f"{domain}.json",
    }


def _reset_domain(paths: dict[str, Path]) -> None:
    for key in ("events", "rejected", "chunks"):
        if paths[key].exists():
            shutil.rmtree(paths[key])
    if paths["marker"].exists():
        paths["marker"].unlink()


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
    chunksize: int | None = None,
) -> dict[str, Any]:
    ensure_pyarrow()
    src = raw_dir / CSV_NAMES[domain]
    if not src.exists():
        raise FileNotFoundError(src)
    paths = _domain_paths(processed_dir, profile, domain)
    fingerprint = config_fingerprint(profile, users, start, end, timezone)

    fp_file = paths["chunks"] / "_fingerprint"
    if force or (fp_file.exists() and fp_file.read_text(encoding="utf-8") != fingerprint):
        _reset_domain(paths)
    paths["chunks"].mkdir(parents=True, exist_ok=True)
    fp_file.write_text(fingerprint, encoding="utf-8")

    start_ts = pd.Timestamp(start) if start else None
    end_ts = pd.Timestamp(end) if end else None
    size = chunksize or CHUNK_SIZES[domain]
    totals = {"raw_rows_seen": 0, "rows_written": 0, "rows_rejected": 0, "chunks_skipped": 0}
    peak = memory_rss_mb()
    runlog = processed_dir / "_runlog" / "stages.jsonl"

    with timed_stage(f"stage0:{domain}", runlog, profile=profile, fingerprint=fingerprint):
        reader = pd.read_csv(src, usecols=DOMAIN_COLUMNS[domain], dtype=_READ_DTYPES, chunksize=size, low_memory=False)
        for part, chunk in enumerate(reader):
            done = paths["chunks"] / f"chunk-{part:06d}.done"
            if done.exists():
                counts = json.loads(done.read_text(encoding="utf-8"))
                for key in ("raw_rows_seen", "rows_written", "rows_rejected"):
                    totals[key] += counts[key]
                totals["chunks_skipped"] += 1
                continue

            chunk.columns = [str(c).strip().lower() for c in chunk.columns]
            valid, rejected = _split_valid(domain, chunk)
            normalized = _canonical_domain_chunk(domain, valid, timezone)
            if users is not None:
                normalized = normalized[normalized["user_id"].isin(users)]
                rejected = rejected[normalize_user(rejected["user"]).isin(users) | rejected["user"].isna()]
            if start_ts is not None:
                normalized = normalized[normalized["date_day"] >= start_ts]
            if end_ts is not None:
                normalized = normalized[normalized["date_day"] < end_ts]

            written = 0
            for month_value, month_df in normalized.groupby("month", sort=False):
                target = paths["events"] / f"month={month_value}" / f"part-{part:06d}.parquet"
                atomic_to_parquet(month_df.drop(columns=["month"]), target)
                written += len(month_df)
            if not rejected.empty:
                atomic_to_parquet(rejected.reset_index(drop=True), paths["rejected"] / f"part-{part:06d}.parquet")

            counts = {"raw_rows_seen": len(chunk), "rows_written": written, "rows_rejected": len(rejected)}
            tmp = done.with_suffix(".tmp")
            tmp.write_text(json.dumps(counts), encoding="utf-8")
            os.replace(tmp, done)
            for key in counts:
                totals[key] += counts[key]
            peak = max(peak, memory_rss_mb())

    result = {"domain": domain, "profile": profile, "fingerprint": fingerprint, "peak_rss_mb": round(peak, 1), **totals}
    paths["marker"].parent.mkdir(parents=True, exist_ok=True)
    paths["marker"].write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


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
    domains: tuple[str, ...] = DOMAINS,
) -> list[dict[str, Any]]:
    raw_dir, processed_dir = Path(raw_dir), Path(processed_dir)
    fingerprint = config_fingerprint(profile, users, start, end, timezone)
    results = []
    for domain in domains:
        marker = _domain_paths(processed_dir, profile, domain)["marker"]
        if marker.exists() and not force:
            cached = json.loads(marker.read_text(encoding="utf-8"))
            if cached.get("fingerprint") == fingerprint:
                results.append(cached)
                continue
        results.append(
            convert_domain(
                raw_dir, processed_dir, domain,
                profile=profile, timezone=timezone, users=users,
                start=start, end=end, force=force,
            )
        )
    return results


def main() -> None:
    from app.core.runtime import apply_thread_caps

    apply_thread_caps()
    from .pipeline import PROFILE_CONFIG, _profile_users  # local import: avoids a cycle
    from .context import build_context

    p = argparse.ArgumentParser(description="CIRA Chapter 5 Stage 0 (CSV -> Parquet)")
    p.add_argument("--raw-dir", default=os.getenv("CERT_RAW_DIR"), required=os.getenv("CERT_RAW_DIR") is None)
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--ground-truth-dir", default=os.getenv("CERT_GROUND_TRUTH_DIR"))
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "dev"), choices=tuple(PROFILE_CONFIG))
    p.add_argument("--timezone", default=os.getenv("CERT_SOURCE_TIMEZONE", "UTC"))
    p.add_argument("--domain", action="append", choices=DOMAINS, help="repeatable; default all")
    p.add_argument("--force", action="store_true")
    args = p.parse_args()

    raw_dir, processed_dir = Path(args.raw_dir), Path(args.processed_dir)
    cfg = PROFILE_CONFIG[args.profile]
    build_context(raw_dir, processed_dir)
    users = _profile_users(processed_dir, raw_dir, args.profile, ground_truth_dir=args.ground_truth_dir)
    results = run_stage0(
        raw_dir, processed_dir, profile=args.profile, timezone=args.timezone,
        users=users, start=cfg["start"], end=cfg["end"], force=args.force,
        domains=tuple(args.domain) if args.domain else DOMAINS,
    )
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
