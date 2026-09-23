"""CIRA Chapter 5 end-to-end feature pipeline.

Execution model (HCEA v1.0 §5):
Stage 0  raw CERT CSV -> typed, feature-safe Parquet (resumable per chunk)
Stage 1  domain Parquet -> independent user-day aggregates (cached per domain)
Stage 2  dense calendar spine + explicit missing-value policy + temporal
Stage 3  trailing historical baselines
Stage 4  point-in-time peer context, static psychometric context,
         final float32 matrix + feature_schema.json

Labels are absent from every function in this module.  The only ground-truth
access is ``_profile_users``, which returns a bare set of user ids used to
choose which users are *in* a dev/mid profile (HCEA §4 sampling rule).  No
label value, window or scenario reaches a feature.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Callable

import numpy as np
import pandas as pd

from . import authentication, email, file_activity, network, temporal, usb
from .common import (
    append_experiment_runlog,
    atomic_to_parquet,
    combine_rule,
    ensure_pyarrow,
    is_distinct_column,
    is_ratio_column,
    memory_rss_mb,
    timed_stage,
    to_float32,
)
from .context import build_context, email_directory, load_ldap, load_psychometric
from .historical_baseline import add_baselines
from .network_domains import HOST_CATEGORIES_VERSION
from .peer_group import add_peer_features
from .stage0 import config_fingerprint, run_stage0

FEATURE_PIPELINE_VERSION = "chapter5-v2"

# dev window: CERT r4.2 malicious activity starts mid-2010, so a Jan-Apr 2010
# window contains no insider behaviour at all.  Jun-Aug 2010 keeps the
# 3-month dev budget while overlapping real scenario activity.
PROFILE_CONFIG = {
    "dev": {"insiders": 10, "benign": 40, "start": "2010-06-01", "end": "2010-09-01", "output": "user_day_dev.parquet"},
    "mid": {"insiders": None, "benign": 180, "start": None, "end": None, "output": "user_day_mid.parquet"},
    "full": {"insiders": None, "benign": None, "start": None, "end": None, "output": "user_day_full.parquet"},
}

DOMAIN_ORDER = ("logon", "device", "file", "email", "http")
LABEL_LIKE = {"label", "labels", "malicious", "is_malicious", "ground_truth", "scenario", "target", "y", "insider", "is_insider"}
CONTEXT_STRING_COLUMNS = ["email", "employee_name", "role", "department", "business_unit", "functional_unit", "team", "supervisor"]
PSYCH_RENAME = {"o": "psych_openness", "c": "psych_conscientiousness", "e": "psych_extraversion", "a": "psych_agreeableness", "n": "psych_neuroticism"}


# ---------------------------------------------------------------------------
# Profile selection (user-level sampling only)
# ---------------------------------------------------------------------------

def _ground_truth_dir(raw_dir: Path, override: str | Path | None) -> Path:
    if override:
        return Path(override)
    env = os.getenv("CERT_GROUND_TRUTH_DIR")
    if env:
        return Path(env)
    return raw_dir.parent.parent / "ground_truth" / raw_dir.name


def _profile_users(
    processed_dir: Path,
    raw_dir: Path,
    profile: str,
    *,
    ground_truth_dir: str | Path | None = None,
) -> set[str] | None:
    """Deterministic user set for dev/mid; None (= everyone) for full."""
    if profile == "full":
        return None
    cfg = PROFILE_CONFIG[profile]

    psych = pd.read_parquet(processed_dir / "context" / "psychometric.parquet", columns=["user_id"])
    available = set(psych["user_id"].astype(str).str.strip())

    insiders_path = _ground_truth_dir(raw_dir, ground_truth_dir) / "insiders.csv"
    if not insiders_path.exists():
        raise FileNotFoundError(f"CERT r4.2 insiders.csv not found: {insiders_path}")
    gt = pd.read_csv(insiders_path)
    gt.columns = [str(c).strip().lower() for c in gt.columns]
    gt = gt[gt["dataset"].astype(str).str.strip() == "4.2"].copy()
    gt["user"] = gt["user"].astype(str).str.strip().str.casefold()
    insiders = set(gt["user"])

    missing = insiders - available
    if missing:
        raise RuntimeError(f"{len(missing)} r4.2 insiders missing from the user population: {sorted(missing)}")

    if cfg["start"] is not None:
        # Keep only insiders whose documented activity window overlaps the
        # profile window; otherwise a dev run contains no insider behaviour.
        s = pd.to_datetime(gt["start"], errors="coerce")
        e = pd.to_datetime(gt["end"], errors="coerce")
        overlap = (s < pd.Timestamp(cfg["end"])) & (e >= pd.Timestamp(cfg["start"]))
        eligible = sorted(set(gt.loc[overlap, "user"]))
    else:
        eligible = sorted(insiders)

    n_insiders = cfg["insiders"] if cfg["insiders"] is not None else len(eligible)
    if len(eligible) < n_insiders:
        raise RuntimeError(
            f"profile={profile} needs {n_insiders} insiders active in "
            f"{cfg['start']}..{cfg['end']}, found {len(eligible)}"
        )
    benign = sorted(available - insiders)
    if len(benign) < cfg["benign"]:
        raise RuntimeError(f"profile={profile} needs {cfg['benign']} benign users, found {len(benign)}")
    return set(eligible[:n_insiders]) | set(benign[: cfg["benign"]])


# ---------------------------------------------------------------------------
# Stage 1 helpers: chunk-safe combination and exact distinct counts
# ---------------------------------------------------------------------------

def _parts(processed_dir: Path, domain: str, profile: str) -> list[Path]:
    root = processed_dir / "events" / f"profile={profile}" / f"source_type={domain}"
    return sorted(root.rglob("*.parquet"))


def _combine_partials(parts: list[pd.DataFrame]) -> pd.DataFrame:
    """Combine per-part aggregates with per-column rules (HCEA §5.3).

    Ratios and distinct counts are dropped here; ratios are recomputed from
    combined numerators/denominators and distincts from exact triples.
    """
    parts = [p for p in parts if not p.empty]
    if not parts:
        return pd.DataFrame(columns=["user_id", "date"])
    out = pd.concat(parts, ignore_index=True)
    out["date"] = pd.to_datetime(out["date"])
    value_cols = [c for c in out.columns if c not in {"user_id", "date"} and not is_ratio_column(c) and not is_distinct_column(c)]
    rules = {c: combine_rule(c) for c in value_cols}
    return out.groupby(["user_id", "date"], as_index=False, observed=True).agg(rules)


def _recompute_derived_ratios(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    def r(num: str, den: str, name: str) -> None:
        if num in out.columns and den in out.columns:
            out[name] = (out[num] / out[den].replace(0, np.nan)).astype("float32")

    r("off_hours_logins", "login_count", "off_hours_login_ratio")
    r("weekend_logins", "login_count", "weekend_login_ratio")
    r("usb_off_hours_events", "usb_event_count", "usb_off_hours_ratio")
    r("email_external_recipient_count", "email_recipient_count", "external_email_ratio")
    r("email_external_sender_count", "emails_sent", "email_external_sender_ratio")
    r("email_attachment_count", "emails_sent", "email_attachment_avg")
    r("email_off_hours_count", "emails_sent", "email_off_hours_ratio")
    return out


def _read_triples(paths: list[Path], item: str) -> pd.DataFrame:
    """Globally deduplicated (user_id, date_day, item) rows.

    Arrow-backed strings keep this intermediate compact even for http.
    """
    frames = [
        pd.read_parquet(p, columns=["user_id", "date_day", item], engine="pyarrow", dtype_backend="pyarrow").drop_duplicates()
        for p in paths
    ]
    if not frames:
        return pd.DataFrame(columns=["user_id", "date_day", item])
    return pd.concat(frames, ignore_index=True).drop_duplicates()


def _distinct_count(triples: pd.DataFrame, name: str) -> pd.DataFrame:
    if triples.empty:
        return pd.DataFrame(columns=["user_id", "date", name])
    counts = triples.groupby(["user_id", "date_day"], observed=True).size().rename(name).reset_index()
    counts = counts.rename(columns={"date_day": "date"})
    counts["user_id"] = counts["user_id"].astype("string")
    counts["date"] = pd.to_datetime(counts["date"]).astype("datetime64[ns]")
    counts[name] = counts[name].astype("int32")
    return counts


def _first_seen_count(triples: pd.DataFrame, item: str, name: str) -> pd.DataFrame:
    """Items seen for the first time (within the profile window) on each day."""
    if triples.empty:
        return pd.DataFrame(columns=["user_id", "date", name])
    first = triples.groupby(["user_id", item], observed=True)["date_day"].min().reset_index()
    return _distinct_count(first, name)


def _attach(base: pd.DataFrame, extra: pd.DataFrame, fill_zero: bool = True) -> pd.DataFrame:
    base = base.copy()
    base["user_id"] = base["user_id"].astype("string")
    base["date"] = pd.to_datetime(base["date"]).astype("datetime64[ns]")
    name = [c for c in extra.columns if c not in {"user_id", "date"}]
    out = base.drop(columns=name, errors="ignore").merge(extra, on=["user_id", "date"], how="left")
    if fill_zero:
        for c in name:
            out[c] = out[c].fillna(0)
    return out


def aggregate_logon(processed_dir: Path, profile: str) -> pd.DataFrame:
    paths = _parts(processed_dir, "logon", profile)
    partials = [authentication.aggregate(pd.read_parquet(p, engine="pyarrow")) for p in paths]
    out = _combine_partials(partials)
    if out.empty:
        return out
    triples = _read_triples(paths, "device_id")
    out = _attach(out, _distinct_count(triples, "distinct_auth_pcs"))
    out = _attach(out, _first_seen_count(triples, "device_id", "new_device_count"))
    out["new_device_flag"] = (out["new_device_count"] > 0).astype("float32")
    return _recompute_derived_ratios(out)


def aggregate_usb(processed_dir: Path, profile: str) -> pd.DataFrame:
    paths = _parts(processed_dir, "device", profile)
    out = _combine_partials([usb.aggregate(pd.read_parquet(p, engine="pyarrow")) for p in paths])
    if out.empty:
        return out
    out = _attach(out, _distinct_count(_read_triples(paths, "device_id"), "usb_distinct_pcs"))
    return _recompute_derived_ratios(out)


def aggregate_file(processed_dir: Path, profile: str) -> pd.DataFrame:
    paths = _parts(processed_dir, "file", profile)
    out = _combine_partials([file_activity.aggregate(pd.read_parquet(p, engine="pyarrow")) for p in paths])
    if out.empty:
        return out
    return _attach(out, _distinct_count(_read_triples(paths, "device_id"), "file_distinct_pcs"))


def aggregate_email(processed_dir: Path, profile: str) -> pd.DataFrame:
    directory = email_directory(processed_dir)
    paths = _parts(processed_dir, "email", profile)
    partials, domain_triples = [], []
    for p in paths:
        df = pd.read_parquet(p, engine="pyarrow")
        partials.append(email.aggregate(df, directory))
        domain_triples.append(email.external_domain_triples(df, directory))
    out = _combine_partials(partials)
    if out.empty:
        return out
    triples = pd.concat(domain_triples, ignore_index=True).drop_duplicates() if domain_triples else pd.DataFrame()
    out = _attach(out, _distinct_count(triples, "email_distinct_external_domains"))
    return _recompute_derived_ratios(out)


def aggregate_http(processed_dir: Path, profile: str, fingerprint: str) -> pd.DataFrame:
    """HTTP aggregation with part-level checkpoints (HCEA §5.5 resumability)."""
    root = processed_dir / "_runlog" / "http_parts" / profile / fingerprint
    agg_root, host_root = root / "aggregates", root / "hosts"
    agg_root.mkdir(parents=True, exist_ok=True)
    host_root.mkdir(parents=True, exist_ok=True)
    for path in _parts(processed_dir, "http", profile):
        key = hashlib.sha1(str(path.relative_to(processed_dir)).encode()).hexdigest()[:16]
        agg_path, host_path = agg_root / f"{key}.parquet", host_root / f"{key}.parquet"
        if agg_path.exists() and host_path.exists():
            continue
        df = pd.read_parquet(path, engine="pyarrow")
        atomic_to_parquet(df[["user_id", "date_day", "host"]].drop_duplicates(), host_path)
        atomic_to_parquet(network.aggregate(df), agg_path)  # written last = completion marker

    out = _combine_partials([pd.read_parquet(p, engine="pyarrow") for p in sorted(agg_root.glob("*.parquet"))])
    if out.empty:
        return out
    triples = _read_triples(sorted(host_root.glob("*.parquet")), "host")
    out = _attach(out, _distinct_count(triples, "http_distinct_hosts"))
    out = _attach(out, _first_seen_count(triples, "host", "http_new_host_count"))
    return out


# ---------------------------------------------------------------------------
# Stage 2: spine + missing-value policy
# ---------------------------------------------------------------------------

def build_calendar_spine(domain_frames: list[pd.DataFrame]) -> pd.DataFrame:
    nonempty = [x for x in domain_frames if not x.empty]
    if not nonempty:
        return pd.DataFrame(columns=["user_id", "date"])
    keys = pd.concat([x[["user_id", "date"]] for x in nonempty], ignore_index=True)
    keys["date"] = pd.to_datetime(keys["date"])
    bounds = keys.groupby("user_id", observed=True)["date"].agg(["min", "max"]).reset_index()
    rows = [pd.DataFrame({"user_id": r.user_id, "date": pd.date_range(r.min, r.max, freq="D")}) for r in bounds.itertuples(index=False)]
    spine = pd.concat(rows, ignore_index=True)
    spine["user_id"] = spine["user_id"].astype("string")
    spine["date"] = spine["date"].astype("datetime64[ns]")
    return spine


def _merge_feature_frames(spine: pd.DataFrame, frames: list[pd.DataFrame]) -> pd.DataFrame:
    out = spine.copy()
    for frame in frames:
        if frame.empty:
            continue
        frame = frame.copy()
        frame["user_id"] = frame["user_id"].astype("string")
        frame["date"] = pd.to_datetime(frame["date"]).astype("datetime64[ns]")
        dup = set(out.columns).intersection(frame.columns) - {"user_id", "date"}
        if dup:
            raise RuntimeError(f"Two domains emitted the same feature column(s): {sorted(dup)}")
        out = out.merge(frame, on=["user_id", "date"], how="left", sort=False)
    return out


def _is_hour_column(col: str) -> bool:
    return col.endswith(("_first_hour", "_last_hour")) or col in {"first_auth_hour", "last_auth_hour"}


def apply_missing_policy(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, str]]:
    """Absent is not zero for every column (HCEA §5.4, Chapter 4 policy).

    counts / sums / flags -> 0     (no event of that kind happened that day)
    ratios / averages     -> null  (undefined: denominator is zero)
    first/last hours      -> null  (there is no such clock time)
    """
    policy: dict[str, str] = {}
    for col in df.columns:
        if col in {"user_id", "date"} or not pd.api.types.is_numeric_dtype(df[col]):
            continue
        if is_ratio_column(col):
            policy[col] = "null: undefined when the denominator is zero (no qualifying events that day)"
        elif _is_hour_column(col):
            policy[col] = "null: no event of this type that day (absence is not a clock time)"
        else:
            df[col] = df[col].fillna(0)
            policy[col] = "zero: no observed event of this kind on the calendar day"
    return df, policy


# ---------------------------------------------------------------------------
# Stage 4 helpers
# ---------------------------------------------------------------------------

def add_psychometric(df: pd.DataFrame, psych: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, dict]]:
    p = psych.rename(columns=PSYCH_RENAME)[["user_id", *PSYCH_RENAME.values()]].drop_duplicates("user_id")
    p["user_id"] = p["user_id"].astype("string")
    out = df.merge(p, on="user_id", how="left")
    meta = {c: {"null_policy": "null when the user has no psychometric record", "static": True} for c in PSYCH_RENAME.values()}
    return out, meta


def _source_domain(col: str) -> str:
    if col.startswith(("login", "logoff", "auth_event", "off_hours_login", "weekend_login", "first_auth_hour", "last_auth_hour", "distinct_auth", "new_device")):
        return "logon"
    if col.startswith("usb_"):
        return "device"
    if col.startswith("file_"):
        return "file"
    if col.startswith(("email", "emails_", "external_email")):
        return "email"
    if col.startswith("http_"):
        return "http"
    if col.startswith("hist_"):
        return "historical_baseline"
    if col.startswith("peer_"):
        return "peer_group"
    if col.startswith("psych_"):
        return "psychometric_context"
    if col in temporal.TEMPORAL_META or col.startswith("rolling_"):
        return "temporal"
    return "derived"


def _schema(df: pd.DataFrame, meta_sources: list[dict], profile: str, fingerprint: str) -> dict[str, Any]:
    merged: dict[str, dict] = {}
    for source in meta_sources:
        for k, v in source.items():
            merged.setdefault(k, {}).update(v if isinstance(v, dict) else {"null_policy": v})
    columns = []
    for col in df.columns:
        if col in {"user_id", "date"}:
            continue
        entry = {"name": col, "dtype": str(df[col].dtype), "source_domain": _source_domain(col)}
        entry.update(merged.get(col, {}))
        entry.setdefault("null_policy", "not applicable")
        columns.append(entry)
    return {
        "chapter": 5,
        "pipeline_version": FEATURE_PIPELINE_VERSION,
        "host_categories_version": HOST_CATEGORIES_VERSION,
        "profile": profile,
        "config_fingerprint": fingerprint,
        "dataset": "CERT r4.2",
        "granularity": "user-day",
        "index_columns": ["user_id", "date"],
        "timezone": os.getenv("CERT_SOURCE_TIMEZONE", "UTC"),
        "calendar_policy": "dense spine from each user's first to last active day",
        "label_policy": "labels excluded; evaluation-only join from <processed>/labels/ happens outside this path",
        "downstream_note": "matrix contains nulls by design; Chapter 6+ must impute with a policy fitted on the training split only",
        "columns": columns,
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_pipeline(
    raw_dir: str | Path,
    processed_dir: str | Path,
    *,
    profile: str = "dev",
    force_stage0: bool = False,
    timezone: str = "UTC",
    ground_truth_dir: str | Path | None = None,
) -> Path:
    ensure_pyarrow()
    if profile not in PROFILE_CONFIG:
        raise ValueError(f"Unknown CIRA_PROFILE={profile}; expected dev, mid, full")
    started = time.perf_counter()
    cfg = PROFILE_CONFIG[profile]
    raw_dir, processed_dir = Path(raw_dir), Path(processed_dir)
    processed_dir.mkdir(parents=True, exist_ok=True)
    runlog = processed_dir / "_runlog" / "stages.jsonl"

    build_context(raw_dir, processed_dir)
    users = _profile_users(processed_dir, raw_dir, profile, ground_truth_dir=ground_truth_dir)
    s0_fp = config_fingerprint(profile, users, cfg["start"], cfg["end"], timezone)
    fingerprint = hashlib.sha256(f"{s0_fp}|{FEATURE_PIPELINE_VERSION}|{HOST_CATEGORIES_VERSION}".encode()).hexdigest()[:16]

    with timed_stage("stage0", runlog, profile=profile):
        stage0 = run_stage0(
            raw_dir, processed_dir, profile=profile, timezone=timezone, users=users,
            start=cfg["start"], end=cfg["end"], force=force_stage0,
        )

    features_dir = processed_dir / "features"
    features_dir.mkdir(parents=True, exist_ok=True)
    with timed_stage("stage1", runlog, profile=profile, fingerprint=fingerprint):
        builders: list[tuple[str, Callable[[], pd.DataFrame]]] = [
            ("logon", lambda: aggregate_logon(processed_dir, profile)),
            ("device", lambda: aggregate_usb(processed_dir, profile)),
            ("file", lambda: aggregate_file(processed_dir, profile)),
            ("email", lambda: aggregate_email(processed_dir, profile)),
            ("http", lambda: aggregate_http(processed_dir, profile, fingerprint)),
        ]
        stage1 = []
        for name, builder in builders:
            target = features_dir / "stage1" / f"{profile}_{name}_{fingerprint}.parquet"
            if target.exists():
                frame = pd.read_parquet(target, engine="pyarrow")
            else:
                with timed_stage(f"stage1:{name}", runlog, profile=profile):
                    frame = builder()
                atomic_to_parquet(frame, target)
            stage1.append(frame)

    with timed_stage("stage2_4", runlog, profile=profile):
        spine = build_calendar_spine(stage1)
        out = _merge_feature_frames(spine, stage1)
        out, null_policy = apply_missing_policy(out)
        out = temporal.add_temporal(out)
        out, baseline_meta = add_baselines(out)
        out, peer_meta = add_peer_features(out, load_ldap(processed_dir))
        out, psych_meta = add_psychometric(out, load_psychometric(processed_dir))
        out = out.drop(columns=[c for c in CONTEXT_STRING_COLUMNS if c in out.columns])

        non_numeric = [c for c in out.columns if c not in {"user_id", "date"} and not pd.api.types.is_numeric_dtype(out[c])]
        if non_numeric:
            raise RuntimeError(f"Non-numeric columns reached the feature matrix: {non_numeric}")
        leaked = [c for c in out.columns if c.lower() in LABEL_LIKE or "malicious" in c.lower() or "insider" in c.lower()]
        if leaked:
            raise RuntimeError(f"Label leakage guard triggered in final feature matrix: {leaked}")

        out = to_float32(out)
        out["user_id"] = out["user_id"].astype("string")
        out["date"] = pd.to_datetime(out["date"]).dt.strftime("%Y-%m-%d").astype("string")
        out = out.sort_values(["user_id", "date"]).reset_index(drop=True)

        schema = _schema(out, [null_policy, temporal.TEMPORAL_META, baseline_meta, peer_meta, psych_meta], profile, fingerprint)
        output = features_dir / cfg["output"]
        atomic_to_parquet(out, output)
        schema_text = json.dumps(schema, indent=2)
        (features_dir / f"feature_schema_{profile}.json").write_text(schema_text, encoding="utf-8")
        (features_dir / "feature_schema.json").write_text(schema_text, encoding="utf-8")

    summary = {
        "stage": "chapter5_pipeline",
        "profile": profile,
        "config_fingerprint": fingerprint,
        "rows_in": int(sum(r.get("rows_written", 0) for r in stage0)),
        "rows_rejected": int(sum(r.get("rows_rejected", 0) for r in stage0)),
        "rows_out": int(len(out)),
        "users": int(out["user_id"].nunique()),
        "features": int(len(out.columns) - 2),
        "wall_seconds": round(time.perf_counter() - started, 2),
        "peak_rss_mb": round(memory_rss_mb(), 1),
        "output": str(output),
    }
    (processed_dir / "_runlog" / f"summary_{profile}.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    append_experiment_runlog(summary)
    return output


def main() -> None:
    from app.core.runtime import apply_thread_caps

    apply_thread_caps()
    p = argparse.ArgumentParser(description="CIRA Chapter 5 feature pipeline")
    p.add_argument("--raw-dir", default=os.getenv("CERT_RAW_DIR"), required=os.getenv("CERT_RAW_DIR") is None)
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--ground-truth-dir", default=os.getenv("CERT_GROUND_TRUTH_DIR"))
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "dev"), choices=tuple(PROFILE_CONFIG))
    p.add_argument("--timezone", default=os.getenv("CERT_SOURCE_TIMEZONE", "UTC"))
    p.add_argument("--force-stage0", action="store_true")
    args = p.parse_args()
    print(run_pipeline(
        args.raw_dir, args.processed_dir, profile=args.profile,
        force_stage0=args.force_stage0, timezone=args.timezone,
        ground_truth_dir=args.ground_truth_dir,
    ))


if __name__ == "__main__":
    main()
