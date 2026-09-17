"""CIRA Chapter 5 end-to-end feature pipeline.

Execution model:
Stage 0  raw CERT CSV -> typed, feature-safe Parquet
Stage 1  domain Parquet -> independent user-day aggregates
Stage 2  calendar spine + temporal features
Stage 3  trailing historical baselines
Stage 4  point-in-time peer context + final float32 matrix/schema

Labels are intentionally absent from every function in this module.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Callable

import numpy as np
import pandas as pd

from . import authentication, email, file_activity, network, temporal, usb
from .common import atomic_to_parquet, ensure_pyarrow, memory_rss_mb, timed_stage, to_float32
from .context import build_context, email_directory, load_ldap
from .historical_baseline import add_baselines
from .stage0 import run_stage0
from .peer_group import add_peer_features


PROFILE_CONFIG = {
    "dev": {"users": 50, "start": "2010-01-02", "end": "2010-04-02", "output": "user_day_dev.parquet"},
    "mid": {"users": 250, "start": None, "end": None, "output": "user_day_mid.parquet"},
    "full": {"users": None, "start": None, "end": None, "output": "user_day_full.parquet"},
}

DOMAIN_ORDER = ("logon", "device", "file", "email", "http")


def _profile_users(
    processed_dir: Path,
    raw_dir: Path,
    profile: str,
) -> set[str] | None:
    """Build deterministic user-level execution profiles.

    Ground truth is used only to construct the execution profile.  Only the
    resulting user-ID set is passed into Stage 0; labels never enter feature
    engineering.
    """
    if profile == "full":
        return None

    psych = pd.read_parquet(
        processed_dir / "context" / "psychometric.parquet",
        columns=["user_id"],
    )
    available_users = set(psych["user_id"].astype(str).str.strip())

    gt_dir = raw_dir.parent.parent / "ground_truth" / raw_dir.name
    insiders_path = gt_dir / "insiders.csv"

    if not insiders_path.exists():
        raise FileNotFoundError(
            f"Required CERT r4.2 insider profile file not found: {insiders_path}"
        )

    gt = pd.read_csv(insiders_path, usecols=["dataset", "user"])
    insiders = set(
        gt.loc[gt["dataset"].astype(str).str.strip() == "4.2", "user"]
        .astype(str)
        .str.strip()
        .str.casefold()
    )

    missing_insiders = insiders - available_users
    if missing_insiders:
        raise RuntimeError(
            f"{len(missing_insiders)} CERT r4.2 insiders are missing from "
            f"the available user population: {sorted(missing_insiders)}"
        )

    benign = sorted(available_users - insiders)

    if profile == "dev":
        insider_count = 10
        benign_count = 40
    elif profile == "mid":
        insider_count = len(insiders)
        benign_count = 180
    else:
        raise ValueError(f"Unsupported profile: {profile}")

    if len(insiders) < insider_count:
        raise RuntimeError(
            f"Need {insider_count} insiders for {profile}, found {len(insiders)}"
        )
    if len(benign) < benign_count:
        raise RuntimeError(
            f"Need {benign_count} benign users for {profile}, found {len(benign)}"
        )

    selected_insiders = sorted(insiders)[:insider_count]
    selected_benign = benign[:benign_count]

    return set(selected_insiders + selected_benign)

def _parts(processed_dir: Path, domain: str, profile: str):
    root = (
        processed_dir
        / "events"
        / f"profile={profile}"
        / f"source_type={domain}"
    )
    return sorted(root.rglob("*.parquet"))


def _concat_aggregates(parts: list[pd.DataFrame]) -> pd.DataFrame:
    if not parts:
        return pd.DataFrame(columns=["user_id", "date"])
    out = pd.concat(parts, ignore_index=True)
    out["date"] = pd.to_datetime(out["date"])
    numeric = [c for c in out.columns if c not in {"user_id", "date"}]
    agg = {c: "sum" for c in numeric}
    for c in ("first_auth_hour",):
        if c in agg:
            agg[c] = "min"
    for c in ("last_auth_hour",):
        if c in agg:
            agg[c] = "max"
    result = out.groupby(["user_id", "date"], as_index=False, observed=True).agg(agg)
    return result


def _recompute_derived_ratios(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    def r(num, den, name):
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


def aggregate_logon(processed_dir: Path, profile: str) -> pd.DataFrame:
    partials, distinct = [], []
    for path in _parts(processed_dir, "logon", profile):
        df = pd.read_parquet(path, engine="pyarrow")
        partials.append(authentication.aggregate(df))
        distinct.append(df[["user_id", "date_day", "device_id"]].drop_duplicates())
    out = _recompute_derived_ratios(_concat_aggregates(partials))
    if distinct:
        d = pd.concat(distinct, ignore_index=True).drop_duplicates()
        pc = d.groupby(["user_id", "date_day"], observed=True)["device_id"].nunique().rename("distinct_auth_pcs").reset_index().rename(columns={"date_day": "date"})
        out = out.drop(columns=["distinct_auth_pcs"], errors="ignore").merge(pc, on=["user_id", "date"], how="left")
    # New-PC flag is point-in-time and uses only earlier activity.
    first_seen = None
    if distinct:
        d = pd.concat(distinct, ignore_index=True).drop_duplicates().sort_values(["user_id", "date_day"])
        d["first_pc_day"] = d.groupby(["user_id", "device_id"], observed=True)["date_day"].transform("min")
        d["new_pc"] = d["first_pc_day"].eq(d["date_day"])
        first = d.groupby(["user_id", "date_day"], observed=True)["new_pc"].sum().astype("int32").reset_index(name="new_device_count")
        first = first.rename(columns={"date_day": "date"})
        out = out.merge(first, on=["user_id", "date"], how="left")
    if "new_device_count" not in out.columns:
        out["new_device_count"] = 0.0
    out["new_device_count"] = out["new_device_count"].fillna(0).astype("float32")
    out["new_device_flag"] = (out["new_device_count"] > 0).astype("float32")
    return out


def aggregate_usb(processed_dir: Path, profile: str) -> pd.DataFrame:
    parts = [usb.aggregate(pd.read_parquet(p, engine="pyarrow")) for p in _parts(processed_dir, "device", profile)]
    return _recompute_derived_ratios(_concat_aggregates(parts))


def aggregate_file(processed_dir: Path, profile: str) -> pd.DataFrame:
    parts = [file_activity.aggregate(pd.read_parquet(p, engine="pyarrow")) for p in _parts(processed_dir, "file", profile)]
    return _concat_aggregates(parts)


def aggregate_email(processed_dir: Path, profile: str) -> pd.DataFrame:
    directory = email_directory(processed_dir)
    parts = [email.aggregate(pd.read_parquet(p, engine="pyarrow"), directory) for p in _parts(processed_dir, "email", profile)]
    return _recompute_derived_ratios(_concat_aggregates(parts))


def aggregate_http(processed_dir: Path, profile: str) -> pd.DataFrame:
    """HTTP aggregation with part-level checkpoints.

    Each source Parquet part produces two tiny checkpoint files: user-day
    aggregates and unique user-day-host pairs.  A killed run resumes from the
    last completed part; the final distinct-host calculation is exact after a
    global drop_duplicates over the checkpoint tree.
    """
    root = processed_dir / "_runlog" / "http_parts" / profile
    agg_root = root / "aggregates"
    host_root = root / "hosts"
    agg_root.mkdir(parents=True, exist_ok=True)
    host_root.mkdir(parents=True, exist_ok=True)
    parts = _parts(processed_dir, "http", profile)
    for idx, path in enumerate(parts):
        agg_path = agg_root / f"part-{idx:06d}.parquet"
        host_path = host_root / f"part-{idx:06d}.parquet"
        if agg_path.exists() and host_path.exists():
            continue
        df = pd.read_parquet(path, engine="pyarrow")
        part_agg = network.aggregate(df)
        part_hosts = df[["user_id", "date_day", "host"]].drop_duplicates()
        atomic_to_parquet(part_agg, agg_path)
        atomic_to_parquet(part_hosts, host_path)

    partials = [pd.read_parquet(p, engine="pyarrow") for p in sorted(agg_root.glob("*.parquet"))]
    out = _concat_aggregates(partials)
    host_parts = [pd.read_parquet(p, engine="pyarrow") for p in sorted(host_root.glob("*.parquet"))]
    if host_parts:
        hp = pd.concat(host_parts, ignore_index=True).drop_duplicates()
        counts = hp.groupby(["user_id", "date_day"], observed=True)["host"].nunique().rename("http_distinct_hosts").reset_index().rename(columns={"date_day": "date"})
        out = out.drop(columns=["http_distinct_hosts"], errors="ignore").merge(counts, on=["user_id", "date"], how="left")
        hp = hp.sort_values(["user_id", "date_day", "host"])
        hp["first_day"] = hp.groupby(["user_id", "host"], observed=True)["date_day"].transform("min")
        new = hp[hp["date_day"].eq(hp["first_day"])].groupby(["user_id", "date_day"], observed=True).size().rename("http_new_host_count").reset_index().rename(columns={"date_day": "date"})
        out = out.drop(columns=["http_new_host_count"], errors="ignore").merge(new, on=["user_id", "date"], how="left")
    if "http_new_host_count" not in out.columns:
        out["http_new_host_count"] = 0.0
    out["http_new_host_count"] = out["http_new_host_count"].fillna(0).astype("float32")
    return out


def build_calendar_spine(domain_frames: list[pd.DataFrame]) -> pd.DataFrame:
    nonempty = [x for x in domain_frames if not x.empty]
    if not nonempty:
        return pd.DataFrame(columns=["user_id", "date"])
    keys = pd.concat([x[["user_id", "date"]] for x in nonempty], ignore_index=True)
    bounds = keys.groupby("user_id", observed=True)["date"].agg(["min", "max"]).reset_index()
    rows = []
    for r in bounds.itertuples(index=False):
        dates = pd.date_range(r.min, r.max, freq="D")
        rows.append(pd.DataFrame({"user_id": r.user_id, "date": dates}))
    return pd.concat(rows, ignore_index=True)


def _merge_feature_frames(spine: pd.DataFrame, frames: list[pd.DataFrame]) -> pd.DataFrame:
    out = spine.copy()
    for frame in frames:
        if frame.empty:
            continue
        frame = frame.copy()
        frame["date"] = pd.to_datetime(frame["date"])
        dup = set(out.columns).intersection(frame.columns) - {"user_id", "date"}
        if dup:
            frame = frame.drop(columns=list(dup))
        out = out.merge(frame, on=["user_id", "date"], how="left", sort=False)
    return out


def _fill_missing(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, str]]:
    policy: dict[str, str] = {}
    for col in df.columns:
        if col in {"user_id", "date", "role", "department", "business_unit", "functional_unit", "team", "supervisor", "email"}:
            continue
        if pd.api.types.is_numeric_dtype(df[col]):
            df[col] = df[col].fillna(0)
            policy[col] = "zero: no observed event for this domain on the calendar day"
    return df, policy


def _schema(df: pd.DataFrame, null_policy: dict[str, str], baseline_meta: dict[str, dict], peer_meta: dict[str, dict]) -> dict[str, Any]:
    columns = []
    for col in df.columns:
        if col in {"user_id", "date"}:
            continue
        source = "derived"
        if col.startswith(("login", "logoff", "auth", "off_hours_login", "weekend_login", "first_auth", "last_auth", "distinct_auth", "new_device")):
            source = "logon"
        elif col.startswith("usb_"):
            source = "device"
        elif col.startswith("file_"):
            source = "file"
        elif col.startswith(("email", "emails_", "external_email")):
            source = "email"
        elif col.startswith("http_"):
            source = "http"
        elif col.startswith("hist_"):
            source = "historical_baseline"
        elif col.startswith("peer_"):
            source = "peer_group"
        elif col in {"day_of_week", "is_weekend", "first_auth_off_hours", "last_auth_off_hours"}:
            source = "temporal"
        elif col in {"role", "department", "business_unit", "functional_unit", "team", "supervisor"}:
            source = "ldap_context"
        columns.append({
            "name": col,
            "dtype": str(df[col].dtype),
            "source_domain": source,
            "null_policy": null_policy.get(col, "not applicable"),
            **baseline_meta.get(col, {}),
            **peer_meta.get(col, {}),
        })
    return {
        "chapter": 5,
        "dataset": "CERT r4.2",
        "granularity": "user-day",
        "timezone": os.getenv("CERT_TIMEZONE", "UTC"),
        "calendar_policy": "dense active-span user-day spine",
        "label_policy": "labels excluded; evaluation-only join occurs outside this feature path",
        "columns": columns,
    }


def run_pipeline(raw_dir: str | Path, processed_dir: str | Path, *, profile: str = "dev", force_stage0: bool = False, timezone: str = "UTC") -> Path:
    ensure_pyarrow()
    if profile not in PROFILE_CONFIG:
        raise ValueError(f"Unknown CIRA_PROFILE={profile}; expected dev, mid, full")
    cfg = PROFILE_CONFIG[profile]
    raw_dir, processed_dir = Path(raw_dir), Path(processed_dir)
    processed_dir.mkdir(parents=True, exist_ok=True)
    runlog = processed_dir / "_runlog" / "stages.jsonl"

    build_context(raw_dir, processed_dir)
    users = _profile_users(processed_dir, raw_dir, profile)
    stage0_marker = processed_dir / "_runlog" / f"stage0_{profile}.json"
    if force_stage0 or not stage0_marker.exists():
        with timed_stage("stage0", runlog):
            result = run_stage0(
                raw_dir,
                processed_dir,
                profile=profile,
                timezone=timezone,
                users=users,
                start=cfg["start"],
                end=cfg["end"],
                force=force_stage0,
            )
            stage0_marker.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")

    with timed_stage("stage1", runlog):
        features_dir = processed_dir / "features"
        features_dir.mkdir(parents=True, exist_ok=True)
        builders: list[tuple[str, Callable[[], pd.DataFrame]]] = [
            ("logon", lambda: aggregate_logon(processed_dir, profile)),
            ("device", lambda: aggregate_usb(processed_dir, profile)),
            ("file", lambda: aggregate_file(processed_dir, profile)),
            ("email", lambda: aggregate_email(processed_dir, profile)),
            ("http", lambda: aggregate_http(processed_dir, profile)),
        ]
        stage1 = []
        for name, builder in builders:
            target = features_dir / f"stage1_{profile}_{name}.parquet"
            if target.exists():
                frame = pd.read_parquet(target, engine="pyarrow")
            else:
                frame = builder()
                atomic_to_parquet(frame, target)
            stage1.append(frame)

    with timed_stage("stage2_4", runlog):
        spine = build_calendar_spine(stage1)
        out = _merge_feature_frames(spine, stage1)
        out = temporal.add_temporal(out)
        out, null_policy = _fill_missing(out)
        out, baseline_meta = add_baselines(out)
        ldap = load_ldap(processed_dir)
        out, peer_meta = add_peer_features(out, ldap)
        # Keep only numeric model inputs plus identity/date.  LDAP categorical
        # context is used to compute peer deviations but is not silently encoded.
        drop_context = [c for c in ["email", "employee_name", "role", "department", "business_unit", "functional_unit", "team", "supervisor"] if c in out.columns]
        out = out.drop(columns=drop_context, errors="ignore")
        out = to_float32(out)
        out["user_id"] = out["user_id"].astype("string")
        out["date"] = pd.to_datetime(out["date"]).dt.date.astype("string")
        out = out.sort_values(["user_id", "date"]).reset_index(drop=True)
        if any(c.lower() in {"label", "labels", "malicious", "is_malicious", "ground_truth", "scenario", "target", "y"} for c in out.columns):
            raise RuntimeError("Label leakage guard triggered in final feature matrix")
        schema = _schema(out, null_policy, baseline_meta, peer_meta)
        output_name = cfg["output"]
        atomic_to_parquet(out, processed_dir / "features" / output_name)
        (processed_dir / "features").mkdir(parents=True, exist_ok=True)
        (processed_dir / "features" / "feature_schema.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")
        summary = {"profile": profile, "rows": int(len(out)), "features": int(len(out.columns)-2), "peak_rss_mb": memory_rss_mb()}
        (processed_dir / "_runlog" / f"summary_{profile}.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return processed_dir / "features" / output_name


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--raw-dir", required=True)
    p.add_argument("--processed-dir", required=True)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "dev"), choices=tuple(PROFILE_CONFIG))
    p.add_argument("--timezone", default=os.getenv("CERT_TIMEZONE", "UTC"))
    p.add_argument("--force-stage0", action="store_true")
    args = p.parse_args()
    print(run_pipeline(args.raw_dir, args.processed_dir, profile=args.profile, force_stage0=args.force_stage0, timezone=args.timezone))

if __name__ == "__main__":
    main()
