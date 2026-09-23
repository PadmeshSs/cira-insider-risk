"""Temporal features on the dense user-day spine.

Must run AFTER the missing-value policy has been applied (counts are 0 on
inactive days; hour columns stay null).  Absence is never turned into a
clock time: a day with no logon has a null first_auth_hour and therefore
null off-hours indicators, not "logged in at midnight".

Rolling windows are trailing and exclude the current day (shift(1)), so a
row never contributes to its own context.
"""
from __future__ import annotations

import pandas as pd

from .common import OFF_HOURS_END, OFF_HOURS_START

ACTIVITY_COUNT_COLUMNS = (
    "auth_event_count",
    "usb_event_count",
    "file_event_count",
    "emails_sent",
    "http_request_count",
)
ROLLING_WINDOW = 7

TEMPORAL_META = {
    "day_of_week": {"null_policy": "never null"},
    "is_weekend": {"null_policy": "never null"},
    "total_event_count": {"null_policy": "zero: no observed events in any domain"},
    "is_active_day": {"null_policy": "never null"},
    "first_auth_off_hours": {"null_policy": "null: no logon that day"},
    "last_auth_off_hours": {"null_policy": "null: no logon that day"},
    "auth_active_span_hours": {"null_policy": "null: no logon that day"},
    f"rolling_{ROLLING_WINDOW}d_event_count": {
        "null_policy": "null until the first prior day exists",
        "window_days": ROLLING_WINDOW,
        "method": "trailing sum, current day excluded with shift(1)",
    },
    f"rolling_{ROLLING_WINDOW}d_active_days": {
        "null_policy": "null until the first prior day exists",
        "window_days": ROLLING_WINDOW,
        "method": "trailing count of active days, current day excluded with shift(1)",
    },
}


def _off_hours_nullable(hour: pd.Series) -> pd.Series:
    h = hour.astype("float32")
    flag = ((h < OFF_HOURS_START) | (h >= OFF_HOURS_END)).astype("float32")
    return flag.where(h.notna())


def add_temporal(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["date"] = pd.to_datetime(out["date"])
    out = out.sort_values(["user_id", "date"]).reset_index(drop=True)
    out["day_of_week"] = out["date"].dt.dayofweek.astype("int8")
    out["is_weekend"] = (out["day_of_week"] >= 5).astype("int8")

    present = [c for c in ACTIVITY_COUNT_COLUMNS if c in out.columns]
    total = out[present].fillna(0).sum(axis=1) if present else pd.Series(0, index=out.index)
    out["total_event_count"] = total.astype("float32")
    out["is_active_day"] = (total > 0).astype("int8")

    if "first_auth_hour" in out:
        out["first_auth_off_hours"] = _off_hours_nullable(out["first_auth_hour"])
    if "last_auth_hour" in out:
        out["last_auth_off_hours"] = _off_hours_nullable(out["last_auth_hour"])
    if "first_auth_hour" in out and "last_auth_hour" in out:
        out["auth_active_span_hours"] = (out["last_auth_hour"] - out["first_auth_hour"]).astype("float32")

    by_user = out.groupby("user_id", sort=False, observed=True)
    prior_total = by_user["total_event_count"].shift(1)
    prior_active = by_user["is_active_day"].shift(1)
    grp = out["user_id"]
    out[f"rolling_{ROLLING_WINDOW}d_event_count"] = (
        prior_total.groupby(grp, sort=False).rolling(ROLLING_WINDOW, min_periods=1).sum()
        .reset_index(level=0, drop=True).astype("float32")
    )
    out[f"rolling_{ROLLING_WINDOW}d_active_days"] = (
        prior_active.astype("float32").groupby(grp, sort=False).rolling(ROLLING_WINDOW, min_periods=1).sum()
        .reset_index(level=0, drop=True).astype("float32")
    )
    return out
