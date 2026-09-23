"""Per-user historical baseline deviation (Bible Ch5 step 8, HCEA §5.4).

Method (recorded per column in feature_schema.json):
  trailing rolling z-score over the previous ``window`` calendar days of the
  dense user-day spine; ``shift(1)`` excludes the current day; null until
  ``min_periods`` prior days exist and null when the prior std is zero.
"""
from __future__ import annotations
import numpy as np
import pandas as pd
from .common import BASELINE_MIN_PERIODS, BASELINE_WINDOW

DEFAULT_BASELINES = [
    "login_count", "off_hours_login_ratio", "distinct_auth_pcs",
    "usb_connect_count", "file_event_count", "emails_sent",
    "external_email_ratio", "email_total_size", "http_request_count",
    "http_distinct_hosts", "http_off_hours_count",
    "usb_event_count", "total_event_count",
]

def add_baselines(df: pd.DataFrame, columns: list[str] | None = None, window: int = BASELINE_WINDOW, min_periods: int = BASELINE_MIN_PERIODS) -> tuple[pd.DataFrame, dict[str, dict]]:
    out = df.sort_values(["user_id", "date"]).copy()
    cols = [c for c in (columns or DEFAULT_BASELINES) if c in out.columns]
    meta: dict[str, dict] = {}
    for col in cols:
        shifted = out.groupby("user_id", sort=False)[col].transform(lambda s: s.shift(1).rolling(window, min_periods=min_periods).mean())
        std = out.groupby("user_id", sort=False)[col].transform(lambda s: s.shift(1).rolling(window, min_periods=min_periods).std(ddof=0))
        z = ((out[col] - shifted) / std.replace(0, np.nan)).astype("float32")
        out[f"hist_z_{col}"] = z
        out[f"hist_abs_z_{col}"] = z.abs().astype("float32")
        meta[f"hist_z_{col}"] = {"window_days": window, "min_periods": min_periods, "method": "trailing rolling z-score; current day excluded with shift(1)", "null_policy": f"null until {min_periods} prior observations; null when prior std=0"}
        meta[f"hist_abs_z_{col}"] = dict(meta[f"hist_z_{col}"])
    return out, meta
