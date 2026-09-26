"""Small in-memory user-day matrix with real Chapter 5 column names.

For fast unit tests of Chapter 6 code that do not need the full pipeline.
Rows are a dense calendar per user, sorted by (user_id, date).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from app.baselines.lstm_autoencoder import CORE_COLUMNS
from app.baselines.rule_based import RULES

NULLABLE = ("off_hours_login_ratio", "first_auth_hour", "hist_z_login_count", "peer_dev_login_count")


def build(n_users: int = 12, n_days: int = 60, seed: int = 0, start: str = "2010-06-01") -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    dates = pd.date_range(start, periods=n_days, freq="D").strftime("%Y-%m-%d")
    rows = []
    for u in range(n_users):
        frame = pd.DataFrame({"user_id": f"u{u:04d}", "date": dates})
        rows.append(frame)
    out = pd.concat(rows, ignore_index=True)
    n = len(out)
    cols = sorted(set(CORE_COLUMNS) | {c for r in RULES for c in r.columns})
    for c in cols:
        out[c] = rng.poisson(2.0, n).astype("float32")
    out["is_active_day"] = (rng.random(n) > 0.2).astype("float32")
    out["is_weekend"] = (pd.to_datetime(out["date"]).dt.dayofweek >= 5).astype("float32")
    for c in NULLABLE:
        v = rng.normal(0, 1, n).astype("float32")
        v[rng.random(n) < 0.3] = np.nan
        out[c] = v
    out["user_id"] = out["user_id"].astype("string")
    out["date"] = out["date"].astype("string")
    return out
