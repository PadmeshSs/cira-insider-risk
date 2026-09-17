from __future__ import annotations
import pandas as pd
from .common import off_hours

def add_temporal(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["date"] = pd.to_datetime(out["date"])
    out["day_of_week"] = out["date"].dt.dayofweek.astype("int8")
    out["is_weekend"] = (out["day_of_week"] >= 5).astype("int8")
    # Daily first/last active hour are sourced from authentication; keep them
    # separate and do not pretend every source has an independent login hour.
    if "first_auth_hour" in out:
        out["first_auth_off_hours"] = off_hours(out["first_auth_hour"].fillna(0)).astype("float32")
    if "last_auth_hour" in out:
        out["last_auth_off_hours"] = off_hours(out["last_auth_hour"].fillna(0)).astype("float32")
    return out
