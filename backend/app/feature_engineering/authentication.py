from __future__ import annotations
import pandas as pd
from .common import off_hours, ratio

def aggregate(df: pd.DataFrame) -> pd.DataFrame:
    x = df.copy()
    x["is_logon"] = x["activity"].eq("logon")
    x["is_logoff"] = x["activity"].eq("logoff")
    x["off"] = off_hours(x["hour"])
    g = x.groupby(["user_id", "date_day"], observed=True)
    out = g.agg(
        login_count=("is_logon", "sum"),
        logoff_count=("is_logoff", "sum"),
        auth_event_count=("event_id", "size"),
        distinct_auth_pcs=("device_id", "nunique"),
        first_auth_hour=("hour", "min"),
        last_auth_hour=("hour", "max"),
        off_hours_logins=("off", lambda s: int(s[x.loc[s.index, "is_logon"]].sum())),
        weekend_logins=("weekday", lambda s: int((s >= 5)[x.loc[s.index, "is_logon"]].sum())),
    ).reset_index().rename(columns={"date_day": "date"})
    out["off_hours_login_ratio"] = ratio(out["off_hours_logins"], out["login_count"])
    out["weekend_login_ratio"] = ratio(out["weekend_logins"], out["login_count"])
    return out
