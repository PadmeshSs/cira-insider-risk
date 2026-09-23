"""Authentication (logon) features per user-day.

CERT r4.2 logon.csv records only Logon/Logoff; it has no failed-login or
source-IP fields, so failed-login and new-IP features are not produced
(Architecture §10.1 items unsupported by this dataset are omitted, not faked).

Chunk safety: counts are additive; first/last hour combine by min/max
(see common.combine_rule); ``distinct_auth_pcs`` and ``new_device_count`` are
recomputed exactly by pipeline.aggregate_logon from deduplicated triples.
"""
from __future__ import annotations

import pandas as pd

from .common import off_hours, ratio


def aggregate(df: pd.DataFrame) -> pd.DataFrame:
    x = df[["user_id", "date_day", "hour", "weekday", "device_id", "activity", "event_id"]].copy()
    is_logon = x["activity"].eq("logon")
    x["is_logon"] = is_logon.astype("int32")
    x["is_logoff"] = x["activity"].eq("logoff").astype("int32")
    x["off_logon"] = (off_hours(x["hour"]).astype(bool) & is_logon).astype("int32")
    x["weekend_logon"] = ((x["weekday"] >= 5) & is_logon).astype("int32")
    # First/last *logon* hour: NaN on rows that are not logons so min/max
    # ignore them.
    x["logon_hour"] = x["hour"].where(is_logon).astype("float32")

    g = x.groupby(["user_id", "date_day"], observed=True)
    out = g.agg(
        login_count=("is_logon", "sum"),
        logoff_count=("is_logoff", "sum"),
        auth_event_count=("event_id", "size"),
        distinct_auth_pcs=("device_id", "nunique"),
        first_auth_hour=("logon_hour", "min"),
        last_auth_hour=("logon_hour", "max"),
        off_hours_logins=("off_logon", "sum"),
        weekend_logins=("weekend_logon", "sum"),
    ).reset_index().rename(columns={"date_day": "date"})
    out["off_hours_login_ratio"] = ratio(out["off_hours_logins"], out["login_count"])
    out["weekend_login_ratio"] = ratio(out["weekend_logins"], out["login_count"])
    return out
