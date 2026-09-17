from __future__ import annotations
import pandas as pd
from .common import FILE_EXTENSIONS, off_hours

def aggregate(df: pd.DataFrame) -> pd.DataFrame:
    x = df.copy()
    x["off"] = off_hours(x["hour"])
    g = x.groupby(["user_id", "date_day"], observed=True)
    out = g.agg(
        file_event_count=("event_id", "size"),
        file_distinct_pcs=("device_id", "nunique"),
        file_off_hours_events=("off", "sum"),
    ).reset_index().rename(columns={"date_day": "date"})
    for ext in FILE_EXTENSIONS:
        s = x["file_extension"].eq(ext).groupby([x["user_id"], x["date_day"]], observed=True).sum()
        out = out.merge(s.rename(f"file_{ext}_count").reset_index().rename(columns={"date_day": "date"}), on=["user_id", "date"], how="left")
    out["file_archive_or_executable_count"] = out["file_zip_count"] + out["file_exe_count"]
    return out
