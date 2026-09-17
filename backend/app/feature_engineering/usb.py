from __future__ import annotations
import pandas as pd
from .common import off_hours, ratio

def aggregate(df: pd.DataFrame) -> pd.DataFrame:
    x = df.copy()
    x["connect"] = x["activity"].eq("connect")
    x["disconnect"] = x["activity"].eq("disconnect")
    x["off"] = off_hours(x["hour"])
    g = x.groupby(["user_id", "date_day"], observed=True)
    out = g.agg(
        usb_connect_count=("connect", "sum"),
        usb_disconnect_count=("disconnect", "sum"),
        usb_event_count=("event_id", "size"),
        usb_distinct_pcs=("device_id", "nunique"),
        usb_off_hours_events=("off", "sum"),
        usb_first_hour=("hour", "min"),
        usb_last_hour=("hour", "max"),
    ).reset_index().rename(columns={"date_day": "date"})
    out["usb_off_hours_ratio"] = ratio(out["usb_off_hours_events"], out["usb_event_count"])
    return out
