"""Removable-media (device.csv) features per user-day.

Chunk safety: counts sum; first/last hour combine by min/max;
``usb_distinct_pcs`` is recomputed exactly by the pipeline.
CERT r4.2 device.csv has no file-transfer linkage, so the Bible's
"file-transfer association" is approximated only by same-day file activity
in file_activity.py (r4.2 file.csv records copies to removable media).
"""
from __future__ import annotations

import pandas as pd

from .common import off_hours, ratio


def aggregate(df: pd.DataFrame) -> pd.DataFrame:
    x = df[["user_id", "date_day", "hour", "device_id", "activity", "event_id"]].copy()
    x["connect"] = x["activity"].eq("connect").astype("int32")
    x["disconnect"] = x["activity"].eq("disconnect").astype("int32")
    x["off"] = off_hours(x["hour"]).astype("int32")
    x["hour_f"] = x["hour"].astype("float32")
    g = x.groupby(["user_id", "date_day"], observed=True)
    out = g.agg(
        usb_connect_count=("connect", "sum"),
        usb_disconnect_count=("disconnect", "sum"),
        usb_event_count=("event_id", "size"),
        usb_distinct_pcs=("device_id", "nunique"),
        usb_off_hours_events=("off", "sum"),
        usb_first_hour=("hour_f", "min"),
        usb_last_hour=("hour_f", "max"),
    ).reset_index().rename(columns={"date_day": "date"})
    out["usb_off_hours_ratio"] = ratio(out["usb_off_hours_events"], out["usb_event_count"])
    return out
