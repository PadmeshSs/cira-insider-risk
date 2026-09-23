"""File-activity features per user-day.

In CERT r4.2, file.csv records file copies to removable media; there is no
create/modify/delete activity column (that arrives in later releases), so
those Bible §10.2 sub-features are unsupported and not fabricated.

Chunk safety: counts sum; ``file_distinct_pcs`` is recomputed exactly by the
pipeline from deduplicated (user, day, pc) triples.
"""
from __future__ import annotations

import pandas as pd

from .common import FILE_EXTENSIONS, off_hours


def aggregate(df: pd.DataFrame) -> pd.DataFrame:
    x = df[["user_id", "date_day", "hour", "device_id", "file_extension", "event_id"]].copy()
    x["off"] = off_hours(x["hour"]).astype("int32")
    ext = x["file_extension"].astype("string").fillna("other")
    for e in FILE_EXTENSIONS:
        x[f"file_{e}_count"] = ext.eq(e).astype("int32")
    x["file_other_ext_count"] = (~ext.isin(FILE_EXTENSIONS)).astype("int32")

    g = x.groupby(["user_id", "date_day"], observed=True)
    spec = {
        "file_event_count": ("event_id", "size"),
        "file_distinct_pcs": ("device_id", "nunique"),
        "file_off_hours_events": ("off", "sum"),
    }
    for e in FILE_EXTENSIONS:
        spec[f"file_{e}_count"] = (f"file_{e}_count", "sum")
    spec["file_other_ext_count"] = ("file_other_ext_count", "sum")
    out = g.agg(**spec).reset_index().rename(columns={"date_day": "date"})
    out["file_archive_or_executable_count"] = out["file_zip_count"] + out["file_exe_count"]
    return out
