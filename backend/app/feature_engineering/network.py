"""HTTP / network features per user-day.

CERT r4.2 http.csv has no byte counts, ports or inbound/outbound direction,
so Bible §10.5 byte-volume features are unsupported and not produced.
What *is* supported: request volume, off-hours volume, destination
diversity, first-seen destinations, and expert host-class counts from the
committed, human-reviewed list in network_domains.py (HCEA §5.2).

Chunk safety: all columns emitted here are additive counts.
``http_distinct_hosts`` and ``http_new_host_count`` are recomputed exactly
by pipeline.aggregate_http from deduplicated (user, day, host) triples.
"""
from __future__ import annotations

import pandas as pd

from .common import categorize_hosts, off_hours
from .network_domains import HOST_CATEGORIES


def aggregate(df: pd.DataFrame, categories: dict[str, tuple[str, ...]] | None = None) -> pd.DataFrame:
    cats = HOST_CATEGORIES if categories is None else categories
    x = df[["user_id", "date_day", "hour", "host", "event_id"]].copy()
    x["off"] = off_hours(x["hour"]).astype("int32")
    flags = categorize_hosts(x["host"], cats)
    spec = {
        "http_request_count": ("event_id", "size"),
        "http_distinct_hosts": ("host", "nunique"),
        "http_off_hours_count": ("off", "sum"),
    }
    for name in cats:
        col = f"http_{name}_count"
        x[col] = flags[name].astype("int32")
        spec[col] = (col, "sum")
    g = x.groupby(["user_id", "date_day"], observed=True)
    return g.agg(**spec).reset_index().rename(columns={"date_day": "date"})
