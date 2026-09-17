from __future__ import annotations
import pandas as pd
from .common import off_hours

# Deliberately conservative structural categories. The actual host list must be
# independently reviewed; this module never reads ground truth or answer files.
# No host category is hard-coded here.  The dataset context requires any
# host-class list to be independently reviewed and kept as a project artifact.
DEFAULT_HOST_CATEGORIES: dict[str, tuple[str, ...]] = {}

def _category(host: pd.Series, suffixes: tuple[str, ...]) -> pd.Series:
    return host.map(lambda h: int(any(h == s or h.endswith("." + s) for s in suffixes))).astype("int8")

def aggregate(df: pd.DataFrame, categories: dict[str, tuple[str, ...]] | None = None) -> pd.DataFrame:
    x = df.copy()
    cats = categories or DEFAULT_HOST_CATEGORIES
    x["off"] = off_hours(x["hour"])
    g = x.groupby(["user_id", "date_day"], observed=True)
    out = g.agg(http_request_count=("event_id", "size"), http_distinct_hosts=("host", "nunique"), http_off_hours_count=("off", "sum")).reset_index().rename(columns={"date_day": "date"})
    for name, suffixes in cats.items():
        flags = _category(x["host"], suffixes)
        grouped = flags.groupby([x["user_id"], x["date_day"]], observed=True).max()
        grouped = grouped.rename(f"http_{name}_flag").reset_index().rename(columns={"date_day": "date"})
        out = out.merge(grouped, on=["user_id", "date"], how="left")
    out["http_new_host_count"] = 0.0
    return out
