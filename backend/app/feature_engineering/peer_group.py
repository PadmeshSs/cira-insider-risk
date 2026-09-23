"""Peer-group deviation features (Architecture §10.9, HCEA §5.4).

Peer population
    Users sharing the same functional_unit + department in the LDAP snapshot
    for the feature month (point-in-time join), compared on the SAME calendar
    day.  Same-day comparison means a row never sees peers' future days
    (the previous month-pooled version did).  functional_unit is part of the
    key because CERT department names are only unique within a functional
    unit.

Statistic
    Exact leave-one-out median: the target user is excluded from their own
    peer median.  Computed in O(n log n) with a sort + rank lookup instead of
    a per-row Python loop, so the full ~4x10^5-row matrix takes seconds.

Nulls
    Null when the user has no LDAP row for that month, the department is
    blank, the feature value is null, or the user has no peers that day.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

PEER_FEATURES = [
    "login_count",
    "file_event_count",
    "emails_sent",
    "usb_connect_count",
    "http_request_count",
    "http_distinct_hosts",
]

PEER_KEY_COLUMNS = ["functional_unit", "department"]
_CONTEXT_COLUMNS = ["user_id", "snapshot_month", *PEER_KEY_COLUMNS]


def leave_one_out_median(values: pd.Series, groups: pd.Series) -> pd.Series:
    """Median of each row's group with that row removed (NaN if alone).

    ``values`` must have no nulls; ``groups`` is any hashable group key.
    """
    n_rows = len(values)
    if n_rows == 0:
        return pd.Series(dtype="float64", index=values.index)

    gcode = pd.factorize(groups, sort=False)[0]
    v = values.to_numpy(dtype="float64")
    order = np.lexsort((v, gcode))           # sort by group, then value
    g_sorted = gcode[order]
    v_sorted = v[order]

    # group start offset and size for every sorted position
    boundaries = np.flatnonzero(np.r_[True, g_sorted[1:] != g_sorted[:-1]])
    sizes = np.diff(np.r_[boundaries, n_rows])
    group_idx = np.repeat(np.arange(len(boundaries)), sizes)
    start = boundaries[group_idx]
    n = sizes[group_idx]
    rank = np.arange(n_rows) - start           # position of the row in its group

    m = n - 1                                   # size after removing the row
    k1 = (m - 1) // 2
    k2 = m // 2
    idx1 = k1 + (k1 >= rank)                    # skip over the removed row
    idx2 = k2 + (k2 >= rank)
    valid = m > 0
    safe1 = np.where(valid, start + idx1, 0)
    safe2 = np.where(valid, start + idx2, 0)
    med_sorted = np.where(valid, (v_sorted[safe1] + v_sorted[safe2]) / 2.0, np.nan)

    result = np.empty(n_rows, dtype="float64")
    result[order] = med_sorted
    return pd.Series(result, index=values.index)


def add_peer_features(
    df: pd.DataFrame,
    ldap: pd.DataFrame,
) -> tuple[pd.DataFrame, dict[str, dict]]:
    out = df.copy()
    out["date"] = pd.to_datetime(out["date"])
    out["snapshot_month"] = out["date"].dt.to_period("M").dt.to_timestamp()

    ctx = ldap.copy()
    for col in PEER_KEY_COLUMNS:
        if col not in ctx.columns:
            ctx[col] = ""
    ctx["snapshot_month"] = pd.to_datetime(ctx["snapshot_month"]).dt.to_period("M").dt.to_timestamp()
    ctx = ctx[_CONTEXT_COLUMNS].drop_duplicates(["user_id", "snapshot_month"], keep="last")

    out = out.merge(ctx, on=["user_id", "snapshot_month"], how="left", suffixes=("", "_ctx"))

    dept = out["department"].astype("string").fillna("").str.strip()
    fu = out["functional_unit"].astype("string").fillna("").str.strip()
    has_group = dept.ne("")
    group_key = fu + "\x1f" + dept + "\x1f" + out["date"].dt.strftime("%Y-%m-%d")

    meta: dict[str, dict] = {}
    for feature in PEER_FEATURES:
        if feature not in out.columns:
            continue
        mask = has_group & out[feature].notna()
        median = pd.Series(np.nan, index=out.index, dtype="float64")
        if mask.any():
            median.loc[mask] = leave_one_out_median(out.loc[mask, feature], group_key[mask])
        median = median.astype("float32")
        out[f"peer_median_{feature}"] = median
        dev = (out[feature].astype("float32") - median).astype("float32")
        out[f"peer_dev_{feature}"] = dev
        out[f"peer_abs_dev_{feature}"] = dev.abs().astype("float32")
        info = {
            "peer_key": "functional_unit + department + same calendar day (LDAP snapshot of that month)",
            "peer_statistic": "leave-one-out median (target user excluded)",
            "peer_excludes_target": True,
            "null_policy": "null when LDAP department missing, value missing, or no peers that day",
        }
        meta[f"peer_median_{feature}"] = dict(info)
        meta[f"peer_dev_{feature}"] = dict(info)
        meta[f"peer_abs_dev_{feature}"] = dict(info)

    # Distinct peers (excluding self) in the same group on the same day.
    size = group_key.where(has_group).map(group_key[has_group].value_counts()) - 1
    out["peer_department_size"] = size.clip(lower=0).astype("float32")
    meta["peer_department_size"] = {
        "peer_key": "functional_unit + department + same calendar day",
        "null_policy": "null when LDAP department missing",
    }

    out = out.drop(columns=["snapshot_month", *PEER_KEY_COLUMNS])
    return out, meta
