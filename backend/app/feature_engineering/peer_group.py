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


def add_peer_features(
    df: pd.DataFrame,
    ldap: pd.DataFrame,
) -> tuple[pd.DataFrame, dict[str, dict]]:
    out = df.copy()
    out["date"] = pd.to_datetime(out["date"])

    ctx = ldap.copy()
    ctx["snapshot_month"] = pd.to_datetime(ctx["snapshot_month"])
    ctx["snapshot_month"] = (
        ctx["snapshot_month"].dt.to_period("M").dt.to_timestamp()
    )

    out["snapshot_month"] = (
        out["date"].dt.to_period("M").dt.to_timestamp()
    )

    # Point-in-time join: only the LDAP snapshot for the feature month
    # is eligible for the peer-group context.
    ctx = ctx.sort_values(["user_id", "snapshot_month"])
    out = out.sort_values(["user_id", "snapshot_month"])

    out = out.merge(
        ctx,
        on=["user_id", "snapshot_month"],
        how="left",
        suffixes=("", "_ctx"),
    )

    meta = {}

    valid_dept = (
        out["department"]
        .fillna("")
        .astype("string")
        .str.strip()
        .ne("")
    )

    # Peer population is department + snapshot_month, excluding
    # the target user from their own peer statistics.
    peer_keys = ["snapshot_month", "department"]

    for feature in PEER_FEATURES:
        if feature not in out.columns:
            continue

        peer_median = pd.Series(
            np.nan,
            index=out.index,
            dtype="float32",
        )

        valid = out.loc[
            valid_dept
            & out[feature].notna()
        ]

        for _, group in valid.groupby(peer_keys, observed=True):
            values = group[[ "user_id", feature ]]

            for idx, row in values.iterrows():
                peers = values.loc[
                    values["user_id"] != row["user_id"],
                    feature,
                ]

                if not peers.empty:
                    peer_median.loc[idx] = np.float32(
                        peers.median()
                    )

        out[f"peer_median_{feature}"] = peer_median
        out[f"peer_dev_{feature}"] = (
            out[feature] - peer_median
        ).astype("float32")
        out[f"peer_abs_dev_{feature}"] = (
            out[feature] - peer_median
        ).abs().astype("float32")

        meta[f"peer_dev_{feature}"] = {
            "peer_key": "department + snapshot_month",
            "peer_excludes_target": True,
            "null_policy": (
                "null when department is missing, "
                "peer population is empty, or peer median unavailable"
            ),
        }

        meta[f"peer_abs_dev_{feature}"] = dict(
            meta[f"peer_dev_{feature}"]
        )

    # Count distinct users, not user-day rows.
    peer_sizes = (
        out.loc[valid_dept]
        .groupby(peer_keys, observed=True)["user_id"]
        .transform("nunique")
        - 1
    )

    out["peer_department_size"] = (
        peer_sizes.where(valid_dept)
        .clip(lower=0)
        .astype("float32")
    )

    out = out.drop(columns=["snapshot_month"])

    return out, meta