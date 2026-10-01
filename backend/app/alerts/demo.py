"""The bounded demo sample, c12-demo-sample-v1 (HCEA D-6, N31).

D-6 persists alert-linked rows plus "a bounded, deterministic sample for
demonstration purposes (suggested: all events for ~20 users across the demo
window)", with the selection rule recorded. This is the rule. It is
label-free: it reads alerts and scored keys, never a label (N5).

    window      ``window_days`` consecutive calendar days. Among open alerts of
                test users (validation users if no test user has one), the
                window starting on some alert's peak day that contains the
                most open-alert peak days; ties go to the earliest start. With
                no open alert at all, the last ``window_days`` days of the
                eligible users' scored dates.
    users       at most ``max_users``: first up to ``max_alerting_users``
                users with an open alert peaking in the window (test before
                validation, higher queue score first, then user_id), then
                users with no open alert anywhere in the run and some scored
                day in the window, test before validation, ordered by
                sha256(seed|user_id). The dashboard needs ordinary users too,
                so an analyst sees what a quiet day looks like. A user whose
                only open alerts fall outside the window is in neither group.
    rows        every scored user-day of those users inside the window.

Only validation and test users are eligible: in-sample rows are never
example material (N31), and test users are preferred because validation
chose the model.
"""
from __future__ import annotations

import hashlib

import pandas as pd

DEMO_VERSION = "c12-demo-sample-v1"
ELIGIBLE = ("test", "validation")


def _prefer(split: str) -> int:
    return ELIGIBLE.index(split) if split in ELIGIBLE else len(ELIGIBLE)


def demo_sample(keys: pd.DataFrame, alerts: pd.DataFrame, *, window_days: int = 30, max_users: int = 20,
                max_alerting_users: int = 10, seed: int = 42) -> tuple[pd.DataFrame, dict]:
    """``keys``: user_id, date, model_split of every scored row. Returns (user_id, date) rows and the record."""
    info = {"rule": DEMO_VERSION, "window_days": int(window_days), "max_users": int(max_users),
            "max_alerting_users": int(max_alerting_users), "seed": int(seed), "eligible_splits": list(ELIGIBLE)}
    k = keys[keys["model_split"].astype(str).isin(ELIGIBLE)][["user_id", "date", "model_split"]].copy()
    if k.empty or max_users < 1 or window_days < 1:
        return pd.DataFrame(columns=["user_id", "date"]), {**info, "users": [], "rows": 0, "window": None}
    k["date"] = k["date"].astype(str)
    open_a = alerts[(alerts["status"] == "open") & alerts["model_split"].astype(str).isin(ELIGIBLE)] \
        if len(alerts) else alerts
    pool = pd.DataFrame()
    for split in ELIGIBLE:
        pool = open_a[open_a["model_split"].astype(str) == split] if len(open_a) else open_a
        if len(pool):
            break
    W = pd.Timedelta(days=window_days - 1)
    if len(pool):
        peaks = pd.to_datetime(pool["peak_date"].astype(str)).sort_values().to_numpy()
        best, start = -1, None
        for s in sorted(set(peaks)):
            n = int(((peaks >= s) & (peaks <= s + W)).sum())
            if n > best:
                best, start = n, pd.Timestamp(s)
    else:
        start = pd.Timestamp(k["date"].max()) - W
    end = start + W
    lo, hi = start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")

    split_of = k.groupby("user_id")["model_split"].first().astype(str).to_dict()
    chosen: list[str] = []
    if len(open_a):
        inside = open_a[(open_a["peak_date"].astype(str) >= lo) & (open_a["peak_date"].astype(str) <= hi)]
        best_q = inside.groupby("user_id")["queue_score"].max()
        ranked = sorted(best_q.index, key=lambda u: (_prefer(split_of.get(u, "")), -float(best_q[u]), str(u)))
        chosen = [u for u in ranked if u in split_of][:max(0, min(max_alerting_users, max_users))]
    alerting = set(open_a["user_id"].astype(str)) if len(open_a) else set()
    active = set(k.loc[(k["date"] >= lo) & (k["date"] <= hi), "user_id"].astype(str))
    rest = sorted((u for u in active if u not in alerting and u not in chosen),
                  key=lambda u: (_prefer(split_of.get(u, "")), hashlib.sha256(f"{seed}|{u}".encode()).hexdigest()))
    chosen += rest[:max(0, max_users - len(chosen))]
    rows = k[k["user_id"].isin(chosen) & (k["date"] >= lo) & (k["date"] <= hi)][["user_id", "date"]]
    rows = rows.sort_values(["user_id", "date"], kind="mergesort").reset_index(drop=True)
    return rows, {**info, "window": {"start": lo, "end": hi}, "users": chosen,
                  "alerting_users": [u for u in chosen if u in alerting], "rows": int(len(rows))}
