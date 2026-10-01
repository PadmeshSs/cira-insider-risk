"""Triggered user-days -> alerts (Bible Ch12 step 1, Architecture §17).

    alerts, members = correlate(days, policy)

``days`` holds the triggered user-days only, one row each, with user_id,
date, model_split, anomaly_score, cri_score, severity, by_band, by_top_k,
top_feature (the day's top raising model factor, or null) and techniques
(comma-separated ATT&CK ids, or null).

Rule (deterministic, label-free)
    Per user, days in date order. A day joins the current alert if it is at
    most ``correlation_gap_days`` calendar days after the previous triggered
    day and at most ``max_span_days - 1`` days after the alert's first day;
    otherwise it starts a new alert. So the §17 example, an unusual logon, a
    large copy, an archive and an external visit on consecutive days, is one
    alert, and a user who triggers every day for a month is several.

Alert fields
    the peak day is the member with the highest ordering score (ties: the
    earlier day); ``queue_score`` is that score and orders the queue;
    ``max_severity`` / ``max_cri_score`` are over the members, shown as
    context (N40); ``techniques`` is the union over members; ``top_feature``
    is the peak day's top raising factor (N52 reports how often it is
    ``usb_disconnect_count``). ``alert_key`` is a hash of the policy, the user
    and the first day, so re-running the same policy gives the same keys.

An alert never mixes users. The CRI is never recomputed here and the anomaly
score is never changed (N34).
"""
from __future__ import annotations

import hashlib

import numpy as np
import pandas as pd

from .policy import SEVERITY_RANK, AlertPolicy

DAY_COLUMNS = ("user_id", "date", "model_split", "anomaly_score", "cri_score", "severity", "by_band", "by_top_k",
               "top_feature", "techniques")
ALERT_COLUMNS = (
    "alert_key", "user_id", "first_date", "last_date", "n_days", "span_days", "peak_date", "peak_anomaly_score",
    "peak_cri_score", "max_cri_score", "max_severity", "queue_score", "ordering", "triggers", "techniques",
    "top_feature", "model_split", "n_by_band", "n_by_top_k",
)
MEMBER_COLUMNS = ("alert_key", "user_id", "date", "is_peak", "by_band", "by_top_k", "anomaly_score", "cri_score",
                  "severity", "model_split", "top_feature", "techniques")


def alert_key(policy_hash: str, user_id: str, first_date: str) -> str:
    return hashlib.sha256(f"{policy_hash}|{user_id}|{first_date}".encode()).hexdigest()[:16]


def _split_list(value) -> list[str]:
    if value is None or (isinstance(value, float) and np.isnan(value)) or value is pd.NA:
        return []
    return [x for x in str(value).split(",") if x]


def groups(dates: list[pd.Timestamp], gap: int, span: int) -> list[int]:
    """Group index per date (dates sorted ascending)."""
    out, g, first, prev = [], -1, None, None
    for d in dates:
        if prev is None or (d - prev).days > gap or (d - first).days >= span:
            g += 1
            first = d
        out.append(g)
        prev = d
    return out


def correlate(days: pd.DataFrame, policy: AlertPolicy) -> tuple[pd.DataFrame, pd.DataFrame]:
    missing = [c for c in DAY_COLUMNS if c not in days.columns]
    if missing:
        raise ValueError(f"correlate needs {missing}")
    if days.empty:
        return pd.DataFrame(columns=list(ALERT_COLUMNS)), pd.DataFrame(columns=list(MEMBER_COLUMNS))
    if days.duplicated(["user_id", "date"]).any():
        raise ValueError("a user-day appears twice among the triggered days")
    d = days.assign(_ts=pd.to_datetime(days["date"].astype(str))).sort_values(["user_id", "_ts"], kind="mergesort")
    d = d.reset_index(drop=True)
    gid = np.empty(len(d), dtype=np.int64)
    offset = 0
    for _, idx in d.groupby("user_id", sort=False).indices.items():
        g = groups(list(d["_ts"].iloc[idx]), policy.correlation_gap_days, policy.max_span_days)
        gid[idx] = np.asarray(g) + offset
        offset += max(g) + 1
    d["_g"] = gid
    h = policy.policy_hash
    alerts, members = [], []
    for _, grp in d.groupby("_g", sort=True):
        order = grp.assign(_o=-grp[policy.ordering].astype("float64")).sort_values(["_o", "_ts"], kind="mergesort")
        peak = order.iloc[0]
        user, first, last = str(grp["user_id"].iloc[0]), str(grp["date"].iloc[0]), str(grp["date"].iloc[-1])
        key = alert_key(h, user, first)
        techs = sorted({t for v in grp["techniques"] for t in _split_list(v)})
        sev = max(grp["severity"].astype(str), key=lambda s: SEVERITY_RANK.get(s, -1))
        splits = sorted(set(grp["model_split"].astype(str)))
        trig = [n for n, c in (("band", "by_band"), ("top_k", "by_top_k")) if grp[c].any()]
        alerts.append({
            "alert_key": key, "user_id": user, "first_date": first, "last_date": last, "n_days": int(len(grp)),
            "span_days": int((grp["_ts"].iloc[-1] - grp["_ts"].iloc[0]).days) + 1,
            "peak_date": str(peak["date"]), "peak_anomaly_score": float(peak["anomaly_score"]),
            "peak_cri_score": float(peak["cri_score"]), "max_cri_score": float(grp["cri_score"].max()),
            "max_severity": sev, "queue_score": float(peak[policy.ordering]), "ordering": policy.ordering,
            "triggers": ",".join(trig), "techniques": ",".join(techs) or None,
            "top_feature": None if pd.isna(peak["top_feature"]) else str(peak["top_feature"]),
            "model_split": splits[0] if len(splits) == 1 else "mixed",
            "n_by_band": int(grp["by_band"].sum()), "n_by_top_k": int(grp["by_top_k"].sum()),
        })
        for _, r in grp.iterrows():
            members.append({
                "alert_key": key, "user_id": user, "date": str(r["date"]), "is_peak": str(r["date"]) == str(peak["date"]),
                "by_band": bool(r["by_band"]), "by_top_k": bool(r["by_top_k"]),
                "anomaly_score": float(r["anomaly_score"]), "cri_score": float(r["cri_score"]),
                "severity": str(r["severity"]), "model_split": str(r["model_split"]),
                "top_feature": None if pd.isna(r["top_feature"]) else str(r["top_feature"]),
                "techniques": None if not _split_list(r["techniques"]) else ",".join(_split_list(r["techniques"])),
            })
    return pd.DataFrame(alerts, columns=list(ALERT_COLUMNS)), pd.DataFrame(members, columns=list(MEMBER_COLUMNS))
