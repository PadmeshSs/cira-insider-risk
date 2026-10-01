"""Suppress a repeat of the same pattern inside the cooldown (Bible Ch12 step 2).

    alerts = deduplicate(alerts, policy)     # adds status, duplicate_of, signature

Signature of an alert: its ATT&CK technique ids plus ``factor:<top_feature>``
(the peak day's top raising model factor). It describes what the analyst
would read first, and it is label-free.

Rule, per user in first_date order, against the user's most recent OPEN
alert:

    suppressed  if the new alert starts at most ``cooldown_days`` after that
                open alert's last day, its signature is not empty, and every
                element of it is already in that open alert's signature
    open        otherwise (a new pattern, the cooldown has passed, or nothing
                identifies the pattern)

A suppressed alert is kept, not dropped: it is written to Parquet and to
PostgreSQL with ``status = 'suppressed'`` and ``duplicate_of`` naming the
open alert it repeats, so the suppression can be audited. It does not enter
the analyst queue. A suppressed alert never suppresses another one: the
comparison is always with an open alert, so a chain of repeats cannot hide a
change of pattern.
"""
from __future__ import annotations

import pandas as pd

from .correlation import _split_list
from .policy import AlertPolicy

STATUSES = ("open", "suppressed")


def signature(techniques, top_feature) -> list[str]:
    sig = set(_split_list(techniques))
    if top_feature is not None and not pd.isna(top_feature) and str(top_feature):
        sig.add(f"factor:{top_feature}")
    return sorted(sig)


def deduplicate(alerts: pd.DataFrame, policy: AlertPolicy) -> pd.DataFrame:
    out = alerts.copy()
    if out.empty:
        return out.assign(signature=pd.Series(dtype=object), status=pd.Series(dtype=object),
                          duplicate_of=pd.Series(dtype=object))
    out["signature"] = [",".join(signature(t, f)) or None for t, f in zip(out["techniques"], out["top_feature"])]
    out = out.sort_values(["user_id", "first_date", "alert_key"], kind="mergesort").reset_index(drop=True)
    status, dup = [], []
    last_open: dict[str, tuple[pd.Timestamp, set, str]] = {}
    for user, first, last, sig, key in zip(out["user_id"], out["first_date"], out["last_date"], out["signature"],
                                           out["alert_key"]):
        s = set(_split_list(sig))
        prev = last_open.get(user)
        if prev is not None and s and (pd.Timestamp(first) - prev[0]).days <= policy.cooldown_days and s <= prev[1]:
            status.append("suppressed")
            dup.append(prev[2])
            continue
        status.append("open")
        dup.append(None)
        last_open[user] = (pd.Timestamp(last), s, key)
    out["status"] = status
    out["duplicate_of"] = pd.Series(dup, index=out.index, dtype=object)   # keep None, not NaN
    return out
