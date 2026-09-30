"""Which user-days get the bounded treatment (HCEA D-5, N31, N39, N40).

TreeSHAP runs on every user-day. KernelSHAP, the deletion check and the
written reasons (``reasons.jsonl``) run on a bounded set, because D-5 limits
KernelSHAP to "alert rows plus the dashboard's top-k". Alerts do not exist
until Chapter 12, and Chapter 12 has not chosen the analyst-queue ordering
(N40, N46: no ordering dominates on validation). So this rule does not choose
one either. A user-day is selected if any of these holds:

    severity    its CRI severity is HIGH or CRITICAL (the band view, N39)
    anomaly     it is in its day's top-k by the served anomaly score
    cri         it is in its day's top-k by the CRI score

and it belongs to a validation or test user of the served model's split
(N31: in-sample rows are never used as example explanations). Chapter 12
explains its own alert rows on demand through the same code.

The rule is label-free and deterministic. Ties inside a day are broken by
user_id, which is fine for picking examples and is never used as a detection
metric (the evaluation harness uses a seeded tie-break instead). If the
union exceeds ``max_rows``, rows are kept in this order: test before
validation (test users are preferred for examples, N31), then higher
severity, higher CRI, higher anomaly score, user_id, date. The number cut is
recorded.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SELECT_SEVERITIES = ("HIGH", "CRITICAL")
SELECT_SPLITS = ("validation", "test")
DEFAULT_TOP_K = 1
DEFAULT_MAX_ROWS = 300
RULE_VERSION = "c11-selection-v1"


def per_day_top_k(frame: pd.DataFrame, score: str, k: int) -> np.ndarray:
    order = frame.assign(_s=-frame[score].to_numpy(dtype="float64"), _pos=np.arange(len(frame)))
    order = order.sort_values(["date", "_s", "user_id"], kind="mergesort")
    rank = order.groupby("date", sort=False).cumcount().to_numpy()
    mask = np.zeros(len(frame), dtype=bool)
    mask[order["_pos"].to_numpy()[rank < k]] = True
    return mask


def select_rows(risk: pd.DataFrame, *, top_k_per_day: int = DEFAULT_TOP_K, max_rows: int = DEFAULT_MAX_ROWS,
                splits=SELECT_SPLITS, severities=SELECT_SEVERITIES) -> tuple[pd.DataFrame, dict]:
    """``risk`` needs user_id, date, model_split, anomaly_score, cri_score, severity."""
    need = ["user_id", "date", "model_split", "anomaly_score", "cri_score", "severity"]
    missing = [c for c in need if c not in risk.columns]
    if missing:
        raise ValueError(f"selection needs {missing}")
    pool = risk[risk["model_split"].astype(str).isin(splits)].reset_index(drop=True)
    if pool.empty:
        empty = pool[need].assign(by_severity=False, by_anomaly=False, by_cri=False)
        return empty, {"rule": RULE_VERSION, "candidates": 0, "selected": 0, "truncated": 0}
    by_sev = pool["severity"].astype(str).isin(severities).to_numpy()
    by_anom = per_day_top_k(pool, "anomaly_score", top_k_per_day)
    by_cri = per_day_top_k(pool, "cri_score", top_k_per_day)
    keep = by_sev | by_anom | by_cri
    sel = pool.loc[keep, need].assign(by_severity=by_sev[keep], by_anomaly=by_anom[keep], by_cri=by_cri[keep])
    sel = sel.assign(_test=(sel["model_split"].astype(str) != "test").astype(int),
                     _sev=-sel["severity"].astype(str).map(SEVERITY_RANK).fillna(0).astype(int),
                     _cri=-sel["cri_score"].astype("float64"), _an=-sel["anomaly_score"].astype("float64"))
    sel = sel.sort_values(["_test", "_sev", "_cri", "_an", "user_id", "date"], kind="mergesort")
    n = len(sel)
    sel = sel.head(max(0, int(max_rows))).drop(columns=["_test", "_sev", "_cri", "_an"])
    sel = sel.sort_values(["user_id", "date"], kind="mergesort").reset_index(drop=True)
    info = {
        "rule": RULE_VERSION, "splits": list(splits), "severities": list(severities),
        "top_k_per_day": int(top_k_per_day), "max_rows": int(max_rows), "candidates": int(n),
        "selected": int(len(sel)), "truncated": int(n - len(sel)),
        "by_reason": {"severity": int(sel["by_severity"].sum()), "anomaly_top_k": int(sel["by_anomaly"].sum()),
                      "cri_top_k": int(sel["by_cri"].sum())},
        "by_split": {k: int(v) for k, v in sel["model_split"].astype(str).value_counts().sort_index().items()},
    }
    return sel, info
