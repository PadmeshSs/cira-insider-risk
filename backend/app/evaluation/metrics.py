"""Imbalance-aware metrics for user-day scoring (CARRY_FORWARD N1, N2).

Headline numbers are PR-AUC (average precision) and recall / precision at a
fixed daily alert budget: the top-k user-days per calendar day, which is
what an analyst could actually review. Per-user detection counts an insider
as caught if any of their malicious days is alerted within the budget.
ROC-AUC is reported as a secondary number only. Accuracy is not computed
anywhere in this module, on purpose: at ~0.9% positives it says nothing.

Masquerade account-days (``exclude``) are neither positives nor negatives
in the primary view. They are still ranked with everyone else, because a
real analyst queue would contain them; if they take an alert slot they are
counted as neither a true nor a false positive.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

DEFAULT_BUDGETS = (1, 5, 10)


def _check_scores(scores: np.ndarray) -> np.ndarray:
    s = np.asarray(scores, dtype="float64")
    if not np.isfinite(s).all():
        raise ValueError(f"{int((~np.isfinite(s)).sum())} non-finite scores; a detector must never emit NaN/inf")
    return s


def pr_auc(y: np.ndarray, scores: np.ndarray) -> float | None:
    y = np.asarray(y)
    if y.sum() == 0 or y.sum() == len(y):
        return None
    return float(average_precision_score(y, _check_scores(scores)))


def roc_auc(y: np.ndarray, scores: np.ndarray) -> float | None:
    y = np.asarray(y)
    if y.sum() == 0 or y.sum() == len(y):
        return None
    return float(roc_auc_score(y, _check_scores(scores)))


def daily_top_k(dates: pd.Series, scores: np.ndarray, k: int, *, seed: int) -> np.ndarray:
    """Boolean mask: the k highest-scoring rows on each calendar day.

    Ties are broken by a seeded random key, not by user id, so a detector
    with many tied scores (the rule baseline) is not helped or hurt by the
    alphabetical order of user ids.
    """
    if k < 1:
        raise ValueError("budget k must be >= 1")
    s = _check_scores(scores)
    rng = np.random.default_rng(seed)
    frame = pd.DataFrame({"d": dates.astype("string").to_numpy(), "s": -s, "t": rng.random(len(s)), "i": np.arange(len(s))})
    frame = frame.sort_values(["d", "s", "t"], kind="mergesort")
    rank = frame.groupby("d", sort=False).cumcount().to_numpy()
    mask = np.zeros(len(s), dtype=bool)
    mask[frame["i"].to_numpy()[rank < k]] = True
    return mask


def budget_counts(y: np.ndarray, alerted: np.ndarray, exclude: np.ndarray | None = None) -> dict:
    y = np.asarray(y).astype(bool)
    alerted = np.asarray(alerted).astype(bool)
    excl = np.zeros_like(y) if exclude is None else np.asarray(exclude).astype(bool)
    keep = ~excl
    tp = int((alerted & y & keep).sum())
    fp = int((alerted & ~y & keep).sum())
    positives = int((y & keep).sum())
    return {
        "alerts": int(alerted.sum()),
        "alerts_on_excluded_rows": int((alerted & excl).sum()),
        "true_positives": tp,
        "false_positives": fp,
        "positives": positives,
        "precision": tp / (tp + fp) if (tp + fp) else None,
        "recall": tp / positives if positives else None,
    }


def per_scenario_recall(y, alerted, scenario, exclude=None) -> dict[str, dict]:
    y = np.asarray(y).astype(bool)
    alerted = np.asarray(alerted).astype(bool)
    scenario = np.asarray(scenario)
    keep = np.ones_like(y) if exclude is None else ~np.asarray(exclude).astype(bool)
    out = {}
    for s in sorted(set(scenario[y & keep].tolist())):
        m = y & keep & (scenario == s)
        out[str(int(s))] = {"positives": int(m.sum()), "alerted": int((m & alerted).sum()), "recall": float((m & alerted).sum() / m.sum())}
    return out


def per_user_detection(users, dates, y, alerted, scenario, exclude=None) -> dict:
    """Insider caught = at least one of their malicious days alerted.

    Latency is days from the insider's first malicious day in this split to
    the first alerted malicious day, for caught insiders only.
    """
    frame = pd.DataFrame(
        {
            "u": pd.Series(users).astype("string").to_numpy(),
            "d": pd.to_datetime(pd.Series(dates).astype("string")).to_numpy(),
            "y": np.asarray(y).astype(bool),
            "a": np.asarray(alerted).astype(bool),
            "s": np.asarray(scenario),
        }
    )
    if exclude is not None:
        frame = frame[~np.asarray(exclude).astype(bool)]
    pos = frame[frame["y"]]
    if pos.empty:
        return {"insiders": 0, "caught": 0, "by_scenario": {}, "latency_days": None}
    first_mal = pos.groupby("u")["d"].min()
    hit = pos[pos["a"]]
    first_hit = hit.groupby("u")["d"].min()
    scen = pos.groupby("u")["s"].min()
    by_scenario = {}
    for s in sorted(scen.unique().tolist()):
        members = scen[scen == s].index
        caught = [u for u in members if u in first_hit.index]
        by_scenario[str(int(s))] = {"insiders": int(len(members)), "caught": int(len(caught))}
    latency = (first_hit - first_mal.loc[first_hit.index]).dt.days
    return {
        "insiders": int(len(first_mal)),
        "caught": int(len(first_hit)),
        "by_scenario": by_scenario,
        "latency_days": None
        if latency.empty
        else {"median": float(latency.median()), "mean": float(latency.mean()), "max": int(latency.max())},
    }


def _view_metrics(users, dates, scores, y, scenario, exclude, budgets, seed) -> dict:
    y = np.asarray(y).astype("int8")
    excl = np.zeros(len(y), dtype=bool) if exclude is None else np.asarray(exclude).astype(bool)
    keep = ~excl
    out = {
        "rows": int(len(y)),
        "rows_excluded": int(excl.sum()),
        "positives": int(y[keep].sum()),
        "positive_rate": float(y[keep].mean()) if keep.any() else None,
        "users": int(pd.Series(users).nunique()),
        "days": int(pd.Series(dates).nunique()),
        "pr_auc": pr_auc(y[keep], scores[keep]),
        "roc_auc_secondary": roc_auc(y[keep], scores[keep]),
        "budgets": {},
    }
    for k in budgets:
        alerted = daily_top_k(pd.Series(dates), scores, k, seed=seed)
        out["budgets"][str(k)] = {
            **budget_counts(y, alerted, excl),
            "recall_by_scenario": per_scenario_recall(y, alerted, scenario, excl),
            "per_user": per_user_detection(users, dates, y, alerted, scenario, excl),
        }
    return out


def evaluate_scores(
    keys: pd.DataFrame,
    scores: np.ndarray,
    labels: pd.DataFrame,
    *,
    budgets=DEFAULT_BUDGETS,
    seed: int = 42,
) -> dict:
    """Full metric block for one detector on one split.

    ``keys`` (user_id, date) and ``labels`` (from ``attach_labels``) must be
    aligned row for row with ``scores``.
    """
    s = _check_scores(scores)
    if not (len(keys) == len(labels) == len(s)):
        raise ValueError("keys, labels and scores must have the same length")
    users = keys["user_id"].astype("string").to_numpy()
    dates = keys["date"].astype("string").to_numpy()

    primary = _view_metrics(
        users, dates, s, labels["y_primary"].to_numpy(), labels["scenario_primary"].to_numpy(),
        labels["exclude_primary"].to_numpy(), budgets, seed,
    )
    account = _view_metrics(
        users, dates, s, labels["y_account"].to_numpy(), labels["scenario_account"].to_numpy(),
        None, budgets, seed,
    )
    differ = labels["y_primary"].to_numpy() != labels["y_account"].to_numpy()
    return {
        "primary": primary,
        "secondary_account_view": account,
        "view_difference": {
            "rows_with_different_label": int(differ.sum()),
            "primary_positive_account_negative": int(((labels["y_primary"] == 1) & (labels["y_account"] == 0)).sum()),
            "account_positive_primary_negative": int(((labels["y_account"] == 1) & (labels["y_primary"] == 0)).sum()),
            "masquerade_rows_excluded_from_primary": int(labels["exclude_primary"].sum()),
        },
    }


def headline(metrics: dict, budgets=DEFAULT_BUDGETS) -> dict:
    """Flat summary for the runlog and console table (primary view)."""
    p = metrics["primary"]
    out = {"pr_auc": p["pr_auc"], "roc_auc_secondary": p["roc_auc_secondary"], "positives": p["positives"]}
    for k in budgets:
        b = p["budgets"][str(k)]
        out[f"recall_at_{k}"] = b["recall"]
        out[f"precision_at_{k}"] = b["precision"]
        out[f"insiders_caught_at_{k}"] = f'{b["per_user"]["caught"]}/{b["per_user"]["insiders"]}'
    return out
