"""Confidence intervals and paired tests for Chapter 16 (Bible item 5, N3, N15, N26).

Why a cluster bootstrap and not a row bootstrap
    User-days of one user are not independent: an insider's malicious days sit together and a benign
    user's days all look alike to a model. Resampling rows would make every interval too narrow. The
    unit of resampling is the USER (the same unit the split is made on, N3). One replicate draws
    ``n_users`` users with replacement; a row's weight is how many times its user was drawn.

What is held fixed in a replicate
    * Scores are fixed. Nothing is refitted, so the interval is about which users the test set holds,
      not about training noise. Training noise is measured separately, over seeds (``paired_wilcoxon``,
      ``seed_summary``).
    * Alert masks (daily top-k, a CRI band, the alert queue) are fixed: they are what the analyst's
      queue held on the real population that day. A replicate only changes how many times each user's
      outcomes are counted. Re-ranking each day inside a resampled population would measure a queue
      nobody saw.

Paired comparisons
    Two rankings are compared on the SAME replicates, so the difference interval removes the part of the
    noise they share. ``p_two_sided`` is the bootstrap sign proportion, 2 * min(P(diff <= 0),
    P(diff >= 0)), floored at 2 / (B + 1). It is an approximate p-value; the interval is the evidence.

Seeds
    ``paired_wilcoxon`` is the Wilcoxon signed-rank test over per-seed paired metrics. With n pairs the
    smallest two-sided p it can reach is 2 / 2**n, so n = 5 can never go below 0.0625. The result says so
    instead of reporting a p that cannot be significant (N26).

No label is read here. Callers pass aligned arrays (N5).
"""
from __future__ import annotations

from typing import Mapping, Sequence

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

DEFAULT_BOOT = 1000
ALPHA = 0.05


def _user_index(users) -> tuple[np.ndarray, np.ndarray]:
    uniq, inverse = np.unique(np.asarray(users).astype(str), return_inverse=True)
    return uniq, inverse


def _interval(values: np.ndarray, point: float | None) -> dict:
    v = values[np.isfinite(values)]
    if v.size == 0:
        return {"point": point, "lo": None, "hi": None, "valid_replicates": 0}
    lo, hi = np.quantile(v, [ALPHA / 2, 1 - ALPHA / 2])
    return {"point": point, "lo": float(lo), "hi": float(hi), "valid_replicates": int(v.size)}


def _weighted_pr_auc(y, s, w) -> float:
    m = w > 0
    yy = y[m]
    if yy.sum() == 0 or yy.sum() == len(yy):
        return float("nan")
    return float(average_precision_score(yy, s[m], sample_weight=w[m]))


def _weighted_roc_auc(y, s, w) -> float:
    m = w > 0
    yy = y[m]
    if yy.sum() == 0 or yy.sum() == len(yy):
        return float("nan")
    return float(roc_auc_score(yy, s[m], sample_weight=w[m]))


def _mask_stats(tp_u, fp_u, pos_u, w) -> dict[str, float]:
    """Recall, precision and insiders-caught share for one fixed mask under user weights ``w``."""
    pos = float((w * pos_u).sum())
    tp = float((w * tp_u).sum())
    alerts = tp + float((w * fp_u).sum())
    insiders = float((w * (pos_u > 0)).sum())
    caught = float((w * (tp_u > 0)).sum())
    return {
        "recall": tp / pos if pos else float("nan"),
        "precision": tp / alerts if alerts else float("nan"),
        "insiders_caught_share": caught / insiders if insiders else float("nan"),
    }


def cluster_bootstrap(
    users,
    y,
    exclude,
    scores: Mapping[str, np.ndarray],
    masks: Mapping[str, np.ndarray] | None = None,
    *,
    pairs: Sequence[tuple[str, str]] = (),
    n_boot: int = DEFAULT_BOOT,
    seed: int = 42,
) -> dict:
    """Percentile intervals (95%) for PR-AUC / ROC-AUC of ``scores`` and recall / precision / insiders-caught
    share of ``masks``, plus paired differences for ``pairs`` (names present in ``scores`` and / or ``masks``).

    ``exclude`` marks masquerade account-days (N1): they carry weight 0 in every statistic.
    """
    masks = dict(masks or {})
    y = np.asarray(y).astype(bool)
    keep = ~np.asarray(exclude).astype(bool)
    uniq, inverse = _user_index(users)
    n_users = len(uniq)
    if n_users < 2:
        raise ValueError("a cluster bootstrap needs at least two users")
    for name, s in scores.items():
        if len(s) != len(y) or not np.isfinite(np.asarray(s, dtype="float64")).all():
            raise ValueError(f"scores[{name!r}] must be finite and aligned with y")
    for name, m in masks.items():
        if len(m) != len(y):
            raise ValueError(f"masks[{name!r}] must be aligned with y")

    rng = np.random.default_rng(seed)
    counts = rng.multinomial(n_users, np.full(n_users, 1.0 / n_users), size=n_boot).astype("float64")   # B x U

    yk = y[keep]
    inv_k = inverse[keep]
    s_k = {n: np.asarray(s, dtype="float64")[keep] for n, s in scores.items()}

    # per-user sufficient statistics for every mask
    def per_user(mask):
        a = np.asarray(mask).astype(bool)[keep]
        tp = np.bincount(inv_k, weights=(a & yk).astype(float), minlength=n_users)
        fp = np.bincount(inv_k, weights=(a & ~yk).astype(float), minlength=n_users)
        return tp, fp
    pos_u = np.bincount(inv_k, weights=yk.astype(float), minlength=n_users)
    mask_u = {n: per_user(m) for n, m in masks.items()}

    full_w = np.ones(n_users)
    point: dict[tuple[str, str], float] = {}
    draws: dict[tuple[str, str], np.ndarray] = {}
    for n, s in s_k.items():
        row_full = np.ones(len(yk))
        point[(n, "pr_auc")] = _weighted_pr_auc(yk, s, row_full)
        point[(n, "roc_auc")] = _weighted_roc_auc(yk, s, row_full)
        d_pr, d_roc = np.empty(n_boot), np.empty(n_boot)
        for b in range(n_boot):
            w_rows = counts[b][inv_k]
            d_pr[b] = _weighted_pr_auc(yk, s, w_rows)
            d_roc[b] = _weighted_roc_auc(yk, s, w_rows)
        draws[(n, "pr_auc")], draws[(n, "roc_auc")] = d_pr, d_roc
    for n, (tp, fp) in mask_u.items():
        base = _mask_stats(tp, fp, pos_u, full_w)
        reps = [_mask_stats(tp, fp, pos_u, counts[b]) for b in range(n_boot)]
        for k in ("recall", "precision", "insiders_caught_share"):
            point[(n, k)] = base[k]
            draws[(n, k)] = np.array([r[k] for r in reps])

    out: dict = {
        "method": "user-clustered bootstrap, fixed scores and fixed alert masks (module docstring)",
        "n_boot": int(n_boot), "seed": int(seed), "users": int(n_users),
        "insiders": int((pos_u > 0).sum()), "interval": "95% percentile",
        "scores": {n: {m: _interval(draws[(n, m)], _clean(point[(n, m)])) for m in ("pr_auc", "roc_auc")} for n in s_k},
        "masks": {n: {m: _interval(draws[(n, m)], _clean(point[(n, m)]))
                      for m in ("recall", "precision", "insiders_caught_share")} for n in mask_u},
        "pairs": [],
    }
    floor = 2.0 / (n_boot + 1)
    for a, b in pairs:
        metrics = [m for m in ("pr_auc", "roc_auc") if (a, m) in draws and (b, m) in draws] + \
                  [m for m in ("recall", "precision", "insiders_caught_share") if (a, m) in draws and (b, m) in draws]
        if not metrics:
            raise ValueError(f"pair ({a!r}, {b!r}): both must be scores, or both masks")
        for m in metrics:
            d = draws[(a, m)] - draws[(b, m)]
            d = d[np.isfinite(d)]
            pt = point[(a, m)] - point[(b, m)]
            if d.size == 0 or not np.isfinite(pt):
                out["pairs"].append({"a": a, "b": b, "metric": m, "point_difference": None, "lo": None, "hi": None,
                                     "p_two_sided": None, "valid_replicates": 0})
                continue
            lo, hi = np.quantile(d, [ALPHA / 2, 1 - ALPHA / 2])
            p = max(floor, 2.0 * min(float((d <= 0).mean()), float((d >= 0).mean())))
            out["pairs"].append({"a": a, "b": b, "metric": m, "point_difference": float(pt), "lo": float(lo),
                                 "hi": float(hi), "p_two_sided": min(1.0, p), "valid_replicates": int(d.size),
                                 "interval_excludes_zero": bool(lo > 0 or hi < 0)})
    return out


def _clean(v: float) -> float | None:
    return None if v is None or not np.isfinite(v) else float(v)


def paired_wilcoxon(a: Sequence[float], b: Sequence[float]) -> dict:
    """Wilcoxon signed-rank test on per-seed paired metrics (a - b), two-sided, exact for small n."""
    x, z = np.asarray(a, dtype="float64"), np.asarray(b, dtype="float64")
    if x.shape != z.shape or x.ndim != 1:
        raise ValueError("paired_wilcoxon needs two 1-D arrays of the same length")
    ok = np.isfinite(x) & np.isfinite(z)
    x, z = x[ok], z[ok]
    n = int(len(x))
    d = x - z
    out = {"n_pairs": n, "mean_difference": float(d.mean()) if n else None,
           "wins": int((d > 0).sum()), "losses": int((d < 0).sum()), "ties": int((d == 0).sum()),
           "min_attainable_p_two_sided": (2.0 / 2 ** n) if n else None}
    if n < 2 or not np.any(d != 0):
        out.update({"statistic": None, "p_two_sided": 1.0 if n and not np.any(d != 0) else None,
                    "note": "no non-zero paired difference" if n else "no pairs"})
        return out
    from scipy.stats import wilcoxon

    res = wilcoxon(x, z, zero_method="wilcox", alternative="two-sided", method="auto")
    out.update({"statistic": float(res.statistic), "p_two_sided": float(res.pvalue)})
    if out["min_attainable_p_two_sided"] > ALPHA:
        out["note"] = (f"with {n} pairs the smallest attainable two-sided p is {out['min_attainable_p_two_sided']:.4f}, "
                       f"above {ALPHA}: this test cannot show significance at that size; read the interval and the wins")
    return out


def seed_summary(values: Sequence[float]) -> dict:
    v = np.asarray([x for x in values if x is not None and np.isfinite(x)], dtype="float64")
    if v.size == 0:
        return {"n": 0}
    return {"n": int(v.size), "min": float(v.min()), "median": float(np.median(v)), "max": float(v.max()),
            "mean": float(v.mean()), "std": float(v.std(ddof=1)) if v.size > 1 else 0.0}
