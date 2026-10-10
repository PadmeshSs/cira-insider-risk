"""Operating-point metrics the Bible's Chapter 16 list asks for and metrics.py does not compute.

Bible Chapter 16, item 1: precision, recall, F1, ROC-AUC, PR-AUC, false positive rate, detection
latency, top-k precision, risk coverage. ``app.evaluation.metrics`` already has precision, recall,
the two AUCs, top-k and latency. This module adds what is left, for any boolean "alerted" mask:

    F1 and the false positive rate, from the full confusion matrix
    risk coverage, defined below

Masquerade account-days (``exclude``) follow N1: they are neither a true nor a false positive, and
they are out of the true-negative count as well, so the false positive rate is not diluted by rows
that are neither benign nor malicious.

Risk coverage (the repository's definition; the Architecture document that names the metric was
not available when this was written, so the definition is recorded here and in the report):

    risk coverage = share of the split's malicious user-days that sit in an alert of the stated
                    kind, next to the share of ALL user-days that the same alerts occupy (the
                    review cost). Both numbers are always printed together.

It is a day-level companion of "insiders caught" (an insider counts as caught with one day), so a
detector that catches an insider once and then loses them shows a high caught count and a low
coverage. Accuracy is not computed anywhere (N2).
"""
from __future__ import annotations

import numpy as np


def confusion(y, alerted, exclude=None) -> dict:
    y = np.asarray(y).astype(bool)
    a = np.asarray(alerted).astype(bool)
    keep = np.ones_like(y) if exclude is None else ~np.asarray(exclude).astype(bool)
    tp = int((a & y & keep).sum())
    fp = int((a & ~y & keep).sum())
    fn = int((~a & y & keep).sum())
    tn = int((~a & ~y & keep).sum())
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def operating_point(y, alerted, exclude=None) -> dict:
    """Precision, recall, F1 and false positive rate for one alert mask (primary-view rules, N1)."""
    c = confusion(y, alerted, exclude)
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else (0.0 if (tp + fp) and (tp + fn) else None)
    fpr = fp / (fp + tn) if (fp + tn) else None
    return {**c, "alerts": tp + fp, "precision": precision, "recall": recall, "f1": f1, "false_positive_rate": fpr}


def risk_coverage(y, alerted, exclude=None) -> dict:
    """Malicious days in alerts, next to the share of all days the alerts occupy (see module docstring)."""
    y = np.asarray(y).astype(bool)
    a = np.asarray(alerted).astype(bool)
    keep = np.ones_like(y) if exclude is None else ~np.asarray(exclude).astype(bool)
    positives = int((y & keep).sum())
    rows = int(keep.sum())
    covered = int((a & y & keep).sum())
    occupied = int((a & keep).sum())
    return {
        "malicious_days": positives,
        "malicious_days_in_alerts": covered,
        "coverage": covered / positives if positives else None,
        "rows": rows,
        "rows_in_alerts": occupied,
        "review_load": occupied / rows if rows else None,
    }
