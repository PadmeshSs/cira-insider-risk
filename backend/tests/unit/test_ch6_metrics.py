"""Metric rules (CARRY_FORWARD N1, N2)."""
import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import average_precision_score

from app.evaluation import metrics
from app.evaluation.metrics import (
    budget_counts,
    daily_top_k,
    evaluate_scores,
    per_user_detection,
)


def _labels(y, excl=None, scen=None, y_acc=None):
    y = np.asarray(y, dtype="int8")
    return pd.DataFrame({
        "y_primary": y,
        "scenario_primary": np.asarray(scen if scen is not None else y, dtype="int8"),
        "exclude_primary": np.zeros(len(y), bool) if excl is None else np.asarray(excl, bool),
        "y_account": y if y_acc is None else np.asarray(y_acc, dtype="int8"),
        "scenario_account": np.asarray(scen if scen is not None else y, dtype="int8"),
    })


def test_no_accuracy_function_exists():
    assert not [n for n in dir(metrics) if "accuracy" in n.lower()]


def test_daily_top_k_picks_k_per_day():
    dates = pd.Series(["d1"] * 4 + ["d2"] * 3)
    scores = np.array([0.1, 0.9, 0.5, 0.2, 0.3, 0.8, 0.7])
    mask = daily_top_k(dates, scores, 2, seed=0)
    assert mask.tolist() == [False, True, True, False, False, True, True]


def test_ties_are_broken_randomly_but_reproducibly():
    dates = pd.Series(["d"] * 100)
    scores = np.zeros(100)
    a = daily_top_k(dates, scores, 5, seed=1)
    assert a.sum() == 5 and not a[:5].all()                       # not "first five users"
    assert (a == daily_top_k(dates, scores, 5, seed=1)).all()


def test_masquerade_rows_are_neither_tp_nor_fp():
    y = np.array([1, 0, 0])
    alerted = np.array([True, True, False])
    excl = np.array([False, True, False])
    c = budget_counts(y, alerted, excl)
    assert c["true_positives"] == 1 and c["false_positives"] == 0 and c["precision"] == 1.0
    assert c["alerts_on_excluded_rows"] == 1


def test_per_user_detection_and_latency():
    users = ["a", "a", "a", "b", "b"]
    dates = ["2010-01-01", "2010-01-02", "2010-01-05", "2010-01-01", "2010-01-02"]
    y = [1, 1, 1, 1, 0]
    alerted = [False, False, True, False, True]
    out = per_user_detection(users, dates, y, alerted, [1, 1, 1, 2, 0])
    assert out["insiders"] == 2 and out["caught"] == 1
    assert out["by_scenario"] == {"1": {"insiders": 1, "caught": 1}, "2": {"insiders": 1, "caught": 0}}
    assert out["latency_days"]["median"] == 4.0


def test_evaluate_scores_primary_excludes_masquerade_and_reports_view_difference():
    keys = pd.DataFrame({"user_id": ["a", "b", "c", "d"], "date": ["2010-01-01"] * 4})
    scores = np.array([0.9, 0.8, 0.1, 0.2])
    labels = _labels([1, 0, 0, 0], excl=[False, True, False, False], y_acc=[1, 1, 0, 0])
    out = evaluate_scores(keys, scores, labels, budgets=(1, 2), seed=0)
    p = out["primary"]
    assert p["rows_excluded"] == 1 and p["positives"] == 1
    assert p["pr_auc"] == pytest.approx(average_precision_score([1, 0, 0], [0.9, 0.1, 0.2]))
    assert out["secondary_account_view"]["positives"] == 2
    assert out["view_difference"]["rows_with_different_label"] == 1
    assert out["view_difference"]["masquerade_rows_excluded_from_primary"] == 1


def test_nan_scores_are_refused():
    keys = pd.DataFrame({"user_id": ["a"], "date": ["2010-01-01"]})
    with pytest.raises(ValueError):
        evaluate_scores(keys, np.array([np.nan]), _labels([1]))
