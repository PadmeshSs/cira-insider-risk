"""Uniform detector contract, persistence and budgets (Bible Ch6, HCEA §6)."""
import ast
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.baselines.base import ScoreCalibrator, user_stratified_sample
from app.baselines.gbdt import GBDTDetector
from app.baselines.isolation_forest import IsolationForestDetector
from app.baselines.lof import LOFDetector
from app.baselines.preprocess import TrainFittedImputer
from app.baselines.rule_based import RuleBasedDetector
from fixtures import synthetic_matrix

UNSUPERVISED = (RuleBasedDetector, IsolationForestDetector, LOFDetector)


@pytest.fixture(scope="module")
def data():
    m = synthetic_matrix.build(n_users=12, n_days=60)
    train = m[m["user_id"] < "u0008"].reset_index(drop=True)
    test = m[m["user_id"] >= "u0008"].reset_index(drop=True)
    return train, test


@pytest.mark.parametrize("cls", UNSUPERVISED)
def test_unsupervised_contract(cls, data):
    train, test = data
    det = cls(seed=1, **({"nullable_columns": list(synthetic_matrix.NULLABLE)} if cls is not RuleBasedDetector else {}))
    s = det.fit(train).score(test)
    assert s.shape == (len(test),)
    assert np.isfinite(s).all() and (s >= 0).all() and (s <= 1).all()
    again = cls(seed=1, **det.config).fit(train).score(test)
    assert np.allclose(s, again)                                     # fixed seed -> same scores


@pytest.mark.parametrize("cls", UNSUPERVISED)
def test_unsupervised_detectors_refuse_labels(cls, data):
    train, _ = data
    with pytest.raises(ValueError, match="unsupervised"):
        cls().fit(train, np.zeros(len(train)))


@pytest.mark.parametrize("cls", UNSUPERVISED + (GBDTDetector,))
def test_save_load_round_trip(cls, data, tmp_path):
    train, test = data
    y = (train["http_cloud_storage_count"] > 4).astype("int8").to_numpy()
    det = cls(seed=3)
    det.fit(train, y) if det.supervised else det.fit(train)
    det.save(tmp_path / det.name, extra={"profile": "dev"})
    back = cls.load(tmp_path / det.name)
    assert np.allclose(det.score(test), back.score(test))
    meta = (tmp_path / det.name / "meta.json").read_text()
    for key in ('"seed"', '"config"', '"fit_wall_seconds"', '"process_peak_rss_mb"', '"profile"', '"model_version"'):
        assert key in meta


def test_calibration_is_monotone_and_does_not_saturate():
    raw = np.array([-5.0, 0.0, 1.0, 10.0, 1e6, 1e9, 1e12])
    cal = ScoreCalibrator().fit(raw[:4]).transform(raw)
    assert (np.diff(cal) > 0).all()                                   # strictly ordered, no ties at the top
    assert (cal > 0).all() and (cal < 1).all()


def test_imputer_uses_training_statistics_only():
    train = pd.DataFrame({"a": [1.0, 3.0, np.nan], "b": [1.0, 1.0, 1.0]})
    test = pd.DataFrame({"a": [np.nan, 100.0], "b": [2.0, 2.0]})
    imp = TrainFittedImputer().fit(train, ["a", "b"], nullable=["a"])
    out = imp.transform(test)
    assert out[0, 0] == 2.0                                            # train median, not test's 100
    assert imp.output_columns == ["a", "b", "isnull__a"]
    assert out[:, 2].tolist() == [1.0, 0.0]


def test_lof_respects_the_hcea_budget_and_reports_it(data):
    train, test = data
    det = LOFDetector(seed=0, max_fit_rows=200, n_components=5, score_chunk_rows=37).fit(train)
    meta = det.metadata()
    assert meta["lof_fit_rows"] <= 200
    assert meta["pca_components"] == 5
    assert 0 < meta["pca_retained_variance"] <= 1
    assert det.score(test).shape == (len(test),)                        # chunked scoring covers every row


def test_stratified_sample_is_label_blind_and_covers_users():
    users = pd.Series(np.repeat([f"u{i}" for i in range(10)], 100))
    idx = user_stratified_sample(users, 200, seed=0)
    assert len(idx) <= 200
    assert users.iloc[idx].nunique() == 10


def test_rule_baseline_uses_fixed_rules(data):
    train, _ = data
    det = RuleBasedDetector().fit(train)
    assert {r["name"] for r in det.metadata()["rules"]} >= {"off_hours_logon", "off_hours_usb", "job_search_sites"}
    zero = train.head(1).copy()
    for r in det.metadata()["rules"]:
        for c in r["columns"]:
            zero[c] = 0
    assert det.score(zero)[0] == 0.0


def test_gbdt_needs_labels_and_learns_a_planted_signal(data):
    train, test = data
    with pytest.raises(ValueError, match="supervised"):
        GBDTDetector().fit(train)
    y_tr = (train["http_leak_paste_count"] >= 5).astype("int8").to_numpy()
    y_te = (test["http_leak_paste_count"] >= 5).astype("int8").to_numpy()
    det = GBDTDetector(seed=0, n_estimators=50).fit(train, y_tr, validation=test, y_validation=y_te)
    s = det.score(test)
    assert s[y_te == 1].mean() > s[y_te == 0].mean()
    assert det.metadata()["scale_pos_weight"] == pytest.approx((len(y_tr) - y_tr.sum()) / y_tr.sum())


def test_unsupervised_baseline_modules_never_touch_labels():
    """Only the runner and gbdt (via the runner) see labels; N5."""
    import app.baselines as pkg

    for name in ("rule_based", "isolation_forest", "lof", "lstm_autoencoder", "base", "preprocess", "gbdt"):
        tree = ast.parse((Path(pkg.__file__).parent / f"{name}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods = [node.module or ""] if isinstance(node, ast.ImportFrom) else [a.name for a in node.names] if isinstance(node, ast.Import) else []
            for m in mods:
                assert "ground_truth" not in m and "evaluation.labels" not in m and m != "labels", (name, m)
