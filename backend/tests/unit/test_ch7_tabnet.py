"""TabNet detector: contract, imbalance, checkpoints, persistence (Bible Ch7, HCEA §7)."""
import ast
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.tabnet.dataset import (
    INDICATOR_PREFIX,
    TabNetPreprocessor,
    feature_fingerprint,
    feature_groups,
    grouped_importance,
)
from app.tabnet.infer import ModelUnavailableError, load_model, sigmoid
from app.tabnet.train import ClassWeightedCrossEntropy, TabNetDetector
from fixtures import synthetic_matrix

NULLABLE = list(synthetic_matrix.NULLABLE)
FAST = dict(n_d=8, n_a=8, n_steps=3, max_epochs=4, patience=10, batch_size=128, virtual_batch_size=64,
            device="cpu", nullable_columns=NULLABLE)


def _label(frame: pd.DataFrame) -> np.ndarray:
    return (frame["http_leak_paste_count"] >= 5).astype("int8").to_numpy()


@pytest.fixture(scope="module")
def data():
    m = synthetic_matrix.build(n_users=16, n_days=90)
    train = m[m["user_id"] < "u0011"].reset_index(drop=True)
    test = m[m["user_id"] >= "u0011"].reset_index(drop=True)
    return train, test


@pytest.fixture(scope="module")
def fitted(data):
    train, test = data
    return TabNetDetector(seed=0, **FAST).fit(train, _label(train), validation=test, y_validation=_label(test))


def test_supervised_contract(fitted, data):
    train, test = data
    with pytest.raises(ValueError, match="supervised"):
        TabNetDetector(**FAST).fit(train)
    raw, s = fitted.scores(test)
    assert s.shape == (len(test),) and np.isfinite(s).all() and ((s >= 0) & (s <= 1)).all()
    assert np.array_equal(s, sigmoid(raw))                             # N10: monotone map of the margin
    assert np.array_equal(fitted.score(test), s)
    assert fitted.model_version.startswith("tabnet-chapter7-v1-")


def test_class_weight_comes_from_training_rows_only(fitted, data):
    train, _ = data
    y = _label(train)
    imb = fitted.metadata()["imbalance"]
    assert imb["method"] == "class_weighted_loss" and imb["resampling"] == "none"
    assert imb["effective_positive_weight"] == pytest.approx((len(y) - y.sum()) / y.sum())
    assert imb["train_positive_rate"] == pytest.approx(y.mean())


def test_weighted_loss_scales_the_positive_class():
    import torch

    logits = torch.tensor([[0.0, 0.0], [0.0, 0.0]])
    target = torch.tensor([0, 1])
    plain = torch.nn.functional.cross_entropy(logits, target)
    weighted = ClassWeightedCrossEntropy(1.0, 9.0)(logits, target)
    assert torch.isclose(plain, weighted)                              # equal per-row losses: weighted mean unchanged
    skewed = torch.tensor([[0.0, 2.0], [0.0, 2.0]])                     # right on the positive, wrong on the negative
    assert ClassWeightedCrossEntropy(1.0, 9.0)(skewed, target) < torch.nn.functional.cross_entropy(skewed, target)


def test_learns_a_planted_signal(data):
    train, test = data
    det = TabNetDetector(seed=0, **dict(FAST, max_epochs=25, patience=25, batch_size=256)).fit(
        train, _label(train), validation=test, y_validation=_label(test))
    from sklearn.metrics import average_precision_score

    y = _label(test)
    assert average_precision_score(y, det.score(test)) > 3 * y.mean()
    top = [f for f, _ in det.metadata()["top_features_by_mask"][:3]]
    assert "http_leak_paste_count" in top


def test_early_stopping_uses_validation_pr_auc(fitted):
    md = fitted.metadata()
    assert md["early_stopping"].startswith("validation pr_auc")
    assert "valid_pr_auc" in md["history"] and "valid_auc" in md["history"]
    assert 0 <= md["best_epoch"] < md["epochs_run"]
    assert md["best_valid_pr_auc"] == pytest.approx(max(md["history"]["valid_pr_auc"]))


def test_no_positive_in_validation_means_no_early_stopping(data):
    train, test = data
    det = TabNetDetector(seed=0, **dict(FAST, max_epochs=2)).fit(
        train, _label(train), validation=test, y_validation=np.zeros(len(test), dtype="int8"))
    md = det.metadata()
    assert md["early_stopping"].startswith("not used") and md["best_epoch"] is None and md["epochs_run"] == 2


def test_balanced_sampler_option(data):
    train, test = data
    det = TabNetDetector(seed=0, **dict(FAST, max_epochs=2, imbalance="balanced_sampler")).fit(train, _label(train))
    imb = det.metadata()["imbalance"]
    assert imb["method"] == "balanced_sampler" and "WeightedRandomSampler" in imb["resampling"]
    assert det.score(test).shape == (len(test),)


@pytest.mark.parametrize("bad", [dict(virtual_batch_size=1024, batch_size=4096), dict(virtual_batch_size=256, batch_size=128),
                                 dict(pretrain_max_epochs=21), dict(imbalance="smote"), dict(mask_type="softmax")])
def test_config_guards(bad):
    with pytest.raises(ValueError):
        TabNetDetector(**bad)


def test_save_load_round_trip(fitted, data, tmp_path):
    _, test = data
    fitted.save(tmp_path / "m", extra={"profile": "dev"})
    back = TabNetDetector.load(tmp_path / "m")
    assert np.array_equal(back.score(test), fitted.score(test))
    scorer = load_model(tmp_path / "m")                                # serving path, CPU
    assert scorer.model_version == fitted.model_version
    assert np.array_equal(scorer.score(test), fitted.score(test))
    assert scorer.feature_names == fitted.preprocessor.output_columns
    assert {p.name for p in (tmp_path / "m").iterdir()} >= {"tabnet_model.zip", "preprocessor.json", "global_importance.json", "meta.json"}


def test_scores_do_not_depend_on_batch_composition(fitted, data):
    _, test = data
    whole = fitted.raw_score(test)
    part = fitted.raw_score(test.iloc[:37].reset_index(drop=True))
    assert np.allclose(whole[:37], part, atol=1e-5)


def test_load_failures_are_explicit(tmp_path):
    with pytest.raises(ModelUnavailableError):
        load_model(tmp_path / "missing")
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "meta.json").write_text('{"name": "tabnet"}')
    with pytest.raises(ModelUnavailableError):
        load_model(tmp_path / "broken")


def test_checkpoint_resume_and_fresh(data, tmp_path):
    train, test = data
    cfg = dict(FAST, max_epochs=3, checkpoint_dir=str(tmp_path), data_fingerprint="a")
    first = TabNetDetector(seed=0, **cfg).fit(train, _label(train), validation=test, y_validation=_label(test))
    ckdir = first.checkpoint_path()
    assert sorted(p.name for p in ckdir.glob("epoch_*.pt")) == ["epoch_000.pt", "epoch_001.pt", "epoch_002.pt"]
    again = TabNetDetector(seed=0, **cfg).fit(train, _label(train), validation=test, y_validation=_label(test))
    md = again.metadata()
    assert md["resumed_from_epoch"] == 2 and md["completed_from_checkpoint"] is True
    assert md["epochs_run"] == 3 and md["best_epoch"] == first.metadata()["best_epoch"]
    assert np.array_equal(first.score(test), again.score(test))
    other = TabNetDetector(seed=0, **dict(cfg, data_fingerprint="b")).fit(train, _label(train))
    assert other.metadata()["resumed_from_epoch"] is None           # different data -> no reuse
    assert TabNetDetector(seed=0, **cfg).clear_checkpoints() == 3 and not ckdir.exists()


def test_interrupted_training_resumes_to_the_same_model(data, tmp_path, monkeypatch):
    """Kill during epoch 3, resume, and end with the model an uninterrupted run gives (R7)."""
    import app.tabnet.train as tr

    train, test = data
    cfg = dict(FAST, max_epochs=5, patience=99, data_fingerprint="z")
    straight = TabNetDetector(seed=0, **cfg).fit(train, _label(train), validation=test, y_validation=_label(test))

    real = tr._EpochCheckpoint.on_epoch_begin

    def boom(self, epoch, logs=None):
        if self.offset + epoch == 2:
            raise KeyboardInterrupt
        return real(self, epoch, logs)

    monkeypatch.setattr(tr._EpochCheckpoint, "on_epoch_begin", boom)
    with pytest.raises(KeyboardInterrupt):
        TabNetDetector(seed=0, checkpoint_dir=str(tmp_path), **cfg).fit(train, _label(train), validation=test, y_validation=_label(test))
    monkeypatch.setattr(tr._EpochCheckpoint, "on_epoch_begin", real)
    resumed = TabNetDetector(seed=0, checkpoint_dir=str(tmp_path), **cfg).fit(
        train, _label(train), validation=test, y_validation=_label(test))
    md, ref = resumed.metadata(), straight.metadata()
    assert md["resumed_from_epoch"] == 1
    assert md["history"]["valid_pr_auc"] == pytest.approx(ref["history"]["valid_pr_auc"])
    assert md["best_epoch"] == ref["best_epoch"]
    assert np.allclose(straight.raw_score(test), resumed.raw_score(test), atol=1e-6)


def test_drop_last_only_for_a_one_row_final_batch():
    det = TabNetDetector(batch_size=128, virtual_batch_size=64)
    assert det._drop_last(128 * 3) == (False, None)
    flag, reason = det._drop_last(128 * 3 + 1)
    assert flag and "batch norm" in reason


def test_runs_on_cpu_when_cuda_requested_but_missing(data, monkeypatch):
    import torch

    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    train, _ = data
    det = TabNetDetector(seed=0, **dict(FAST, device="cuda", max_epochs=1)).fit(train, _label(train))
    assert det.metadata()["device_used"] == "cpu"


def test_pretraining_is_time_boxed_and_label_free(data):
    train, test = data
    det = TabNetDetector(seed=0, **dict(FAST, max_epochs=2, pretrain=True, pretrain_max_epochs=2)).fit(
        train, _label(train), validation=test, y_validation=_label(test))
    pre = det.metadata()["pretraining"]
    assert pre["used"] and pre["epochs_run"] <= 2 and pre["data"] == "training features only, no labels"


# --- preprocessing ------------------------------------------------------------

def test_preprocessor_uses_training_statistics_and_indicators():
    train = pd.DataFrame({"user_id": ["a"] * 3, "date": ["d1", "d2", "d3"], "x": [1.0, 3.0, np.nan], "k": [0.0, 10.0, 100.0]})
    test = pd.DataFrame({"user_id": ["b"] * 2, "date": ["d1", "d2"], "x": [np.nan, 1000.0], "k": [5.0, 5.0]})
    prep = TabNetPreprocessor().fit(train, nullable=["x"])
    assert prep.output_columns == ["x", "k", f"{INDICATOR_PREFIX}x"]
    out = prep.transform(test)
    assert out.dtype == np.float32 and np.isfinite(out).all()
    # the null in test is filled with the TRAIN median (2.0), not anything from test
    two = pd.DataFrame({"user_id": ["c"], "date": ["d"], "x": [2.0], "k": [5.0]})
    assert out[0, 0] == pytest.approx(prep.transform(two)[0, 0])
    # indicator 1/0 goes through the same signed log1p + train standardisation
    expect = [(np.log1p(1.0) - prep.mean[2]) / prep.std[2], (0.0 - prep.mean[2]) / prep.std[2]]
    assert out[:, 2].tolist() == pytest.approx(expect, rel=1e-5)
    back = TabNetPreprocessor.from_dict(prep.to_dict())
    assert np.array_equal(back.transform(test), out)


def test_constant_training_column_does_not_divide_by_zero():
    train = pd.DataFrame({"user_id": ["a", "a"], "date": ["1", "2"], "c": [3.0, 3.0], "v": [1.0, 2.0]})
    prep = TabNetPreprocessor().fit(train, nullable=[])
    assert prep.constant_columns == ["c"]
    assert np.isfinite(prep.transform(train)).all()


def test_feature_groups_pair_values_with_indicators():
    cols = ["a", "b", f"{INDICATOR_PREFIX}a"]
    assert feature_groups(cols) == {"a": [0, 2], "b": [1]}
    assert grouped_importance(np.array([0.2, 0.5, 0.3]), cols) == [("a", 0.5), ("b", 0.5)]


def test_feature_fingerprint_matches_chapter6(tmp_path):
    from app.baselines.run import _feature_fingerprint

    f = tmp_path / "user_day_mid.parquet"
    f.write_bytes(b"abc")
    assert feature_fingerprint(f) == _feature_fingerprint(f)


def test_serving_modules_never_import_labels():
    """Only the runner (train.py) joins labels; the rest must stay label-free (N5)."""
    import app.tabnet as pkg

    for name in ("dataset", "infer", "model_registry", "__init__"):
        tree = ast.parse((Path(pkg.__file__).parent / f"{name}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods = [node.module or ""] if isinstance(node, ast.ImportFrom) else [a.name for a in node.names] if isinstance(node, ast.Import) else []
            for m in mods:
                assert "ground_truth" not in m and "evaluation.labels" not in m and m != "labels", (name, m)
