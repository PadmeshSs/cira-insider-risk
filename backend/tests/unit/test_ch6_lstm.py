"""LSTM autoencoder: lazy windows, causal scoring, resumable training (HCEA D-3)."""
import numpy as np
import pytest

from app.baselines.lstm_autoencoder import LSTMAutoencoderDetector
from fixtures import synthetic_matrix

FAST = dict(window=10, train_stride=3, hidden=8, max_epochs=2, batch_size=32, device="cpu")


@pytest.fixture(scope="module")
def data():
    m = synthetic_matrix.build(n_users=6, n_days=40)
    return m[m["user_id"] < "u0004"].reset_index(drop=True), m[m["user_id"] >= "u0004"].reset_index(drop=True)


def test_scores_are_causal(data):
    """Changing a later day must not change an earlier day's score."""
    train, test = data
    det = LSTMAutoencoderDetector(seed=0, **FAST).fit(train)
    before = det.raw_score(test)
    changed = test.copy()
    late = changed["date"] > "2010-06-20"
    changed.loc[late, "http_request_count"] = 500.0
    after = det.raw_score(changed)
    early = ~late.to_numpy()
    assert np.allclose(before[early], after[early])
    assert not np.allclose(before[~early], after[~early])


def test_history_gives_context_without_scoring_it(data):
    train, test = data
    det = LSTMAutoencoderDetector(seed=0, **FAST).fit(train)
    tail = test[test["date"] >= "2010-06-25"].reset_index(drop=True)
    with_hist = det.raw_score(tail, history=test)
    alone = det.raw_score(tail)
    assert with_hist.shape == alone.shape == (len(tail),)
    full = det.raw_score(test)
    idx = np.flatnonzero((test["date"] >= "2010-06-25").to_numpy())
    assert np.allclose(with_hist, full[idx], atol=1e-6)             # same as scoring inside the full sequence


def test_training_windows_use_stride_and_cover_each_user_end(data):
    train, _ = data
    det = LSTMAutoencoderDetector(seed=0, **FAST)
    _, _, start = det._matrix(train)
    ends = det._train_ends(start)
    per_user = 40
    assert len(ends) == 4 * len(list(range(9, 40, 3)) + ([39] if (39 - 9) % 3 else []))
    assert set(range(per_user - 1, 4 * per_user, per_user)) <= set(ends.tolist())


def test_resume_from_checkpoint(data, tmp_path):
    train, test = data
    cfg = dict(FAST, checkpoint_dir=str(tmp_path), data_fingerprint="x")
    first = LSTMAutoencoderDetector(seed=0, **cfg).fit(train)
    assert first.metadata()["epochs_run"] == 2
    ckpts = list(tmp_path.rglob("epoch_*.pt"))
    assert len(ckpts) == 2
    second = LSTMAutoencoderDetector(seed=0, **cfg).fit(train)
    assert second.metadata().get("resumed_from_epoch") == 1
    assert np.allclose(first.raw_score(test), second.raw_score(test))
    other = LSTMAutoencoderDetector(seed=0, **dict(cfg, data_fingerprint="y")).fit(train)
    assert "resumed_from_epoch" not in other.metadata()              # different data -> no reuse


def test_core_columns_must_not_contain_nulls(data):
    train, _ = data
    bad = train.copy()
    bad.loc[0, "login_count"] = np.nan
    with pytest.raises(ValueError, match="zero null policy"):
        LSTMAutoencoderDetector(seed=0, **FAST).fit(bad)


def test_runs_on_cpu_when_cuda_requested_but_missing(data, monkeypatch):
    import torch

    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    train, _ = data
    det = LSTMAutoencoderDetector(seed=0, **dict(FAST, device="cuda", max_epochs=1)).fit(train)
    assert det.metadata()["device_used"] == "cpu"
