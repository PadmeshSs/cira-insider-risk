"""Chapter 6 baselines (Bible Ch6, Architecture §13, HCEA §6).

Baselines exist for honest comparison with TabNet, not for production use.
Each detector follows one contract (see ``base.BaselineDetector``):

    fit(train_frame, y=None)            -> self
    score(frame) -> np.ndarray in [0, 1], higher = more anomalous

This package init stays import-light (no numpy) so that
``python -m app.baselines.run`` can apply thread caps first (N8, HCEA R6).
"""

DETECTORS = ("rule_based", "isolation_forest", "lof", "lstm_autoencoder", "gbdt")
