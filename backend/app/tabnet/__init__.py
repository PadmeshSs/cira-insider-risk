"""Chapter 7: TabNet, the primary behavioural model.

Bible Chapter 7 / Architecture Phase 5, executed under HCEA v1.0 §7.

Modules
    dataset.py         feature matrix loading, train-only preprocessing,
                       leakage-safe split assembly (reuses the saved
                       Chapter 6 split, CARRY_FORWARD N11)
    train.py           TabNetDetector (Chapter 6 detector contract) and the
                       ``python -m app.tabnet.train`` runner
    infer.py           label-free loading and scoring: ``load_model(...)``
                       and ``TabNetScorer.score(frame) -> [0, 1]``
    model_registry.py  versioned, append-only artifact registry

This init stays import-light (no numpy, no torch) so the runner can apply
thread caps before any BLAS or torch import (N8, HCEA R6).
"""

MODEL_NAME = "tabnet"
CHAPTER7_VERSION = "chapter7-v1"
