"""Behaviour-only XGBoost, as a servable model (Chapter 8, deviation C8-2).

Same learner, settings and imbalance handling as the Chapter 6 baseline
(``app.baselines.gbdt.GBDTDetector``): hist trees, ``scale_pos_weight`` =
negatives / positives on the training rows, early stopping on validation
``aucpr``, native null handling. Two things differ:

1. The static per-user columns (psychometrics, department size) are not
   model inputs. The runner drops them before ``fit``, exactly as Chapter 7
   did for TabNet (N25), so the two supervised candidates see the same
   information and the serving decision compares models, not feature sets.
   The Chapter 6 XGBoost had them; its top 10 by gain held none, but a
   served model must not score a person partly on a personality test.
2. The score is ``sigmoid(margin)`` in float64 instead of the float32
   ``predict_proba``. Same ranking up to float32 ties; it avoids the
   artificial ties at 1.0 that Chapter 7 removed for TabNet (C7-3).

``model_version`` is ``gbdt-chapter8-v1-<hash of config + seed>``, so it can
never be mistaken for a Chapter 6 reference run.

This module is on the serving path. It never imports label code (N5).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from app.baselines.base import config_hash
from app.baselines.gbdt import GBDTDetector

from . import SERVING_VERSION
from .contracts import stable_sigmoid, static_inputs


class BehaviourGBDTDetector(GBDTDetector):
    name = "gbdt"
    supervised = True
    calibrate = False    # score is sigmoid(margin), see module docstring

    @property
    def model_version(self) -> str:
        return f"{self.name}-{SERVING_VERSION}-{config_hash({'config': self.config, 'seed': self.seed})}"

    def _raw_score(self, frame: pd.DataFrame, **_) -> np.ndarray:
        # With early stopping, the sklearn wrapper predicts with the best
        # iteration; that survives save/load (checked by a unit test).
        return np.asarray(self.model.predict(self._x(frame), output_margin=True), dtype="float64")

    def score(self, frame: pd.DataFrame, **kwargs) -> np.ndarray:
        return stable_sigmoid(self.raw_score(frame, **kwargs))

    def scores(self, frame: pd.DataFrame, **kwargs) -> tuple[np.ndarray, np.ndarray]:
        raw = self.raw_score(frame, **kwargs)
        return raw, stable_sigmoid(raw)

    @property
    def input_columns(self) -> list[str]:
        return list(self.columns)

    def metadata(self) -> dict:
        meta = super().metadata()
        meta["calibrator"] = {"method": "sigmoid(XGBoost margin), float64; equals predict_proba up to float32 rounding"}
        meta["raw_score"] = "XGBoost margin (log-odds of the positive class)"
        meta["n_input_columns"] = len(self.columns)
        meta["static_inputs"] = static_inputs(self.columns)
        return meta

    def use_cpu(self, n_jobs: int) -> None:
        """Serve on CPU whatever device trained it (HCEA §8)."""
        self.model.set_params(device="cpu", n_jobs=int(n_jobs))
