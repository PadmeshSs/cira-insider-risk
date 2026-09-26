"""Isolation Forest baseline (Bible Ch6 step 2, HCEA §6 table).

Settings per HCEA: n_estimators=100, max_samples=256, fixed random_state,
n_jobs capped (R6). Sub-sampling is the algorithm's own design, not a
compromise. Unsupervised: fitted on every training row, labels never seen.

Input: the Chapter 5 matrix after train-only median imputation plus
missing-value indicators (N4). No scaling: split points are drawn uniformly
between a feature's min and max, and the raw feature space is the standard
way this baseline is reported.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.core.runtime import max_workers

from .base import BaselineDetector
from .preprocess import TrainFittedImputer, feature_columns


class IsolationForestDetector(BaselineDetector):
    name = "isolation_forest"

    def __init__(self, *, seed: int = 42, **config) -> None:
        config.setdefault("n_estimators", 100)
        config.setdefault("max_samples", 256)
        config.setdefault("nullable_columns", None)
        super().__init__(seed=seed, **config)
        self.imputer = TrainFittedImputer()
        self.model: IsolationForest | None = None

    def _fit(self, train, y, validation, y_validation) -> None:
        self.imputer.fit(train, feature_columns(train), self.config["nullable_columns"])
        self.model = IsolationForest(
            n_estimators=int(self.config["n_estimators"]),
            max_samples=min(int(self.config["max_samples"]), len(train)),
            random_state=self.seed,
            n_jobs=max_workers(),
        ).fit(self.imputer.transform(train))

    def _raw_score(self, frame: pd.DataFrame, **_) -> np.ndarray:
        # score_samples: higher = more normal. Negate so higher = more anomalous.
        return -self.model.score_samples(self.imputer.transform(frame)).astype("float64")

    def _extra_metadata(self) -> dict:
        return {
            "n_input_columns": len(self.imputer.output_columns),
            "n_missing_indicators": len(self.imputer.indicator_columns),
            "all_null_in_train": self.imputer.all_null_in_train,
        }

    def _save_artifacts(self, directory: Path) -> dict:
        joblib.dump({"model": self.model, "imputer": self.imputer.to_dict()}, directory / "model.joblib")
        return {"model": "model.joblib"}

    def _load_artifacts(self, directory: Path, meta: dict) -> None:
        blob = joblib.load(directory / "model.joblib")
        self.model = blob["model"]
        self.imputer = TrainFittedImputer.from_dict(blob["imputer"])
