"""Local Outlier Factor baseline with the HCEA D-2 approximation.

Exact LOF needs a k-nearest-neighbour search. In ~100-200 dimensions tree
indices degenerate to brute force, which is quadratic in N: at N ~ 4x10^5
that is ~10^11 distance computations. So, per HCEA §6.1 / deviation D-2:

1. Train-only median imputation + missing indicators (N4), then signed
   log1p (compresses heavy count tails such as http requests), then
   StandardScaler, then PCA to ``n_components`` (default 20). Scaler and
   PCA are fitted on the full training split.
2. ``LocalOutlierFactor(n_neighbors=20, novelty=True)`` is fitted on a
   training subsample of at most ``max_fit_rows`` (default 50,000) user-days.
   The subsample is stratified by user and label-blind: each training user
   contributes rows in proportion to their share of the split.
3. Validation / test rows are scored in chunks of ``score_chunk_rows``.
4. Subsample size, PCA dimensionality and retained variance are stored in
   the metadata and must be reported beside every LOF number.

This is a documented, reproducible approximation of LOF, not exact LOF on
the full matrix.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

from app.core.runtime import max_workers

from .base import BaselineDetector, user_stratified_sample
from .preprocess import TrainFittedImputer, feature_columns, signed_log1p


class LOFDetector(BaselineDetector):
    name = "lof"

    def __init__(self, *, seed: int = 42, **config) -> None:
        config.setdefault("n_components", 20)
        config.setdefault("n_neighbors", 20)
        config.setdefault("max_fit_rows", 50_000)
        config.setdefault("score_chunk_rows", 50_000)
        config.setdefault("nullable_columns", None)
        super().__init__(seed=seed, **config)
        self.imputer = TrainFittedImputer()
        self.scaler: StandardScaler | None = None
        self.pca: PCA | None = None
        self.model: LocalOutlierFactor | None = None
        self.info: dict = {}
        self._fit_rows = np.arange(0)

    def _project(self, frame: pd.DataFrame) -> np.ndarray:
        x = signed_log1p(self.imputer.transform(frame))
        return self.pca.transform(self.scaler.transform(x)).astype("float32")

    def _fit(self, train, y, validation, y_validation) -> None:
        self.imputer.fit(train, feature_columns(train), self.config["nullable_columns"])
        x = signed_log1p(self.imputer.transform(train))
        self.scaler = StandardScaler().fit(x)
        xs = self.scaler.transform(x)
        n_comp = int(min(self.config["n_components"], xs.shape[1], xs.shape[0]))
        self.pca = PCA(n_components=n_comp, random_state=self.seed).fit(xs)
        z = self.pca.transform(xs).astype("float32")
        del x, xs

        idx = user_stratified_sample(train["user_id"], int(self.config["max_fit_rows"]), self.seed)
        n_neighbors = int(min(self.config["n_neighbors"], max(1, len(idx) - 1)))
        self.model = LocalOutlierFactor(n_neighbors=n_neighbors, novelty=True, n_jobs=max_workers()).fit(z[idx])
        self._fit_rows = idx
        self.info = {
            "lof_fit_rows": int(len(idx)),
            "train_rows_available": int(len(train)),
            "subsample": "user-stratified, label-blind" if len(idx) < len(train) else "none (all training rows)",
            "pca_components": n_comp,
            "pca_retained_variance": float(self.pca.explained_variance_ratio_.sum()),
            "n_neighbors_used": n_neighbors,
            "n_input_columns": len(self.imputer.output_columns),
            "n_missing_indicators": len(self.imputer.indicator_columns),
        }

    def _calibration_scores(self, train: pd.DataFrame) -> np.ndarray:
        """Calibrate on training rows LOF was not fitted on.

        With novelty=True, scoring the fit points themselves is biased (each
        point is its own neighbour), and scoring every training row would
        cost a full kNN pass. A second label-blind sample of held-out
        training rows is enough to estimate median and scale.
        """
        held_out = np.setdiff1d(np.arange(len(train)), self._fit_rows)
        if len(held_out) == 0:
            held_out = np.arange(len(train))
        pick = user_stratified_sample(train["user_id"].iloc[held_out], int(self.config["max_fit_rows"]), self.seed + 1)
        rows = held_out[pick]
        self.info["calibration_rows"] = int(len(rows))
        return self._raw_score(train.iloc[rows])

    def _raw_score(self, frame: pd.DataFrame, **_) -> np.ndarray:
        step = int(self.config["score_chunk_rows"])
        out = np.empty(len(frame), dtype="float64")
        for start in range(0, len(frame), step):
            part = frame.iloc[start : start + step]
            # score_samples = -LOF (higher = more normal); negate.
            out[start : start + len(part)] = -self.model.score_samples(self._project(part))
        return out

    def _extra_metadata(self) -> dict:
        return dict(self.info)

    def _save_artifacts(self, directory: Path) -> dict:
        joblib.dump(
            {"model": self.model, "scaler": self.scaler, "pca": self.pca, "imputer": self.imputer.to_dict(), "info": self.info},
            directory / "model.joblib",
        )
        return {"model": "model.joblib"}

    def _load_artifacts(self, directory: Path, meta: dict) -> None:
        blob = joblib.load(directory / "model.joblib")
        self.model, self.scaler, self.pca, self.info = blob["model"], blob["scaler"], blob["pca"], blob["info"]
        self.imputer = TrainFittedImputer.from_dict(blob["imputer"])
