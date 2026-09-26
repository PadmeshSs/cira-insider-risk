"""Supervised gradient-boosted trees baseline (Bible Ch6 step 5).

XGBoost only. CatBoost is listed in the Bible's stack as an alternative and
is not implemented here; nothing in this repository claims a CatBoost result.

Label handling
    * Labels are the primary view (N1), joined in memory by the runner from
      ``<processed>/labels/``; this module never reads the label tree (N5).
    * Masquerade account-days are removed from training and validation rows
      as well as from evaluation. Keeping them as negatives would teach the
      model that malicious-looking activity is benign.
    * ``scale_pos_weight`` = negatives / positives computed on the training
      split only (N2). No resampling of any split.

Nulls: XGBoost handles missing values natively, so no imputation (N4 allows
this for tree models that accept nulls; the model is still evaluated on the
same split as every other detector).

Early stopping uses validation PR-AUC (``aucpr``) when the validation split
has positives; otherwise a fixed number of trees is used and that fact is
recorded.

Device: ``tree_method="hist"``; CUDA only if ``CIRA_DEVICE`` allows it and
torch reports a GPU (R11: the CPU path must always work).
"""
from __future__ import annotations

import os
from pathlib import Path

import numpy as np
import pandas as pd

from app.core.runtime import max_workers

from .base import BaselineDetector
from .preprocess import feature_columns


def _xgb():
    try:
        import xgboost
    except ImportError as exc:  # pragma: no cover - depends on local install
        raise ImportError("gbdt baseline needs xgboost: pip install -r backend/requirements.txt") from exc
    return xgboost


def _xgb_device(requested: str) -> str:
    requested = (requested or "auto").lower()
    if requested in ("auto", "cuda"):
        try:
            import torch

            if torch.cuda.is_available():
                return "cuda"
        except Exception:
            pass
    return "cpu"


class GBDTDetector(BaselineDetector):
    name = "gbdt"
    supervised = True
    calibrate = False  # predict_proba is already in [0, 1]

    def __init__(self, *, seed: int = 42, **config) -> None:
        config.setdefault("library", "xgboost")
        config.setdefault("n_estimators", 600)
        config.setdefault("learning_rate", 0.05)
        config.setdefault("max_depth", 6)
        config.setdefault("subsample", 0.8)
        config.setdefault("colsample_bytree", 0.8)
        config.setdefault("min_child_weight", 1.0)
        config.setdefault("reg_lambda", 1.0)
        config.setdefault("early_stopping_rounds", 50)
        config.setdefault("device", os.getenv("CIRA_DEVICE", "auto"))
        super().__init__(seed=seed, **config)
        self.model = None
        self.columns: list[str] = []
        self.info: dict = {}

    def _x(self, frame: pd.DataFrame) -> np.ndarray:
        return frame[self.columns].to_numpy(dtype="float32")

    def _params(self, spw: float, early: bool) -> dict:
        c = self.config
        params = dict(
            n_estimators=int(c["n_estimators"]), learning_rate=float(c["learning_rate"]), max_depth=int(c["max_depth"]),
            subsample=float(c["subsample"]), colsample_bytree=float(c["colsample_bytree"]),
            min_child_weight=float(c["min_child_weight"]), reg_lambda=float(c["reg_lambda"]),
            tree_method="hist", device=_xgb_device(c["device"]), n_jobs=max_workers(),
            random_state=self.seed, scale_pos_weight=spw, eval_metric="aucpr", objective="binary:logistic",
        )
        if early:
            params["early_stopping_rounds"] = int(c["early_stopping_rounds"])
        return params

    def _fit(self, train, y, validation, y_validation) -> None:
        xgb = _xgb()
        y = np.asarray(y).astype("int8")
        pos, neg = int(y.sum()), int(len(y) - y.sum())
        if pos == 0:
            raise ValueError("gbdt: the training split has no positive user-days")
        spw = neg / pos
        self.columns = feature_columns(train)
        early = validation is not None and y_validation is not None and 0 < int(np.sum(y_validation)) < len(y_validation)
        params = self._params(spw, early)
        self.model = xgb.XGBClassifier(**params)
        fit_kwargs = {"verbose": False}
        if early:
            fit_kwargs["eval_set"] = [(self._x(validation), np.asarray(y_validation).astype("int8"))]
        self.model.fit(self._x(train), y, **fit_kwargs)
        self.info = {
            "train_positives": pos,
            "train_negatives": neg,
            "train_positive_rate": pos / len(y),
            "scale_pos_weight": spw,
            "early_stopping": "validation aucpr" if early else "not used (validation split has no positives)",
            "best_iteration": int(getattr(self.model, "best_iteration", params["n_estimators"] - 1) or 0) if early else None,
            "device_used": params["device"],
            "n_features": len(self.columns),
            "null_handling": "native (no imputation)",
            "xgboost_version": xgb.__version__,
        }

    def _raw_score(self, frame: pd.DataFrame, **_) -> np.ndarray:
        return self.model.predict_proba(self._x(frame))[:, 1].astype("float64")

    def feature_importance(self, top: int = 20) -> list[tuple[str, float]]:
        imp = self.model.get_booster().get_score(importance_type="gain")
        named = {self.columns[int(k[1:])] if k.startswith("f") and k[1:].isdigit() else k: v for k, v in imp.items()}
        return sorted(named.items(), key=lambda kv: -kv[1])[:top]

    def _extra_metadata(self) -> dict:
        extra = dict(self.info)
        if self.model is not None:
            extra["top_features_by_gain"] = self.feature_importance()
        return extra

    def _save_artifacts(self, directory: Path) -> dict:
        self.model.save_model(directory / "model.json")
        (directory / "columns.txt").write_text("\n".join(self.columns), encoding="utf-8")
        return {"model": "model.json", "columns": "columns.txt"}

    def _load_artifacts(self, directory: Path, meta: dict) -> None:
        xgb = _xgb()
        self.columns = (directory / "columns.txt").read_text(encoding="utf-8").splitlines()
        self.model = xgb.XGBClassifier()
        self.model.load_model(directory / "model.json")
        self.info = {k: meta[k] for k in ("scale_pos_weight", "device_used") if k in meta}
