"""Uniform detector contract (Bible Ch6 step 6, HCEA §6.3).

Score convention, shared with TabNet in Chapter 7:

* ``raw_score(frame)`` is the detector's native anomaly measure, oriented so
  that higher means more anomalous.
* ``score(frame)`` maps it into [0, 1] with a monotone calibrator fitted on
  the training rows only. Monotone means every ranking metric (PR-AUC, top-k)
  is identical on raw and calibrated scores.

The calibrator is ``sigmoid(asinh((raw - median) / scale))`` with median and
robust scale from the training scores. ``asinh`` compresses extreme values
logarithmically, so float64 scores stay strictly ordered even for LOF values
many orders of magnitude above the median (a plain sigmoid would saturate to
exactly 1.0 and create artificial ties at the top of the alert queue).

Detectors that already emit a [0, 1] quantity (rule fraction, GBDT
probability) skip calibration.

Every detector persists {model, config, profile, seed, wall_clock, peak_rss}
(HCEA §6.3) so Chapter 16 can compare them with provenance.
"""
from __future__ import annotations

import hashlib
import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar

import numpy as np
import pandas as pd

from app.feature_engineering.common import memory_rss_mb

CHAPTER6_VERSION = "chapter6-v1"


class ScoreCalibrator:
    def __init__(self) -> None:
        self.median = 0.0
        self.scale = 1.0
        self.fitted = False

    def fit(self, raw: np.ndarray) -> "ScoreCalibrator":
        r = np.asarray(raw, dtype="float64")
        r = r[np.isfinite(r)]
        if r.size == 0:
            raise ValueError("cannot fit calibrator on an empty score set")
        q25, q50, q75 = np.percentile(r, [25, 50, 75])
        scale = (q75 - q25) / 1.349
        if not scale > 0:
            scale = float(r.std())
        if not scale > 0:
            scale = 1.0
        self.median, self.scale, self.fitted = float(q50), float(scale), True
        return self

    def transform(self, raw: np.ndarray) -> np.ndarray:
        if not self.fitted:
            raise RuntimeError("calibrator is not fitted")
        z = np.arcsinh((np.asarray(raw, dtype="float64") - self.median) / self.scale)
        return 1.0 / (1.0 + np.exp(-z))

    def to_dict(self) -> dict:
        return {"method": "sigmoid(asinh((raw - median) / scale))", "median": self.median, "scale": self.scale}

    @classmethod
    def from_dict(cls, d: dict) -> "ScoreCalibrator":
        obj = cls()
        obj.median, obj.scale, obj.fitted = float(d["median"]), float(d["scale"]), True
        return obj


def config_hash(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:12]


class BaselineDetector(ABC):
    name: ClassVar[str] = "base"
    supervised: ClassVar[bool] = False
    calibrate: ClassVar[bool] = True

    def __init__(self, *, seed: int = 42, **config: Any) -> None:
        self.seed = int(seed)
        self.config: dict[str, Any] = dict(config)
        self.calibrator = ScoreCalibrator()
        self.fitted = False
        self.fit_info: dict[str, Any] = {}

    # --- subclass hooks -------------------------------------------------
    @abstractmethod
    def _fit(self, train: pd.DataFrame, y: np.ndarray | None, validation: pd.DataFrame | None, y_validation: np.ndarray | None) -> None: ...

    @abstractmethod
    def _raw_score(self, frame: pd.DataFrame, **kwargs: Any) -> np.ndarray: ...

    def _calibration_scores(self, train: pd.DataFrame) -> np.ndarray:
        return self._raw_score(train)

    def _extra_metadata(self) -> dict:
        return {}

    def _save_artifacts(self, directory: Path) -> dict:
        return {}

    def _load_artifacts(self, directory: Path, meta: dict) -> None:
        raise NotImplementedError

    # --- public contract ------------------------------------------------
    def fit(
        self,
        train: pd.DataFrame,
        y: np.ndarray | None = None,
        *,
        validation: pd.DataFrame | None = None,
        y_validation: np.ndarray | None = None,
    ) -> "BaselineDetector":
        if self.supervised and y is None:
            raise ValueError(f"{self.name} is supervised and needs training labels")
        if not self.supervised and (y is not None or y_validation is not None):
            raise ValueError(f"{self.name} is unsupervised; it must not receive labels")
        started = time.perf_counter()
        self._fit(train, y, validation, y_validation)
        self.fitted = True
        if self.calibrate:
            self.calibrator.fit(self._calibration_scores(train))
        self.fit_info = {
            "n_train_rows": int(len(train)),
            "fit_wall_seconds": round(time.perf_counter() - started, 3),
            "process_peak_rss_mb": round(memory_rss_mb(), 1),
        }
        return self

    def raw_score(self, frame: pd.DataFrame, **kwargs: Any) -> np.ndarray:
        if not self.fitted:
            raise RuntimeError(f"{self.name} is not fitted")
        raw = np.asarray(self._raw_score(frame, **kwargs), dtype="float64")
        if raw.shape != (len(frame),):
            raise RuntimeError(f"{self.name} returned {raw.shape} scores for {len(frame)} rows")
        if not np.isfinite(raw).all():
            raise RuntimeError(f"{self.name} produced {int((~np.isfinite(raw)).sum())} non-finite scores")
        return raw

    def score(self, frame: pd.DataFrame, **kwargs: Any) -> np.ndarray:
        raw = self.raw_score(frame, **kwargs)
        return self.calibrator.transform(raw) if self.calibrate else np.clip(raw, 0.0, 1.0)

    def scores(self, frame: pd.DataFrame, **kwargs: Any) -> tuple[np.ndarray, np.ndarray]:
        raw = self.raw_score(frame, **kwargs)
        return raw, (self.calibrator.transform(raw) if self.calibrate else np.clip(raw, 0.0, 1.0))

    @property
    def model_version(self) -> str:
        return f"{self.name}-{CHAPTER6_VERSION}-{config_hash({'config': self.config, 'seed': self.seed})}"

    def metadata(self) -> dict:
        return {
            "name": self.name,
            "model_version": self.model_version,
            "supervised": self.supervised,
            "seed": self.seed,
            "config": self.config,
            "calibrator": self.calibrator.to_dict() if self.calibrate else {"method": "none (native [0, 1] score)"},
            "score_convention": "higher = more anomalous; score in [0, 1]",
            **self.fit_info,
            **self._extra_metadata(),
        }

    def save(self, directory: str | Path, *, extra: dict | None = None) -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        artifacts = self._save_artifacts(directory)
        meta = {**self.metadata(), "artifacts": artifacts, **(extra or {})}
        tmp = directory / "meta.json.tmp"
        tmp.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
        tmp.replace(directory / "meta.json")
        return directory

    @classmethod
    def load(cls, directory: str | Path) -> "BaselineDetector":
        directory = Path(directory)
        meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
        obj = cls(seed=meta["seed"], **meta["config"])
        if cls.calibrate:
            obj.calibrator = ScoreCalibrator.from_dict(meta["calibrator"])
        obj._load_artifacts(directory, meta)
        obj.fit_info = {k: meta[k] for k in ("n_train_rows", "fit_wall_seconds", "process_peak_rss_mb") if k in meta}
        obj.fitted = True
        return obj


def user_stratified_sample(users: pd.Series, max_rows: int, seed: int) -> np.ndarray:
    """Row positions of a label-blind sample, proportional per user."""
    n = len(users)
    if n <= max_rows:
        return np.arange(n)
    frac = max_rows / n
    frame = pd.DataFrame({"u": users.astype("string").to_numpy(), "i": np.arange(n)})
    picked = frame.groupby("u", sort=True, group_keys=False).sample(frac=frac, random_state=seed)["i"].to_numpy()
    if len(picked) > max_rows:
        picked = np.random.default_rng(seed).choice(picked, size=max_rows, replace=False)
    return np.sort(picked)
