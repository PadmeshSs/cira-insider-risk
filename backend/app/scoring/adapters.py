"""Load one pinned registry version and expose the scoring interface.

Both models are resolved through ``app.tabnet.model_registry.ModelRegistry``
(the registry class is model-agnostic: ``<MODEL_PATH>/<model_name>/``), with
the sha256 of every artifact file checked before anything is loaded (N21).
A model is always loaded on CPU (HCEA §8).

Refusals, each raised as ScoringUnavailableError:
    * the pin does not resolve, or its files fail sha256 verification;
    * the entry is not reportable (a dev-profile model, N6), unless the
      caller explicitly allows it (tests only);
    * the artifact is a different model than the pin names.

TabNet is imported lazily so an XGBoost-only process never loads torch.
Never imports label code (N5).
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from app.core.runtime import max_workers
from app.tabnet.model_registry import ModelRegistry, RegistryError

from .contracts import ModelPin, ScoringUnavailableError, stable_sigmoid, static_inputs


def _resolve(pin: ModelPin, registry_root: str | Path, *, allow_unreportable: bool) -> tuple[ModelRegistry, dict]:
    registry = ModelRegistry(registry_root, pin.model_name)
    try:
        entry = registry.resolve(pin.registry_version)
    except RegistryError as exc:
        raise ScoringUnavailableError(f"{pin}: {exc}") from exc
    if entry.get("registry_version") != pin.registry_version:
        raise ScoringUnavailableError(f"{pin} resolved to {entry.get('registry_version')}; refusing an inexact match")
    problems = registry.verify(entry)
    if problems:
        raise ScoringUnavailableError(f"{pin} failed sha256 verification: {problems}")
    if not entry.get("reportable") and not allow_unreportable:
        raise ScoringUnavailableError(
            f"{pin} was trained on profile {entry.get('profile')!r} and is not reportable (N6); it cannot be served"
        )
    return registry, entry


class _AdapterBase:
    model_name: str = ""

    def __init__(self, pin: ModelPin, entry: dict, artifact_dir: Path) -> None:
        self.pin = pin
        self.entry = entry
        self.artifact_dir = artifact_dir

    @property
    def registry_version(self) -> str:
        return self.pin.registry_version

    def describe(self) -> dict:
        cols = self.input_columns
        return {
            "model_name": self.model_name,
            "registry_version": self.registry_version,
            "model_version": self.model_version,
            "run_id": self.entry.get("run_id"),
            "profile": self.entry.get("profile"),
            "trained_at": self.entry.get("trained_at"),
            "split_mode": (self.entry.get("split") or {}).get("mode"),
            "n_input_columns": len(cols),
            "static_inputs": static_inputs(cols),
            "device": "cpu",
            "artifact_dir": str(self.artifact_dir),
        }


class TabNetAdapter(_AdapterBase):
    model_name = "tabnet"

    def __init__(self, pin: ModelPin, entry: dict, artifact_dir: Path, scorer) -> None:
        super().__init__(pin, entry, artifact_dir)
        self.scorer = scorer

    @classmethod
    def load(cls, pin: ModelPin, registry_root: str | Path, *, allow_unreportable: bool = False) -> "TabNetAdapter":
        registry, entry = _resolve(pin, registry_root, allow_unreportable=allow_unreportable)
        from app.tabnet.infer import ModelUnavailableError, load_artifact_dir

        try:
            scorer = load_artifact_dir(registry.artifact_dir(entry), device="cpu")
        except ModelUnavailableError as exc:
            raise ScoringUnavailableError(f"{pin}: {exc}") from exc
        if scorer.model_version != entry.get("model_version"):
            raise ScoringUnavailableError(f"{pin}: artifact holds {scorer.model_version}, registry says {entry.get('model_version')}")
        return cls(pin, entry, registry.artifact_dir(entry), scorer)

    @property
    def model_version(self) -> str:
        return self.scorer.model_version

    @property
    def input_columns(self) -> list[str]:
        return list(self.scorer.preprocessor.input_columns)

    def raw_score(self, frame: pd.DataFrame) -> np.ndarray:
        return np.asarray(self.scorer.raw_score(frame), dtype="float64")

    @staticmethod
    def score_from_raw(raw: np.ndarray) -> np.ndarray:
        return stable_sigmoid(raw)


class GBDTAdapter(_AdapterBase):
    model_name = "gbdt"

    def __init__(self, pin: ModelPin, entry: dict, artifact_dir: Path, detector) -> None:
        super().__init__(pin, entry, artifact_dir)
        self.detector = detector

    @classmethod
    def load(cls, pin: ModelPin, registry_root: str | Path, *, allow_unreportable: bool = False) -> "GBDTAdapter":
        registry, entry = _resolve(pin, registry_root, allow_unreportable=allow_unreportable)
        from .gbdt_model import BehaviourGBDTDetector

        directory = registry.artifact_dir(entry)
        try:
            detector = BehaviourGBDTDetector.load(directory)
            detector.use_cpu(max_workers())
        except Exception as exc:   # any failure means there is no model to score with
            raise ScoringUnavailableError(f"{pin}: cannot load XGBoost artifact from {directory}: {exc}") from exc
        if detector.model_version != entry.get("model_version"):
            raise ScoringUnavailableError(f"{pin}: artifact holds {detector.model_version}, registry says {entry.get('model_version')}")
        return cls(pin, entry, directory, detector)

    @property
    def model_version(self) -> str:
        return self.detector.model_version

    @property
    def input_columns(self) -> list[str]:
        return self.detector.input_columns

    def raw_score(self, frame: pd.DataFrame) -> np.ndarray:
        return self.detector.raw_score(frame)

    @staticmethod
    def score_from_raw(raw: np.ndarray) -> np.ndarray:
        return stable_sigmoid(raw)


ADAPTERS = {"tabnet": TabNetAdapter, "gbdt": GBDTAdapter}


def load_adapter(pin: ModelPin, registry_root: str | Path, *, allow_unreportable: bool = False):
    return ADAPTERS[pin.model_name].load(pin, registry_root, allow_unreportable=allow_unreportable)
