"""Load a saved TabNet model and score user-days (Bible Ch7 step 5).

Score convention (CARRY_FORWARD N10, same as every Chapter 6 detector):

    raw_score(frame) -> logit margin  z = logit(malicious) - logit(benign)
    score(frame)     -> sigmoid(z) in [0, 1], higher = more anomalous

``sigmoid(z)`` equals TabNet's ``predict_proba(X)[:, 1]``. It is computed in
float64 from the margin rather than taken from the float32 softmax, because a
float32 probability rounds to exactly 1.0 once z passes about 17, and ties at
the top of the alert queue would then be broken by the random tie key instead
of by the model. In float64 that happens only past z ~ 37; the runner counts
such rows and reports them. The map is strictly monotone, so ranking metrics
are the same on raw and on calibrated scores.

Under the class-weighted loss this number is a ranking score, not a
calibrated probability of malice. Chapter 9 must treat it as a score.

This module is on the serving path (Chapter 8 builds on it). It never
imports label or ground-truth code (N5), it loads on CPU unless told
otherwise (HCEA §8), and it raises ``ModelUnavailableError`` rather than
return a made-up score when a model cannot be loaded (Architecture §36).
"""
from __future__ import annotations

import json
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from .dataset import TabNetPreprocessor
from .model_registry import ModelRegistry, RegistryError

TABNET_ZIP = "tabnet_model.zip"
PREPROCESSOR_FILE = "preprocessor.json"
IMPORTANCE_FILE = "global_importance.json"
META_FILE = "meta.json"
SCORE_BATCH_ROWS = 16_384


class ModelUnavailableError(RuntimeError):
    """The requested model could not be loaded. Never answer with a score."""


def sigmoid(z: np.ndarray) -> np.ndarray:
    z = np.asarray(z, dtype="float64")
    out = np.empty_like(z)
    pos = z >= 0
    out[pos] = 1.0 / (1.0 + np.exp(-z[pos]))
    ez = np.exp(z[~pos])
    out[~pos] = ez / (1.0 + ez)
    return out


@torch.no_grad()
def margins(clf, x: np.ndarray, batch_size: int = SCORE_BATCH_ROWS) -> np.ndarray:
    """Logit margin per row, from TabNet's network in eval mode.

    Eval-mode batch norm uses running statistics, so a row's margin does not
    depend on which other rows share its batch.
    """
    net = clf.network
    net.eval()
    out = []
    for start in range(0, len(x), batch_size):
        xb = torch.from_numpy(np.ascontiguousarray(x[start:start + batch_size])).to(clf.device).float()
        logits, _ = net(xb)
        logits = logits.float().cpu().numpy()
        out.append((logits[:, 1] - logits[:, 0]).astype("float64"))
    return np.concatenate(out) if out else np.zeros(0, dtype="float64")


def load_tabnet_classifier(zip_path: str | Path, device_name: str = "cpu"):
    from pytorch_tabnet.tab_model import TabNetClassifier

    clf = TabNetClassifier(device_name=device_name, verbose=0)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        clf.load_model(str(zip_path))
    clf.network.eval()
    return clf


class TabNetScorer:
    """Read-only view of one saved TabNet artifact directory."""

    def __init__(self, directory: Path, meta: dict, clf, preprocessor: TabNetPreprocessor, entry: dict | None = None) -> None:
        self.directory = directory
        self.meta = meta
        self.clf = clf
        self.preprocessor = preprocessor
        self.entry = entry or {}

    @property
    def model_version(self) -> str:
        return self.meta["model_version"]

    @property
    def registry_version(self) -> str | None:
        return self.entry.get("registry_version")

    @property
    def device(self) -> str:
        return self.clf.device.type

    @property
    def feature_names(self) -> list[str]:
        """Model input columns in order, missing indicators included."""
        return self.preprocessor.output_columns

    def raw_score(self, frame: pd.DataFrame) -> np.ndarray:
        z = margins(self.clf, self.preprocessor.transform(frame))
        if z.shape != (len(frame),) or not np.isfinite(z).all():
            raise RuntimeError(f"TabNet produced invalid scores for {len(frame)} rows")
        return z

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        return sigmoid(self.raw_score(frame))


def load_artifact_dir(directory: str | Path, *, device: str = "cpu") -> TabNetScorer:
    directory = Path(directory)
    try:
        meta = json.loads((directory / META_FILE).read_text(encoding="utf-8"))
        prep = TabNetPreprocessor.from_dict(json.loads((directory / PREPROCESSOR_FILE).read_text(encoding="utf-8")))
        clf = load_tabnet_classifier(directory / TABNET_ZIP, device_name=device)
        entry_path = directory / "registry_entry.json"
        entry = json.loads(entry_path.read_text(encoding="utf-8")) if entry_path.exists() else None
    except Exception as exc:   # any failure means there is no model to score with
        raise ModelUnavailableError(f"cannot load TabNet artifact from {directory}: {exc}") from exc
    if meta.get("name") != "tabnet":
        raise ModelUnavailableError(f"{directory} holds a {meta.get('name')!r} model, not tabnet")
    if len(prep.output_columns) != int(clf.network.input_dim):
        raise ModelUnavailableError(
            f"{directory}: preprocessor emits {len(prep.output_columns)} columns, network expects {clf.network.input_dim}"
        )
    return TabNetScorer(directory, meta, clf, prep, entry)


def load_model(
    ref: str | Path = "latest",
    *,
    registry_root: str | Path | None = None,
    profile: str | None = None,
    device: str = "cpu",
    verify: bool = True,
) -> TabNetScorer:
    """Load by artifact directory, or resolve ``ref`` in the registry.

    ``ref`` may be a directory path, "latest", a registry version
    ("v0003"), a model_version string or a run id. With ``verify`` the
    artifact files are checked against the sha256 values recorded at
    registration.
    """
    path = Path(str(ref))
    if path.is_dir():
        return load_artifact_dir(path, device=device)
    if registry_root is None:
        raise ModelUnavailableError(f"{ref!r} is not a directory and no registry_root was given")
    registry = ModelRegistry(registry_root)
    try:
        entry = registry.resolve(str(ref), profile=profile)
    except RegistryError as exc:
        raise ModelUnavailableError(str(exc)) from exc
    if verify:
        problems = registry.verify(entry)
        if problems:
            raise ModelUnavailableError(f"registry artifact {entry['registry_version']} failed verification: {problems}")
    return load_artifact_dir(registry.artifact_dir(entry), device=device)
