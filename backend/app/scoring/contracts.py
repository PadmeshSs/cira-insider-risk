"""The Chapter 8 score contract (Bible Ch8, Architecture §14/§36/§37, N10).

What a score is
    ``anomaly_score`` in [0, 1], higher = more anomalous, computed as a
    float64 sigmoid of the model's margin (logit). Each model's score is a
    ranking score, not a probability of malice: both supervised models were
    trained with a positive-class weight of negatives / positives, so the
    number is inflated relative to a true probability (N20). CRI treats it
    as a score input.

What travels with a score (lineage, Architecture §37)
    model_name, model_version (hash of config + seed), registry_version
    (the pinned artifact directory, sha256-verified at load), and role
    ("served" feeds CRI; "shadow" is logged for comparison only).

What never happens (Architecture §36 "model unavailable")
    No fallback score, no default score, no score from a model other than
    the pinned one. A failure raises one of the errors below.

Input policy
    A feature vector carries the raw Chapter 5 columns, by name. Extra
    columns are ignored. A missing column is an error. A null value is
    allowed, because Chapter 5 nulls are deliberate (N4) and each model
    handles them the way it was trained to (TabNet: train medians plus
    indicators; XGBoost: native missing-value routing). Infinite and
    non-numeric values are errors.
"""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Protocol, Sequence

import numpy as np
import pandas as pd

KEY_COLUMNS = ("user_id", "date")
ROLES = ("served", "shadow")
MODEL_NAMES = ("tabnet", "gbdt")
# Same static per-user traits as app.tabnet.dataset.STATIC_TRAIT_PREFIXES
# (kept literal here so this module stays free of the training imports; a
# unit test checks the two are equal).
STATIC_TRAIT_PREFIXES = ("psych_", "peer_department_size")
SCORE_FRAME_COLUMNS = (
    "user_id", "date", "role", "model_name", "model_version", "registry_version", "raw_score", "anomaly_score",
)
_PIN_RE = re.compile(r"^v\d{4,}$")


class ScoringUnavailableError(RuntimeError):
    """No model can be served. The caller gets this, never a score."""


class ScoringInputError(ValueError):
    """The feature vector cannot be scored as given."""


class ScoringFailedError(RuntimeError):
    """The model raised, or returned something that is not a valid score."""


@dataclass(frozen=True)
class ModelPin:
    """A registry version of one model. "latest" is refused on purpose (N21)."""

    model_name: str
    registry_version: str

    def __post_init__(self) -> None:
        if self.model_name not in MODEL_NAMES:
            raise ValueError(f"model_name must be one of {MODEL_NAMES}, got {self.model_name!r}")
        if not _PIN_RE.match(self.registry_version or ""):
            raise ValueError(
                f"registry_version must be a pinned version like 'v0005', got {self.registry_version!r}; "
                "the served model is never 'latest' (N21)"
            )

    @classmethod
    def parse(cls, text: str) -> "ModelPin":
        """``"gbdt:v0003"`` -> ModelPin("gbdt", "v0003")."""
        name, sep, version = (text or "").strip().partition(":")
        if not sep:
            raise ValueError(f"expected <model_name>:<registry_version>, got {text!r}")
        return cls(name.strip(), version.strip())

    def __str__(self) -> str:
        return f"{self.model_name}:{self.registry_version}"


@dataclass(frozen=True)
class ScoreResult:
    anomaly_score: float
    raw_score: float
    model_name: str
    model_version: str
    registry_version: str
    role: str
    scored_at: str
    user_id: str | None = None
    date: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class AnomalyModel(Protocol):
    """What the service needs from a loaded model (see adapters.py)."""

    model_name: str

    @property
    def model_version(self) -> str: ...

    @property
    def registry_version(self) -> str: ...

    @property
    def input_columns(self) -> list[str]: ...

    def raw_score(self, frame: pd.DataFrame) -> np.ndarray: ...

    def score_from_raw(self, raw: np.ndarray) -> np.ndarray: ...

    def describe(self) -> dict: ...


def stable_sigmoid(z: np.ndarray) -> np.ndarray:
    """float64 sigmoid without overflow; identical to app.tabnet.infer.sigmoid."""
    z = np.asarray(z, dtype="float64")
    out = np.empty_like(z)
    pos = z >= 0
    out[pos] = 1.0 / (1.0 + np.exp(-z[pos]))
    ez = np.exp(z[~pos])
    out[~pos] = ez / (1.0 + ez)
    return out


def static_inputs(columns: Sequence[str]) -> list[str]:
    return sorted(c for c in columns if str(c).startswith(STATIC_TRAIT_PREFIXES))


def check_frame(frame: pd.DataFrame, input_columns: Sequence[str]) -> None:
    """Raise ScoringInputError unless ``frame`` can be scored as it is."""
    if not isinstance(frame, pd.DataFrame):
        raise ScoringInputError(f"expected a DataFrame, got {type(frame).__name__}")
    if len(frame) == 0:
        raise ScoringInputError("nothing to score: the frame has no rows")
    missing = [c for c in input_columns if c not in frame.columns]
    if missing:
        raise ScoringInputError(
            f"{len(missing)} model input column(s) missing, e.g. {missing[:5]}; "
            "a missing column is never imputed at serving time"
        )
    block = frame[list(input_columns)]
    bad_types = [c for c in input_columns if not (pd.api.types.is_numeric_dtype(block[c]) or pd.api.types.is_bool_dtype(block[c]))]
    if bad_types:
        raise ScoringInputError(f"non-numeric input column(s): {bad_types[:5]}")
    values = block.to_numpy(dtype="float64", na_value=np.nan)
    if np.isinf(values).any():
        cols = [input_columns[j] for j in sorted(set(np.argwhere(np.isinf(values))[:, 1].tolist()))]
        raise ScoringInputError(f"infinite value(s) in {cols[:5]}; Chapter 5 never emits inf, so the input is corrupt")


def vector_to_frame(feature_vector: Mapping[str, Any], input_columns: Sequence[str]) -> pd.DataFrame:
    """One feature vector (column -> value) as a one-row frame.

    ``None`` becomes NaN (a deliberate null, N4). A column absent from the
    mapping is an error, so "no value" and "forgot to send it" never look the
    same.
    """
    if not isinstance(feature_vector, Mapping):
        raise ScoringInputError(f"feature_vector must be a mapping of column -> value, got {type(feature_vector).__name__}")
    missing = [c for c in input_columns if c not in feature_vector]
    if missing:
        raise ScoringInputError(f"{len(missing)} model input column(s) missing, e.g. {missing[:5]}")
    row = {}
    for c in input_columns:
        v = feature_vector[c]
        if v is None:
            row[c] = math.nan
        elif isinstance(v, (bool, np.bool_)):
            row[c] = float(v)
        elif isinstance(v, (int, float, np.integer, np.floating)):
            row[c] = float(v)
        else:
            raise ScoringInputError(f"column {c!r} has a non-numeric value of type {type(v).__name__}")
    return pd.DataFrame([row], columns=list(input_columns)).astype("float64")


def check_scores(raw: np.ndarray, score: np.ndarray, n_rows: int, what: str) -> None:
    if raw.shape != (n_rows,) or score.shape != (n_rows,):
        raise ScoringFailedError(f"{what} returned {raw.shape} scores for {n_rows} rows")
    if not np.isfinite(raw).all():
        raise ScoringFailedError(f"{what} returned {int((~np.isfinite(raw)).sum())} non-finite raw scores")
    if not ((score >= 0.0) & (score <= 1.0)).all():
        raise ScoringFailedError(f"{what} returned scores outside [0, 1]")
