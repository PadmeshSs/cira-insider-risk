"""Data side of Chapter 7: the feature matrix, train-only preprocessing and
the leakage-safe split (Bible Ch7 step 1, HCEA §7.5, CARRY_FORWARD N3/N4/N11).

Nothing in this module reads labels. The runner (``train.py``) joins labels
in memory with ``app.evaluation.labels`` and passes the per-insider scenario
map and the label frame in. That keeps this module, ``infer.py`` and
``model_registry.py`` usable from the serving path without ever importing
label code (N5).

Split
    The user split is the file Chapter 6 wrote under ``experiments/splits/``
    (N11). ``load_or_create_split`` returns it unchanged and refuses a file
    that no longer matches the population or seed. The time split uses the
    same default dates as Chapter 6. Either way the data fingerprint is
    computed with the Chapter 6 formula, so a TabNet run and a baseline run
    on the same matrix and split carry the same fingerprint.

Preprocessing (TabNet cannot take NaN)
    1. ``TrainFittedImputer`` from Chapter 6: train medians, and a 0/1
       missing indicator for every column whose schema null policy starts
       with "null" (N4). The indicator set comes from the schema, so it is
       the same in every split.
    2. signed log1p, which compresses count tails (http requests run into
       the hundreds on some days).
    3. standardisation with the training mean and standard deviation.

    Every step is per column and monotone, so output column ``c`` still
    describes input column ``c``. Chapter 11 relies on that when it names
    mask and SHAP contributions. ``feature_groups`` pairs each column with
    its missing indicator so importance can be summed per base feature.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from app.baselines.preprocess import (
    TrainFittedImputer,
    feature_columns,
    load_schema,
    nullable_columns_from_schema,
    signed_log1p,
)
from app.evaluation.splitting import (
    SPLITS,
    assert_user_disjoint,
    load_or_create_split,
    rows_for_split,
    split_summary,
    time_split,
)

PROFILE_OUTPUT = {"dev": "user_day_dev.parquet", "mid": "user_day_mid.parquet", "full": "user_day_full.parquet"}
INDICATOR_PREFIX = "isnull__"
PREPROCESSOR_VERSION = "tabnet-preprocess-v1"
# Static per-user traits. If these lead the importance ranking the model has
# learned who insiders resemble rather than what they did (same check as the
# GBDT inspection in Chapter 6).
STATIC_TRAIT_PREFIXES = ("psych_", "peer_department_size")


# ---------------------------------------------------------------------------
# Feature matrix
# ---------------------------------------------------------------------------

@dataclass
class FeatureMatrix:
    matrix: pd.DataFrame
    schema: dict
    features_path: Path
    schema_path: Path

    @property
    def keys(self) -> pd.DataFrame:
        return self.matrix[["user_id", "date"]]

    @property
    def nullable(self) -> list[str]:
        return nullable_columns_from_schema(self.schema)


def load_feature_matrix(processed_dir: str | Path, profile: str) -> FeatureMatrix:
    """Read ``features/user_day_<profile>.parquet`` and its schema.

    Keys are normalised the same way as in the Chapter 6 runner and rows are
    sorted by (user_id, date), so row order matches a baseline run.
    """
    if profile not in PROFILE_OUTPUT:
        raise ValueError(f"unknown profile {profile!r}")
    processed = Path(processed_dir)
    features_path = processed / "features" / PROFILE_OUTPUT[profile]
    schema_path = processed / "features" / f"feature_schema_{profile}.json"
    if not schema_path.exists():
        schema_path = processed / "features" / "feature_schema.json"
    if not features_path.exists():
        raise FileNotFoundError(f"{features_path} not found; run the Chapter 5 pipeline for profile={profile}")
    schema = load_schema(schema_path)
    if schema.get("profile") not in (None, profile):
        raise RuntimeError(f"{schema_path} describes profile {schema.get('profile')!r}, not {profile!r}")
    matrix = pd.read_parquet(features_path)
    matrix["user_id"] = matrix["user_id"].astype("string").str.strip().str.casefold()
    matrix["date"] = matrix["date"].astype("string")
    matrix = matrix.sort_values(["user_id", "date"], kind="mergesort").reset_index(drop=True)
    if matrix.duplicated(["user_id", "date"]).any():
        raise ValueError(f"{features_path} has duplicate (user_id, date) rows")
    feature_columns(matrix)  # raises on non-numeric feature columns
    return FeatureMatrix(matrix=matrix, schema=schema, features_path=features_path, schema_path=schema_path)


def feature_fingerprint(path: str | Path) -> str:
    """Same formula as the Chapter 6 runner, so fingerprints are comparable."""
    st = Path(path).stat()
    return hashlib.sha256(f"{Path(path).name}|{st.st_size}|{int(st.st_mtime)}".encode()).hexdigest()[:12]


def file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Split
# ---------------------------------------------------------------------------

@dataclass
class SplitAssignment:
    rows: np.ndarray                     # split name per matrix row
    info: dict                           # what goes into metrics.json / the registry
    parts: dict[str, np.ndarray] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.parts = {s: np.flatnonzero(self.rows == s) for s in SPLITS}


def make_split(
    keys: pd.DataFrame,
    *,
    mode: str,
    insider_scenarios: dict[str, int],
    seed: int,
    profile: str,
    splits_dir: str | Path,
    fractions: Iterable[float] = (0.6, 0.2, 0.2),
    rebuild: bool = False,
    time_validation_start: str = "2011-01-01",
    time_test_start: str = "2011-02-01",
) -> SplitAssignment:
    """User split from the saved file (N11) or the time split (N3)."""
    fractions = tuple(float(f) for f in fractions)
    info: dict = {"mode": mode}
    if mode == "user":
        path = Path(splits_dir) / f"user_split_{profile}_seed{seed}.json"
        users = set(keys["user_id"].astype("string").unique().tolist())
        assignment, _meta, created = load_or_create_split(
            path, users, insider_scenarios, seed=seed, fractions=fractions, profile=profile, rebuild=rebuild
        )
        rows = rows_for_split(keys["user_id"], assignment)
        assert_user_disjoint(keys["user_id"], rows)
        info.update({
            "file": str(path),
            "file_sha256": file_sha256(path),
            "created_now": created,
            "counts": split_summary(assignment, insider_scenarios),
        })
    elif mode == "time":
        rows = time_split(keys["date"], validation_start=time_validation_start, test_start=time_test_start)
        info.update({"validation_start": time_validation_start, "test_start": time_test_start})
    else:
        raise ValueError(f"unknown split mode {mode!r}")
    out = SplitAssignment(rows=rows, info=info)
    out.info["rows"] = {s: int(len(ix)) for s, ix in out.parts.items()}
    for s in SPLITS:
        if len(out.parts[s]) == 0:
            raise RuntimeError(f"split {s!r} is empty under mode={mode}")
    return out


def data_fingerprint(features_fp: str, split: SplitAssignment) -> str:
    """Identical to the Chapter 6 runner's data fingerprint."""
    info = split.info
    payload = {
        "features": features_fp,
        "split": info.get("file") or [info.get("validation_start"), info.get("test_start")],
        "rows": info["rows"],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:12]


def supervised_rows(label_part: pd.DataFrame) -> np.ndarray:
    """Boolean mask of rows a supervised model may train or early-stop on.

    Masquerade account-days are dropped (N13): the supervisor's account did
    carry malicious activity, so keeping it as a negative would teach the
    model that malicious behaviour is benign.
    """
    return ~label_part["exclude_primary"].to_numpy().astype(bool)


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------

class TabNetPreprocessor:
    """Train-fitted imputation + indicators, signed log1p, standardisation."""

    def __init__(self) -> None:
        self.imputer = TrainFittedImputer()
        self.mean: np.ndarray | None = None
        self.std: np.ndarray | None = None
        self.constant_columns: list[str] = []
        self.n_fit_rows = 0
        self.fitted = False

    def fit(self, frame: pd.DataFrame, nullable: Iterable[str] | None = None) -> "TabNetPreprocessor":
        self.imputer.fit(frame, feature_columns(frame), nullable)
        z = signed_log1p(self.imputer.transform(frame))
        self.mean = z.mean(axis=0, dtype="float64")
        std = z.std(axis=0, dtype="float64")
        cols = self.imputer.output_columns
        self.constant_columns = [c for c, s in zip(cols, std) if not s > 0]
        self.std = np.where(std > 0, std, 1.0)
        self.n_fit_rows = int(len(frame))
        self.fitted = True
        return self

    @property
    def input_columns(self) -> list[str]:
        return list(self.imputer.columns)

    @property
    def output_columns(self) -> list[str]:
        return list(self.imputer.output_columns)

    def transform(self, frame: pd.DataFrame) -> np.ndarray:
        if not self.fitted:
            raise RuntimeError("preprocessor is not fitted")
        z = signed_log1p(self.imputer.transform(frame))
        out = ((z - self.mean) / self.std).astype("float32")
        if not np.isfinite(out).all():
            raise ValueError(f"preprocessing produced {int((~np.isfinite(out)).sum())} non-finite values")
        return out

    def to_dict(self) -> dict:
        return {
            "version": PREPROCESSOR_VERSION,
            "steps": [
                "train median imputation + schema missing indicators (N4)",
                "signed log1p",
                "(x - train mean) / train std",
            ],
            "imputer": self.imputer.to_dict(),
            "mean": [float(v) for v in self.mean],
            "std": [float(v) for v in self.std],
            "output_columns": self.output_columns,
            "constant_columns_in_train": self.constant_columns,
            "n_fit_rows": self.n_fit_rows,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TabNetPreprocessor":
        if d.get("version") != PREPROCESSOR_VERSION:
            raise ValueError(f"preprocessor version {d.get('version')!r}, expected {PREPROCESSOR_VERSION!r}")
        obj = cls()
        obj.imputer = TrainFittedImputer.from_dict(d["imputer"])
        obj.mean = np.asarray(d["mean"], dtype="float64")
        obj.std = np.asarray(d["std"], dtype="float64")
        obj.constant_columns = list(d.get("constant_columns_in_train", []))
        obj.n_fit_rows = int(d.get("n_fit_rows", 0))
        if obj.output_columns != list(d["output_columns"]):
            raise ValueError("preprocessor output columns do not match the stored list")
        obj.fitted = True
        return obj


def feature_groups(output_columns: list[str]) -> dict[str, list[int]]:
    """Base feature -> output column positions (value and its missing indicator)."""
    pos = {c: i for i, c in enumerate(output_columns)}
    groups: dict[str, list[int]] = {}
    for c, i in pos.items():
        base = c[len(INDICATOR_PREFIX):] if c.startswith(INDICATOR_PREFIX) else c
        groups.setdefault(base, []).append(i)
    return groups


def grouped_importance(importance: np.ndarray, output_columns: list[str]) -> list[tuple[str, float]]:
    """Sum importance over each base feature's columns, largest first."""
    imp = np.asarray(importance, dtype="float64")
    rows = [(base, float(imp[idx].sum())) for base, idx in feature_groups(output_columns).items()]
    return sorted(rows, key=lambda kv: (-kv[1], kv[0]))
