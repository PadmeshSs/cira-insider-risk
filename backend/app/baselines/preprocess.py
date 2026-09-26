"""Train-only imputation and transforms shared by the baselines (N4).

The Chapter 5 matrix keeps nulls where a value is undefined (ratios with a
zero denominator, clock hours on days without that activity, baselines
before 7 prior days, peers without a department). Here:

* medians are fitted on the training rows only and applied unchanged to
  validation and test rows;
* every column whose schema null policy starts with ``null`` gets a 0/1
  missing indicator, so a model can tell "no activity" from a real value.
  The indicator set comes from the schema, not from which columns happened
  to contain nulls in the training split, so it is stable across splits.

Chapter 7 (TabNet) can reuse this module unchanged.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

INDEX_COLUMNS = ("user_id", "date")


def load_schema(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def nullable_columns_from_schema(schema: dict) -> list[str]:
    return [c["name"] for c in schema.get("columns", []) if str(c.get("null_policy", "")).strip().lower().startswith("null")]


def feature_columns(frame: pd.DataFrame) -> list[str]:
    cols = [c for c in frame.columns if c not in INDEX_COLUMNS]
    bad = [c for c in cols if not pd.api.types.is_numeric_dtype(frame[c])]
    if bad:
        raise ValueError(f"Non-numeric feature columns: {bad[:5]}")
    return cols


def signed_log1p(x: np.ndarray) -> np.ndarray:
    """sign(x) * log(1 + |x|): monotone, compresses heavy count tails."""
    return (np.sign(x) * np.log1p(np.abs(x))).astype("float32")


class TrainFittedImputer:
    def __init__(self) -> None:
        self.columns: list[str] = []
        self.medians: dict[str, float] = {}
        self.indicator_columns: list[str] = []
        self.all_null_in_train: list[str] = []
        self.fitted = False

    def fit(self, train: pd.DataFrame, columns: Iterable[str], nullable: Iterable[str] | None = None) -> "TrainFittedImputer":
        self.columns = list(columns)
        block = train[self.columns]
        med = block.median(skipna=True)
        self.all_null_in_train = [c for c in self.columns if pd.isna(med[c])]
        # A column that is null on every training row has no median; 0 is
        # used and the fact is recorded, not hidden.
        self.medians = {c: (0.0 if pd.isna(med[c]) else float(med[c])) for c in self.columns}
        if nullable is None:
            nullable = [c for c in self.columns if block[c].isna().any()]
        allowed = set(self.columns)
        self.indicator_columns = [c for c in nullable if c in allowed]
        self.fitted = True
        return self

    @property
    def output_columns(self) -> list[str]:
        return self.columns + [f"isnull__{c}" for c in self.indicator_columns]

    def transform(self, frame: pd.DataFrame) -> np.ndarray:
        if not self.fitted:
            raise RuntimeError("imputer is not fitted")
        missing = [c for c in self.columns if c not in frame.columns]
        if missing:
            raise KeyError(f"frame lacks feature columns seen at fit time: {missing[:5]}")
        block = frame[self.columns].astype("float32")
        indicators = block[self.indicator_columns].isna().to_numpy(dtype="float32") if self.indicator_columns else None
        filled = block.fillna(self.medians).to_numpy(dtype="float32")
        return filled if indicators is None else np.hstack([filled, indicators])

    def to_dict(self) -> dict:
        return {
            "columns": self.columns,
            "medians": self.medians,
            "indicator_columns": self.indicator_columns,
            "all_null_in_train": self.all_null_in_train,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TrainFittedImputer":
        obj = cls()
        obj.columns = list(d["columns"])
        obj.medians = {k: float(v) for k, v in d["medians"].items()}
        obj.indicator_columns = list(d["indicator_columns"])
        obj.all_null_in_train = list(d.get("all_null_in_train", []))
        obj.fitted = True
        return obj
