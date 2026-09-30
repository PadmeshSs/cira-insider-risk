"""The attribution contract and the choice of explainer (N30).

``Attributions`` is what every model-side explainer returns for a block of
user-days: one value per (row, base feature), in the model's own units, with
enough lineage to trace it back to the artifact that produced the score.

    method        "treeshap"     exact TreeSHAP on the served XGBoost; signed,
                                 log-odds contributions to the margin; they
                                 add up to the margin the model scored
                                 (additivity is checked, never assumed)
                  "tabnet_mask"  TabNet's aggregate attention mask; unsigned
                                 shares that sum to 1 per row. Importance,
                                 not direction: a mask never says whether a
                                 feature raised or lowered the score
                  "kernelshap"   model-agnostic estimate (corroboration only)

Which explainer (N30)
    ``explainer_for(adapter)`` picks by the model that produced the score:
    XGBoost -> TreeSHAP, TabNet -> masks. There is no way to ask for TabNet's
    masks as the explanation of an XGBoost score. Shadow models are explained
    only on explicit request, and the result is tagged ``role="shadow"``; the
    reason builder refuses it (N32).

Grouping (N22)
    TabNet's inputs are the preprocessed columns plus one ``isnull__<c>``
    indicator per nullable column. Attributions are summed per base feature
    (value + indicator), so a feature is never split into two half-reasons.
    XGBoost reads the raw Chapter 5 columns with native nulls, so its
    attributions are already per base feature.

Label-free (N5).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .features import CALENDAR_COLUMNS, STATIC_PREFIXES

METHODS = ("treeshap", "tabnet_mask", "kernelshap")
UNITS = {
    "treeshap": "log-odds contribution to the model's margin (signed; sums to margin - expected value)",
    "tabnet_mask": "share of TabNet's aggregate attention mask (unsigned; sums to 1 per row)",
    "kernelshap": "estimated log-odds contribution to the model's margin (signed)",
}
ATTRIBUTION_COLUMNS = (
    "user_id", "date", "rank", "feature", "contribution", "abs_contribution", "direction",
    "feature_value", "is_static", "is_calendar",
)
DEFAULT_TOP_K = 10


class ExplanationUnavailableError(RuntimeError):
    """No explainer can be built for this model."""


class ExplanationFailedError(RuntimeError):
    """The explainer ran but its output cannot be trusted (for example, it does not add up)."""


@dataclass
class Attributions:
    keys: pd.DataFrame                   # user_id, date (aligned with values)
    features: list[str]                  # base features, column order of ``values``
    values: np.ndarray                   # [n x F] float64
    method: str
    raw_score: np.ndarray                # the model's margin for each row, as it scores
    model: dict                          # model_name, model_version, registry_version, role
    expected_value: np.ndarray | None = None
    additivity_error: np.ndarray | None = None
    info: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.method not in METHODS:
            raise ValueError(f"unknown attribution method {self.method!r}")
        n = len(self.keys)
        if self.values.shape != (n, len(self.features)):
            raise ValueError(f"values {self.values.shape} do not match {n} rows x {len(self.features)} features")
        if self.raw_score.shape != (n,):
            raise ValueError("raw_score must have one value per row")

    @property
    def signed(self) -> bool:
        return self.method in ("treeshap", "kernelshap")

    @property
    def units(self) -> str:
        return UNITS[self.method]


def is_static(feature: str) -> bool:
    return str(feature).startswith(STATIC_PREFIXES)


def order_by_importance(values: np.ndarray) -> np.ndarray:
    """Per row, feature positions by |value| descending; ties by position (deterministic)."""
    a = np.abs(np.asarray(values, dtype="float64"))
    return np.argsort(-a, axis=1, kind="stable")


def top_k_long(attr: Attributions, raw_values: pd.DataFrame, k: int = DEFAULT_TOP_K) -> pd.DataFrame:
    """The top-k features per row by |attribution|, one row each (HCEA §11.1: never the dense matrix).

    ``raw_values`` is aligned with ``attr.keys`` and holds the raw Chapter 5
    columns; ``feature_value`` comes from there, never from a model input (N22).
    Zero attributions are not listed: a feature that did nothing is not a factor.
    """
    n, f = attr.values.shape
    k = max(1, min(int(k), f))
    if len(raw_values) != n:
        raise ValueError(f"raw_values has {len(raw_values)} rows, attributions {n}")
    order = order_by_importance(attr.values)[:, :k]
    rows = np.repeat(np.arange(n), k)
    cols = order.reshape(-1)
    contrib = attr.values[rows, cols]
    keep = contrib != 0
    rows, cols, contrib = rows[keep], cols[keep], contrib[keep]
    rank = np.tile(np.arange(1, k + 1), n)[keep]
    names = np.asarray(attr.features, dtype=object)[cols]
    raw = np.full(len(rows), np.nan)
    present = [c for c in attr.features if c in raw_values.columns]
    if present:
        block = raw_values.reindex(columns=attr.features).to_numpy(dtype="float64", na_value=np.nan)
        raw = block[rows, cols]
    if attr.signed:
        direction = np.where(contrib > 0, "raises", "lowers")
    else:
        direction = np.full(len(rows), "attends", dtype=object)
    return pd.DataFrame({
        "user_id": attr.keys["user_id"].astype("string").to_numpy()[rows],
        "date": attr.keys["date"].astype("string").to_numpy()[rows],
        "rank": rank.astype("int16"),
        "feature": names,
        "contribution": contrib.astype("float64"),
        "abs_contribution": np.abs(contrib).astype("float64"),
        "direction": direction,
        "feature_value": raw,
        "is_static": np.asarray([is_static(x) for x in names], dtype=bool),
        "is_calendar": np.asarray([x in CALENDAR_COLUMNS for x in names], dtype=bool),
    }, columns=list(ATTRIBUTION_COLUMNS))


def row_summary(attr: Attributions) -> pd.DataFrame:
    """One row per user-day: what the explanation says in aggregate, for the batch file."""
    v = attr.values
    n = len(v)
    names = np.asarray(attr.features, dtype=object)
    if attr.signed:
        pos = np.where(v > 0, v, -np.inf)
        top = pos.argmax(axis=1)
        has_pos = np.isfinite(pos[np.arange(n), top])
        top_contrib = np.where(has_pos, v[np.arange(n), top], np.nan)
    else:
        top = v.argmax(axis=1)
        has_pos = v[np.arange(n), top] > 0
        top_contrib = np.where(has_pos, v[np.arange(n), top], np.nan)
    top_name = np.where(has_pos, names[top], None)
    order = order_by_importance(v)[:, :5]
    static_cols = np.asarray([is_static(x) for x in attr.features], dtype=bool)
    static_in_top5 = static_cols[order].any(axis=1) & (np.abs(v[np.arange(n)[:, None], order]) > 0).any(axis=1)
    out = pd.DataFrame({
        "user_id": attr.keys["user_id"].astype("string").to_numpy(),
        "date": attr.keys["date"].astype("string").to_numpy(),
        "method": attr.method,
        "raw_score": attr.raw_score.astype("float64"),
        "expected_value": (attr.expected_value if attr.expected_value is not None else np.full(n, np.nan)),
        "attribution_sum": v.sum(axis=1),
        "additivity_error": (attr.additivity_error if attr.additivity_error is not None else np.full(n, np.nan)),
        "n_raising": (v > 0).sum(axis=1).astype("int32"),
        "top_feature": top_name,
        "top_contribution": top_contrib,
        "top_is_calendar": np.asarray([x in CALENDAR_COLUMNS for x in top_name], dtype=bool),
        "static_in_top5": static_in_top5,
    })
    return out


def explainer_for(adapter, *, role: str = "served", **kwargs):
    """The model-side explainer for the model that produced the score (N30)."""
    if role not in ("served", "shadow"):
        raise ValueError(f"role must be served or shadow, got {role!r}")
    name = getattr(adapter, "model_name", None)
    if name == "gbdt":
        from .shap_explainer import TreeShapExplainer

        return TreeShapExplainer(adapter, role=role, **kwargs)
    if name == "tabnet":
        from .tabnet_masks import TabNetMaskExplainer

        return TabNetMaskExplainer(adapter, role=role, **kwargs)
    raise ExplanationUnavailableError(f"no explainer for model {name!r}")
