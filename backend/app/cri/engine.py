"""CRIEngine: anomaly score + context -> 0-100 risk score and severity (Bible Ch9 step 2).

    engine = CRIEngine.load(CRIConfig.from_env())        # pinned calibration, sha256-checked
    risk = engine.compute(scores, context)                # vectorised over a frame
    variants = engine.compute_variants(scores, context, ["default", "anomaly_only"])

The formula (a configurable implementation decision, not a "final" formula;
Architecture §15, CLAUDE §12)

    component_c in [0, 1]      rarity of the component's statistic against the
                               calibration reference (user_context: 0 or 1)
    w_c                        configured weight, renormalised over the
                               components this deployment can provide
    points_c  = 100 * w_c * component_c      (0 when the row has no value)
    cri_score = sum_c points_c               in [0, 100]
    severity  = LOW / MEDIUM / HIGH / CRITICAL by the configured maxima

    anomaly               rarity(anomaly_score)
    historical_deviation  rarity(max_j max(hist_z_j, 0))
    peer_deviation        rarity(max_j rarity(max(peer_dev_j, 0)))   two-stage, see calibration.py
    user_context          1.0 privileged role, 0.0 otherwise
    asset_criticality     supplied column in [0, 1], else unavailable
    mitre_context         supplied column in [0, 1] (Chapter 10), else unavailable

A null for an available component on one row means "no contextual
evidence" and contributes 0; the other weights are not inflated for that
row. A component the deployment cannot provide at all is removed from the
formula and its reason is reported. Nothing is imputed.

Guarantees (Architecture §14, §36, §37; N10, N29, N31, N32)
    * The anomaly score is carried through unchanged in its own column. The
      CRI is a separate value; nothing overwrites or merges the two.
    * Only served scores: a row with role != "served" is refused (N32).
    * Only the calibrated model: every row's model_version must equal the
      calibration's, or CRIModelMismatchError. A different served model
      means a new calibration, never reuse (N29).
    * No score, no CRI: a missing or invalid anomaly score is an error,
      never a default.
    * Every row carries cri_version, cri_config_hash, cri_variant and
      calibration_id next to the anomaly score's model_version.

Never imports label code (N5).
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

import numpy as np
import pandas as pd

from . import CRI_VERSION
from .assets import UNAVAILABLE_REASON as ASSET_UNAVAILABLE
from .calibration import (
    ANOMALY_STAT,
    HISTORICAL_STAT,
    PEER_POS_PREFIX,
    PEER_STAT,
    CalibrationUnavailableError,
    LoadedCalibration,
    load_calibration,
)
from .config import COMPONENTS, SEVERITIES, CRIConfig

MITRE_UNAVAILABLE = "MITRE ATT&CK enrichment is Chapter 10; not wired yet"
SCORE_COLUMNS = ("user_id", "date", "model_name", "model_version", "registry_version", "anomaly_score")
RISK_COLUMNS = (
    "user_id", "date", "model_split", "model_name", "model_version", "registry_version", "anomaly_score",
    *(f"component_{c}" for c in COMPONENTS),
    *(f"points_{c}" for c in COMPONENTS),
    "cri_score", "severity", "missing_components", "anomaly_beyond_reference",
    "historical_top_feature", "peer_top_feature", "role",
    "cri_version", "cri_config_hash", "cri_variant", "calibration_id",
)


class CRIUnavailableError(RuntimeError):
    """The CRI cannot be computed (no calibration, bad configuration)."""


class CRIModelMismatchError(RuntimeError):
    """The scores come from a model the calibration was not fitted for (N29)."""


class CRIInputError(ValueError):
    """The scores or the context cannot be combined as given."""


def severity_of(cri: np.ndarray, config: CRIConfig) -> np.ndarray:
    idx = np.searchsorted(np.asarray(config.band_edges(), dtype="float64"), np.asarray(cri, dtype="float64"), side="right")
    return np.asarray(SEVERITIES, dtype=object)[idx]


def combine(components: Mapping[str, np.ndarray], available: set[str], config: CRIConfig) -> dict[str, Any]:
    """Pure recombination: components in [0, 1] (NaN = no value) -> points, cri, severity.

    This is the ablation hook (HCEA §9): variants reuse the same components
    and only this function runs again.
    """
    weights = config.effective_weights(available)
    n = len(next(iter(components.values())))
    points = {}
    for c in COMPONENTS:
        if c in weights:
            v = np.asarray(components[c], dtype="float64")
            points[c] = 100.0 * weights[c] * np.where(np.isnan(v), 0.0, v)
        else:
            points[c] = np.zeros(n)
    cri = np.zeros(n)
    for c in COMPONENTS:
        cri = cri + points[c]
    cri = np.clip(cri, 0.0, 100.0)
    return {"weights": weights, "points": points, "cri": cri, "severity": severity_of(cri, config)}


class CRIEngine:
    def __init__(self, config: CRIConfig, calibration: LoadedCalibration) -> None:
        self.config = config
        self.calibration = calibration

    @classmethod
    def load(cls, config: CRIConfig | None = None, *, pin_path=None, models_root=None) -> "CRIEngine":
        config = config or CRIConfig.from_env()
        try:
            cal = load_calibration(pin_path, models_root)
        except CalibrationUnavailableError as exc:
            raise CRIUnavailableError(str(exc)) from exc
        if cal.maps.decades != config.rarity_decades:
            raise CRIUnavailableError(
                f"calibration {cal.calibration_id} was fitted with rarity_decades={cal.maps.decades}, the "
                f"configuration says {config.rarity_decades}; refit instead of mixing scales")
        return cls(config, cal)

    # --- identity -----------------------------------------------------------
    @property
    def model(self) -> dict:
        return self.calibration.model

    def check_model(self, model_name: str, model_version: str, registry_version: str | None = None) -> None:
        m = self.model
        if model_name != m.get("model_name") or model_version != m.get("model_version"):
            raise CRIModelMismatchError(
                f"scores from {model_name} {model_version} cannot use calibration {self.calibration.calibration_id}, "
                f"fitted for {m.get('model_name')} {m.get('model_version')} ({m.get('registry_version')}); a different "
                "served model needs its own calibration (N29): run `python -m app.cri.calibrate`")
        if registry_version is not None and m.get("registry_version") and registry_version != m.get("registry_version"):
            raise CRIModelMismatchError(
                f"registry version {registry_version} differs from the calibrated {m.get('registry_version')}")

    def status(self) -> dict:
        return {"status": "loaded", "cri_version": CRI_VERSION, "config": self.config.to_dict(),
                "config_hash": self.config.config_hash, "config_overrides": dict(self.config.overrides),
                "calibration": self.calibration.describe()}

    # --- validation ---------------------------------------------------------
    def _check_scores(self, scores: pd.DataFrame) -> None:
        missing = [c for c in SCORE_COLUMNS if c not in scores.columns]
        if missing:
            raise CRIInputError(f"score frame lacks {missing}; scores must carry their lineage (§37)")
        if len(scores) == 0:
            raise CRIInputError("no scores to contextualise")
        if "role" in scores.columns:
            roles = set(scores["role"].astype(str).unique())
            if roles != {"served"}:
                raise CRIInputError(f"only served scores feed the CRI; got roles {sorted(roles)} (N32)")
        for col in ("model_name", "model_version", "registry_version"):
            if scores[col].nunique(dropna=False) != 1:
                raise CRIModelMismatchError(f"scores mix several values of {col}; one model per CRI run")
        self.check_model(str(scores["model_name"].iloc[0]), str(scores["model_version"].iloc[0]),
                         str(scores["registry_version"].iloc[0]))
        s = scores["anomaly_score"].to_numpy(dtype="float64", na_value=np.nan)
        if not np.isfinite(s).all():
            raise CRIInputError(f"{int((~np.isfinite(s)).sum())} missing or non-finite anomaly scores; "
                                "no score, no CRI (§36)")
        if ((s < 0) | (s > 1)).any():
            raise CRIInputError("anomaly scores outside [0, 1]")

    @staticmethod
    def _check_aligned(scores: pd.DataFrame, context: pd.DataFrame) -> None:
        if len(context) != len(scores):
            raise CRIInputError(f"context has {len(context)} rows, scores {len(scores)}")
        for key in ("user_id", "date"):
            a = scores[key].astype("string").str.strip().str.casefold().to_numpy()
            b = context[key].astype("string").str.strip().str.casefold().to_numpy()
            if not (a == b).all():
                raise CRIInputError(f"context is not aligned with the scores on {key!r}")

    # --- components ---------------------------------------------------------
    def components(self, scores: pd.DataFrame, context: pd.DataFrame) -> dict[str, Any]:
        """Every component in [0, 1] (NaN = no value), plus availability and diagnostics."""
        self._check_scores(scores)
        self._check_aligned(scores, context)
        maps = self.calibration.maps
        s = scores["anomaly_score"].to_numpy(dtype="float64")
        comp: dict[str, np.ndarray] = {"anomaly": maps.apply(ANOMALY_STAT, s)}
        comp["historical_deviation"] = maps.apply(HISTORICAL_STAT, context["historical_statistic"].to_numpy(dtype="float64", na_value=np.nan))
        peer_cols = maps.peer_columns()
        absent = [c for c in peer_cols if PEER_POS_PREFIX + c not in context.columns]
        if absent:
            raise CRIInputError(f"context lacks peer columns the calibration was fitted with: {absent[:5]}")
        positives = pd.DataFrame({c: context[PEER_POS_PREFIX + c].to_numpy(dtype="float64", na_value=np.nan) for c in peer_cols})
        peer_stat, peer_top = maps.peer_statistic(positives)
        comp["peer_deviation"] = maps.apply(PEER_STAT, peer_stat)
        comp["user_context"] = context["user_context_value"].to_numpy(dtype="float64", na_value=np.nan)

        unavailable: dict[str, str] = {}
        for name, reason in (("asset_criticality", ASSET_UNAVAILABLE), ("mitre_context", MITRE_UNAVAILABLE)):
            if name in context.columns:
                v = context[name].to_numpy(dtype="float64", na_value=np.nan)
                if np.nanmin(np.r_[v, 0.0]) < 0 or np.nanmax(np.r_[v, 0.0]) > 1:
                    raise CRIInputError(f"{name} must be in [0, 1]")
                comp[name] = v
            else:
                comp[name] = np.full(len(scores), np.nan)
                unavailable[name] = reason
        return {
            "components": comp,
            "available": {c for c in COMPONENTS if c not in unavailable},
            "unavailable": unavailable,
            "anomaly_beyond_reference": maps.beyond(ANOMALY_STAT, s),
            "peer_top_feature": peer_top,
        }

    # --- assembly -----------------------------------------------------------
    def assemble(self, scores: pd.DataFrame, context: pd.DataFrame, parts: dict, config: CRIConfig) -> pd.DataFrame:
        out = combine(parts["components"], parts["available"], config)
        n = len(scores)
        active = set(out["weights"])
        missing = np.full(n, "", dtype=object)
        for c in COMPONENTS:
            if c in active:
                nan = np.isnan(parts["components"][c])
                missing = np.where(nan, np.where(missing == "", c, missing + "," + c), missing)
        frame = {
            "user_id": scores["user_id"].astype("string").to_numpy(),
            "date": scores["date"].astype("string").to_numpy(),
            "model_split": (scores["model_split"].astype("string").to_numpy() if "model_split" in scores.columns
                            else np.full(n, None, dtype=object)),
            "model_name": scores["model_name"].astype("string").to_numpy(),
            "model_version": scores["model_version"].astype("string").to_numpy(),
            "registry_version": scores["registry_version"].astype("string").to_numpy(),
            "anomaly_score": scores["anomaly_score"].to_numpy(dtype="float64"),
        }
        for c in COMPONENTS:
            frame[f"component_{c}"] = parts["components"][c] if c in parts["available"] else np.full(n, np.nan)
        for c in COMPONENTS:
            frame[f"points_{c}"] = out["points"][c]
        frame.update({
            "cri_score": out["cri"],
            "severity": out["severity"],
            "missing_components": missing,
            "anomaly_beyond_reference": parts["anomaly_beyond_reference"],
            "historical_top_feature": context["historical_top_feature"].to_numpy(dtype=object),
            "peer_top_feature": parts["peer_top_feature"],
            "role": context["role"].to_numpy(dtype=object),
            "cri_version": np.full(n, CRI_VERSION, dtype=object),
            "cri_config_hash": np.full(n, config.config_hash, dtype=object),
            "cri_variant": np.full(n, config.variant_name, dtype=object),
            "calibration_id": np.full(n, self.calibration.calibration_id, dtype=object),
        })
        return pd.DataFrame(frame, columns=list(RISK_COLUMNS))

    def compute(self, scores: pd.DataFrame, context: pd.DataFrame) -> pd.DataFrame:
        parts = self.components(scores, context)
        return self.assemble(scores, context, parts, self.config)

    def compute_variants(self, scores: pd.DataFrame, context: pd.DataFrame,
                         variants: Iterable[str]) -> dict[str, pd.DataFrame]:
        parts = self.components(scores, context)
        return {name: self.assemble(scores, context, parts, self.config.variant(name)) for name in variants}

    def effective_weights(self, available: set[str] | None = None) -> dict[str, float]:
        available = available if available is not None else {c for c in COMPONENTS if c not in ("asset_criticality", "mitre_context")}
        return self.config.effective_weights(available)

    # --- one user-day (Chapter 13 will call this) ---------------------------
    def compute_event(self, score: Mapping[str, Any], feature_vector: Mapping[str, Any], role: str | None,
                      *, asset_criticality: float | None = None, mitre_context: float | None = None) -> dict:
        """One scored user-day -> one risk row, as a dict.

        ``score`` is a ScoreResult.to_dict() (or the same keys); the feature
        vector carries the raw Chapter 5 hist_z_* / peer_dev_* values.
        """
        from .context import build_context

        if score.get("role", "served") != "served":
            raise CRIInputError("only served scores feed the CRI (N32)")
        keys = pd.DataFrame({"user_id": [score.get("user_id") or ""], "date": [score.get("date") or ""]})
        scores = keys.assign(model_name=score["model_name"], model_version=score["model_version"],
                             registry_version=score["registry_version"], anomaly_score=float(score["anomaly_score"]))
        feats = pd.DataFrame([{k: (np.nan if v is None else v) for k, v in feature_vector.items()
                               if str(k).startswith(("hist_z_", "peer_dev_"))}])
        for c in self.calibration.maps.peer_columns():
            if f"peer_dev_{c}" not in feats.columns:
                raise CRIInputError(f"feature vector lacks peer_dev_{c}")
        roles = None if role is None else pd.DataFrame({
            "user_id": keys["user_id"].astype("string").str.casefold(),
            "month": keys["date"].astype("string").str.slice(0, 7), "role": [role]})
        ctx = build_context(keys, feats.astype("float64"), roles, self.config.privileged_roles)
        if asset_criticality is not None:
            ctx["asset_criticality"] = float(asset_criticality)
        if mitre_context is not None:
            ctx["mitre_context"] = float(mitre_context)
        return self.compute(scores, ctx).iloc[0].to_dict()
