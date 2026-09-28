"""AnomalyScoringService: the one object downstream code scores through.

Bible Ch8 steps 1-4, HCEA §8, Architecture §14/§36/§37.

    service = AnomalyScoringService.load(resolve_serving_config())
    service.score_frame(frame)            # batch, long format, one row per (row, model)
    service.score_event(feature_vector)   # one user-day -> ScoreResult (served model only)
    service.status()                      # for /health and the batch runlog

Guarantees
    * Load once. ``load`` never raises: if the served model cannot be
      loaded the service is created unavailable, keeps the reason, and every
      scoring call raises ScoringUnavailableError. There is no fallback
      model and no default score.
    * The served model and the shadow model are separate. A shadow that
      fails to load or to score never blocks, delays or changes a served
      score; its failure is counted and reported. Shadow rows exist for
      comparison (Chapter 16) and never feed CRI or alerts (N32).
    * Every score row carries model_name, model_version and
      registry_version (§37). The anomaly score is not the CRI risk score;
      nothing here combines scores or adds context (§14).
    * No ensemble. Averaging TabNet and XGBoost was never evaluated, so it
      is not offered (C8-4).

Never imports label code (N5).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Mapping

import numpy as np
import pandas as pd

from .adapters import load_adapter
from .contracts import (
    SCORE_FRAME_COLUMNS,
    ScoreResult,
    ScoringFailedError,
    ScoringInputError,
    ScoringUnavailableError,
    check_frame,
    check_scores,
    vector_to_frame,
)
from .serving_config import ServingConfig

log = logging.getLogger("cira.scoring")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AnomalyScoringService:
    def __init__(self, served=None, shadows=(), *, config: ServingConfig | None = None,
                 unavailable_reason: str | None = None, shadow_load_errors: dict[str, str] | None = None) -> None:
        self.served = served
        self.shadows = list(shadows)
        self.config = config
        self.unavailable_reason = None if served is not None else (unavailable_reason or "no model loaded")
        self.shadow_load_errors = dict(shadow_load_errors or {})
        self.shadow_score_failures = 0
        self.loaded_at = _now() if served is not None else None

    # --- construction ---------------------------------------------------
    @classmethod
    def load(cls, config: ServingConfig, *, allow_unreportable: bool = False) -> "AnomalyScoringService":
        if config.served is None:
            return cls(None, config=config, unavailable_reason=config.problem or "no served model configured")
        try:
            served = load_adapter(config.served, config.registry_root, allow_unreportable=allow_unreportable)
        except ScoringUnavailableError as exc:
            log.error("served model %s unavailable: %s", config.served, exc)
            return cls(None, config=config, unavailable_reason=str(exc))
        shadows, errors = [], {}
        for pin in config.shadows:
            if pin == config.served:
                continue
            try:
                shadows.append(load_adapter(pin, config.registry_root, allow_unreportable=allow_unreportable))
            except ScoringUnavailableError as exc:     # a shadow never blocks serving
                log.warning("shadow model %s unavailable: %s", pin, exc)
                errors[str(pin)] = str(exc)
        return cls(served, shadows, config=config, shadow_load_errors=errors)

    # --- state ------------------------------------------------------------
    @property
    def available(self) -> bool:
        return self.served is not None

    def require(self):
        if self.served is None:
            raise ScoringUnavailableError(self.unavailable_reason or "no model loaded")
        return self.served

    @property
    def input_columns(self) -> list[str]:
        return list(self.require().input_columns)

    def status(self) -> dict:
        cfg = self.config
        out: dict[str, Any] = {
            "status": "loaded" if self.available else "unavailable",
            "source": None if cfg is None else cfg.source,
            "decision_file": None if cfg is None or cfg.decision_path is None else str(cfg.decision_path),
            "decision_rule": None if cfg is None else cfg.decision_rule,
            "served": self.served.describe() if self.served is not None else None,
            "shadow": [s.describe() for s in self.shadows],
            "shadow_load_errors": self.shadow_load_errors,
            "shadow_score_failures": self.shadow_score_failures,
            "loaded_at": self.loaded_at,
            "score_convention": "anomaly_score = sigmoid(margin) in [0, 1], higher = more anomalous; "
                                "a ranking score, not a probability (N20)",
        }
        if not self.available:
            out["reason"] = self.unavailable_reason
        return out

    # --- scoring ----------------------------------------------------------
    @staticmethod
    def _run(model, frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        check_frame(frame, model.input_columns)
        try:
            raw = np.asarray(model.raw_score(frame), dtype="float64")
            score = np.asarray(model.score_from_raw(raw), dtype="float64")
        except (ScoringInputError, ScoringUnavailableError):
            raise
        except Exception as exc:
            raise ScoringFailedError(f"{model.model_name} {model.registry_version} failed to score {len(frame)} rows: {exc}") from exc
        check_scores(raw, score, len(frame), f"{model.model_name} {model.registry_version}")
        return raw, score

    @staticmethod
    def _rows(frame: pd.DataFrame, model, role: str, raw: np.ndarray, score: np.ndarray) -> pd.DataFrame:
        n = len(frame)
        return pd.DataFrame({
            "user_id": frame["user_id"].astype("string").to_numpy(),
            "date": frame["date"].astype("string").to_numpy(),
            "role": np.full(n, role, dtype=object),
            "model_name": np.full(n, model.model_name, dtype=object),
            "model_version": np.full(n, model.model_version, dtype=object),
            "registry_version": np.full(n, model.registry_version, dtype=object),
            "raw_score": raw,
            "anomaly_score": score,
        }, columns=list(SCORE_FRAME_COLUMNS))

    def score_frame(self, frame: pd.DataFrame, *, include_shadow: bool = False) -> pd.DataFrame:
        """Score user-days. Served rows first, then shadow rows (long format)."""
        served = self.require()
        for key in ("user_id", "date"):
            if key not in frame.columns:
                raise ScoringInputError(f"frame needs a {key!r} column so every score can be traced to its user-day")
        raw, score = self._run(served, frame)
        parts = [self._rows(frame, served, "served", raw, score)]
        if include_shadow:
            for shadow in self.shadows:
                try:
                    s_raw, s_score = self._run(shadow, frame)
                except Exception as exc:      # a shadow never blocks serving
                    self.shadow_score_failures += 1
                    log.warning("shadow %s failed on %d rows: %s", shadow.pin, len(frame), exc)
                    continue
                parts.append(self._rows(frame, shadow, "shadow", s_raw, s_score))
        return pd.concat(parts, ignore_index=True) if len(parts) > 1 else parts[0]

    def score_event(self, feature_vector: Mapping[str, Any], *, user_id: str | None = None, date: str | None = None) -> ScoreResult:
        """Bible Ch8: ``score_event(feature_vector) -> anomaly_score`` with its model version."""
        served = self.require()
        frame = vector_to_frame(feature_vector, served.input_columns)
        raw, score = self._run(served, frame)
        return ScoreResult(
            anomaly_score=float(score[0]), raw_score=float(raw[0]), model_name=served.model_name,
            model_version=served.model_version, registry_version=served.registry_version, role="served",
            scored_at=_now(), user_id=user_id, date=date,
        )
