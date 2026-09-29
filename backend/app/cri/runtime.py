"""The CRI as the API holds it: loaded once at startup, next to the scorer.

``CRIRuntime.load(scoring_service)`` never raises. It loads the pinned
calibration and checks that it was fitted for the model the scoring service
is serving (N29). If there is no calibration, the calibration was tampered
with, or the served model changed (for example a rollback through
``CIRA_SERVED_MODEL``), the runtime is unavailable with the reason, and
``engine()`` raises instead of producing a risk score (Architecture §36).
Label-free (N5).
"""
from __future__ import annotations

from .config import CRIConfig, CRIConfigError
from .engine import CRIEngine, CRIModelMismatchError, CRIUnavailableError


class CRIRuntime:
    def __init__(self, engine: CRIEngine | None, reason: str | None = None) -> None:
        self._engine = engine
        self.reason = None if engine is not None else (reason or "CRI not loaded")

    @classmethod
    def load(cls, scoring_service=None, *, config: CRIConfig | None = None, pin_path=None, models_root=None) -> "CRIRuntime":
        try:
            engine = CRIEngine.load(config or CRIConfig.from_env(), pin_path=pin_path, models_root=models_root)
        except (CRIUnavailableError, CRIConfigError) as exc:
            return cls(None, str(exc))
        served = getattr(scoring_service, "served", None)
        if served is None:
            return cls(None, "no anomaly model is served, so there is no score to contextualise")
        try:
            engine.check_model(served.model_name, served.model_version, served.registry_version)
        except CRIModelMismatchError as exc:
            return cls(None, str(exc))
        return cls(engine)

    @property
    def available(self) -> bool:
        return self._engine is not None

    def engine(self) -> CRIEngine:
        if self._engine is None:
            raise CRIUnavailableError(self.reason)
        return self._engine

    def status(self) -> dict:
        if self._engine is None:
            return {"status": "unavailable", "reason": self.reason}
        return self._engine.status()
