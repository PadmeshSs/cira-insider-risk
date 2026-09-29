"""The MITRE enrichment as the API holds it: loaded once at startup.

``MitreRuntime.load()`` never raises. It loads the committed technique table
and the pinned reference (both sha256-checked) and validates the rules. If
anything is missing or altered, the runtime is unavailable with the reason
and ``enricher()`` raises; a risk score is then computed without MITRE
context, with the reason recorded, never with an invented one (§36, N35).

It does not depend on the served model (N42), so a rollback through
``CIRA_SERVED_MODEL`` leaves it loaded. Label-free (N5).
"""
from __future__ import annotations

from .enrich import MitreEnricher, MitreUnavailableError


class MitreRuntime:
    def __init__(self, enricher: MitreEnricher | None, reason: str | None = None) -> None:
        self._enricher = enricher
        self.reason = None if enricher is not None else (reason or "MITRE enrichment not loaded")

    @classmethod
    def load(cls, *, table_path=None, pin_path=None, models_root=None) -> "MitreRuntime":
        try:
            return cls(MitreEnricher.load(table_path=table_path, pin_path=pin_path, models_root=models_root))
        except MitreUnavailableError as exc:
            return cls(None, str(exc))

    @property
    def available(self) -> bool:
        return self._enricher is not None

    def enricher(self) -> MitreEnricher:
        if self._enricher is None:
            raise MitreUnavailableError(self.reason)
        return self._enricher

    def status(self) -> dict:
        if self._enricher is None:
            return {"status": "unavailable", "reason": self.reason}
        return self._enricher.status()
