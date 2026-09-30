"""Explanations as the API holds them: built once at startup, next to the scorer.

``ExplainRuntime.load(scoring_service)`` never raises. It builds the explainer
for the model the scoring service is serving (N30): TreeSHAP for XGBoost,
masks for TabNet. If no model is served, or the explainer cannot be built, the
runtime is unavailable with the reason and ``/health`` shows it; an alert can
still exist with its score and context, and its explanation is deferred
(Architecture §36).

``explain_event`` explains one user-day on demand (Chapter 13 will route to
it; Chapter 12 calls it for alert rows). KernelSHAP is not run here: it needs
the training background and is the batch path's job (D-5). Until Celery
exists (Chapter 17) a missing corroboration is filled by re-running the batch.

Label-free (N5). No shadow model is ever explained here (N32).
"""
from __future__ import annotations

from typing import Any, Mapping

from app.scoring.contracts import vector_to_frame

from . import EXPLAIN_VERSION
from .attributions import ExplanationFailedError, ExplanationUnavailableError, explainer_for, row_summary, top_k_long
from .features import undescribed
from .reason_builder import build_explanation, jsonable, model_evidence


class ExplainRuntime:
    def __init__(self, explainer=None, reason: str | None = None, served=None) -> None:
        self._explainer = explainer
        self._served = served
        self.reason = None if explainer is not None else (reason or "explanations not loaded")

    @classmethod
    def load(cls, scoring_service=None) -> "ExplainRuntime":
        served = getattr(scoring_service, "served", None)
        if served is None:
            return cls(None, "no anomaly model is served, so there is no score to explain")
        try:
            explainer = explainer_for(served, role="served")
        except ExplanationUnavailableError as exc:
            return cls(None, str(exc))
        missing = undescribed(explainer.features)
        if missing:
            return cls(None, f"no plain-language description for model input(s) {missing[:5]}")
        return cls(explainer, served=served)

    @property
    def available(self) -> bool:
        return self._explainer is not None

    def explainer(self):
        if self._explainer is None:
            raise ExplanationUnavailableError(self.reason)
        return self._explainer

    def status(self) -> dict:
        if self._explainer is None:
            return {"status": "unavailable", "reason": self.reason}
        return {"status": "loaded", "explain_version": EXPLAIN_VERSION, **self._explainer.describe(),
                "kernelshap": "batch only, bounded rows (HCEA D-5); python -m app.explainability.batch",
                "shadow": "never explained for analysts (N32)"}

    def explain_event(self, feature_vector: Mapping[str, Any], *, user_id: str, date: str,
                      risk: Mapping | None = None, mitre: Mapping | None = None,
                      unavailable_components: Mapping[str, str] | None = None, top_k: int = 10) -> dict:
        """One user-day -> the full analyst explanation. Degrades, never invents (§36)."""
        model, reason = None, None
        try:
            ex = self.explainer()
            frame = vector_to_frame(feature_vector, ex.features if ex.method == "treeshap"
                                    else ex.scorer.preprocessor.input_columns)
            frame.insert(0, "date", str(date))
            frame.insert(0, "user_id", str(user_id))
            attr = ex.explain(frame)
            long = top_k_long(attr, frame, top_k)
            score = float(self._served.score_from_raw(attr.raw_score)[0])
            model = model_evidence(row_summary(attr).iloc[0].to_dict(), long.to_dict("records"), method=ex.method,
                                   model_name=self._served.model_name, model_version=self._served.model_version,
                                   registry_version=self._served.registry_version, anomaly_score=score)
        except (ExplanationUnavailableError, ExplanationFailedError) as exc:
            reason = str(exc)
        detail = {k: v for k, v in feature_vector.items() if str(k).startswith(("hist_z_", "peer_dev_"))}
        expl = build_explanation(user_id, date, model=model, risk=risk, mitre=mitre, features_row=detail,
                                 model_unavailable_reason=reason, unavailable_components=unavailable_components)
        return jsonable(expl)
