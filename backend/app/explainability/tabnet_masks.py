"""TabNet's per-row attention masks (Bible Ch11 step 1, HCEA §11.1, N22, N30).

``clf.explain(X)`` returns, per row, TabNet's aggregate mask: how much of
each decision step's attention went to each input column, weighted by the
step's contribution. Here it is

* computed in chunks of 50,000 rows (HCEA §11.1), never as a dense
  [N x F] matrix for the whole profile;
* normalised so each row sums to 1 ("share of the model's attention");
* summed per base feature over the value column and its ``isnull__``
  indicator (``app.tabnet.dataset.feature_groups``, N22). ``grouped_features``
  was not used in training (C7-5), so grouping happens here, after the fact.

What a mask is not
    A mask says where TabNet looked, not whether that raised or lowered the
    score. Mask attributions are unsigned and the reason builder words them
    as attention, never as "raised the score".

When this is used
    * TabNet served (a ``CIRA_SERVED_MODEL`` rollback): masks are the
      model-side explanation, KernelSHAP corroborates (the Bible's plan).
    * XGBoost served (C8-1, now): only the offline readout
      (``evaluate.py``) computes shadow masks, as a clearly labelled second
      model's view. They never reach an analyst-facing explanation (N30, N32).

Label-free (N5).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from app.scoring.contracts import check_frame
from app.tabnet.dataset import feature_groups

from .attributions import Attributions, ExplanationFailedError, ExplanationUnavailableError

CHUNK_ROWS = 50_000


class TabNetMaskExplainer:
    method = "tabnet_mask"

    def __init__(self, adapter, *, role: str = "served", chunk_rows: int = CHUNK_ROWS) -> None:
        scorer = getattr(adapter, "scorer", None)
        if scorer is None or getattr(scorer, "clf", None) is None:
            raise ExplanationUnavailableError(f"{getattr(adapter, 'model_name', '?')} adapter holds no TabNet model")
        self.adapter = adapter
        self.scorer = scorer
        self.role = role
        self.chunk_rows = max(1, int(chunk_rows))
        self.output_columns = list(scorer.preprocessor.output_columns)
        self.groups = feature_groups(self.output_columns)
        self.features = list(self.groups)

    @property
    def model(self) -> dict:
        a = self.adapter
        return {"model_name": a.model_name, "model_version": a.model_version,
                "registry_version": a.registry_version, "role": self.role}

    def describe(self) -> dict:
        return {"method": self.method, **self.model, "engine": "pytorch-tabnet clf.explain (aggregate mask)",
                "normalisation": "per row, shares sum to 1", "grouping": "value + isnull__ indicator (N22)",
                "n_model_inputs": len(self.output_columns), "n_base_features": len(self.features),
                "chunk_rows": self.chunk_rows}

    def masks(self, x: np.ndarray) -> np.ndarray:
        """Row-normalised aggregate mask over the model's input columns, chunked."""
        clf = self.scorer.clf
        out = []
        for start in range(0, len(x), self.chunk_rows):
            m, _ = clf.explain(np.ascontiguousarray(x[start:start + self.chunk_rows]))
            m = np.asarray(m, dtype="float64")
            s = m.sum(axis=1, keepdims=True)
            out.append(np.divide(m, s, out=np.zeros_like(m), where=s > 0))
        return np.vstack(out) if out else np.zeros((0, len(self.output_columns)))

    def explain(self, frame: pd.DataFrame) -> Attributions:
        check_frame(frame, self.scorer.preprocessor.input_columns)
        x = self.scorer.preprocessor.transform(frame)
        m = self.masks(x)
        grouped = np.column_stack([m[:, idx].sum(axis=1) for idx in self.groups.values()])
        if not np.isfinite(grouped).all():
            raise ExplanationFailedError("TabNet masks contain non-finite values")
        raw = np.asarray(self.adapter.raw_score(frame), dtype="float64")
        return Attributions(keys=frame[["user_id", "date"]].reset_index(drop=True), features=list(self.features),
                            values=grouped, method=self.method, raw_score=raw, model=self.model,
                            info=self.describe())
