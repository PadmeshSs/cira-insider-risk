"""Served and shadow models (N21, N28, N32) and the model versions behind persisted scores."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import ModelVersion

from .runs import Runtimes

SHADOW_NOTE = "comparison only (Chapter 16); never feeds the CRI, alerts or explanations (N32)"


async def models(session: AsyncSession, runtimes: Runtimes) -> dict:
    st = runtimes.scoring.status() if runtimes.scoring is not None else {"status": "unavailable",
                                                                          "reason": "scoring service not started"}
    rows = (await session.execute(select(ModelVersion).order_by(ModelVersion.id))).scalars().all()
    return {"status": st.get("status"), "served": st.get("served"), "serving_source": st.get("source"),
            "decision_rule": st.get("decision_rule"), "reason": st.get("reason"),
            "shadow": [{**s, "role": "shadow", "use": SHADOW_NOTE} for s in st.get("shadow") or []],
            "score_convention": st.get("score_convention"),
            "in_database": [{"id": m.id, "model_name": m.model_name, "registry_version": m.registry_version,
                             "model_version": m.model_version, "run_id": m.run_id, "profile": m.profile,
                             "trained_at": m.trained_at, "split_mode": m.split_mode,
                             "n_input_columns": m.n_input_columns, "files": m.files, "created_at": m.created_at}
                            for m in rows]}
