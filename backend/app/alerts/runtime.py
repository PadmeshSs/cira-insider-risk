"""Alerts as the API holds them, and the database probe (/health).

``AlertRuntime.load(scoring_service)`` never raises. It finds the newest
alert run for the served model's profile (``CIRA_PROFILE`` is the execution
budget for batch jobs and is only the fallback here) and checks that it was
built for the model served now (N28, N30). If there is no run, or it belongs to another
model (for example after a ``CIRA_SERVED_MODEL`` rollback), the runtime is
unavailable with the reason. Chapter 13 serves alerts from PostgreSQL; this
block says which run and policy they come from.

``database_status(engine)`` probes PostgreSQL with a short timeout and
reports the Alembic revision and how many alert runs are loaded. When the
database is down it says so instead of hanging or pretending (§36).

Label-free (N5).
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from . import ALERTS_VERSION
from .policy import POLICY_VERSION, AlertPolicy
from .sources import AlertSourceError, alert_run_dir, load_records, read_meta


class AlertRuntime:
    def __init__(self, meta: dict | None = None, reason: str | None = None, loads: list | None = None) -> None:
        self.meta = meta
        self.loads = loads or []
        self.reason = None if meta is not None else (reason or "no alert run loaded")

    @classmethod
    def load(cls, scoring_service=None, *, processed_dir: str | Path | None = None,
             profile: str | None = None) -> "AlertRuntime":
        from app.core.config import settings

        processed = Path(processed_dir or settings.cert_processed_dir)
        served = getattr(scoring_service, "served", None)
        if served is None:
            return cls(None, "no anomaly model is served, so no alert run can be current")
        # The alert run must match the served model, so it follows the
        # profile the served model was trained on, not the batch budget.
        served_profile = (getattr(served, "entry", None) or {}).get("profile")
        profile = profile or served_profile or settings.cira_profile
        try:
            run_dir = alert_run_dir(processed, None, profile)
            meta = read_meta(run_dir)
        except (AlertSourceError, OSError, ValueError) as exc:
            return cls(None, f"{exc}; run `python -m app.alerts.batch --profile {profile}`")
        m = meta.get("served") or {}
        if (m.get("model_name"), m.get("registry_version")) != (served.model_name, served.registry_version):
            return cls(None, f"newest alert run {meta.get('alert_run_id')} was built for {m.get('model_name')}:"
                             f"{m.get('registry_version')}, the served model is {served.model_name}:"
                             f"{served.registry_version}; build a new alert run (N28, N30)")
        return cls(meta, loads=load_records(run_dir))

    @property
    def available(self) -> bool:
        return self.meta is not None

    def status(self) -> dict:
        if self.meta is None:
            return {"status": "unavailable", "reason": self.reason, "policy_version": POLICY_VERSION,
                    "default_policy_hash": AlertPolicy().policy_hash}
        m, s = self.meta, self.meta.get("summary") or {}
        return {"status": "loaded", "alerts_version": ALERTS_VERSION, "alert_run_id": m.get("alert_run_id"),
                "policy": m.get("policy"), "policy_hash": m.get("policy_hash"),
                "policy_overrides": m.get("policy_overrides"), "queue": m.get("queue"),
                "open_alerts": s.get("open_alerts"), "suppressed_alerts": s.get("suppressed_alerts"),
                "explanation_status": s.get("explanation_status"),
                "explain_run_id": (m.get("explain_run") or {}).get("explain_run_id"),
                "cri_run_id": (m.get("risk_run") or {}).get("cri_run_id"),
                "loaded_into_database": [x.get("loaded_at") for x in self.loads],
                "shadow": "never feeds an alert (N32)"}


async def database_status(engine=None, timeout: float = 2.0) -> dict:
    """Reachability, Alembic revision and loaded alert runs. Never raises."""
    import sqlalchemy as sa

    if engine is None:
        from app.database.session import engine as default_engine

        engine = default_engine

    async def probe():
        async with engine.connect() as conn:
            rev = (await conn.execute(sa.text("SELECT version_num FROM alembic_version"))).scalar()
            try:
                runs = (await conn.execute(sa.text(
                    "SELECT count(*) FROM audit_logs WHERE action = 'alert_run_loaded'"))).scalar()
            except Exception:
                runs = None
            return rev, runs

    try:
        rev, runs = await asyncio.wait_for(probe(), timeout)
    except Exception as exc:
        return {"status": "unavailable", "reason": f"{type(exc).__name__}: {str(exc).splitlines()[0][:200] if str(exc) else ''}",
                "effect": "no alert can be stored or read from PostgreSQL; the Parquet alert runs are unaffected (§36)"}
    return {"status": "reachable", "alembic_revision": rev, "alert_runs_loaded": runs}
