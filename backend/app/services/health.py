"""/health (Bible Ch13 step 4): the real state of every component, and which route groups can answer.

The top-level ``status`` keeps its Chapter 8 meaning (C8-7): ``healthy`` when
the served anomaly model is loaded, ``degraded`` otherwise. Each component
reports its own block, as before. Chapter 13 adds:

    auth    whether tokens can be issued (SECRET_KEY usable), never the secret
    routes  per API group, whether it can answer now and, if not, why

so an operator, or the dashboard's login screen, can see that the API is up
but, for example, the alert routes have no loaded run (C13-6).
"""
from __future__ import annotations

from app.alerts.runtime import database_status
from app.core.security import auth_problem

from .runs import Runtimes

UNSTARTED = {"status": "unavailable", "reason": "not started"}


def _block(obj, name: str) -> dict:
    return obj.status() if obj is not None else {"status": "unavailable", "reason": f"{name} not started"}


def _ok(block: dict) -> bool:
    return block.get("status") in ("loaded", "reachable")


async def served_run_loaded(engine, model_version: str, timeout: float = 2.0) -> str | None:
    """Newest loaded alert run built for the served model, or None. Never raises."""
    import asyncio

    import sqlalchemy as sa

    if engine is None:
        from app.database.session import engine as default_engine

        engine = default_engine

    async def probe():
        async with engine.connect() as conn:
            return (await conn.execute(sa.text(
                "SELECT a.target_id FROM audit_logs a WHERE a.action = 'alert_run_loaded' AND EXISTS "
                "(SELECT 1 FROM alerts x WHERE x.alert_run_id = a.target_id AND x.model_version = :mv) "
                "ORDER BY a.id DESC LIMIT 1"), {"mv": model_version})).scalar()

    try:
        return await asyncio.wait_for(probe(), timeout)
    except Exception:
        return None


async def health(runtimes: Runtimes, *, engine=None, secret: str | None = None) -> dict:
    model = _block(runtimes.scoring, "scoring service")
    cri, mitre = _block(runtimes.cri, "CRI"), _block(runtimes.mitre, "MITRE")
    explain, alerts = _block(runtimes.explain, "explainability"), _block(runtimes.alerts, "alerts")
    database = await database_status(engine)
    problem = auth_problem(secret)
    auth = {"status": "configured" if problem is None else "unavailable", "reason": problem,
            "scheme": "OAuth2 password flow, HS256 bearer token"}
    db_ok, model_ok = _ok(database), _ok(model)
    served = (model.get("served") or {}).get("model_version")
    run = await served_run_loaded(engine, served) if db_ok and served else None

    def route(ok: bool, why: str | None) -> dict:
        return {"ready": ok, "reason": None if ok else why}

    need_db = None if db_ok else f"database {database.get('status')}: {database.get('reason')}"
    need_model = None if model_ok else f"anomaly model unavailable: {model.get('reason')}"
    need_run = None if run else "no loaded alert run was built for the served model (python -m app.alerts.load)"
    read_why = need_db or need_model or need_run
    return {
        "status": "healthy" if model_ok else "degraded",
        "service": "cira-backend",
        "anomaly_model": model, "cri": cri, "mitre": mitre, "explainability": explain, "alerts": alerts,
        "database": database, "auth": auth,
        "routes": {
            "auth": route(db_ok and problem is None, need_db or problem),
            "alerts_risk_investigations": {**route(read_why is None, read_why), "alert_run_id": run},
            "anomaly_score": route(model_ok, need_model),
            "risk_score": route(model_ok and _ok(cri), need_model or (None if _ok(cri) else f"CRI: {cri.get('reason')}")),
            "mitre_techniques": route(_ok(mitre), None if _ok(mitre) else f"MITRE: {mitre.get('reason')}"),
        },
    }
