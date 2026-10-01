"""Which loaded alert run the API serves, and the runtimes it serves with.

The API reads decisions from PostgreSQL (Architecture §20). An alert run is
in the database if and only if its ``alert_run_loaded`` audit row exists
(N58), so that row, not a row count, is what this module checks. The run
served is the newest loaded run built for the model served now (N28, N30);
a run for another model (for example after a ``CIRA_SERVED_MODEL`` rollback)
is refused with the reason, not shown as current.

Every read of risk, anomaly, feature, ATT&CK or explanation rows is scoped
to the run ids this module returns (batch, CRI, enrichment and explain
run), so two runs over overlapping user-days are never mixed (N50).

This works without the Parquet tree: ``AlertRuntime`` (Chapter 12) needs
``CERT_PROCESSED_DIR`` and is reported by /health, but the routes only need
the database and the served model.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.alerts.persistence import AUDIT_ACTION
from app.alerts.policy import POLICY_VERSION, AlertPolicy
from app.database.models import Alert, AuditLog, Configuration

from .errors import Conflict, NotFound, Unavailable

DEMO_RULE_PREFIX = "c12-demo-sample-"


@dataclass
class Runtimes:
    """What the lifespan handler loaded once at startup (HCEA §8)."""

    scoring: Any = None
    cri: Any = None
    mitre: Any = None
    explain: Any = None
    alerts: Any = None

    @property
    def served(self):
        return getattr(self.scoring, "served", None)

    def require_served(self):
        served = self.served
        if served is None:
            reason = getattr(self.scoring, "unavailable_reason", None) or "scoring service not started"
            raise Unavailable(f"no anomaly model is served: {reason}", component="anomaly_model")
        return served


@dataclass(frozen=True)
class CurrentRun:
    alert_run_id: str
    loaded_at: datetime | None
    loaded_by: str | None
    policy: dict
    policy_version: str
    policy_hash: str
    ordering: str
    model_name: str
    model_version: str
    registry_version: str
    model_version_id: int
    batch_run_id: str
    cri_run_id: str
    explain_run_id: str
    mitre_run_id: str | None
    demo_sample: dict | None = field(default=None)

    @property
    def alert_policy(self) -> AlertPolicy:
        return AlertPolicy.from_dict(self.policy)

    def lineage(self) -> dict:
        return {"alert_run_id": self.alert_run_id, "policy_version": self.policy_version,
                "policy_hash": self.policy_hash, "model_version": self.model_version,
                "registry_version": self.registry_version, "batch_run_id": self.batch_run_id,
                "cri_run_id": self.cri_run_id, "explain_run_id": self.explain_run_id,
                "mitre_run_id": self.mitre_run_id}


async def loaded_runs(session: AsyncSession) -> list[AuditLog]:
    """Audit rows of loaded alert runs, newest first."""
    rows = (await session.execute(select(AuditLog).where(AuditLog.action == AUDIT_ACTION)
                                  .order_by(AuditLog.id.desc()))).scalars().all()
    return list(rows)


async def _first_alert(session: AsyncSession, run_id: str) -> Alert | None:
    return (await session.execute(select(Alert).where(Alert.alert_run_id == run_id)
                                  .order_by(Alert.id).limit(1))).scalars().first()


async def _config(session: AsyncSession, key: str) -> dict | None:
    row = (await session.execute(select(Configuration).where(Configuration.key == key))).scalars().first()
    return None if row is None else json.loads(row.value)


async def _demo(session: AsyncSession, run_id: str) -> dict | None:
    rows = (await session.execute(select(Configuration).where(Configuration.key.like(f"{DEMO_RULE_PREFIX}%:{run_id}"))
                                  )).scalars().all()
    return json.loads(rows[0].value) if rows else None


async def current_run(session: AsyncSession, runtimes: Runtimes, alert_run_id: str | None = None) -> CurrentRun:
    """The loaded alert run the routes read. Raises, never guesses."""
    served = runtimes.require_served()
    audits = await loaded_runs(session)
    if alert_run_id is not None:
        audits = [a for a in audits if a.target_id == alert_run_id]
        if not audits:
            raise NotFound(f"alert run {alert_run_id} is not loaded in this database (no {AUDIT_ACTION} audit row, N58)",
                           component="alerts")
    if not audits:
        raise Unavailable("no alert run is loaded in the database; run `python -m app.alerts.load --profile full` "
                          "(Chapter 12)", component="alerts")
    skipped = []
    for audit in audits:
        alert = await _first_alert(session, audit.target_id)
        if alert is None:
            skipped.append(f"{audit.target_id} has no alert rows")
            continue
        if alert.model_version != served.model_version:
            skipped.append(f"{audit.target_id} was built for {alert.model_version}")
            continue
        policy = await _config(session, f"{alert.policy_version}:{alert.policy_hash}")
        if policy is None:
            raise Unavailable(f"alert run {audit.target_id} names policy {alert.policy_version}:{alert.policy_hash}, "
                              "which is not recorded in configurations", component="alerts")
        if policy.get("version") != POLICY_VERSION:
            raise Unavailable(f"alert run {audit.target_id} uses policy {policy.get('version')}, this API knows "
                              f"{POLICY_VERSION}", component="alerts")
        return CurrentRun(
            alert_run_id=audit.target_id, loaded_at=audit.created_at, loaded_by=audit.actor, policy=policy,
            policy_version=alert.policy_version, policy_hash=alert.policy_hash, ordering=alert.ordering,
            model_name=served.model_name, model_version=alert.model_version, registry_version=served.registry_version,
            model_version_id=alert.model_version_id, batch_run_id=alert.batch_run_id, cri_run_id=alert.cri_run_id,
            explain_run_id=alert.explain_run_id, mitre_run_id=alert.mitre_run_id,
            demo_sample=await _demo(session, audit.target_id))
    what = f"alert run {alert_run_id} was not" if alert_run_id else "no loaded alert run was"
    exc = Conflict if alert_run_id else Unavailable
    raise exc(f"{what} built for the model served now ({served.model_name} {served.registry_version}, "
              f"{served.model_version}): {'; '.join(skipped)}. Build and load a new alert run (N28, N30)",
              component="alerts", code="other_model")
