"""ATT&CK context of alerts and the technique table (N42, N43, N45; HCEA D-4).

An alert's techniques are read through its member days, scoped to the
enrichment run the alert run names: alert -> member -> (user, day,
mitre_run_id). That path does not depend on ``mitre_mappings.alert_id``,
which holds only the first alert that covered a day (C12-11). A day with no
row was not evaluated (CERT columns missing); it is said so, never filled in.
The technique table comes from the pinned ATT&CK table the MITRE runtime
loaded at startup; nothing reads the STIX bundle at runtime (D-4).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import AlertMember, MITREMapping

from .alerts import get_alert_row
from .errors import NotFound, Unavailable
from .runs import CurrentRun, Runtimes


def mapping_dict(m: MITREMapping) -> dict:
    tags = m.unmapped_behaviours
    return {"id": m.id, "user_id": m.user_id, "activity_date": m.activity_date, "status": m.status,
            "technique_id": m.technique_id, "technique_name": m.technique_name, "tactic": m.tactic,
            "rule_id": m.rule_id, "evidence": m.evidence, "trigger_column": m.trigger_column,
            "trigger_value": m.trigger_value, "strength": m.strength, "mitre_context": m.mitre_context,
            "unmapped_behaviours": list(tags) if isinstance(tags, list) else None,
            "ruleset_version": m.ruleset_version, "ruleset_hash": m.ruleset_hash, "attack_version": m.attack_version,
            "mitre_run_id": m.mitre_run_id}


async def for_alert(session: AsyncSession, run: CurrentRun, alert_id: int) -> dict:
    a = await get_alert_row(session, run, alert_id)
    days = sorted({d for (d,) in (await session.execute(select(AlertMember.activity_date)
                                                         .where(AlertMember.alert_id == a.id))).all()})
    rows = []
    if run.mitre_run_id and days:
        rows = (await session.execute(select(MITREMapping).where(MITREMapping.mitre_run_id == run.mitre_run_id,
                                                                 MITREMapping.user_id == a.user_id,
                                                                 MITREMapping.activity_date.in_(days))
                                      .order_by(MITREMapping.activity_date, MITREMapping.id))).scalars().all()
    by_day = defaultdict(list)
    for m in rows:
        by_day[m.activity_date].append(mapping_dict(m))
    out_days, tech = [], {}
    for d in days:
        ms = by_day.get(d, [])
        status = "not_evaluated" if not ms else ("mapped" if any(x["status"] == "mapped" for x in ms) else "unmapped")
        out_days.append({"activity_date": d, "status": status, "mappings": ms})
        for x in ms:
            if x["status"] == "mapped":
                t = tech.setdefault(x["technique_id"], {"technique_id": x["technique_id"],
                                                        "technique_name": x["technique_name"],
                                                        "tactic": x["tactic"], "days": set()})
                t["days"].add(d)
    techniques = [{**t, "days": len(t["days"])} for t in sorted(tech.values(), key=lambda t: t["technique_id"])]
    return {"alert_id": a.id, "days": out_days, "techniques": techniques, "run": run.lineage()}


def technique(runtimes: Runtimes, technique_id: str) -> dict:
    from app.mitre.enrich import MitreUnavailableError
    from app.mitre.mapping_rules import RULES
    from app.mitre.techniques import TechniqueTableError

    if runtimes.mitre is None:
        raise Unavailable("MITRE runtime not started", component="mitre")
    try:
        table = runtimes.mitre.enricher().table
    except MitreUnavailableError as exc:
        raise Unavailable(str(exc), component="mitre") from exc
    tid = (technique_id or "").strip().upper()
    try:
        t = table.get(tid)
    except TechniqueTableError as exc:
        raise NotFound(str(exc)) from exc
    rules = [{k: v for k, v in asdict(r).items() if k in ("rule_id", "pattern", "trigger_column", "evidence",
                                                          "reasoning", "not_observable")}
             for r in RULES if r.technique_id == tid]
    return {"technique_id": t.technique_id, "name": t.name, "full_name": table.full_name(tid),
            "tactics": list(t.tactics), "is_subtechnique": t.is_subtechnique, "parent_id": t.parent_id,
            "short_description": t.short_description, "url": t.url, "attack_version": table.attack_version,
            "rules": rules}
