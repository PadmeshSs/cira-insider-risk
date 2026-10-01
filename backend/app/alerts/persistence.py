"""The bounded load into PostgreSQL (Bible Ch12 steps 3-5; HCEA §12, D-6, R12; Architecture §36, §37).

    counts = persist(connection, plan)      # inside ONE transaction the caller owns
    problems = check_stored(connection, plan)

``persist`` takes a synchronous SQLAlchemy ``Connection``. The CLI runs it
inside ``AsyncConnection.run_sync`` on the application's asyncpg engine
(the same pattern Alembic uses), and the tests run it on SQLite, so one code
path serves both.

What is written, in lineage order (§37)
    model_versions   the served model's registry entry (N21)
    feature_vectors  one per member day and demo day (D-6)
    event_logs       the Stage 0 events of those user-days
    anomaly_scores   the served score of each of those user-days (N32: role
                     'served' is a check constraint)
    risk_scores      the CRI of each, pointing at its anomaly score; both
                     values kept (N34)
    alerts           open alerts first, then suppressed ones naming the open
                     alert they repeat
    alert_members    alert -> risk score, with triggers and the explanation
    alert_reasons    one row per explanation item, section and source kept (N50)
    mitre_mappings   each mapped technique (or the explicit unmapped record) of
                     those user-days, linked to the alert that covers the day
    configurations   the alert policy (key ``c12-alert-policy-v1:<hash>``) and
                     the run's demo-sample rule and selection
                     (``c12-demo-sample-v1:<alert_run_id>``): D-6 asks for the
                     sample's rule to be recorded in configuration. A key is
                     written once; a different value under an existing key is
                     refused
    audit_logs       one ``alert_run_loaded`` row

Rows that already exist under their natural key (an event id, a user-day of
the same matrix, batch, CRI run or enrichment run) are reused, not written
twice, so two alert runs over the same scores share their lineage rows.

Failure (§36: "PostgreSQL unavailable")
    The caller owns the transaction. Any error rolls everything back; there
    is no partial load, and the audit row that would claim the load exists
    only if the transaction committed. ``check_stored`` then reads the rows
    back in a new connection before the CLI reports anything as stored.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Iterable

import sqlalchemy as sa
from sqlalchemy.engine import Connection

import app.database.models  # noqa: F401  (registers every table on Base.metadata)
from app.database.base import Base

AUDIT_ACTION = "alert_run_loaded"
CHUNK = 2_000


class AlreadyLoadedError(RuntimeError):
    """This alert run is already in the database (its audit row exists)."""


class PersistenceError(RuntimeError):
    """The plan is inconsistent; nothing is written."""


@dataclass
class LoadPlan:
    alert_run_id: str
    summary: dict
    model_version: dict
    feature_vectors: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    anomaly_scores: list[dict] = field(default_factory=list)
    risk_scores: list[dict] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    members: list[dict] = field(default_factory=list)
    reasons: list[dict] = field(default_factory=list)
    mitre_mappings: list[dict] = field(default_factory=list)
    configuration: list[dict] = field(default_factory=list)
    actor: str = "cli:app.alerts.load"


def T(name: str) -> sa.Table:
    return Base.metadata.tables[name]


def _d(v) -> date:
    return v if isinstance(v, date) else date.fromisoformat(str(v)[:10])


def _chunks(items: list, n: int = CHUNK) -> Iterable[list]:
    for i in range(0, len(items), n):
        yield items[i:i + n]


def _insert(conn: Connection, table: sa.Table, rows: list[dict]) -> None:
    """executemany in chunks; every row gets the same keys (absent = NULL), unknown keys are refused."""
    if not rows:
        return
    keys = sorted({k for r in rows for k in r})
    unknown = [k for k in keys if k not in table.c]
    if unknown:
        raise PersistenceError(f"{table.name}: unknown columns {unknown}")
    uniform = [{k: r.get(k) for k in keys} for r in rows]
    for part in _chunks(uniform):
        conn.execute(sa.insert(table), part)


def _existing(conn: Connection, table: sa.Table, key_cols: tuple[str, ...], scope: dict, probe: str,
              values: Iterable) -> dict[tuple, int]:
    """(key tuple) -> id for rows already present, looked up in chunks by ``probe IN values``."""
    out: dict[tuple, int] = {}
    vals = sorted({v for v in values if v is not None}, key=str)
    for part in _chunks(vals, 900):
        q = sa.select(table.c.id, *[table.c[k] for k in key_cols]).where(table.c[probe].in_(part))
        for k, v in scope.items():
            q = q.where(table.c[k] == v)
        for row in conn.execute(q):
            out[tuple(_d(x) if isinstance(x, date) else x for x in row[1:])] = row[0]
    return out


def _get_or_create(conn, table, rows, key_cols, scope, probe) -> tuple[dict[tuple, int], int, int]:
    key = lambda r: tuple(_d(r[k]) if k == "activity_date" else r[k] for k in key_cols)  # noqa: E731
    have = _existing(conn, table, key_cols, scope, probe, (r[probe] for r in rows))
    new, seen = [], set()
    for r in rows:
        k = key(r)
        if k not in have and k not in seen:
            new.append(r)
            seen.add(k)
    _insert(conn, table, new)
    ids = _existing(conn, table, key_cols, scope, probe, (r[probe] for r in rows))
    missing = [key(r) for r in rows if key(r) not in ids]
    if missing:
        raise PersistenceError(f"{table.name}: {len(missing)} rows not found after insert, e.g. {missing[0]}")
    return ids, len(new), len(rows) - len(new)


def loaded_runs(conn: Connection) -> list[str]:
    a = T("audit_logs")
    return [r[0] for r in conn.execute(sa.select(a.c.target_id).where(a.c.action == AUDIT_ACTION).order_by(a.c.id))]


def persist(conn: Connection, plan: LoadPlan) -> dict:
    """Write the plan. The caller commits or rolls back; see the module docstring."""
    if plan.alert_run_id in loaded_runs(conn):
        raise AlreadyLoadedError(f"alert run {plan.alert_run_id} is already loaded")
    counts: dict[str, dict] = {}

    # model version (N21)
    mv = dict(plan.model_version)
    mids, n_new, n_old = _get_or_create(conn, T("model_versions"), [mv], ("model_version",), {}, "model_version")
    model_version_id = mids[(mv["model_version"],)]
    counts["model_versions"] = {"inserted": n_new, "reused": n_old}

    # feature vectors
    fvs = [{**r, "activity_date": _d(r["activity_date"]), "first_alert_run_id": plan.alert_run_id}
           for r in plan.feature_vectors]
    fps = {r["features_fingerprint"] for r in fvs}
    if len(fps) > 1:
        raise PersistenceError(f"feature vectors from {len(fps)} matrices in one load")
    fv_ids, n_new, n_old = (_get_or_create(conn, T("feature_vectors"), fvs, ("user_id", "activity_date"),
                                           {"features_fingerprint": next(iter(fps))}, "user_id") if fvs else ({}, 0, 0))
    counts["feature_vectors"] = {"inserted": n_new, "reused": n_old}

    # events
    evs = []
    for r in plan.events:
        k = (r["user_id"], _d(r["activity_date"]))
        evs.append({**r, "activity_date": k[1], "feature_vector_id": fv_ids.get(k), "first_alert_run_id": plan.alert_run_id})
    by_type: dict[str, list] = {}
    for r in evs:
        by_type.setdefault(r["source_type"], []).append(r)
    ins = reu = 0
    for st, rows in sorted(by_type.items()):
        _ids, a, b = _get_or_create(conn, T("event_logs"), rows, ("event_id",), {"source_type": st}, "event_id")
        ins, reu = ins + a, reu + b
    counts["event_logs"] = {"inserted": ins, "reused": reu}

    # anomaly scores
    an = []
    for r in plan.anomaly_scores:
        k = (r["user_id"], _d(r["activity_date"]))
        if k not in fv_ids:
            raise PersistenceError(f"anomaly score {k} has no feature vector in this load")
        an.append({**r, "activity_date": k[1], "feature_vector_id": fv_ids[k], "model_version_id": model_version_id})
    batches = {r["batch_run_id"] for r in an}
    if len(batches) > 1:
        raise PersistenceError("anomaly scores from more than one batch in one load")
    an_ids, n_new, n_old = (_get_or_create(conn, T("anomaly_scores"), an, ("user_id", "activity_date"),
                                           {"batch_run_id": next(iter(batches))}, "user_id") if an else ({}, 0, 0))
    counts["anomaly_scores"] = {"inserted": n_new, "reused": n_old}

    # risk scores (N34: both values kept, one points at the other)
    rk = []
    for r in plan.risk_scores:
        k = (r["user_id"], _d(r["activity_date"]))
        if k not in an_ids:
            raise PersistenceError(f"risk score {k} has no anomaly score in this load")
        rk.append({**r, "activity_date": k[1], "anomaly_score_id": an_ids[k]})
    runs = {r["cri_run_id"] for r in rk}
    if len(runs) > 1:
        raise PersistenceError("risk scores from more than one CRI run in one load")
    rk_ids, n_new, n_old = (_get_or_create(conn, T("risk_scores"), rk, ("user_id", "activity_date"),
                                           {"cri_run_id": next(iter(runs))}, "user_id") if rk else ({}, 0, 0))
    counts["risk_scores"] = {"inserted": n_new, "reused": n_old}

    # alerts: open first, then suppressed (their duplicate_of must already have an id)
    alerts = T("alerts")
    base = [{**{k: v for k, v in a.items() if k != "duplicate_of"}, "model_version_id": model_version_id,
             "first_date": _d(a["first_date"]), "last_date": _d(a["last_date"]), "peak_date": _d(a["peak_date"])}
            for a in plan.alerts]
    opened = [a for a in base if a["status"] == "open"]
    _insert(conn, alerts, opened)
    a_ids = _existing(conn, alerts, ("alert_key",), {"alert_run_id": plan.alert_run_id}, "alert_key",
                      (a["alert_key"] for a in opened))
    dup_of = {a["alert_key"]: a.get("duplicate_of") for a in plan.alerts}
    supp = []
    for a in base:
        if a["status"] != "suppressed":
            continue
        target = a_ids.get((dup_of.get(a["alert_key"]),))
        if target is None:
            raise PersistenceError(f"suppressed alert {a['alert_key']} repeats {dup_of.get(a['alert_key'])}, "
                                   "which is not an open alert of this run")
        supp.append({**a, "duplicate_of_id": target})
    _insert(conn, alerts, supp)
    a_ids = _existing(conn, alerts, ("alert_key",), {"alert_run_id": plan.alert_run_id}, "alert_key",
                      (a["alert_key"] for a in base))
    counts["alerts"] = {"inserted": len(base), "open": len(opened), "suppressed": len(supp)}

    # members
    mem = []
    for m in plan.members:
        k = (m["user_id"], _d(m["activity_date"]))
        if k not in rk_ids:
            raise PersistenceError(f"alert member {k} has no risk score in this load")
        mem.append({**{x: v for x, v in m.items() if x != "alert_key"}, "activity_date": k[1],
                    "alert_id": a_ids[(m["alert_key"],)], "risk_score_id": rk_ids[k]})
    _insert(conn, T("alert_members"), mem)
    mt = T("alert_members")
    m_ids = {}
    for part in _chunks(sorted({x["alert_id"] for x in mem}), 900):
        for row in conn.execute(sa.select(mt.c.id, mt.c.alert_id, mt.c.activity_date).where(mt.c.alert_id.in_(part))):
            m_ids[(row[1], _d(row[2]))] = row[0]
    counts["alert_members"] = {"inserted": len(mem)}

    # reasons (N50)
    rs = []
    for r in plan.reasons:
        aid = a_ids[(r["alert_key"],)]
        mid = m_ids.get((aid, _d(r["activity_date"])))
        if mid is None:
            raise PersistenceError(f"reason for {r['user_id']} {r['activity_date']} has no member row")
        rs.append({**{x: v for x, v in r.items() if x != "alert_key"}, "activity_date": _d(r["activity_date"]),
                   "alert_id": aid, "member_id": mid})
    _insert(conn, T("alert_reasons"), rs)
    counts["alert_reasons"] = {"inserted": len(rs)}

    # ATT&CK mappings of those user-days, linked to the alert covering the day
    mm = T("mitre_mappings")
    status_of = {a["alert_key"]: a["status"] for a in base}
    covering = {}
    for m in plan.members:                       # a day in an open alert links there; else to its suppressed alert
        k = (m["user_id"], _d(m["activity_date"]))
        if k not in covering or status_of[m["alert_key"]] == "open":
            covering[k] = a_ids[(m["alert_key"],)]
    ins = linked = 0
    for run_id in sorted({r["mitre_run_id"] for r in plan.mitre_mappings}):
        rows = [r for r in plan.mitre_mappings if r["mitre_run_id"] == run_id]
        have = set()
        for part in _chunks(sorted({r["user_id"] for r in rows}), 900):
            q = sa.select(mm.c.user_id, mm.c.activity_date).where(mm.c.mitre_run_id == run_id, mm.c.user_id.in_(part))
            have |= {(u, _d(d)) for u, d in conn.execute(q)}
        new = []
        for r in rows:
            k = (r["user_id"], _d(r["activity_date"]))
            if k not in have:
                new.append({**r, "activity_date": k[1], "alert_id": covering.get(k)})
        _insert(conn, mm, new)
        ins += len(new)
        for (u, d), aid in covering.items():
            if (u, d) in have:
                res = conn.execute(sa.update(mm).where(mm.c.mitre_run_id == run_id, mm.c.user_id == u,
                                                       mm.c.activity_date == d, mm.c.alert_id.is_(None))
                                   .values(alert_id=aid))
                linked += res.rowcount or 0
    counts["mitre_mappings"] = {"inserted": ins, "existing_linked_to_alert": linked}

    # policy and demo-sample rule recorded in configuration (D-6); write-once per key
    cfg = T("configurations")
    written = 0
    for c in plan.configuration:
        old = conn.execute(sa.select(cfg.c.value).where(cfg.c.key == c["key"])).scalar()
        if old is None:
            _insert(conn, cfg, [c])
            written += 1
        elif old != c["value"]:
            raise PersistenceError(f"configuration {c['key']} already holds a different value")
    counts["configurations"] = {"inserted": written, "already_recorded": len(plan.configuration) - written}

    # audit row, inside the same transaction (§36)
    conn.execute(sa.insert(T("audit_logs")), [{
        "action": AUDIT_ACTION, "actor": plan.actor, "target_type": "alert_run", "target_id": plan.alert_run_id,
        "details": {"counts": counts, "summary": plan.summary}}])
    return counts


def check_stored(conn: Connection, plan: LoadPlan) -> list[str]:
    """Read the load back. Empty list = everything the plan promised is in the database."""
    problems = []
    if plan.alert_run_id not in loaded_runs(conn):
        problems.append("no audit row for this alert run")
    a, m, r = T("alerts"), T("alert_members"), T("alert_reasons")
    n_alerts = conn.execute(sa.select(sa.func.count()).select_from(a).where(a.c.alert_run_id == plan.alert_run_id)).scalar()
    if n_alerts != len(plan.alerts):
        problems.append(f"{n_alerts} alerts stored, {len(plan.alerts)} planned")
    ids = sa.select(a.c.id).where(a.c.alert_run_id == plan.alert_run_id)
    n_mem = conn.execute(sa.select(sa.func.count()).select_from(m).where(m.c.alert_id.in_(ids))).scalar()
    if n_mem != len(plan.members):
        problems.append(f"{n_mem} members stored, {len(plan.members)} planned")
    n_rs = conn.execute(sa.select(sa.func.count()).select_from(r).where(r.c.alert_id.in_(ids))).scalar()
    if n_rs != len(plan.reasons):
        problems.append(f"{n_rs} reasons stored, {len(plan.reasons)} planned")
    return problems
