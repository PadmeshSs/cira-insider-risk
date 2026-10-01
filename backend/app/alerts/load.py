"""Load one alert run into PostgreSQL (Bible Ch12 steps 3-5; HCEA §12, D-6; Architecture §36, §37).

Usage, from backend/ with CERT_PROCESSED_DIR set in the shell (or
--processed-dir; DATABASE_URL comes from .env if not given), after ``python -m app.alerts.batch``
and ``alembic upgrade head``:

    python -m app.alerts.load --profile full                       # newest alert run
    python -m app.alerts.load --alert-run-id <id> --database-url <url>

What it does
    1. Builds the load plan from Parquet, checking lineage as it goes: the
       served model now is the one the alert run names (N28), its registry
       entry is intact (sha256, N21), the matrix is the one the run was built
       from (fingerprint), and every member day has its feature row, served
       score and risk row.
    2. Reads the Stage 0 events of member days and demo days only (D-6,
       R12), month by month, filtered by user, and refuses if they exceed
       ``--max-events``: the load is bounded by design, not by luck.
    3. Writes everything in ONE transaction (persistence.py). On any error
       the transaction rolls back and the command prints ``NOT STORED`` with
       the reason and exits 3 (§36). Nothing is claimed.
    4. Reads the load back in a new connection. Only if that agrees does it
       print ``stored``, write ``loads/load_<stamp>.json`` next to the run and
       append a ``chapter12_alert_load`` runlog line.

Loading the same alert run twice is refused (exit 2). Label-free (N5).
"""
from __future__ import annotations

from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import asyncio  # noqa: E402
import json  # noqa: E402
import math  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import pyarrow.parquet as pq  # noqa: E402

from app.cri.sources import RISK_OUTPUT, chapter8_batch  # noqa: E402
from app.explainability.sources import aligned  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, memory_rss_mb  # noqa: E402
from app.scoring.serving_config import resolve_serving_config  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, feature_fingerprint, load_feature_matrix  # noqa: E402

from .persistence import AlreadyLoadedError, LoadPlan, PersistenceError, check_stored, persist  # noqa: E402
from .sources import (  # noqa: E402
    ALERTS_OUTPUT,
    DEMO_OUTPUT,
    LOADS_DIR,
    MEMBERS_OUTPUT,
    REASONS_OUTPUT,
    AlertSourceError,
    alert_run_dir,
    read_explanations,
    read_meta,
)

DEFAULT_MAX_EVENTS = 500_000
DOMAINS = ("logon", "device", "file", "email", "http")
BASE_EVENT_COLUMNS = ("event_id", "timestamp", "date_day", "hour", "weekday", "user_id", "device_id")


class LoadRefused(RuntimeError):
    """The plan cannot be built; nothing was sent to the database."""


def _parse_args(argv):
    p = argparse.ArgumentParser(description="CIRA Chapter 12 bounded load into PostgreSQL")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--alert-run-id", default=None)
    p.add_argument("--database-url", default=None, help="default: DATABASE_URL from the settings")
    p.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS)
    p.add_argument("--connect-timeout", type=float, default=10.0)
    return p.parse_args(argv)


def _clean(v):
    """JSON-safe scalar: NaN -> None, numpy -> Python."""
    if v is None or v is pd.NA:
        return None
    if hasattr(v, "item") and not isinstance(v, (str, bytes)):
        try:
            v = v.item()
        except (ValueError, AttributeError):
            pass
    if isinstance(v, float) and math.isnan(v):
        return None
    return v


def event_type(domain: str, activity) -> str:
    if domain in ("logon", "device"):
        a = _clean(activity)
        return f"{domain}_{a}" if a else f"{domain}_event"
    return {"file": "file_event", "email": "email_event", "http": "http_request"}[domain]


def read_events(processed: Path, profile: str, keys: pd.DataFrame, max_events: int,
                loaded_for: dict | None = None) -> list[dict]:
    """Stage 0 events of the given user-days only; month by month, filtered by user (D-6, R1, R12)."""
    want = set(zip(keys["user_id"].astype(str), keys["date"].astype(str)))
    users = sorted({u for u, _ in want})
    months = sorted({d[:7] for _, d in want})
    root = processed / "events" / f"profile={profile}"
    out: list[dict] = []
    for domain in DOMAINS:
        for month in months:
            mdir = root / f"source_type={domain}" / f"month={month}"
            for part in sorted(mdir.glob("*.parquet")) if mdir.exists() else []:
                t = pq.read_table(part, filters=[("user_id", "in", users)])
                if t.num_rows == 0:
                    continue
                f = t.to_pandas()
                day = pd.to_datetime(f["date_day"]).dt.strftime("%Y-%m-%d")
                keep = np.fromiter((k in want for k in zip(f["user_id"].astype(str), day)), dtype=bool, count=len(f))
                f, day = f[keep], day[keep]
                extra = [c for c in f.columns if c not in BASE_EVENT_COLUMNS]
                for i, row in enumerate(f.to_dict("records")):     # not itertuples: email has a 'from' column
                    ts = pd.Timestamp(row["timestamp"])
                    out.append({
                        "source_type": domain, "event_type": event_type(domain, row.get("activity")),
                        "event_id": str(row["event_id"]), "user_id": str(row["user_id"]),
                        "device_id": _clean(row.get("device_id")), "event_time": ts.to_pydatetime(),
                        "activity_date": day.iloc[i], "details": {c: _clean(row[c]) for c in extra},
                        "source_path": str(part),
                        "loaded_for": (loaded_for or {}).get((str(row["user_id"]), day.iloc[i]), "alert")})
                if len(out) > max_events:
                    raise LoadRefused(f"more than {max_events} events for the member and demo days; the load is "
                                      "bounded by design (D-6): check the alert policy and the demo sample before "
                                      "raising --max-events")
    return out


def build_plan(args) -> tuple[LoadPlan, Path, dict]:
    processed = Path(args.processed_dir)
    try:
        run_dir = alert_run_dir(processed, args.alert_run_id, args.profile)
    except AlertSourceError as exc:
        raise LoadRefused(str(exc)) from exc
    meta = read_meta(run_dir)
    run_id = meta["alert_run_id"]
    served = meta["served"]
    cfg = resolve_serving_config()
    if cfg.served is None or (cfg.served.model_name, cfg.served.registry_version) != \
            (served["model_name"], served["registry_version"]):
        raise LoadRefused(f"alert run {run_id} was built for {served['model_name']}:{served['registry_version']}; the "
                          f"model served now is {cfg.served}. Build a new alert run for the served model (N28)")
    from app.tabnet.model_registry import ModelRegistry, RegistryError

    try:
        reg = ModelRegistry(cfg.registry_root, served["model_name"])
        entry = reg.resolve(served["registry_version"])
    except RegistryError as exc:
        raise LoadRefused(f"registry: {exc}") from exc
    problems = reg.verify(entry)
    if problems or entry.get("model_version") != served["model_version"]:
        raise LoadRefused(f"registry entry {served['registry_version']} does not verify: "
                          f"{problems or 'model_version differs'} (N21)")

    alerts = pd.read_parquet(run_dir / ALERTS_OUTPUT)
    members = pd.read_parquet(run_dir / MEMBERS_OUTPUT)
    reasons = pd.read_parquet(run_dir / REASONS_OUTPUT)
    demo = pd.read_parquet(run_dir / DEMO_OUTPUT)
    expl = {(e["user_id"], e["date"]): e for e in read_explanations(run_dir)}

    member_keys = set(zip(members["user_id"].astype(str), members["date"].astype(str)))
    demo_keys = set(zip(demo["user_id"].astype(str), demo["date"].astype(str)))
    all_keys = sorted(member_keys | demo_keys)
    loaded_for = {k: ",".join(n for n, s in (("alert", member_keys), ("demo", demo_keys)) if k in s) for k in all_keys}
    keys = pd.DataFrame(all_keys, columns=["user_id", "date"])

    fm = load_feature_matrix(processed, args.profile)
    fp = feature_fingerprint(fm.features_path)
    if fp != meta["features"]["fingerprint"]:
        raise LoadRefused(f"the matrix changed since alert run {run_id} (fingerprint {fp}, run "
                          f"{meta['features']['fingerprint']})")
    frame = aligned(fm.matrix, keys, "the feature matrix")
    feat_cols = [c for c in frame.columns if c not in ("user_id", "date")]
    fvs = [{"user_id": u, "activity_date": d, "profile": args.profile, "features_fingerprint": fp,
            "pipeline_version": fm.schema.get("pipeline_version"), "source_path": str(fm.features_path),
            "values": {c: _clean(v) for c, v in zip(feat_cols, vals)}, "loaded_for": loaded_for[(u, d)]}
           for u, d, vals in zip(keys["user_id"], keys["date"], frame[feat_cols].itertuples(index=False, name=None))]

    batch = chapter8_batch(processed, meta["source_batch"]["batch_run_id"], args.profile)
    scores = aligned(batch.read(role="served", columns=["user_id", "date", "model_split", "model_name", "model_version",
                                                        "registry_version", "raw_score", "anomaly_score"]),
                     keys, f"batch {batch.batch_run_id}")
    an = [{"user_id": u, "activity_date": d, "model_name": r["model_name"], "model_version": r["model_version"],
           "registry_version": r["registry_version"], "role": "served", "model_split": r["model_split"],
           "raw_score": float(r["raw_score"]), "anomaly_score": float(r["anomaly_score"]),
           "batch_run_id": batch.batch_run_id}
          for u, d, r in zip(keys["user_id"], keys["date"], scores.to_dict("records"))]

    rdir = processed / "risk" / "chapter9" / meta["risk_run"]["cri_run_id"]
    rframe = pd.read_parquet(rdir / RISK_OUTPUT)
    risk = aligned(rframe, keys, f"CRI run {rdir.name}")
    mitre_id = (meta.get("mitre") or {}).get("mitre_run_id")
    rk = []
    for u, d, r in zip(keys["user_id"], keys["date"], risk.to_dict("records")):
        rk.append({"user_id": u, "activity_date": d, "anomaly_score": float(r["anomaly_score"]),
                   "cri_score": float(r["cri_score"]), "severity": str(r["severity"]),
                   "components": {k[len("component_"):]: _clean(v) for k, v in r.items() if k.startswith("component_")},
                   "points": {k[len("points_"):]: _clean(v) for k, v in r.items() if k.startswith("points_")},
                   "missing_components": _clean(r.get("missing_components")) or None,
                   "historical_top_feature": _clean(r.get("historical_top_feature")),
                   "peer_top_feature": _clean(r.get("peer_top_feature")), "ldap_role": _clean(r.get("role")),
                   "model_version": str(r["model_version"]), "cri_version": str(r["cri_version"]),
                   "cri_config_hash": str(r["cri_config_hash"]), "cri_variant": str(r["cri_variant"]),
                   "calibration_id": str(r["calibration_id"]), "formula_hash": meta["risk_run"].get("formula_hash"),
                   "cri_run_id": rdir.name, "mitre_run_id": mitre_id})
    for a, r in zip(an, rk):                                                   # N34: the same score, two rows
        if a["anomaly_score"] != r["anomaly_score"]:
            raise LoadRefused(f"{a['user_id']} {a['activity_date']}: the risk row's anomaly score differs from the batch")

    mm = []
    if mitre_id:
        from app.mitre.sources import CONTEXT_OUTPUT, MATCHES_OUTPUT, mitre_run_dir

        mdir = mitre_run_dir(processed, mitre_id)
        mmeta = json.loads((mdir / "mitre_meta.json").read_text(encoding="utf-8"))
        ctx = aligned(pd.read_parquet(mdir / CONTEXT_OUTPUT), keys, f"enrichment run {mitre_id}")
        matches = pd.read_parquet(mdir / MATCHES_OUTPUT)
        matches["user_id"] = matches["user_id"].astype("string").str.strip().str.casefold()
        matches["date"] = matches["date"].astype("string")
        by_key = {k: g for k, g in matches.groupby(["user_id", "date"], sort=False)}
        common = {"ruleset_version": mmeta.get("ruleset_version"), "ruleset_hash": mmeta.get("ruleset_hash"),
                  "attack_version": (mmeta.get("table") or {}).get("attack_version"),
                  "reference_id": (mmeta.get("reference") or {}).get("reference_id"), "mitre_run_id": mitre_id}
        for u, d, c in zip(keys["user_id"], keys["date"], ctx.to_dict("records")):
            status = str(c["mitre_status"])
            if status == "mapped":
                for m in by_key.get((u, d), pd.DataFrame()).to_dict("records"):
                    mm.append({"user_id": u, "activity_date": d, "status": "mapped", "technique_id": m["technique_id"],
                               "technique_name": _clean(m.get("technique_name")), "tactic": _clean(m.get("tactic")),
                               "rule_id": m["rule_id"], "evidence": m["evidence"], "trigger_column": m["trigger_column"],
                               "trigger_value": _clean(m.get("trigger_value")), "strength": _clean(m.get("strength")),
                               "mitre_context": _clean(c.get("mitre_context")), "unmapped_behaviours": None, **common})
            elif status == "unmapped":
                tags = [t for t in str(_clean(c.get("mitre_unmapped_behaviours")) or "").split(",") if t]
                mm.append({"user_id": u, "activity_date": d, "status": "unmapped",
                           "mitre_context": _clean(c.get("mitre_context")), "unmapped_behaviours": tags or None, **common})
            # not_evaluated: no row; the explanation says the rules could not be evaluated

    alert_rows = []
    for a in alerts.to_dict("records"):
        alert_rows.append({
            "alert_run_id": run_id, "alert_key": a["alert_key"], "user_id": a["user_id"], "status": a["status"],
            "duplicate_of": _clean(a.get("duplicate_of")), "first_date": a["first_date"], "last_date": a["last_date"],
            "peak_date": a["peak_date"], "n_days": int(a["n_days"]), "peak_anomaly_score": float(a["peak_anomaly_score"]),
            "peak_cri_score": float(a["peak_cri_score"]), "max_cri_score": float(a["max_cri_score"]),
            "max_severity": a["max_severity"], "queue_score": float(a["queue_score"]), "ordering": a["ordering"],
            "triggers": [t for t in str(a["triggers"]).split(",") if t],
            "techniques": [t for t in str(_clean(a.get("techniques")) or "").split(",") if t],
            "signature": [t for t in str(_clean(a.get("signature")) or "").split(",") if t],
            "top_feature": _clean(a.get("top_feature")), "model_split": a["model_split"],
            "explanation_status": a["explanation_status"], "policy_version": a["policy_version"],
            "policy_hash": a["policy_hash"], "model_version": a["model_version"], "batch_run_id": a["batch_run_id"],
            "cri_run_id": a["cri_run_id"], "explain_run_id": a["explain_run_id"], "mitre_run_id": _clean(a.get("mitre_run_id"))})
    member_rows = []
    for m in members.to_dict("records"):
        e = expl.get((m["user_id"], m["date"]))
        if e is None:
            raise LoadRefused(f"member {m['user_id']} {m['date']} has no explanation in the alert run")
        corr = e.get("corroboration") or {}
        member_rows.append({
            "alert_key": m["alert_key"], "user_id": m["user_id"], "activity_date": m["date"],
            "is_peak": bool(m["is_peak"]), "by_band": bool(m["by_band"]), "by_top_k": bool(m["by_top_k"]),
            "explanation_status": e["status"], "explanation_reason": e.get("model_unavailable_reason"),
            "explanation_text": e["text"], "explanation": e, "kernel_top5_overlap": _clean(corr.get("top5_overlap")),
            "kernel_deletion_beats_random": _clean(corr.get("deletion_top_beats_random")),
            "explain_run_id": e["explain_run_id"]})
    reason_rows = [{"alert_key": r["alert_key"], "user_id": r["user_id"], "activity_date": r["date"],
                    "section": r["section"], "rank": int(r["rank"]), "subject": r["subject"],
                    "rule_id": _clean(r.get("rule_id")), "value": _clean(r.get("value")), "weight": _clean(r.get("weight")),
                    "text": r["text"], "source": json.loads(r["source"]), "model_version": r["model_version"],
                    "explain_run_id": r["explain_run_id"]} for r in reasons.to_dict("records")]

    events = read_events(processed, args.profile, keys, args.max_events, loaded_for)
    model_version = {"model_name": served["model_name"], "registry_version": served["registry_version"],
                     "model_version": served["model_version"], "run_id": entry.get("run_id"),
                     "profile": entry.get("profile"), "trained_at": _clean(entry.get("trained_at")),
                     "split_mode": (entry.get("split") or {}).get("mode"), "n_input_columns": served.get("n_input_columns"),
                     "artifact_dir": str(reg.artifact_dir(entry)), "files": entry.get("files"),
                     "details": {"served_as": "served", "serving_source": cfg.source}}
    summary = {"alerts": len(alert_rows), "members": len(member_rows), "demo_rows": len(demo),
               "user_days": len(keys), "events": len(events), "policy_hash": meta.get("policy_hash")}
    policy = meta["policy"]
    configuration = [
        {"key": f"{policy['version']}:{meta['policy_hash']}", "value": json.dumps(policy, sort_keys=True),
         "description": "Chapter 12 alert policy (CLI flags of app.alerts.batch; never .env)"},
        {"key": f"{meta['demo_sample']['rule']}:{run_id}", "value": json.dumps(meta["demo_sample"], sort_keys=True),
         "description": "HCEA D-6 demo sample: selection rule and the users and window it chose for this alert run"},
    ]
    plan = LoadPlan(run_id, summary, model_version, feature_vectors=fvs, events=events, anomaly_scores=an,
                    risk_scores=rk, alerts=alert_rows, members=member_rows, reasons=reason_rows, mitre_mappings=mm,
                    configuration=configuration)
    return plan, run_dir, meta


def _is_async(url: str) -> bool:
    from sqlalchemy.engine import make_url

    return make_url(url).get_dialect().is_async


def execute(url: str, plan: LoadPlan, connect_timeout: float = 10.0) -> tuple[dict, list[str]]:
    """One transaction for the whole plan, then a read-back in a new connection."""
    import sqlalchemy as sa

    if _is_async(url):
        from sqlalchemy.ext.asyncio import create_async_engine

        async def go():
            args = {"timeout": connect_timeout} if "asyncpg" in url else {}
            engine = create_async_engine(url, connect_args=args)
            try:
                async with engine.begin() as conn:
                    counts = await conn.run_sync(persist, plan)
                async with engine.connect() as conn:
                    problems = await conn.run_sync(check_stored, plan)
            finally:
                await engine.dispose()
            return counts, problems

        return asyncio.run(go())
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            counts = persist(conn, plan)
        with engine.connect() as conn:
            problems = check_stored(conn, plan)
    finally:
        engine.dispose()
    return counts, problems


def _safe_url(url: str) -> str:
    from sqlalchemy.engine import make_url

    return make_url(url).render_as_string(hide_password=True)


def run(args, built: tuple | None = None) -> dict:
    started = time.perf_counter()
    plan, run_dir, meta = built or build_plan(args)
    if args.database_url:
        url = args.database_url
    else:
        from app.core.config import settings

        url = settings.database_url
    counts, problems = execute(url, plan, args.connect_timeout)
    if problems:
        raise PersistenceError("read-back after commit disagrees: " + "; ".join(problems))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    record = {"alert_run_id": plan.alert_run_id, "loaded_at": stamp, "database": _safe_url(url), "counts": counts,
              "summary": plan.summary, "wall_seconds": round(time.perf_counter() - started, 2),
              "peak_rss_mb": round(memory_rss_mb(), 1)}
    out = run_dir / LOADS_DIR / f"load_{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    append_experiment_runlog({"stage": "chapter12_alert_load", "status": "stored", "alert_run_id": plan.alert_run_id,
                              "profile": args.profile, "database": record["database"], "counts": counts,
                              "wall_seconds": record["wall_seconds"], "peak_rss_mb": record["peak_rss_mb"]})
    print(f"[load] stored alert run {plan.alert_run_id} in {record['database']}: "
          + ", ".join(f"{k} {v}" for k, v in counts.items()), flush=True)
    return record


def main(argv=None) -> int:
    args = _parse_args(argv)
    try:
        built = build_plan(args)
    except Exception as exc:                  # nothing has been sent to the database yet
        print(f"chapter12 load refused (nothing sent to the database): {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    try:
        run(args, built)
    except AlreadyLoadedError as exc:
        print(f"chapter12 load refused: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:                  # §36: any database failure is visible and nothing is claimed
        reason = f"{type(exc).__name__}: {str(exc).splitlines()[0][:300] if str(exc) else ''}"
        append_experiment_runlog({"stage": "chapter12_alert_load", "status": "not_stored",
                                  "alert_run_id": args.alert_run_id, "profile": args.profile, "reason": reason})
        print(f"chapter12 load NOT STORED: {reason}. Nothing was committed (the transaction was rolled back, or never started); "
              "the alert run stays in Parquet and the load can be retried.", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
