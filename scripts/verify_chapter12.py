"""Verify Chapter 12 before any alert is shown to anyone.

Sections (each prints PASS, WARN or FAIL per check; exit code 1 on any FAIL):

    policy        the run's policy is c12-alert-policy-v1 with the recorded
                  hash; overrides are listed (WARN)
    lineage       the alert run belongs to the model served now (N28), to the
                  explain run, batch and default CRI run it names (N50), to
                  the matrix that exists now; no label column (N5); no
                  shadow row (N32)
    alerts        recomputed from the source runs, label-free: the same
                  triggers, alerts, members, statuses and duplicates; every
                  triggered day in exactly one alert; the gap, span and
                  cooldown rules hold; in-sample rows (WARN, N31)
    explanations  one per member day, and each equal to a fresh build through
                  the Chapter 11 builder; deferred ones carry a reason (§36);
                  reason rows equal the explanations, section and source kept
                  (N50); model factors only from the served model; no
                  KernelSHAP value as a reason (N48); indicated ATT&CK matches
                  worded as visits (N45)
    demo          validation or test users only (N31); reproduced by
                  c12-demo-sample-v1; bounded (D-6)
    database      with --database-url: the load is recorded and committed;
                  row counts equal the run; every alert traces alert -> member
                  -> risk score -> anomaly score -> feature vector -> model
                  version, and to its events and ATT&CK rows (§37); the two
                  scores are equal copies (N34); only served scores (N32)
    readout       the validation readout, if present: validation only, of this
                  run, every guard warning as a WARN

Usage, from backend/, with CERT_PROCESSED_DIR set in the shell (or pass
--processed-dir); in PowerShell use $env:DATABASE_URL:

    python ../scripts/verify_chapter12.py --profile full --no-readout
    python ../scripts/verify_chapter12.py --profile full --database-url "$DATABASE_URL"

Writes ``experiments/results/chapter12/verification_<stamp>.json`` and one
``chapter12_verification`` runlog line. Reads no label.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.runtime import apply_thread_caps  # noqa: E402

apply_thread_caps()

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

import pandas as pd  # noqa: E402

from app.alerts.batch import (  # noqa: E402
    AlertBatchRefused,
    build_alerts,
    build_member_explanations,
    lineage,
    load_candidates,
)
from app.alerts.correlation import _split_list  # noqa: E402
from app.alerts.demo import ELIGIBLE, demo_sample  # noqa: E402
from app.alerts.evaluate import READOUT_FILE  # noqa: E402
from app.alerts.explain import reasons_frame  # noqa: E402
from app.alerts.policy import POLICY_VERSION, AlertPolicy  # noqa: E402
from app.alerts.sources import (  # noqa: E402
    ALERTS_OUTPUT,
    DEMO_OUTPUT,
    MEMBERS_OUTPUT,
    REASONS_OUTPUT,
    AlertSourceError,
    alert_run_dir,
    load_records,
    read_explanations,
    read_meta,
)
from app.explainability.reason_builder import GENERIC_PHRASES  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, memory_rss_mb, repo_root  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT  # noqa: E402

LABEL_WORDS = ("malicious", "insider", "scenario", "label", "y_primary", "y_account", "is_masquerade", "target")
DEMO_MAX_ROWS = 5_000


class Checks:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, section, name, status, detail="") -> None:
        self.rows.append({"section": section, "check": name, "status": status, "detail": detail})
        print(f"  {status:<4} {section:<12} {name}" + (f"  -- {detail}" if detail else ""), flush=True)

    def ok(self, section, name, cond, detail="", warn_only=False) -> bool:
        self.add(section, name, "PASS" if cond else ("WARN" if warn_only else "FAIL"), detail)
        return bool(cond)

    def counts(self) -> dict:
        return {s: sum(r["status"] == s for r in self.rows) for s in ("PASS", "WARN", "FAIL")}


def _hits(columns, words) -> list[str]:
    return [c for c in columns if any(w in str(c).lower() for w in words)]


def check_policy(c: Checks, meta: dict) -> AlertPolicy | None:
    s = "policy"
    try:
        policy = AlertPolicy.from_dict(meta["policy"])
    except Exception as exc:
        c.add(s, "policy readable", "FAIL", str(exc))
        return None
    c.ok(s, f"policy is {POLICY_VERSION}", meta["policy"].get("version") == POLICY_VERSION)
    c.ok(s, "policy hash reproduces", policy.policy_hash == meta.get("policy_hash"))
    over = policy.overrides()
    c.ok(s, "no override of the fixed defaults", not over, str(over), warn_only=True)
    c.ok(s, "queue ordering recorded with its reason (N40)", bool((meta.get("queue") or {}).get("why")))
    return policy


def check_run(c: Checks, args, run_dir: Path, meta: dict, policy: AlertPolicy) -> dict | None:
    s = "lineage"
    ns = argparse.Namespace(explain_run_id=(meta.get("explain_run") or {}).get("explain_run_id"), profile=args.profile)
    try:
        L = lineage(Path(args.processed_dir), ns)
    except AlertBatchRefused as exc:
        c.add(s, "served model, explain run, batch, CRI run and matrix agree (N28, N30, N50)", "FAIL", str(exc))
        return None
    c.ok(s, "served model, explain run, batch, CRI run and matrix agree (N28, N30, N50)", True, L["explain_dir"].name)
    c.ok(s, "alert run names the model served now", meta["served"]["model_version"] == L["served"]["model_version"])
    c.ok(s, "alert run names the explain run's CRI run", meta["risk_run"]["cri_run_id"] == L["risk_dir"].name)
    c.ok(s, "alert run names the explain run's batch", meta["source_batch"]["batch_run_id"] == L["batch"].batch_run_id)
    c.ok(s, "matrix fingerprint unchanged", meta["features"]["fingerprint"] == L["fingerprint"])
    frames = {n: pd.read_parquet(run_dir / n) for n in (ALERTS_OUTPUT, MEMBERS_OUTPUT, REASONS_OUTPUT, DEMO_OUTPUT)}
    bad = {n: _hits(f.columns, LABEL_WORDS) for n, f in frames.items() if _hits(f.columns, LABEL_WORDS)}
    c.ok(s, "no label column in any output (N5)", not bad, str(bad))
    c.ok(s, "CRI run with ATT&CK context (Chapter 10 formula)", bool(meta["risk_run"].get("with_mitre")),
         meta.get("mitre_unavailable_reason") or "", warn_only=True)

    s = "alerts"
    C = load_candidates(Path(args.processed_dir), L, meta.get("rows_option", "evaluation"))
    trig, alerts, members = build_alerts(C, policy)
    stored_a, stored_m = frames[ALERTS_OUTPUT], frames[MEMBERS_OUTPUT]
    c.ok(s, "triggers reproduce from the risk run", int(trig["triggered"].sum()) == len(stored_m),
         f"{int(trig['triggered'].sum())} recomputed, {len(stored_m)} stored")
    cols = ["alert_key", "user_id", "first_date", "last_date", "n_days", "peak_date", "status", "max_severity"]
    a1 = alerts[cols].sort_values("alert_key").reset_index(drop=True).astype(str)
    a2 = stored_a[cols].sort_values("alert_key").reset_index(drop=True).astype(str)
    c.ok(s, "alerts, spans, peaks and statuses reproduce", a1.equals(a2), f"{len(alerts)} recomputed, {len(stored_a)} stored")
    d1 = dict(zip(alerts["alert_key"], alerts["duplicate_of"].astype(object).where(alerts["duplicate_of"].notna(), None)))
    d2 = dict(zip(stored_a["alert_key"], stored_a["duplicate_of"].astype(object).where(stored_a["duplicate_of"].notna(), None)))
    c.ok(s, "suppressions reproduce", d1 == d2)
    mcols = ["alert_key", "user_id", "date", "is_peak", "by_band", "by_top_k"]
    m1 = members[mcols].sort_values(["user_id", "date"]).reset_index(drop=True).astype(str)
    m2 = stored_m[mcols].sort_values(["user_id", "date"]).reset_index(drop=True).astype(str)
    c.ok(s, "members and their triggers reproduce", m1.equals(m2))
    c.ok(s, "every member day in exactly one alert", not stored_m.duplicated(["user_id", "date"]).any())
    c.ok(s, "one peak per alert", (stored_m.groupby("alert_key")["is_peak"].sum() == 1).all())
    viol = 0
    for key, g in stored_m.groupby("alert_key"):
        ts = pd.to_datetime(g["date"]).sort_values()
        if len(ts) > 1 and (ts.diff().dt.days.max() > policy.correlation_gap_days):
            viol += 1
        if (ts.iloc[-1] - ts.iloc[0]).days >= policy.max_span_days:
            viol += 1
    c.ok(s, "gap and span rules hold in every alert", viol == 0, f"{viol} violations")
    by_key = stored_a.set_index("alert_key")
    bad_dup = 0
    for key, r in by_key[by_key["status"] == "suppressed"].iterrows():
        o = by_key.loc[r["duplicate_of"]] if r["duplicate_of"] in by_key.index else None
        if (o is None or o["status"] != "open" or o["user_id"] != r["user_id"]
                or (pd.Timestamp(r["first_date"]) - pd.Timestamp(o["last_date"])).days > policy.cooldown_days
                or not set(_split_list(r["signature"])) <= set(_split_list(o["signature"]))
                or not _split_list(r["signature"])):
            bad_dup += 1
    c.ok(s, "every suppressed alert repeats an open alert of the same user inside the cooldown", bad_dup == 0,
         f"{bad_dup} bad")
    train = int((stored_a["model_split"].astype(str) == "train").sum())
    c.ok(s, "no alert from in-sample rows (N31)", train == 0, f"{train} alerts from training users", warn_only=True)
    c.ok(s, "only served scores ranked (N32)", C["risk"]["model_version"].nunique() == 1)
    summ = meta.get("summary") or {}
    c.ok(s, "N52 count reported (open alerts led by usb_disconnect_count)",
         "open_alerts_led_by_usb_disconnect_count" in summ, str(summ.get("open_alerts_led_by_usb_disconnect_count")))
    return {"L": L, "C": C, "members": members, "frames": frames}


def check_explanations(c: Checks, run_dir: Path, ctx: dict) -> None:
    s = "explanations"
    stored = read_explanations(run_dir)
    members = ctx["frames"][MEMBERS_OUTPUT]
    by = {(e["user_id"], e["date"]): e for e in stored}
    c.ok(s, "one explanation per member day", len(stored) == len(members) and
         all((str(u), str(d)) in by for u, d in zip(members["user_id"], members["date"])), f"{len(stored)} / {len(members)}")
    fresh = build_member_explanations(ctx["L"], ctx["C"], ctx["members"])
    fresh_by = {(e["user_id"], e["date"]): e for e in fresh}
    diff = [k for k, e in by.items() if json.dumps(fresh_by.get(k), sort_keys=True, default=str)
            != json.dumps(e, sort_keys=True, default=str)]
    c.ok(s, "every explanation equals a fresh build through the Chapter 11 builder (N50)", not diff,
         f"{len(diff)} differ, e.g. {diff[:2]}")
    deferred = [e for e in stored if e["status"] != "complete"]
    c.ok(s, "a deferred explanation carries its reason (§36)", all(e.get("model_unavailable_reason") for e in deferred),
         f"{len(deferred)} deferred")
    c.ok(s, "no explanation deferred", not deferred, f"{len(deferred)} deferred", warn_only=True)
    served = ctx["L"]["served"]["model_version"]
    c.ok(s, "model factors only from the served model (N30, N32)",
         all((f.get("source") or {}).get("model_version") == served for e in stored for f in e["model_factors"]))
    c.ok(s, "no generic statement", not [e for e in stored if any(p in e["text"].lower() for p in GENERIC_PHRASES)])
    c.ok(s, "every indicated ATT&CK match worded as a visit (N45)",
         all("not what was sent" in m["text"] for e in stored for m in e["attack_context"]["matches"]
             if m.get("evidence") == "indicated"))
    reasons = ctx["frames"][REASONS_OUTPUT].drop(columns=["alert_run_id"])
    expect = reasons_frame(stored)
    same = len(reasons) == len(expect) and reasons.astype(str).reset_index(drop=True).equals(
        expect[list(reasons.columns)].astype(str).reset_index(drop=True))
    c.ok(s, "alert_reasons rows equal the explanations, section and source kept (N50)", same,
         f"{len(reasons)} stored, {len(expect)} expected")
    kinds = {json.loads(x).get("kind") for x in reasons["source"]}
    c.ok(s, "no KernelSHAP value stored as a reason (N48)", "kernelshap" not in str(kinds) and
         not reasons["source"].str.contains("kernelshap").any())
    c.ok(s, "a CRI point or ATT&CK match is never a model reason (N34, N45)",
         set(reasons.loc[reasons["section"].isin(["model", "model_lowering"]), "source"].map(
             lambda x: json.loads(x).get("kind"))) <= {"model"})


def check_demo(c: Checks, run_dir: Path, meta: dict, ctx: dict) -> None:
    s = "demo"
    demo = ctx["frames"][DEMO_OUTPUT]
    risk = ctx["C"]["risk"]
    split = dict(zip(risk["user_id"].astype(str), risk["model_split"].astype(str)))
    bad = sorted({u for u in demo["user_id"].astype(str) if split.get(u) not in ELIGIBLE})
    c.ok(s, "validation or test users only (N31)", not bad, str(bad[:5]))
    info = meta["demo_sample"]
    alerts = ctx["frames"][ALERTS_OUTPUT]
    rows, _ = demo_sample(risk[["user_id", "date", "model_split"]], alerts, window_days=info["window_days"],
                          max_users=info["max_users"], max_alerting_users=info["max_alerting_users"], seed=info["seed"])
    c.ok(s, "c12-demo-sample-v1 reproduces the sample",
         rows[["user_id", "date"]].astype(str).reset_index(drop=True).equals(
             demo[["user_id", "date"]].astype(str).reset_index(drop=True)), f"{len(rows)} / {len(demo)}")
    c.ok(s, f"bounded (<= {DEMO_MAX_ROWS} user-days, D-6)", len(demo) <= DEMO_MAX_ROWS, str(len(demo)))


def check_database(c: Checks, url: str, run_dir: Path, meta: dict, ctx: dict) -> None:
    import sqlalchemy as sa

    s = "database"
    run_id = meta["alert_run_id"]
    c.ok(s, "a committed load is recorded next to the run", bool(load_records(run_dir)), str(len(load_records(run_dir))))
    from sqlalchemy.engine import make_url

    if make_url(url).get_dialect().is_async:
        import asyncio

        from sqlalchemy.ext.asyncio import create_async_engine

        async def q(sql, **kw):
            e = create_async_engine(url)
            try:
                async with e.connect() as conn:
                    return (await conn.execute(sa.text(sql), kw)).all()
            finally:
                await e.dispose()

        def run_q(sql, **kw):
            return asyncio.run(q(sql, **kw))
    else:
        eng = sa.create_engine(url)

        def run_q(sql, **kw):
            with eng.connect() as conn:
                return conn.execute(sa.text(sql), kw).all()
    try:
        audit = run_q("SELECT count(*) FROM audit_logs WHERE action = 'alert_run_loaded' AND target_id = :r", r=run_id)
    except Exception as exc:
        c.add(s, "database reachable", "FAIL", f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}")
        return
    c.ok(s, "audit row for this alert run (committed, §36)", audit[0][0] == 1, str(audit[0][0]))
    fr = ctx["frames"]
    n = run_q("SELECT count(*), sum(CASE WHEN status = 'open' THEN 1 ELSE 0 END) FROM alerts WHERE alert_run_id = :r", r=run_id)[0]
    c.ok(s, "alert rows equal the run", (n[0], n[1]) == (len(fr[ALERTS_OUTPUT]), int((fr[ALERTS_OUTPUT]["status"] == "open").sum())),
         f"{n[0]} stored")
    nm = run_q("SELECT count(*) FROM alert_members m JOIN alerts a ON a.id = m.alert_id WHERE a.alert_run_id = :r", r=run_id)[0][0]
    c.ok(s, "member rows equal the run", nm == len(fr[MEMBERS_OUTPUT]), str(nm))
    nr = run_q("SELECT count(*) FROM alert_reasons x JOIN alerts a ON a.id = x.alert_id WHERE a.alert_run_id = :r", r=run_id)[0][0]
    c.ok(s, "reason rows equal the run (N50)", nr == len(fr[REASONS_OUTPUT]), str(nr))
    chain = run_q("""
        SELECT count(*),
               sum(CASE WHEN s.anomaly_score = r.anomaly_score THEN 1 ELSE 0 END),
               sum(CASE WHEN s.role = 'served' THEN 1 ELSE 0 END),
               sum(CASE WHEN mv.model_version = a.model_version AND s.model_version = a.model_version THEN 1 ELSE 0 END),
               sum(CASE WHEN r.cri_run_id = a.cri_run_id AND s.batch_run_id = a.batch_run_id THEN 1 ELSE 0 END),
               sum(CASE WHEN f.user_id = m.user_id AND f.activity_date = m.activity_date THEN 1 ELSE 0 END)
        FROM alerts a JOIN alert_members m ON m.alert_id = a.id
        JOIN risk_scores r ON r.id = m.risk_score_id JOIN anomaly_scores s ON s.id = r.anomaly_score_id
        JOIN feature_vectors f ON f.id = s.feature_vector_id JOIN model_versions mv ON mv.id = s.model_version_id
        WHERE a.alert_run_id = :r""", r=run_id)[0]
    total = chain[0]
    c.ok(s, "every member traces alert -> risk -> anomaly -> feature vector -> model version (§37)",
         total == len(fr[MEMBERS_OUTPUT]), f"{total} complete chains")
    c.ok(s, "risk and anomaly rows hold the same score, two values (N34)", chain[1] == total)
    c.ok(s, "only served scores (N32)", chain[2] == total)
    c.ok(s, "chain names the alert's model_version, batch and CRI run", chain[3] == total and chain[4] == total)
    c.ok(s, "feature vector is the member's own user-day", chain[5] == total)
    no_ev = run_q("""SELECT count(*) FROM alerts a JOIN alert_members m ON m.alert_id = a.id
        JOIN risk_scores r ON r.id = m.risk_score_id JOIN anomaly_scores s ON s.id = r.anomaly_score_id
        WHERE a.alert_run_id = :r AND NOT EXISTS (SELECT 1 FROM event_logs e WHERE e.feature_vector_id = s.feature_vector_id)""",
                  r=run_id)[0][0]
    c.ok(s, "every member day has its source events (§37)", no_ev == 0, f"{no_ev} member days without events", warn_only=True)
    if meta.get("mitre"):
        unl = run_q("""SELECT count(*) FROM alerts a JOIN alert_members m ON m.alert_id = a.id
            WHERE a.alert_run_id = :r AND NOT EXISTS (SELECT 1 FROM mitre_mappings x WHERE x.user_id = m.user_id
            AND x.activity_date = m.activity_date AND x.mitre_run_id = :mr AND x.alert_id IS NOT NULL)""",
                    r=run_id, mr=meta["mitre"]["mitre_run_id"])[0][0]
        c.ok(s, "ATT&CK rows of member days are linked to an alert", unl == 0,
             f"{unl} member days without a linked row (not_evaluated days have none)", warn_only=True)
    keys = [f"{meta['policy']['version']}:{meta['policy_hash']}", f"{meta['demo_sample']['rule']}:{run_id}"]
    got = {k for (k,) in run_q("SELECT key FROM configurations WHERE key IN (:a, :b)", a=keys[0], b=keys[1])}
    c.ok(s, "policy and demo-sample rule recorded in configuration (D-6)", got == set(keys), str(sorted(got)))
    files = run_q("SELECT files FROM model_versions WHERE model_version = :v", v=meta["served"]["model_version"])
    c.ok(s, "model version row carries the artifact sha256s (N21)", bool(files and files[0][0]))


def check_readout(c: Checks, args, run_dir: Path | None) -> None:
    s = "readout"
    path = Path(args.readout_path)
    if not path.exists():
        c.add(s, "validation readout present", "WARN", f"{path} not written yet; run `python -m app.alerts.evaluate`")
        return
    r = json.loads(path.read_text(encoding="utf-8"))
    c.ok(s, "validation only", r.get("part") == "validation")
    if run_dir is not None:
        c.ok(s, "readout is of this alert run", r.get("alert_run_id") == run_dir.name, r.get("alert_run_id"))
    c.ok(s, "both queue orderings read (N40)", "policy_view" in r and "other_ordering_view" in r)
    for w in r.get("guard", {}).get("warnings", []):
        c.add(s, r["guard"]["version"], "WARN", w)
    if not r.get("guard", {}).get("warnings"):
        c.ok(s, f"{r.get('guard', {}).get('version')}: no guard warning", True)


def _parse_args(argv):
    root = repo_root()
    p = argparse.ArgumentParser(description="Verify Chapter 12 (alert correlation and persistence)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--alert-run-id", default=None)
    p.add_argument("--database-url", default=None, help="also check the PostgreSQL load (sync or asyncpg URL)")
    p.add_argument("--readout-path", default=str(root / "experiments" / READOUT_FILE))
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter12"))
    p.add_argument("--no-readout", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    c = Checks()
    print("[verify chapter12]", flush=True)
    run_dir = None
    try:
        run_dir = alert_run_dir(Path(args.processed_dir), args.alert_run_id, args.profile)
    except AlertSourceError as exc:
        c.add("lineage", "alert run found", "FAIL", str(exc))
    if run_dir is not None:
        meta = read_meta(run_dir)
        c.ok("lineage", "alert run found", True, run_dir.name)
        policy = check_policy(c, meta)
        ctx = check_run(c, args, run_dir, meta, policy) if policy is not None else None
        if ctx is not None:
            check_explanations(c, run_dir, ctx)
            check_demo(c, run_dir, meta, ctx)
            if args.database_url:
                check_database(c, args.database_url, run_dir, meta, ctx)
    if not args.no_readout:
        check_readout(c, args, run_dir)
    counts = c.counts()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.results_dir) / f"verification_{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    rid = None if run_dir is None else run_dir.name
    out.write_text(json.dumps({"profile": args.profile, "alert_run_id": rid, "counts": counts, "checks": c.rows},
                              indent=2), encoding="utf-8")
    append_experiment_runlog({"stage": "chapter12_verification", "profile": args.profile, "alert_run_id": rid,
                              "database_checked": bool(args.database_url), "readout_checked": not args.no_readout,
                              "pass": counts["PASS"], "warn": counts["WARN"], "fail": counts["FAIL"],
                              "peak_rss_mb": round(memory_rss_mb(), 1)})
    print(f"[verify chapter12] {counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL -> {out}", flush=True)
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
