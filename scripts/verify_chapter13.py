"""Verify Chapter 13 against a running API, before the dashboard relies on it.

Sections (each prints PASS, WARN or FAIL per check; exit code 1 on any FAIL):

    health     /health and /api/v1/health answer; the model, database and auth
               blocks are up; every route group says it is ready
    auth       a wrong password and a missing token are refused (401); the
               analyst can sign in and read /users/me
    contract   the OpenAPI document: every API group present, every list
               paginated with the hard cap (HCEA §13), no score called a
               probability (N20)
    queue      the queue is the served run's open alerts, ordered by the
               policy's score (N55), counts open and suppressed together (N57),
               suppressed repeats attach to open alerts (N60), no in-sample
               alert (WARN, N31), the cap is enforced
    alerts     for the top --sample open alerts: one peak, every member
               triggered, explanation sections kept apart and equal to the
               alert_reasons rows (N50), ATT&CK techniques match the alert (N45)
    scoring    the same alerts' peak days scored again through the API from
               their stored feature vectors reproduce the stored anomaly score
               and CRI (§37 lineage, N34); nothing is written; latency
    database   with --database-url: the run the API serves has its
               alert_run_loaded audit row (N58) and the stored counts

Usage, from backend/, with the API running (uvicorn app.main:app) and an
analyst created with `python -m app.services.accounts create`:

    CIRA_ANALYST_PASSWORD=... python ../scripts/verify_chapter13.py --username alice
    python ../scripts/verify_chapter13.py --username alice --database-url "$DATABASE_URL"

Writes ``experiments/results/chapter13/verification_<stamp>.json`` and one
``chapter13_verification`` runlog line. Reads no label.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import argparse  # noqa: E402
import asyncio  # noqa: E402
import getpass  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import time  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

GROUPS = {"auth", "users", "events", "features", "anomaly", "risk", "alerts", "investigations", "mitre",
          "explanations", "models", "health"}
MAX_LIMIT = 200


class Checks:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, section, name, status, detail="") -> None:
        self.rows.append({"section": section, "check": name, "status": status, "detail": detail})
        print(f"  {status:<4} {section:<10} {name}" + (f"  -- {detail}" if detail else ""), flush=True)

    def ok(self, section, name, cond, detail="", warn_only=False) -> bool:
        self.add(section, name, "PASS" if cond else ("WARN" if warn_only else "FAIL"), detail)
        return bool(cond)

    def counts(self) -> dict:
        return {s: sum(1 for r in self.rows if r["status"] == s) for s in ("PASS", "WARN", "FAIL")}


def check_health(c: Checks, client) -> dict | None:
    r1, r2 = client.get("/health"), client.get("/api/v1/health")
    if not c.ok("health", "/health and /api/v1/health answer 200", r1.status_code == r2.status_code == 200,
                f"{r1.status_code}, {r2.status_code}"):
        return None
    h = r2.json()
    c.ok("health", "anomaly model loaded", h["anomaly_model"]["status"] == "loaded",
         (h["anomaly_model"].get("served") or {}).get("model_version") or h["anomaly_model"].get("reason"))
    c.ok("health", "database reachable", h["database"]["status"] == "reachable",
         str(h["database"].get("alembic_revision") or h["database"].get("reason")))
    c.ok("health", "auth configured", h["auth"]["status"] == "configured", h["auth"].get("reason") or "")
    for block in ("cri", "mitre", "explainability"):
        c.ok("health", f"{block} loaded", h[block]["status"] == "loaded", h[block].get("reason") or "", warn_only=True)
    not_ready = {k: v["reason"] for k, v in h["routes"].items() if not v["ready"]}
    c.ok("health", "every route group ready", not not_ready, json.dumps(not_ready)[:300])
    return h


def login(c: Checks, client, username: str, password: str) -> dict | None:
    bad = client.post("/api/v1/auth/token", data={"username": username, "password": password + "-wrong"})
    c.ok("auth", "wrong password refused", bad.status_code == 401, str(bad.status_code))
    anon = client.get("/api/v1/alerts")
    c.ok("auth", "no token refused", anon.status_code == 401, str(anon.status_code))
    r = client.post("/api/v1/auth/token", data={"username": username, "password": password})
    if not c.ok("auth", "analyst signs in", r.status_code == 200, r.text[:200] if r.status_code != 200 else ""):
        return None
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    me = client.get("/api/v1/users/me", headers=headers)
    c.ok("auth", "/users/me is the analyst", me.status_code == 200 and me.json().get("username") == username)
    return headers


def check_contract(c: Checks, client) -> None:
    o = client.get("/openapi.json").json()
    groups = {p.split("/")[3] for p in o["paths"] if p.startswith("/api/v1/")}
    c.ok("contract", "every API group present (Architecture §25)", groups == GROUPS, str(sorted(GROUPS ^ groups)))
    caps = []
    for path, ops in o["paths"].items():
        for op in ops.values():
            for p in op.get("parameters", []):
                if p["name"] == "limit":
                    caps.append((path, p["schema"].get("maximum")))
    c.ok("contract", "every limit has the hard cap", caps and all(m == MAX_LIMIT for _, m in caps), str(caps))
    text = str(o)
    bad = [text[max(0, m.start() - 40):m.end()] for m in re.finditer("probabilit", text)
           if not re.search(r"not (a )?$", text[max(0, m.start() - 8):m.start()])]
    c.ok("contract", "no score described as a probability (N20)", not bad, str(bad[:2]))


def all_alerts(client, headers, status: str) -> list[dict]:
    out, offset = [], 0
    while True:
        page = client.get("/api/v1/alerts", params={"status": status, "limit": MAX_LIMIT, "offset": offset},
                          headers=headers).json()
        out += page["items"]
        offset += MAX_LIMIT
        if offset >= page["page"]["total"]:
            return out


def check_queue(c: Checks, client, headers) -> tuple[dict, list[dict]]:
    first = client.get("/api/v1/alerts", headers=headers).json()
    open_, sup = all_alerts(client, headers, "open"), all_alerts(client, headers, "suppressed")
    counts = first["counts"]
    c.ok("queue", "counts open and suppressed together (N57)", counts == {"open": len(open_), "suppressed": len(sup)},
         f"{counts}")
    c.ok("queue", "ordered by the policy's score (N55)", first["queue"]["ordered_by"] == "anomaly_score" and
         [a["queue_score"] for a in open_] == sorted((a["queue_score"] for a in open_), reverse=True),
         f"{first['queue']['ordered_by']}, policy {first['queue']['policy_hash']}")
    c.ok("queue", "both scores on every alert (N34)",
         all(a["peak_anomaly_score"] is not None and a["max_cri_score"] is not None for a in open_))
    ids = {a["id"] for a in open_}
    c.ok("queue", "suppressed alerts attach to open alerts (N57, N60)",
         all(s["duplicate_of_id"] in ids for s in sup) and sum(a["suppressed"]["count"] for a in open_) == len(sup),
         f"{len(sup)} suppressed")
    insample = [a["id"] for a in open_ if a["in_sample"]]
    c.ok("queue", "no in-sample alert (N31)", not insample, f"{len(insample)} alerts from training users", warn_only=True)
    over = client.get("/api/v1/alerts", params={"limit": MAX_LIMIT + 1}, headers=headers)
    c.ok("queue", "the cap is enforced (HCEA §13)", over.status_code == 422, str(over.status_code))
    return first, open_


def check_alerts(c: Checks, client, headers, sample: list[dict]) -> None:
    problems = []
    for a in sample:
        d = client.get(f"/api/v1/alerts/{a['id']}", headers=headers).json()
        if sum(m["is_peak"] for m in d["members"]) != 1 or not all(m["by_band"] or m["by_top_k"] for m in d["members"]):
            problems.append(f"{a['id']}: members")
        e = client.get(f"/api/v1/explanations/alerts/{a['id']}", headers=headers).json()
        for m in e["members"]:
            s, rr = m["sections"], m["reason_rows"]
            kinds_ok = (all(f["source"]["kind"] == "model" for f in s["model"] + s["model_lowering"])
                        and all(x["source"]["kind"] == "cri" for x in s["cri"]))
            n_mitre = len((s["mitre"] or {}).get("matches", []))
            rows_ok = (rr.get("model", 0), rr.get("model_lowering", 0), rr.get("cri", 0), rr.get("mitre", 0)) == \
                (len(s["model"]), len(s["model_lowering"]), len(s["cri"]), n_mitre)
            if not (kinds_ok and rows_ok):
                problems.append(f"{a['id']} {m['activity_date']}: sections")
        mt = client.get(f"/api/v1/mitre/alerts/{a['id']}", headers=headers).json()
        if {t["technique_id"] for t in mt["techniques"]} != set(a["techniques"]):
            problems.append(f"{a['id']}: techniques")
    c.ok("alerts", f"{len(sample)} alerts: members, explanation sections, ATT&CK (N45, N50)", not problems,
         "; ".join(problems[:5]))


def check_scoring(c: Checks, client, headers, sample: list[dict]) -> list[float]:
    worst_a = worst_c = 0.0
    timings, failures = [], []
    for a in sample:
        u, d = a["user_id"], a["peak_date"]
        fv = client.get(f"/api/v1/features/users/{u}/days/{d}", headers=headers).json()
        stored = client.get(f"/api/v1/risk/users/{u}/days/{d}", headers=headers).json()
        features = {v["column"]: v["value"] for v in fv["values"]}
        t0 = time.perf_counter()
        r = client.post("/api/v1/risk/score", json={"user_id": u, "date": d, "features": features,
                                                    "role": stored.get("ldap_role")}, headers=headers)
        timings.append(time.perf_counter() - t0)
        if r.status_code != 200 or r.json()["risk"] is None:
            failures.append(f"{u} {d}: {r.status_code} {r.text[:120]}")
            continue
        body = r.json()
        worst_a = max(worst_a, abs(body["anomaly"]["anomaly_score"] - stored["anomaly_score"]))
        worst_c = max(worst_c, abs(body["risk"]["cri_score"] - stored["cri_score"]))
    c.ok("scoring", "on-demand scoring answers", not failures, "; ".join(failures[:3]))
    c.ok("scoring", "anomaly score reproduces the stored one", worst_a <= 1e-9, f"max |diff| {worst_a:.2e}")
    c.ok("scoring", "CRI reproduces the stored one (N34)", worst_c <= 1e-6, f"max |diff| {worst_c:.2e}")
    return timings


def check_database(c: Checks, url: str, run_id: str, counts: dict) -> None:
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import create_async_engine

    async def go():
        eng = create_async_engine(url)
        try:
            async with eng.connect() as conn:
                audit = (await conn.execute(sa.text("SELECT count(*) FROM audit_logs WHERE action = 'alert_run_loaded' "
                                                    "AND target_id = :r"), {"r": run_id})).scalar()
                rows = dict((await conn.execute(sa.text("SELECT status, count(*) FROM alerts WHERE alert_run_id = :r "
                                                        "GROUP BY status"), {"r": run_id})).all())
            return audit, rows
        finally:
            await eng.dispose()

    try:
        audit, rows = asyncio.run(go())
    except Exception as exc:
        c.add("database", "database readable", "FAIL", f"{type(exc).__name__}: {exc}")
        return
    c.ok("database", "served run has its alert_run_loaded audit row (N58)", audit == 1, f"{run_id}: {audit}")
    c.ok("database", "stored counts equal the API's", {k: int(v) for k, v in rows.items()} ==
         {k: v for k, v in counts.items() if v}, f"{rows}")


def verify(client, args, password: str) -> tuple[Checks, dict]:
    c = Checks()
    info: dict = {}
    h = check_health(c, client)
    headers = login(c, client, args.username, password)
    check_contract(c, client)
    if headers is None or h is None:
        return c, info
    first, open_ = check_queue(c, client, headers)
    info["alert_run_id"] = first["run"]["alert_run_id"]
    info["policy_hash"] = first["run"]["policy_hash"]
    info["served_model"] = first["run"]["model_version"]
    c.ok("queue", "the run /health reports is the run the queue serves",
         h["routes"]["alerts_risk_investigations"].get("alert_run_id") == info["alert_run_id"], info["alert_run_id"])
    sample = open_[:args.sample]
    check_alerts(c, client, headers, sample)
    timings = check_scoring(c, client, headers, sample)
    if timings:
        info["risk_score_seconds"] = {"median": sorted(timings)[len(timings) // 2], "max": max(timings),
                                      "n": len(timings)}
    if args.database_url:
        check_database(c, args.database_url, info["alert_run_id"], first["counts"])
    return c, info


def _parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--base-url", default="http://localhost:8000")
    p.add_argument("--username", required=True)
    p.add_argument("--sample", type=int, default=10, help="open alerts checked in depth and re-scored (default 10)")
    p.add_argument("--database-url", default=None)
    p.add_argument("--results-dir", default=str(Path(__file__).resolve().parents[1] / "experiments" / "results" /
                                                "chapter13"))
    p.add_argument("--timeout", type=float, default=60.0)
    return p.parse_args(argv)


def main(argv=None, client=None) -> int:
    import httpx
    from app.feature_engineering.common import append_experiment_runlog

    args = _parse_args(argv)
    password = os.environ.get("CIRA_ANALYST_PASSWORD") or getpass.getpass("analyst password: ")
    print(f"[verify chapter13] {args.base_url if client is None else 'in-process client'}", flush=True)
    own = client is None
    client = client or httpx.Client(base_url=args.base_url, timeout=args.timeout)
    try:
        c, info = verify(client, args, password)
    finally:
        if own:
            client.close()
    counts = c.counts()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.results_dir) / f"verification_{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({**info, "counts": counts, "checks": c.rows}, indent=2, default=str), encoding="utf-8")
    append_experiment_runlog({"stage": "chapter13_verification", **info, "database_checked": bool(args.database_url),
                              "pass": counts["PASS"], "warn": counts["WARN"], "fail": counts["FAIL"]})
    print(f"[verify chapter13] {counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL -> {out}", flush=True)
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
