"""Verify Chapter 15: every test layer green, and each Architecture §45 item backed by a passing check.

Sections (each prints PASS, WARN or FAIL; exit code 1 on any FAIL):

    backend    pytest unit, integration and e2e, each with its own JUnit file.
               e2e must run (a skip is a FAIL: no PostgreSQL means no Chapter 15)
               and finish under a minute (HCEA §14, WARN otherwise).
    frontend   eslint, tsc + vite build, Vitest.
    browser    with --browser: builds the synthetic stack if needed, runs the
               Playwright click-through (journey + no-fabrication), tears down.
    cert       with --cert-username: the CERT full API on --cert-api-port is
               checked by scripts/verify_chapter13.py and, with --browser, by
               frontend/e2e/cert.spec.ts. Without it the CERT items are WARN.
    §45        the sixteen acceptance items, each mapped to the named tests
               that evidence it; an item passes only if all of them ran and passed.

Usage, from the repository root, with PostgreSQL reachable:

    $env:CIRA_E2E_DATABASE_URL = "postgresql+asyncpg://cira:<pw>@localhost:5433/postgres"
    python scripts/verify_chapter15.py --browser
    python scripts/verify_chapter15.py --browser --cert-username padmesh     # CERT API running on :8000

Writes experiments/results/chapter15/verification_<stamp>.json and .md and one
``chapter15_verification`` runlog line. Reads no label.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FRONTEND = REPO / "frontend"
sys.path.insert(0, str(REPO / "backend"))

# §45 item -> (description, [evidence]). Evidence names are "pytest:<file>::<test>" or "pw:<spec title prefix>".
ACCEPTANCE: list[tuple[str, list[str]]] = [
    ("1 project starts (API with its lifespan; dashboard builds)",
     ["pytest:test_ch15_api_journey.py::test_health_says_everything_the_dashboard_needs_is_ready", "frontend:build"]),
    ("2 migrations run", ["pytest:test_ch15_chain.py::test_the_database_was_migrated_to_head_by_alembic"]),
    ("3 events ingest", ["pytest:test_ch15_chain.py::test_the_traced_row_is_a_line_of_the_raw_csv",
                         "pytest:test_ch15_chain.py::test_chapter3_and_chapter4_normalize_the_row_as_stage0_stored_it"]),
    ("4 events normalize", ["pytest:test_ch15_chain.py::test_chapter3_and_chapter4_normalize_the_row_as_stage0_stored_it"]),
    ("5 features generate", ["pytest:test_ch15_chain.py::test_the_user_day_feature_counts_the_raw_rows"]),
    ("6 TabNet trains and evaluates (shadow; XGBoost is served, C8-1)",
     ["pytest:test_ch15_chain.py::test_the_served_model_scored_the_day_and_tabnet_scored_it_as_shadow",
      "pytest:test_ch15_chain.py::test_the_shadow_score_reaches_nothing_downstream"]),
    ("7 inference produces a score", ["pytest:test_ch15_chain.py::test_score_event_reproduces_the_batch_with_its_model_version",
                                      "pytest:test_ch15_chain.py::test_a_missing_model_is_an_error_not_a_score"]),
    ("8 CRI converts it to contextual risk", ["pytest:test_ch15_chain.py::test_the_cri_row_carries_the_same_anomaly_score_and_a_band"]),
    ("9 MITRE context attaches where relevant",
     ["pytest:test_ch15_chain.py::test_the_mitre_layer_evaluated_the_day_and_every_match_is_traceable"]),
    ("10 an explanation generates", ["pytest:test_ch15_chain.py::test_the_explanation_adds_up_to_the_served_score"]),
    ("11 an alert persists", ["pytest:test_ch15_chain.py::test_the_day_is_a_member_of_the_traced_alert",
                              "pytest:test_ch15_chain.py::test_postgres_holds_the_whole_lineage_by_foreign_keys",
                              "pytest:test_ch15_failure_modes.py::test_a_connection_lost_mid_load_rolls_everything_back"]),
    ("12 FastAPI exposes it", ["pytest:test_ch15_api_journey.py::test_what_happened_the_queue_starts_with_the_traced_alert",
                               "pytest:test_ch15_api_journey.py::test_what_to_investigate_the_raw_event_is_in_the_users_timeline",
                               "pytest:test_ch15_failure_modes.py::test_a_database_cut_is_a_visible_503_and_the_api_recovers_without_restart"]),
    ("13 React displays it", ["pw:User investigation: the traced raw CSV row", "pw:Alerts: what happened",
                              "pw:with the API unreachable"]),
    ("14 an analyst can understand why", ["pytest:test_ch15_api_journey.py::test_why_risky_explanation_is_the_stored_one",
                                          "pw:Explainability: why risky", "pw:Alert details: how risky"]),
    ("15 tests cover core components", ["layer:unit", "layer:integration", "layer:e2e", "frontend:vitest"]),
    ("16 evaluation metrics are reproducible (fixture; CERT is Chapter 16)",
     ["pytest:test_ch15_chain.py::test_training_is_reproducible_on_the_fixture"]),
]


class Checks:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, section: str, name: str, status: str, detail: str = "") -> str:
        self.rows.append({"section": section, "check": name, "status": status, "detail": detail})
        print(f"  {status:<4} {section:<9} {name}" + (f"  -- {detail}" if detail else ""), flush=True)
        return status

    def ok(self, section, name, cond, detail="", warn_only=False) -> bool:
        self.add(section, name, "PASS" if cond else ("WARN" if warn_only else "FAIL"), detail)
        return bool(cond)

    def counts(self) -> dict:
        return {s: sum(r["status"] == s for r in self.rows) for s in ("PASS", "WARN", "FAIL")}


def run(cmd: list[str], cwd: Path, env: dict | None = None, timeout: int = 1800) -> tuple[int, str, float]:
    t0 = time.perf_counter()
    exe = shutil.which(cmd[0]) or cmd[0]
    # UTF-8 both ways: Windows would otherwise decode the children's output as cp1252 and garble it.
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "FORCE_COLOR": "0", "NO_COLOR": "1", **(env or {})}
    p = subprocess.run([exe, *cmd[1:]], cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=timeout)
    return p.returncode, (p.stdout + p.stderr)[-4000:], time.perf_counter() - t0


def junit(path: Path) -> dict:
    """{tests, failures, errors, skipped, seconds, results: {file::name: passed|failed|skipped}}."""
    if not path.exists():
        return {"tests": 0, "failures": 0, "errors": 1, "skipped": 0, "seconds": 0.0, "results": {}}
    root = ET.parse(path).getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    results, failed = {}, {}
    for tc in suite.iter("testcase"):
        file = (tc.get("file") or tc.get("classname", "").replace(".", "/")).split("/")[-1]
        file = file if file.endswith(".py") else file + ".py"
        bad = tc.find("failure") if tc.find("failure") is not None else tc.find("error")
        state = "failed" if bad is not None else "skipped" if tc.find("skipped") is not None else "passed"
        key = f"{file}::{tc.get('name')}"
        results[key] = state
        if bad is not None:
            failed[key] = (bad.get("message") or (bad.text or "")).strip().splitlines()[0][:220] if \
                (bad.get("message") or bad.text) else ""
    return {k: int(suite.get(k, 0)) for k in ("tests", "failures", "errors", "skipped")} | \
        {"seconds": float(suite.get("time", 0)), "results": results, "failed": failed}


def backend(c: Checks, out: Path, args) -> dict:
    layers = {}
    for layer in ("unit", "integration", "e2e"):
        xml = out / f"junit_{layer}.xml"
        rc, tail, secs = run([sys.executable, "-m", "pytest", f"backend/tests/{layer}", "-q", "-p", "no:cacheprovider",
                              f"--junitxml={xml}"], REPO)
        j = junit(xml)
        layers[layer] = j | {"exit_code": rc, "wall_seconds": round(secs, 1)}
        bad = j["failures"] + j["errors"]
        detail = f"{j['tests'] - j['skipped'] - bad} passed, {bad} failed, {j['skipped']} skipped, {secs:.0f} s"
        if layer == "e2e":
            c.ok("backend", "e2e: raw CSV -> PostgreSQL -> API, all ran and passed",
                 rc == 0 and bad == 0 and j["skipped"] == 0 and j["tests"] > 0, detail if j["skipped"] == 0 else
                 detail + " (a skip means no PostgreSQL: set CIRA_E2E_DATABASE_URL or start Docker)")
            c.ok("backend", "e2e under a minute (HCEA §14)", j["seconds"] < 60, f"{j['seconds']:.1f} s in pytest",
                 warn_only=True)
        elif layer == "integration":
            c.ok("backend", "integration green", rc == 0 and bad == 0, detail)
            pg = j["results"].get("test_ch13_api.py::test_database_is_postgres")
            c.ok("backend", "integration tests hit PostgreSQL (test_database_is_postgres ran)", pg == "passed",
                 f"{pg}; set CIRA_TEST_DATABASE_URL or start Docker" if pg != "passed" else "", warn_only=True)
        else:
            c.ok("backend", "unit green", rc == 0 and bad == 0, detail)
        for name, msg in list(j["failed"].items())[:8]:          # name every failure, not just the count
            print(f"         {layer} failed: {name}\n             {msg}", flush=True)
    return layers


def frontend(c: Checks) -> dict:
    res = {}
    for name, cmd in (("lint", ["npm", "run", "lint"]), ("build", ["npm", "run", "build"]), ("vitest", ["npm", "test"])):
        rc, tail, secs = run(cmd, FRONTEND)
        res[name] = {"exit_code": rc, "seconds": round(secs, 1)}
        c.ok("frontend", name, rc == 0, "" if rc == 0 else tail[-300:].replace("\n", " "))
    return res


def playwright_results() -> dict[str, str]:
    path = FRONTEND / "test-results" / "e2e-report.json"
    if not path.exists():
        return {}
    out: dict[str, str] = {}

    def walk(suite):
        for s in suite.get("suites", []):
            walk(s)
        for spec in suite.get("specs", []):
            states = [r.get("status") for t in spec.get("tests", []) for r in t.get("results", [])]
            out[spec["title"]] = "passed" if states and all(x == "passed" for x in states) else \
                "skipped" if not states or all(x == "skipped" for x in states) else "failed"

    for s in json.loads(path.read_text(encoding="utf-8")).get("suites", []):
        walk(s)
    return out


def playwright_errors(limit: int = 2) -> list[str]:
    """The first error message of each failed test in frontend/test-results/e2e-report.json, without colour codes."""
    import re

    path = FRONTEND / "test-results" / "e2e-report.json"
    if not path.exists():
        return []
    out: list[str] = []

    def walk(suite):
        for s in suite.get("suites", []):
            walk(s)
        for spec in suite.get("specs", []):
            for t in spec.get("tests", []):
                for r in t.get("results", []):
                    for e in ([r.get("error")] if r.get("error") else []) + r.get("errors", []):
                        msg = re.sub(r"\x1b\[[0-9;]*m", "", (e or {}).get("message", "")).strip()
                        if msg and msg not in out:
                            out.append(" ".join(msg.split())[:400])

    for s in json.loads(path.read_text(encoding="utf-8")).get("suites", []):
        walk(s)
    return out[:limit]


def sign_in_works(port: int, username: str, password: str) -> tuple[bool, str]:
    """POST /auth/token once, so a refused login is reported as that and not as two unrelated failures."""
    import urllib.error
    import urllib.parse
    import urllib.request

    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/auth/token", data=data, timeout=15) as r:
            return r.status == 200, ""
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:200]}"
    except OSError as e:
        return False, f"API not reachable on port {port}: {e}"


def browser(c: Checks, args) -> dict[str, str]:
    manifest = REPO / ".e2e" / "stack.json"
    built_here = False
    if not manifest.exists():
        if not os.getenv("CIRA_E2E_DATABASE_URL"):
            c.add("browser", "synthetic stack", "FAIL", "set CIRA_E2E_DATABASE_URL so the stack outlives `build`")
            return {}
        rc, tail, _ = run([sys.executable, "scripts/e2e_stack.py", "build"], REPO)
        if not c.ok("browser", "synthetic stack built", rc == 0, tail[-300:].replace("\n", " ") if rc else ""):
            return {}
        built_here = True
    env = {"CIRA_PYTHON": sys.executable}
    # File filters are regexes on the spec path; names without a directory match on Windows and Linux alike.
    rc, tail, secs = run(["npx", "playwright", "test", "journey.spec", "no-fabrication.spec"], FRONTEND,
                         env, timeout=1200)
    pw = {k: v for k, v in playwright_results().items() if not k.startswith("CERT:")}
    passed = sum(v == "passed" for v in pw.values())
    detail = f"{passed}/{len(pw)} passed in {secs:.0f} s; screenshots frontend/test-results/ch15-run-through/"
    if not pw or rc != 0:                       # say why, instead of "0/0"
        detail += " | playwright: " + (" | ".join(playwright_errors()) or " ".join(tail.strip().splitlines()[-6:])[-500:])
    c.ok("browser", "Playwright click-through (journey + no-fabrication)", rc == 0 and pw and passed == len(pw), detail)
    if built_here and not args.keep_stack:
        run([sys.executable, "scripts/e2e_stack.py", "teardown"], REPO)
    return pw


def cert(c: Checks, args, out: Path) -> dict:
    if not args.cert_username:
        c.add("cert", "CERT full API and dashboard", "WARN", "not run: pass --cert-username with the CERT API "
              "running; Chapter 15 is IMPLEMENTED only after this passes on the development machine")
        return {"ran": False}
    pw = args.cert_password or os.getenv("CIRA_ANALYST_PASSWORD") or getpass.getpass("CERT analyst password: ")
    ok, why = sign_in_works(args.cert_api_port, args.cert_username, pw)
    if not c.ok("cert", f"analyst {args.cert_username} signs in to the CERT API", ok,
                why + (" -- wrong password, unknown username or inactive account; see audit_logs" if "401" in why else "")):
        return {"ran": True, "sign_in": False}
    env = {"CIRA_ANALYST_PASSWORD": pw}
    rc, tail, _ = run([sys.executable, "../scripts/verify_chapter13.py", "--username", args.cert_username,
                       "--base-url", f"http://127.0.0.1:{args.cert_api_port}", "--results-dir", str(out),
                       *(["--database-url", args.cert_database_url] if args.cert_database_url else [])],
                      REPO / "backend", env)
    fails = [ln.strip() for ln in tail.splitlines() if ln.strip().startswith("FAIL")]
    c.ok("cert", "verify_chapter13 against the CERT API (0 FAIL)", rc == 0,
         " | ".join(fails[:4]) or (tail.strip().splitlines()[-1] if tail.strip() else ""))
    res = {"ran": True, "chapter13_exit": rc}
    if args.browser:
        env = {"CIRA_E2E_API_PORT": str(args.cert_api_port), "CIRA_CERT_USERNAME": args.cert_username,
               "CIRA_CERT_PASSWORD": pw, "CIRA_PYTHON": sys.executable}
        rc, tail, secs = run(["npx", "playwright", "test", "cert.spec"], FRONTEND, env, timeout=1200)
        c.ok("cert", "dashboard on CERT: values from the API, top alerts reproduce, nothing survives the API",
             rc == 0, f"{secs:.0f} s; screenshots frontend/test-results/ch15-cert/" if rc == 0 else
             " | ".join(playwright_errors()) + " (failure screenshot and trace under frontend/test-results/)")
        res["dashboard_exit"] = rc
    return res


def acceptance(c: Checks, layers: dict, fe: dict, pw: dict[str, str], browser_ran: bool) -> list[dict]:
    pytest_results = {}
    for layer in layers.values():
        pytest_results.update(layer["results"])
    out = []
    for item, evidence in ACCEPTANCE:
        states = []
        for e in evidence:
            kind, _, key = e.partition(":")
            if kind == "pytest":
                states.append((e, pytest_results.get(key, "missing")))
            elif kind == "pw":
                hit = [v for k, v in pw.items() if k.startswith(key)]
                states.append((e, hit[0] if hit else ("missing" if browser_ran else "not run")))
            elif kind == "frontend":
                states.append((e, "passed" if fe.get(key, {}).get("exit_code") == 0 else "failed"))
            elif kind == "layer":
                ly = layers.get(key) or fe.get(key)
                good = ly is not None and ly.get("exit_code") == 0 and (key != "e2e" or ly.get("skipped") == 0)
                states.append((e, "passed" if good else "failed"))
        if all(s == "passed" for _, s in states):
            status = "PASS"
        elif all(s in ("passed", "not run") for _, s in states):
            status = "WARN"
        else:
            status = "FAIL"
        c.add("§45", item, status, "; ".join(f"{e.split(':', 1)[1].split('::')[-1]}={s}" for e, s in states
                                            if s != "passed"))
        out.append({"item": item, "status": status, "evidence": dict(states)})
    return out


def markdown(report: dict) -> str:
    lines = [f"# Chapter 15 verification {report['stamp']}", "",
             f"Result: {report['counts']['PASS']} PASS, {report['counts']['WARN']} WARN, {report['counts']['FAIL']} FAIL.",
             "", "| Section | Check | Status | Detail |", "|---|---|---|---|"]
    lines += [f"| {r['section']} | {r['check']} | {r['status']} | {r['detail'].replace('|', '/')} |" for r in report["checks"]]
    lines += ["", "Generated by scripts/verify_chapter15.py. Every row above was produced by the run, not written by hand."]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Chapter 15 verification")
    p.add_argument("--browser", action="store_true", help="run the Playwright click-through as well")
    p.add_argument("--keep-stack", action="store_true", help="keep the synthetic stack the browser step built")
    p.add_argument("--cert-username", default=None, help="analyst on the CERT full API (development machine)")
    p.add_argument("--cert-password", default=None)
    p.add_argument("--cert-api-port", type=int, default=8000)
    p.add_argument("--cert-database-url", default=None, help="passed to verify_chapter13 for its database checks")
    p.add_argument("--results-dir", default=str(REPO / "experiments" / "results" / "chapter15"))
    args = p.parse_args(argv)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.results_dir)
    out.mkdir(parents=True, exist_ok=True)
    c = Checks()
    t0 = time.perf_counter()
    print("[ch15] backend")
    layers = backend(c, out, args)
    print("[ch15] frontend")
    fe = frontend(c)
    pw: dict[str, str] = {}
    if args.browser:
        print("[ch15] browser")
        pw = browser(c, args)
    print("[ch15] cert")
    cert_res = cert(c, args, out)
    print("[ch15] §45 acceptance")
    items = acceptance(c, layers, fe, pw, args.browser)

    counts = c.counts()
    report = {"stamp": stamp, "counts": counts, "checks": c.rows, "acceptance": items, "cert": cert_res,
              "backend": {k: {kk: vv for kk, vv in v.items() if kk != "results"} for k, v in layers.items()},  # keeps "failed"
              "frontend": fe, "playwright": pw, "wall_seconds": round(time.perf_counter() - t0, 1)}
    (out / f"verification_{stamp}.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    (out / f"verification_{stamp}.md").write_text(markdown(report), encoding="utf-8")
    try:
        from app.feature_engineering.common import append_experiment_runlog

        append_experiment_runlog({"stage": "chapter15_verification", "stamp": stamp, "counts": counts,
                                  "browser": args.browser, "cert": cert_res.get("ran", False),
                                  "wall_seconds": report["wall_seconds"]})
    except Exception as exc:                                   # the report is already written
        print(f"runlog not written: {exc}", file=sys.stderr)
    print(f"\n[ch15] {counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL; "
          f"report {out / f'verification_{stamp}.md'}")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
