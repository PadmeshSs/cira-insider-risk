"""Verify Chapter 16: tests green, regression gate held, and the CERT test readout complete, traceable and reproducible.

Sections (each check prints PASS, WARN or FAIL; exit code 1 on any FAIL):

    backend     pytest unit, integration and e2e (the N70 regression gate), each with its own JUnit file; the
                Chapter 16 tests must have run. An e2e skip is a FAIL (no PostgreSQL means no regression gate),
                unless --skip-e2e is given, which is itself a WARN.
    readout     experiments/chapter16_test_readout.json: written once, full profile, test part, every
                experiment present, harness checks not failed, seeds complete, lineage consistent with the
                Chapter 8 decision and the alert run, deviations and disclosures stated, no accuracy anywhere.
                Without the file every check here is a WARN and Chapter 16 stays PARTIALLY IMPLEMENTED (N75).
    report      experiments/chapter16_evaluation_report.md equals the report regenerated from the readout, byte
                for byte: no number in it lacks a stored run.
    recompute   with --recompute (needs CERT_PROCESSED_DIR): every ranking is loaded again from the stored runs
                and its PR-AUC on the readout's part must equal the readout's value. Metrics are reproducible
                from stored scores (Architecture §45 item 16, on CERT).
    notes       docs/CARRY_FORWARD.md has N75-N80 and the table rows; the README row and the audit exist.

Usage, from the repository root:

    python scripts/verify_chapter16.py                       # tests + the checks the files on disk allow
    python scripts/verify_chapter16.py --recompute           # with CERT_PROCESSED_DIR set, the full check
    python scripts/verify_chapter16.py --skip-e2e            # no PostgreSQL here (WARN)

Writes experiments/results/chapter16/verification_<stamp>.json and .md and one ``chapter16_verification``
runlog line. Reads no label itself; --recompute reads them through the evaluation modules.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))
sys.path.insert(0, str(REPO / "scripts"))

from verify_chapter15 import Checks, junit, run  # noqa: E402

READOUT = REPO / "experiments" / "chapter16_test_readout.json"
REPORT = REPO / "experiments" / "chapter16_evaluation_report.md"
NOTES = [f"N{n}" for n in range(75, 81)]
CH16_TESTS = ("test_ch16_evaluation.py", "test_ch16_pipeline.py")
CHAIN_STAGES = ("baseline (best on validation)", "TabNet (shadow, behaviour-only)", "XGBoost (served, behaviour-only)",
                "XGBoost + CRI", "XGBoost + CRI + MITRE")


def backend(c: Checks, out: Path, args) -> None:
    ran = {}
    for layer in ("unit", "integration", "e2e"):
        if layer == "e2e" and args.skip_e2e:
            c.add("backend", "e2e regression gate (N70)", "WARN", "skipped by --skip-e2e: run it before calling Chapter 16 done")
            continue
        xml = out / f"junit_{layer}.xml"
        rc, tail, secs = run([sys.executable, "-m", "pytest", f"backend/tests/{layer}", "-q", "-p", "no:cacheprovider",
                              f"--junitxml={xml}"], REPO)
        j = junit(xml)
        bad = j["failures"] + j["errors"]
        detail = f"{j['tests'] - j['skipped'] - bad} passed, {bad} failed, {j['skipped']} skipped, {secs:.0f} s"
        if layer == "e2e":
            c.ok("backend", "e2e regression gate (N70): all ran and passed", rc == 0 and bad == 0 and j["skipped"] == 0 and j["tests"] > 0,
                 detail + ("" if j["skipped"] == 0 else " (a skip means no PostgreSQL: set CIRA_E2E_DATABASE_URL)"))
            c.ok("backend", "e2e under a minute (HCEA §14)", j["seconds"] < 60, f"{j['seconds']:.1f} s", warn_only=True)
        else:
            c.ok("backend", f"{layer} tests green", rc == 0 and bad == 0 and j["tests"] > 0, detail)
        for k, v in j.get("results", {}).items():
            ran[k] = v
        if bad:
            for k, msg in list(j.get("failed", {}).items())[:5]:
                print(f"       {k}: {msg}")
    for f in CH16_TESTS:
        mine = {k: v for k, v in ran.items() if k.startswith(f)}
        c.ok("backend", f"{f} ran and passed", bool(mine) and all(v == "passed" for v in mine.values()),
             f"{sum(v == 'passed' for v in mine.values())} of {len(mine)} passed")


def readout(c: Checks, args) -> dict | None:
    if not READOUT.exists():
        for name in ("test readout written (pinned once)", "every experiment present", "harness checks",
                     "seed runs complete", "lineage consistent"):
            c.add("readout", name, "WARN", f"{READOUT.relative_to(REPO)} does not exist: Chapter 16 stays PARTIALLY IMPLEMENTED (N75)")
        return None
    r = json.loads(READOUT.read_text(encoding="utf-8"))
    c.ok("readout", "part is test, profile is full, version c16-readout-v1",
         (r.get("part"), r.get("profile"), r.get("version")) == ("test", "full", "c16-readout-v1"), str((r.get("part"), r.get("profile"))))
    c.ok("readout", "reportable", bool(r.get("reportable")))
    log = [json.loads(x) for x in (REPO / "experiments" / "runlog.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()] \
        if (REPO / "experiments" / "runlog.jsonl").exists() else []
    pinned = [x for x in log if x.get("stage") == "chapter16_readout" and x.get("pinned")]
    c.ok("readout", "a pinned chapter16_readout line in the runlog names this run", any(x.get("run_id") == r.get("run_id") for x in pinned),
         f"{len(pinned)} pinned readouts logged" + ("; the file was superseded once or more" if r.get("supersedes") else ""))
    c.ok("readout", "every chain stage present", [x["stage"] for x in r.get("chain", [])] == list(CHAIN_STAGES))
    exp = r.get("experiments", {})
    c.ok("readout", "experiments C, D, E1, E2 and A/B/E3 present",
         all(k in exp for k in ("C", "D", "E1_alert_queue", "E2_explanations", "A_B_E3_seeds")))
    bad = [h["check"] for h in r.get("harness", []) if h["ok"] is False]
    na = [h["check"] for h in r.get("harness", []) if h["ok"] is None]
    c.ok("readout", "no harness check failed", not bad, "; ".join(bad) or f"{len(r.get('harness', []))} checks")
    c.ok("readout", "harness checks that could not run (n/a)", not na, f"{len(na)}: " + "; ".join(na[:3]), warn_only=True)
    ab = exp.get("A_B_E3_seeds", {})
    per = ab.get("seed_summary_pr_auc", {}) if ab.get("available") else {}
    c.ok("readout", "seed runs: at least six seeds in every model/configuration", bool(per) and all(v.get("n", 0) >= 6 for v in per.values()),
         ", ".join(f"{k} n={v.get('n')}" for k, v in per.items()) or "no seed block")
    c.ok("readout", "seed runs: no cell failed to load", not ab.get("errors"), str(ab.get("errors") or "ok"))
    c.ok("readout", "bootstrap used at least 1000 replicates", r.get("bootstrap", {}).get("n_boot", 0) >= 1000,
         f"{r.get('bootstrap', {}).get('n_boot')}")
    c.ok("readout", "deviations C16-1..3 and disclosures stated", set(r.get("deviations", {})) >= {"C16-1", "C16-2", "C16-3"}
         and len(r.get("disclosures", [])) >= 4)
    c.ok("readout", "no accuracy metric anywhere (N2)", '"accuracy"' not in json.dumps(r))
    c.ok("readout", "the best baseline was chosen on validation", "validation_pr_auc" in r.get("baseline_choice", {}))
    dec = REPO / "experiments" / "chapter8_serving_decision.json"
    if dec.exists():
        served = json.loads(dec.read_text(encoding="utf-8"))["outcome"]["served"]
        got = (r["lineage"].get("served") or {})
        c.ok("readout", "lineage: the readout's served model is the Chapter 8 decision",
             got.get("model_version") == served.get("model_version") or got.get("registry_version") == served.get("registry_version"),
             f"decision {served.get('model_version')}, readout {got.get('model_version')}")
    else:
        c.add("readout", "lineage: the readout's served model is the Chapter 8 decision", "WARN", "no decision file here")
    c.ok("readout", "guard warnings are listed for the audit", "warnings" in r.get("guard", {}),
         f"{len(r.get('guard', {}).get('warnings', []))} warnings", warn_only=True)
    return r


def report_check(c: Checks, r: dict | None) -> None:
    if r is None:
        c.add("report", "report equals the readout's regeneration", "WARN", "no readout yet")
        return
    from app.evaluation import report

    if not REPORT.exists():
        c.add("report", "report equals the readout's regeneration", "FAIL", f"{REPORT.relative_to(REPO)} missing: run `python -m app.evaluation.report`")
        return
    want = report.render(r, readout_sha256=hashlib.sha256(READOUT.read_bytes()).hexdigest())
    c.ok("report", "report equals the readout's regeneration, byte for byte", REPORT.read_text(encoding="utf-8") == want,
         "a hand-edited or stale report fails here")


def recompute(c: Checks, r: dict | None, args) -> None:
    if not args.recompute:
        c.add("recompute", "rankings reproduce from stored scores", "WARN", "not requested: pass --recompute with CERT_PROCESSED_DIR set")
        return
    if r is None:
        c.add("recompute", "rankings reproduce from stored scores", "FAIL", "no readout to compare with")
        return
    processed = os.getenv("CERT_PROCESSED_DIR")
    if not processed:
        c.add("recompute", "rankings reproduce from stored scores", "FAIL", "CERT_PROCESSED_DIR is not set")
        return
    from app.evaluation.metrics import pr_auc
    from app.evaluation.rankings import build_rankings, load_population

    pop = load_population(processed, r["profile"], r["part"], cri_run_id=r["lineage"]["risk_run_id"])
    scores, _ = build_rankings(pop, experiments=REPO / "experiments")
    keep = ~pop.exclude
    worst = 0.0
    for name, s in scores.items():
        now = pr_auc(pop.y[keep], s[keep])
        want = r["rankings"][name]["summary"]["pr_auc"]
        worst = max(worst, abs(now - want))
    c.ok("recompute", "every ranking's PR-AUC equals the readout's (1e-9)", worst <= 1e-9, f"{len(scores)} rankings, worst difference {worst:.2e}")
    c.ok("recompute", "the risk run's file hash is the one the readout recorded", pop.provenance["risk_scores_sha256"] == r["lineage"]["risk_scores_sha256"])


def notes(c: Checks) -> None:
    cf = (REPO / "docs" / "CARRY_FORWARD.md").read_text(encoding="utf-8")
    missing = [n for n in NOTES if f"## {n}." not in cf]
    c.ok("notes", "carry-forward notes N75-N80 present", not missing, ", ".join(missing) or "all six")
    rows = [n for n in NOTES if f"| {n} " in cf]
    c.ok("notes", "carry-forward table has a row for each", len(rows) == len(NOTES))
    c.ok("notes", "audit and chapter documents exist", all((REPO / p).exists() for p in (
        "docs/audits/chapter_16_audit.md", "docs/chapters/chapter_16_evaluation.md")))
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    row = next((x for x in readme.splitlines() if x.startswith("| 16 ")), "")
    c.ok("notes", "README status row for Chapter 16 is not PLANNED", "PLANNED" not in row, row[:100])
    has_readout = READOUT.exists()
    c.ok("notes", "README claims IMPLEMENTED only if a test readout exists", ("IMPLEMENTED" in row and "PARTIALLY" not in row) <= has_readout,
         "status follows the evidence (N75)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Verify Chapter 16")
    ap.add_argument("--recompute", action="store_true")
    ap.add_argument("--skip-e2e", action="store_true")
    ap.add_argument("--no-tests", action="store_true", help="skip pytest (checks on files only)")
    args = ap.parse_args(argv)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = REPO / "experiments" / "results" / "chapter16"
    out.mkdir(parents=True, exist_ok=True)
    c = Checks()
    print(f"Chapter 16 verification {stamp}")
    if not args.no_tests:
        backend(c, out, args)
    r = readout(c, args)
    report_check(c, r)
    recompute(c, r, args)
    notes(c)
    counts = c.counts()
    (out / f"verification_{stamp}.json").write_text(json.dumps({"stamp": stamp, "counts": counts, "checks": c.rows}, indent=2), encoding="utf-8")
    md = [f"# Chapter 16 verification {stamp}", "", f"{counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL", ""]
    md += [f"- {x['status']} {x['section']}: {x['check']}" + (f" ({x['detail']})" if x["detail"] else "") for x in c.rows]
    (out / f"verification_{stamp}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    try:
        from app.feature_engineering.common import append_experiment_runlog

        append_experiment_runlog({"stage": "chapter16_verification", "stamp": stamp, **counts, "recompute": args.recompute})
    except Exception as exc:                                      # a missing runlog must not hide the result
        print(f"(runlog line not written: {exc})")
    print(f"\n{counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
