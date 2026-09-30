"""Verify Chapter 11 before any explanation is shown to anyone.

Sections (each prints PASS, WARN or FAIL per check; exit code 1 on any FAIL):

    describe   every input of the served model has a written description; no
               description claims a signal CERT r4.2 lacks (N9); nulls are
               described by their meaning, never as 0 (N4)
    run        an explain run (--explain-run-id, or the newest): contract
               columns; no label column (N5); it explains the model served
               now, with the explainer N30 requires; made from the batch and
               the matrix that exist now; one row per scored user-day; every
               row adds up to the served margin; a recomputation on a sample
               reproduces the stored attributions; XGBoost's TreeSHAP equals
               shap.TreeExplainer on a sample; no static trait among the
               served inputs or in any top 5 (N22, N25); runlog line; peak RSS
    selection  bounded rows are validation or test users only (N31); the
               label-free rule reproduces them from the risk run
    kernel     KernelSHAP ran on the bounded rows with nsamples above the
               input count (C11-3), its background drawn from training users
               only; agreement with TreeSHAP and the deletion check (WARN
               only: the two SHAP variants estimate different quantities)
    reasons    one explanation per bounded row; every model factor, CRI
               point and ATT&CK match re-checked against the stored
               attributions, risk run and enrichment run; no generic
               statement, no static trait, nothing from the shadow (N30, N32,
               N34, N45)
    readout    the validation readout, if present: validation only, of this
               run, every guard warning as a WARN

Usage, from backend/:

    python ../scripts/verify_chapter11.py --profile full --no-readout     # before evaluate
    python ../scripts/verify_chapter11.py --profile full

Writes ``experiments/results/chapter11/verification_<stamp>.json`` and one
``chapter11_verification`` runlog line. Reads no label.
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

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.cri.sources import SourceError, chapter8_batch  # noqa: E402
from app.evaluation.splitting import load_split  # noqa: E402
from app.explainability.attributions import ATTRIBUTION_COLUMNS, explainer_for, top_k_long  # noqa: E402
from app.explainability.batch import MARGIN_TOL, SUMMARY_COLUMNS  # noqa: E402
from app.explainability.evaluate import READOUT_FILE  # noqa: E402
from app.explainability.features import BASE, NULL_MEANING, describe, forbidden_in, undescribed, value_text  # noqa: E402
from app.explainability.reason_builder import GENERIC_PHRASES, model_evidence, validate_explanation  # noqa: E402
from app.explainability.selection import select_rows  # noqa: E402
from app.explainability.shap_explainer import ADDITIVITY_TOL, CORROBORATION_COLUMNS, shap_tree_cross_check  # noqa: E402
from app.explainability.sources import (  # noqa: E402
    ATTRIBUTIONS_OUTPUT,
    KERNEL_OUTPUT,
    SELECTION_OUTPUT,
    SUMMARY_OUTPUT,
    ExplainSourceError,
    aligned,
    explain_run_dir,
    read_meta,
    read_reasons,
)
from app.feature_engineering.common import append_experiment_runlog, memory_rss_mb, repo_root  # noqa: E402
from app.scoring.serving_config import resolve_serving_config  # noqa: E402
from app.scoring.service import AnomalyScoringService  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, feature_fingerprint, load_feature_matrix  # noqa: E402

LABEL_WORDS = ("malicious", "insider", "scenario", "label", "y_primary", "y_account", "is_masquerade", "target")
RSS_TARGET_MB = 10 * 1024
RECOMPUTE_ROWS = 2_000
TOL = 1e-9


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
        return {s: sum(r["status"] == s for r in self.rows) for s in ("PASS", "WARN", "FAIL")}


def _hits(columns, words) -> list[str]:
    return [c for c in columns if any(w in str(c).lower() for w in words)]


def check_describe(c: Checks, served, matrix_columns) -> None:
    s = "describe"
    ex = explainer_for(served)
    missing = undescribed(ex.features)
    c.ok(s, "every served-model input has a written description", not missing, str(missing[:5]))
    all_missing = undescribed([x for x in matrix_columns if x not in ("user_id", "date")])
    c.ok(s, "every Chapter 5 column has a written description", not all_missing, str(all_missing[:5]), warn_only=True)
    bad = {col: forbidden_in(describe(col).label) for col in [*BASE, *matrix_columns] if forbidden_in(describe(col).label)}
    c.ok(s, "no description claims a signal CERT lacks (N9)", not bad, str(bad)[:200])
    nulls_ok = all(value_text(col, None) == NULL_MEANING.get(describe(col).kind, "no value")
                   and "0" not in value_text(col, None) for col in ex.features)
    c.ok(s, "a null is described by its meaning, never as 0 (N4)", nulls_ok)


def check_run(c: Checks, args, processed: Path, service, fm) -> dict | None:
    s = "run"
    served = service.served
    try:
        run_dir = explain_run_dir(processed, args.explain_run_id, args.profile)
    except ExplainSourceError as exc:
        c.add(s, "explain run found", "FAIL", str(exc))
        return None
    meta = read_meta(run_dir)
    summary = pd.read_parquet(run_dir / SUMMARY_OUTPUT)
    attr = pd.read_parquet(run_dir / ATTRIBUTIONS_OUTPUT)
    c.ok(s, "explain run found", True, f"{run_dir.name}, {len(summary)} user-days, {len(attr)} attribution rows")
    c.ok(s, "summary contract columns", list(summary.columns) == list(SUMMARY_COLUMNS), str(set(summary.columns) ^ set(SUMMARY_COLUMNS)))
    c.ok(s, "attribution contract columns", list(attr.columns) == [*ATTRIBUTION_COLUMNS, "explain_run_id"])
    c.ok(s, "no label column (N5)", not _hits([*summary.columns, *attr.columns], LABEL_WORDS))
    sv = meta["served"]
    same_model = (sv["model_name"], sv["model_version"], sv["registry_version"]) == \
        (served.model_name, served.model_version, served.registry_version)
    c.ok(s, "explains the model served now (N30)", same_model,
         f"run {sv['model_name']} {sv['registry_version']}, served {served.model_name} {served.registry_version}")
    want = {"gbdt": "treeshap", "tabnet": "tabnet_mask"}[served.model_name]
    c.ok(s, f"explainer is {want} for {served.model_name} (N30)", meta["explainer"]["method"] == want
         and set(summary["method"]) == {want})
    c.ok(s, "no static trait among the served model's inputs (N25)", not sv.get("static_inputs"), str(sv.get("static_inputs")))
    try:
        batch = chapter8_batch(processed, meta["source_batch"]["batch_run_id"], None)
    except SourceError as exc:
        c.add(s, "source batch present", "FAIL", str(exc))
        return None
    c.ok(s, "source batch scored by the same model_version", batch.served.get("model_version") == served.model_version)
    fp = feature_fingerprint(fm.features_path)
    c.ok(s, "made from the matrix that exists now", meta["features"]["fingerprint"] == fp,
         f"run {meta['features']['fingerprint']}, matrix {fp}")
    scores = batch.read(role="served", columns=["user_id", "date", "model_split", "raw_score"])
    if meta.get("rows_option") == "evaluation":
        scores = scores[scores["model_split"] != "train"].reset_index(drop=True)
    same_keys = len(scores) == len(summary) and (scores["user_id"].astype(str).to_numpy() == summary["user_id"].astype(str).to_numpy()).all() \
        and (scores["date"].astype(str).to_numpy() == summary["date"].astype(str).to_numpy()).all()
    c.ok(s, "one row per scored user-day, same order as the batch", bool(same_keys), f"{len(summary)} rows, batch {len(scores)}")
    c.ok(s, "no duplicate user-day", not summary.duplicated(["user_id", "date"]).any())
    if want == "treeshap":
        err = summary["additivity_error"].to_numpy(dtype="float64")
        c.ok(s, f"every row adds up to the served margin (<= {ADDITIVITY_TOL})", bool(np.nanmax(err) <= ADDITIVITY_TOL),
             f"max {np.nanmax(err):.2e}")
    if same_keys:
        diff = float(np.abs(summary["raw_score"].to_numpy() - scores["raw_score"].to_numpy()).max())
        c.ok(s, f"stored margin equals the batch raw_score (<= {MARGIN_TOL})", diff <= MARGIN_TOL, f"max {diff:.2e}")
    split_ok = (summary["model_split"].astype(str).to_numpy() == scores["model_split"].astype(str).to_numpy()).all() if same_keys else False
    c.ok(s, "model_split tags equal the batch (N31)", bool(split_ok))

    rng = np.random.default_rng(0)
    pick = np.sort(rng.choice(len(summary), size=min(RECOMPUTE_ROWS, len(summary)), replace=False))
    keys = summary.iloc[pick][["user_id", "date"]].reset_index(drop=True)
    frame = aligned(fm.matrix, keys, "the matrix")
    ex = explainer_for(served)
    again = ex.explain(frame)
    long = top_k_long(again, frame, meta["top_k"])
    stored = attr.merge(keys, on=["user_id", "date"])
    a = long.sort_values(["user_id", "date", "rank"]).reset_index(drop=True)
    b = stored.sort_values(["user_id", "date", "rank"]).reset_index(drop=True)
    same = len(a) == len(b) and (a["feature"].to_numpy() == b["feature"].to_numpy()).all() and \
        np.allclose(a["contribution"].to_numpy(), b["contribution"].to_numpy(), atol=1e-9, rtol=0)
    c.ok(s, f"a recomputation on {len(keys)} sampled rows reproduces the stored top-{meta['top_k']}", bool(same))
    if want == "treeshap":
        r = shap_tree_cross_check(served, frame.iloc[:500], type(again)(
            keys=again.keys.iloc[:500], features=again.features, values=again.values[:500], method=again.method,
            raw_score=again.raw_score[:500], model=again.model))
        if r["ok"] is None:
            c.add(s, "TreeSHAP equals shap.TreeExplainer", "WARN", r["detail"])
        else:
            c.ok(s, "TreeSHAP equals shap.TreeExplainer", r["ok"], r["detail"])
    c.ok(s, "no static trait in any top 5 (N22)", int(summary["static_in_top5"].sum()) == 0,
         f"{int(summary['static_in_top5'].sum())} rows")
    oos = summary[summary["model_split"].isin(["validation", "test"])]
    share = float(oos["top_is_calendar"].mean()) if len(oos) else 0.0
    c.ok(s, "calendar columns lead few out-of-sample explanations", share < 0.5,
         f"{share:.3f} of validation/test rows have day_of_week or is_weekend as top factor", warn_only=True)
    runlog = Path(os.getenv("CIRA_RUNLOG", str(repo_root() / "experiments" / "runlog.jsonl")))
    lines = [json.loads(x) for x in runlog.read_text(encoding="utf-8").splitlines() if x.strip()] if runlog.exists() else []
    c.ok(s, "runlog line (R8)", any(x.get("stage") == "chapter11_explain_batch" and x.get("explain_run_id") == run_dir.name for x in lines))
    c.ok(s, f"peak RSS under {RSS_TARGET_MB} MB", meta["peak_rss_mb"] < RSS_TARGET_MB, f"{meta['peak_rss_mb']} MB")
    return {"dir": run_dir, "meta": meta, "summary": summary, "attr": attr, "batch": batch}


def check_selection(c: Checks, processed: Path, run: dict) -> pd.DataFrame | None:
    s = "selection"
    meta = run["meta"]
    sel = pd.read_parquet(run["dir"] / SELECTION_OUTPUT)
    c.ok(s, "bounded rows are validation or test users only (N31)", bool(sel["model_split"].isin(["validation", "test"]).all()),
         f"{meta['selection'].get('by_split')}")
    risk_dir = processed / "risk" / "chapter9" / meta["risk_run"]["cri_run_id"]
    risk = pd.read_parquet(risk_dir / "risk_scores.parquet")
    risk["user_id"] = risk["user_id"].astype("string").str.strip().str.casefold()
    risk["date"] = risk["date"].astype("string")
    info = meta["selection"]
    again, _ = select_rows(risk, top_k_per_day=info["top_k_per_day"], max_rows=info["max_rows"])
    same = len(again) == len(sel) and set(zip(again["user_id"].astype(str), again["date"].astype(str))) == \
        set(zip(sel["user_id"].astype(str), sel["date"].astype(str)))
    c.ok(s, f"{info['rule']} reproduces the bounded rows from the risk run", bool(same), f"{len(sel)} rows")
    c.ok(s, "nothing cut by --max-bounded-rows", info.get("truncated", 0) == 0, f"{info.get('truncated', 0)} cut", warn_only=True)
    return risk


def check_kernel(c: Checks, run: dict) -> None:
    s = "kernel"
    info = run["meta"]["kernel"]
    if info.get("status") != "done":
        c.add(s, "KernelSHAP corroboration ran (D-5)", "WARN", f"{info.get('status')}: {info.get('reason', '')}")
        return
    k = pd.read_parquet(run["dir"] / KERNEL_OUTPUT)
    c.ok(s, "KernelSHAP corroboration ran (D-5)", True, f"{len(k)} rows, {info['background']}, nsamples {info['nsamples']}")
    c.ok(s, "contract columns", list(k.columns) == [*CORROBORATION_COLUMNS, "explain_run_id"])
    sel = pd.read_parquet(run["dir"] / SELECTION_OUTPUT)
    c.ok(s, "one row per bounded user-day", len(k) == len(sel))
    c.ok(s, "nsamples above the number of model inputs (C11-3)", info["nsamples"] > info["n_inputs"],
         f"{info['nsamples']} > {info['n_inputs']}")
    bg = info.get("background_keys") or []
    rec = info.get("background_split") or {}
    if rec.get("mode") == "user" and Path(str(rec.get("file", ""))).exists():
        assignment, _ = load_split(rec["file"])
        in_train = bool(bg) and all(assignment.get(str(u)) == "train" for u, _d in bg)
        c.ok(s, "background drawn from the served model's training users only", in_train,
             f"{len(bg)} background user-days; split {Path(rec['file']).name}")
    elif rec.get("mode") == "time":
        in_train = bool(bg) and all(str(d) < rec["validation_start"] for _u, d in bg)
        c.ok(s, "background drawn from the served model's training days only", in_train, f"{len(bg)} user-days")
    else:
        c.add(s, "background drawn from the served model's training users only", "FAIL",
              f"no usable split record in the run meta: {rec}")
    c.ok(s, "KernelSHAP adds up to the margin", float(k["kernel_additivity_error"].max()) < 1e-6,
         f"max {k['kernel_additivity_error'].max():.2e}", warn_only=True)
    ov = float(k["top5_overlap"].median())
    c.ok(s, "median top-5 overlap with the primary explanation >= 0.4", ov >= 0.4, f"{ov:.3f}", warn_only=True)
    beats = k["deletion_top_beats_random"].dropna().astype(bool)
    share = float(beats.mean()) if len(beats) else float("nan")
    c.ok(s, "deleting the top raising features lowers the margin more than random ones on >= 80% of rows",
         bool(len(beats) and share >= 0.8), f"{share:.3f} of {len(beats)} rows with a raising factor", warn_only=True)


def check_reasons(c: Checks, processed: Path, run: dict, risk: pd.DataFrame | None) -> None:
    s = "reasons"
    meta = run["meta"]
    reasons = read_reasons(run["dir"])
    sel = pd.read_parquet(run["dir"] / SELECTION_OUTPUT)
    c.ok(s, "one explanation per bounded user-day", len(reasons) == len(sel), f"{len(reasons)} reasons, {len(sel)} rows")
    if not reasons:
        return
    c.ok(s, "every explanation complete (no deferred model part)", all(r["status"] == "complete" for r in reasons),
         f"{sum(r['status'] != 'complete' for r in reasons)} deferred", warn_only=True)
    served = meta["served"]
    attr = run["attr"].set_index(["user_id", "date"]).sort_index()
    summ = run["summary"].set_index(["user_id", "date"])
    risk_i = risk.set_index(["user_id", "date"]) if risk is not None else None
    mctx = mmatch = None
    if meta.get("mitre"):
        from app.mitre.sources import MATCHES_OUTPUT, mitre_run_dir, read_context

        mdir = mitre_run_dir(processed, meta["mitre"]["mitre_run_id"])
        keys = pd.DataFrame({"user_id": [r["user_id"] for r in reasons], "date": [r["date"] for r in reasons]})
        mctx = read_context(mdir, keys, ["mitre_status", "mitre_context", "mitre_unmapped_behaviours"])
        mmatch = pd.read_parquet(mdir / MATCHES_OUTPUT)
        mmatch["user_id"] = mmatch["user_id"].astype("string").str.strip().str.casefold()
    problems, generic, shadow, static = [], 0, 0, 0
    for i, r in enumerate(reasons):
        key = (r["user_id"], r["date"])
        factors = attr.loc[[key]].reset_index().to_dict("records") if key in attr.index else []
        model = model_evidence(summ.loc[key].to_dict(), factors, method=meta["explainer"]["method"],
                               model_name=served["model_name"], model_version=served["model_version"],
                               registry_version=served["registry_version"],
                               anomaly_score=float(summ.loc[key, "anomaly_score"]))
        rrow = None if risk_i is None else risk_i.loc[key].to_dict()
        mitre = None
        if mctx is not None:
            mitre = mctx.iloc[i].to_dict()
            mitre["matches"] = mmatch[(mmatch["user_id"].astype(str) == key[0]) & (mmatch["date"].astype(str) == key[1])].to_dict("records")
        p = validate_explanation(r, model=model, risk=rrow, mitre=mitre)
        problems += [f"{key}: {x}" for x in p]
        generic += any(g in r["text"].lower() for g in GENERIC_PHRASES)
        shadow += any((f.get("source") or {}).get("model_version") != served["model_version"] for f in r["model_factors"])
        static += any(f["feature"].startswith(("psych_", "peer_department_size")) for f in r["model_factors"])
    c.ok(s, "every model factor, CRI point and ATT&CK match traced to its input", not problems, "; ".join(problems[:3]))
    c.ok(s, "no generic statement", generic == 0, f"{generic} explanations")
    c.ok(s, "model factors only from the served model (N30, N32)", shadow == 0)
    c.ok(s, "no static trait presented as a reason (N22)", static == 0)
    c.ok(s, "ATT&CK and CRI never listed as model factors (N34, N45)",
         all((f.get("source") or {}).get("kind") == "model" for r in reasons for f in r["model_factors"]))
    c.ok(s, "every indicated match worded as a visit (N45)",
         all("not what was sent" in m["text"] for r in reasons for m in r["attack_context"]["matches"]
             if m.get("evidence") == "indicated"))


def check_readout(c: Checks, args, run: dict | None) -> None:
    s = "readout"
    path = Path(args.readout_path)
    if not path.exists():
        c.add(s, "validation readout present", "WARN", f"{path} not written yet; run `python -m app.explainability.evaluate`")
        return
    r = json.loads(path.read_text(encoding="utf-8"))
    c.ok(s, "validation only", r.get("part") == "validation")
    if run is not None:
        c.ok(s, "readout is of this explain run", r.get("explain_run_id") == run["dir"].name, r.get("explain_run_id"))
    view = r.get("second_model_view") or {}
    c.ok(s, "second model's view present and labelled as the shadow's", bool(view.get("available")) and "shadow" in str(view.get("label", "")),
         view.get("reason", ""), warn_only=True)
    for w in r.get("guard", {}).get("warnings", []):
        c.add(s, r["guard"]["version"], "WARN", w)
    if not r.get("guard", {}).get("warnings"):
        c.ok(s, f"{r.get('guard', {}).get('version')}: no static or calendar-led explanations", True)


def _parse_args(argv):
    root = repo_root()
    p = argparse.ArgumentParser(description="Verify Chapter 11 (explainability)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--explain-run-id", default=None)
    p.add_argument("--readout-path", default=str(root / "experiments" / READOUT_FILE))
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter11"))
    p.add_argument("--no-readout", action="store_true")
    p.add_argument("--allow-unreportable", action="store_true", help=argparse.SUPPRESS)   # tests only
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    processed = Path(args.processed_dir)
    c = Checks()
    print("[verify chapter11]", flush=True)
    service = AnomalyScoringService.load(resolve_serving_config(), allow_unreportable=args.allow_unreportable)
    run = None
    if not service.available:
        c.add("run", "a served model to explain", "FAIL", service.unavailable_reason)
    else:
        fm = load_feature_matrix(processed, args.profile)
        check_describe(c, service.served, fm.matrix.columns)
        run = check_run(c, args, processed, service, fm)
        if run is not None:
            risk = check_selection(c, processed, run)
            check_kernel(c, run)
            check_reasons(c, processed, run, risk)
    if not args.no_readout:
        check_readout(c, args, run)
    counts = c.counts()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.results_dir) / f"verification_{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    run_id = None if run is None else run["dir"].name
    out.write_text(json.dumps({"profile": args.profile, "explain_run_id": run_id, "counts": counts, "checks": c.rows},
                              indent=2), encoding="utf-8")
    append_experiment_runlog({"stage": "chapter11_verification", "profile": args.profile, "explain_run_id": run_id,
                              "readout_checked": not args.no_readout, "pass": counts["PASS"], "warn": counts["WARN"],
                              "fail": counts["FAIL"], "peak_rss_mb": round(memory_rss_mb(), 1)})
    print(f"[verify chapter11] {counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL -> {out}", flush=True)
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
