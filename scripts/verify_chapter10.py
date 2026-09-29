"""Verify Chapter 10 before any MITRE context is used.

Sections (each prints PASS, WARN or FAIL per check; exit code 1 on any FAIL):

    table      the committed technique table loads under the pin (version,
               bundle sha256); MITRE_ATTACK_VERSION agrees; every rule names
               an active technique under its tactic; every rule column is in
               the Chapter 5 matrix
    reference  pin + sha256; fitted for the current ruleset and table; no
               label column; rows are exactly the validation users of the
               shared split (N11); stage-1 and stage-2 rarity monotone and in
               [0, 1]; an unmapped user-day maps to exactly 0
    run        an enrichment run (--mitre-run-id, or the newest): contract
               columns; no label and no model column (N5, N42); one row per
               matrix row; made from the matrix that exists now; status and
               mitre_context agree; matches agree with the context rows;
               every match is traceable to an active technique under its
               tactic; a from-scratch recomputation reproduces every row
    cri        a CRI run made with --with-mitre, if present: it names this
               enrichment run; its mitre_context component equals the run's
               values; points only where a technique mapped
    readout    the validation readout, if present: validation only, of that
               CRI run, harness checks, every guard warning as a WARN

Usage, from backend/:

    python ../scripts/verify_chapter10.py --profile full --no-readout     # before evaluate
    python ../scripts/verify_chapter10.py --profile full

Writes ``experiments/results/chapter10/verification_<stamp>.json`` and one
``chapter10_verification`` runlog line. Reads no label.
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

from app.cri.sources import RISK_META, RISK_OUTPUT  # noqa: E402
from app.evaluation.splitting import load_split, rows_for_split  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, memory_rss_mb, repo_root  # noqa: E402
from app.mitre.calibrate import matrix_schema, read_rule_columns  # noqa: E402
from app.mitre.enrich import CONTEXT_COLUMNS, MATCH_COLUMNS, MitreEnricher  # noqa: E402
from app.mitre.evaluate import READOUT_FILE  # noqa: E402
from app.mitre.mapping_rules import RULES, ruleset_hash, validate_rules  # noqa: E402
from app.mitre.reference import (  # noqa: E402
    MitreReferenceUnavailableError,
    default_models_root,
    load_reference,
    resolve_pin_path,
)
from app.mitre.sources import CONTEXT_OUTPUT, MATCHES_OUTPUT, MitreSourceError, mitre_run_dir, read_meta  # noqa: E402
from app.mitre.techniques import TechniqueTableError, load_technique_table  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, feature_fingerprint  # noqa: E402

LABEL_WORDS = ("malicious", "insider", "scenario", "label", "y_primary", "y_account", "is_masquerade", "target")
MODEL_WORDS = ("anomaly_score", "model_version", "model_name", "registry_version", "cri_score")
RSS_TARGET_MB = 10 * 1024
TOL = 1e-12


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


def check_table(c: Checks, features_path: Path):
    s = "table"
    try:
        table = load_technique_table()
    except TechniqueTableError as exc:
        c.add(s, "technique table loads under the pin", "FAIL", str(exc))
        return None
    c.ok(s, "technique table loads under the pin", True,
         f"ATT&CK {table.attack_version}, {len(table.techniques)} techniques, sha256 {table.table_sha256[:12]}")
    problems = validate_rules(table)
    c.ok(s, "every rule names an active technique under its tactic", not problems, "; ".join(problems))
    for r in RULES:
        c.ok(s, f"{r.rule_id} -> {r.technique_id} {table.full_name(r.technique_id)} [{r.tactic}]", True, r.evidence)
    names, _ = matrix_schema(features_path)
    col_problems = validate_rules(table, names)
    c.ok(s, "every rule column is in the Chapter 5 matrix", not col_problems, "; ".join(col_problems))
    return table


def check_reference(c: Checks, args, table, features_path: Path):
    s = "reference"
    try:
        ref = load_reference(args.pin_path, args.models_dir, verify=True, table=table)
    except MitreReferenceUnavailableError as exc:
        c.add(s, "pinned reference loads with sha256 verified", "FAIL", str(exc))
        return None
    c.ok(s, "pinned reference loads with sha256 verified", True, ref.reference_id)
    c.ok(s, "fitted for the current ruleset", ref.meta["ruleset_hash"] == ruleset_hash(), ref.meta["ruleset_version"])
    frame = pd.read_parquet(ref.reference_path)
    c.ok(s, "reference holds no label column (N5)", not _hits(frame.columns, LABEL_WORDS))
    c.ok(s, "reference holds no model column (model-free, N42)", not _hits(frame.columns, MODEL_WORDS))
    split_file = Path(ref.meta["split"]["path"])
    if split_file.exists():
        assignment, _ = load_split(split_file)
        names, _ = matrix_schema(features_path)
        m = read_rule_columns(features_path, names)
        val = m[rows_for_split(m["user_id"], assignment) == "validation"].reset_index(drop=True)
        same = len(val) == len(frame) and (val["user_id"].to_numpy() == frame["user_id"].astype("string").to_numpy()).all() \
            and (val["date"].to_numpy() == frame["date"].astype("string").to_numpy()).all()
        c.ok(s, "reference = validation users of the shared split (N11)", same,
             f"{len(frame)} reference rows, {len(val)} validation rows now")
    else:
        c.add(s, "reference = validation users of the shared split (N11)", "FAIL", f"{split_file} not found")
    maps = ref.maps
    ok = True
    for r in RULES:
        x = np.unique(maps.columns[r.intensity_column])
        v = maps.rule_strength(r, x)
        ok &= bool((np.diff(v) >= 0).all() and v.min() >= 0 and v.max() <= 1)
    x = np.unique(maps.strength_max)
    v = maps.context(x)
    ok &= bool((np.diff(v) >= 0).all() and v.min() >= 0 and v.max() <= 1)
    c.ok(s, "stage-1 and stage-2 rarity monotone and in [0, 1]", ok)
    c.ok(s, "a user-day with no fired rule maps to mitre_context 0", float(maps.context(np.array([0.0]))[0]) == 0.0)
    return ref


def check_run(c: Checks, args, processed: Path, table, ref, features_path: Path) -> dict | None:
    s = "run"
    try:
        run_dir = mitre_run_dir(processed, args.mitre_run_id, args.profile)
    except MitreSourceError as exc:
        c.add(s, "enrichment run found", "FAIL", str(exc))
        return None
    meta = read_meta(run_dir)
    ctx = pd.read_parquet(run_dir / CONTEXT_OUTPUT)
    matches = pd.read_parquet(run_dir / MATCHES_OUTPUT)
    c.ok(s, "enrichment run found", True, f"{run_dir.name}, {len(ctx)} user-days, {len(matches)} matches")
    c.ok(s, "context contract columns", list(ctx.columns) == [*CONTEXT_COLUMNS, "mitre_run_id"],
         str(set(ctx.columns) ^ {*CONTEXT_COLUMNS, "mitre_run_id"}))
    c.ok(s, "matches contract columns", list(matches.columns) == [*MATCH_COLUMNS, "mitre_run_id"],
         str(set(matches.columns) ^ {*MATCH_COLUMNS, "mitre_run_id"}))
    c.ok(s, "no label column (N5)", not _hits([*ctx.columns, *matches.columns], LABEL_WORDS))
    c.ok(s, "no model column: the enrichment is model-free (N42)", not _hits([*ctx.columns, *matches.columns], MODEL_WORDS))
    fp = feature_fingerprint(features_path)
    c.ok(s, "made from the matrix that exists now", meta["features"]["fingerprint"] == fp,
         f"run {meta['features']['fingerprint']}, matrix {fp}")
    if ref is not None:
        c.ok(s, "uses the pinned reference", meta["reference"]["reference_id"] == ref.reference_id,
             f"run {meta['reference']['reference_id']}, pin {ref.reference_id}")
    names, _ = matrix_schema(features_path)
    frame = read_rule_columns(features_path, names)
    c.ok(s, "one row per matrix user-day, unique keys", len(frame) == len(ctx) and not ctx.duplicated(["user_id", "date"]).any(),
         f"{len(ctx)} rows, matrix {len(frame)}")
    st = ctx["mitre_status"].astype(str).to_numpy()
    v = ctx["mitre_context"].to_numpy(dtype="float64", na_value=np.nan)
    n_match = ctx["mitre_match_count"].to_numpy()
    c.ok(s, "mitre_context in [0, 1] where evaluated", bool(np.nanmin(np.r_[v, 0]) >= 0 and np.nanmax(np.r_[v, 0]) <= 1))
    c.ok(s, "unmapped rows: mitre_context 0, no match, no technique",
         bool(((v[st == "unmapped"] == 0).all()) and (n_match[st == "unmapped"] == 0).all()
              and ctx.loc[st == "unmapped", "mitre_techniques"].isna().all()))
    c.ok(s, "not_evaluated rows: mitre_context null", bool(np.isnan(v[st == "not_evaluated"]).all()),
         f"{int((st == 'not_evaluated').sum())} rows")
    c.ok(s, "mapped rows: at least one match and a named top technique",
         bool((n_match[st == "mapped"] > 0).all() and ctx.loc[st == "mapped", "mitre_top_technique"].notna().all()))
    c.ok(s, "mapped rows: mitre_context > 0", bool((v[st == "mapped"] > 0).all()),
         "a mapped row at 0 would mean its strength is not above any reference value", warn_only=True)
    per_day = matches.groupby(["user_id", "date"]).size()
    k = ctx.set_index(["user_id", "date"])["mitre_match_count"]
    c.ok(s, "matches agree with the context rows", bool(per_day.reindex(k.index, fill_value=0).to_numpy().tolist() == k.to_numpy().tolist()))
    bad = [f"{t}/{a}" for t, a in set(zip(matches["technique_id"], matches["tactic"]))
           if t not in table.techniques or a not in table.techniques[t].tactics] if table is not None else ["no table"]
    c.ok(s, "every match: active technique under its tactic, in the pinned table", not bad, str(bad[:5]))
    c.ok(s, "every match names its triggering column and value",
         bool(matches["trigger_column"].notna().all() and (matches["trigger_value"] > 0).all()))
    if ref is not None and table is not None:
        again = MitreEnricher(table, ref).enrich(frame)
        a = again.context.set_index(["user_id", "date"]).loc[k.index]
        b = ctx.set_index(["user_id", "date"])
        same_status = (a["mitre_status"].astype(str).to_numpy() == b["mitre_status"].astype(str).to_numpy()).all()
        av, bv = a["mitre_context"].to_numpy(dtype="float64"), b["mitre_context"].to_numpy(dtype="float64")
        same_v = bool(np.allclose(np.nan_to_num(av, nan=-1), np.nan_to_num(bv, nan=-1), atol=TOL, rtol=0))
        c.ok(s, "a from-scratch recomputation reproduces every row", bool(same_status and same_v and len(again.matches) == len(matches)))
    runlog = Path(os.getenv("CIRA_RUNLOG", str(repo_root() / "experiments" / "runlog.jsonl")))
    lines = [json.loads(x) for x in runlog.read_text(encoding="utf-8").splitlines() if x.strip()] if runlog.exists() else []
    c.ok(s, "runlog line (R8)", any(x.get("stage") == "chapter10_mitre_batch" and x.get("mitre_run_id") == run_dir.name for x in lines))
    c.ok(s, f"peak RSS under {RSS_TARGET_MB} MB", meta["peak_rss_mb"] < RSS_TARGET_MB, f"{meta['peak_rss_mb']} MB")
    return {**meta, "_ctx": ctx}


def find_cri_run(processed: Path, cri_run_id: str | None, mitre_run_id: str) -> Path | None:
    root = processed / "risk" / "chapter9"
    if cri_run_id:
        return root / cri_run_id
    found = None
    for d in sorted(root.iterdir()) if root.exists() else []:
        m = d / RISK_META
        if m.exists() and (json.loads(m.read_text(encoding="utf-8")).get("mitre") or {}).get("mitre_run_id") == mitre_run_id:
            found = d
    return found


def check_cri(c: Checks, args, processed: Path, run: dict) -> dict | None:
    s = "cri"
    d = find_cri_run(processed, args.cri_run_id, run["mitre_run_id"])
    if d is None or not (d / RISK_META).exists():
        c.add(s, "a CRI run made with this enrichment run", "WARN", "none yet; run `python -m app.cri.batch --with-mitre`")
        return None
    meta = json.loads((d / RISK_META).read_text(encoding="utf-8"))
    c.ok(s, "CRI run names this enrichment run", (meta.get("mitre") or {}).get("mitre_run_id") == run["mitre_run_id"], d.name)
    c.ok(s, "mitre_context is an available component", "mitre_context" not in meta.get("unavailable_components", {}))
    w = meta.get("effective_weights", {})
    c.ok(s, "effective weights sum to 1 with MITRE in", abs(sum(w.values()) - 1) < 1e-12,
         ", ".join(f"{k} {v:.3f}" for k, v in w.items()))
    c.ok(s, "formula_hash recorded (N33)", bool(meta.get("formula_hash")), str(meta.get("formula_hash")))
    risk = pd.read_parquet(d / RISK_OUTPUT, columns=["user_id", "date", "component_mitre_context", "points_mitre_context"])
    ctx = run["_ctx"].set_index(["user_id", "date"])
    j = ctx.loc[list(zip(risk["user_id"].astype(str), risk["date"].astype(str)))]
    same = np.allclose(np.nan_to_num(risk["component_mitre_context"].to_numpy(dtype="float64", na_value=np.nan), nan=-1),
                       np.nan_to_num(j["mitre_context"].to_numpy(dtype="float64"), nan=-1), atol=TOL, rtol=0)
    c.ok(s, "component_mitre_context equals the enrichment run", bool(same))
    pts = risk["points_mitre_context"].to_numpy(dtype="float64")
    c.ok(s, "MITRE points only on mapped user-days", bool((pts[j["mitre_status"].astype(str).to_numpy() != "mapped"] == 0).all()))
    return meta


def check_readout(c: Checks, args, cri_meta: dict | None) -> None:
    s = "readout"
    path = Path(args.readout_path)
    if not path.exists():
        c.add(s, "validation readout present", "WARN", f"{path} not written yet; run `python -m app.mitre.evaluate`")
        return
    r = json.loads(path.read_text(encoding="utf-8"))
    c.ok(s, "validation only (test is Chapter 16 ablation D)", r.get("part") == "validation")
    if cri_meta is not None:
        c.ok(s, "readout is of this CRI run", r.get("cri_run_id") == cri_meta["cri_run_id"], r.get("cri_run_id"))
    for h in r.get("harness", []):
        if h["ok"] is None:
            c.add(s, h["check"], "WARN", h["detail"])
        else:
            c.ok(s, h["check"], h["ok"], h["detail"])
    view = r.get("disagreement_view")
    c.ok(s, "disagreement view present (served vs shadow)", view is not None,
         f"shadow {view['shadow_model']}, {view['budget']}" if view else "no shadow rows in the source batch",
         warn_only=True)
    for w in r.get("guard", {}).get("warnings", []):
        c.add(s, r["guard"]["version"], "WARN", w)
    if not r.get("guard", {}).get("warnings"):
        c.ok(s, f"{r.get('guard', {}).get('version')}: MITRE does no harm on validation", True)


def _parse_args(argv):
    root = repo_root()
    p = argparse.ArgumentParser(description="Verify Chapter 10 (MITRE ATT&CK enrichment)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--mitre-run-id", default=None)
    p.add_argument("--cri-run-id", default=None)
    p.add_argument("--pin-path", default=str(resolve_pin_path()))
    p.add_argument("--models-dir", default=os.getenv("MODEL_PATH") or str(default_models_root()))
    p.add_argument("--readout-path", default=str(root / "experiments" / READOUT_FILE))
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter10"))
    p.add_argument("--no-readout", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    processed = Path(args.processed_dir)
    features_path = processed / "features" / PROFILE_OUTPUT[args.profile]
    c = Checks()
    print("[verify chapter10]", flush=True)
    table = check_table(c, features_path)
    ref = check_reference(c, args, table, features_path) if table else None
    run = check_run(c, args, processed, table, ref, features_path)
    cri_meta = check_cri(c, args, processed, run) if run else None
    if not args.no_readout:
        check_readout(c, args, cri_meta)
    counts = c.counts()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.results_dir) / f"verification_{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"profile": args.profile, "mitre_run_id": None if run is None else run["mitre_run_id"],
                               "cri_run_id": None if cri_meta is None else cri_meta["cri_run_id"],
                               "counts": counts, "checks": c.rows}, indent=2), encoding="utf-8")
    append_experiment_runlog({"stage": "chapter10_verification", "profile": args.profile,
                              "mitre_run_id": None if run is None else run["mitre_run_id"],
                              "reference_id": None if ref is None else ref.reference_id,
                              "readout_checked": not args.no_readout, "pass": counts["PASS"], "warn": counts["WARN"],
                              "fail": counts["FAIL"], "peak_rss_mb": round(memory_rss_mb(), 1)})
    print(f"[verify chapter10] {counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL -> {out}", flush=True)
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
