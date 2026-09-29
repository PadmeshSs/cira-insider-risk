"""Verify Chapter 9 before any risk score is used.

Sections (each prints PASS, WARN or FAIL per check; exit code 1 on any FAIL):

    config       weights and bands valid; environment overrides reported
    calibration  pin + sha256; fitted for the model served now; reference is
                 exactly the served model's validation rows of its batch; no
                 label column; rarity monotone and bounded
    risk         a risk run (--cri-run-id, or the newest run): schema,
                 no label column, anomaly score carried through unchanged,
                 one model_version, points sum to the CRI, severity matches the
                 bands, a from-scratch recomputation reproduces every row
                 (joining the same Chapter 10 enrichment run for a --with-mitre run),
                 mismatched model and shadow rows are refused
    readout      the validation readout, if present: validation only, harness
                 checks pass, every guard warning shown as a WARN

Usage, from backend/ (same env vars as the runners):

    python ../scripts/verify_chapter9.py --profile full
    python ../scripts/verify_chapter9.py --profile full --no-readout     # before evaluate

Writes ``experiments/results/chapter9/verification_<stamp>.json`` and one
``chapter9_verification`` runlog line. Reads no label (the readout section
only reads the readout file).
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

from app.cri.calibration import (  # noqa: E402
    ANOMALY_STAT,
    CalibrationUnavailableError,
    default_models_root,
    load_calibration,
    resolve_pin_path,
)
from app.cri.config import COMPONENTS, CRIConfig  # noqa: E402
from app.cri.context import build_context, load_roles, read_feature_columns  # noqa: E402
from app.cri.engine import RISK_COLUMNS, CRIEngine, CRIInputError, CRIModelMismatchError, combine, severity_of  # noqa: E402
from app.cri.evaluate import READOUT_FILE, config_from_meta  # noqa: E402
from app.cri.sources import RISK_META, RISK_OUTPUT, SourceError, chapter8_batch, risk_run_dir  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, memory_rss_mb, repo_root  # noqa: E402
from app.scoring.serving_config import resolve_serving_config  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT  # noqa: E402

LABEL_WORDS = ("malicious", "insider", "scenario", "label", "y_primary", "y_account", "is_masquerade", "target")
RSS_TARGET_MB = 10 * 1024
TOL = 1e-9


class Checks:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, section: str, name: str, status: str, detail: str = "") -> None:
        self.rows.append({"section": section, "check": name, "status": status, "detail": detail})
        print(f"  {status:<4} {section:<11} {name}" + (f"  -- {detail}" if detail else ""), flush=True)

    def ok(self, section, name, cond, detail="", warn_only=False) -> bool:
        self.add(section, name, "PASS" if cond else ("WARN" if warn_only else "FAIL"), detail)
        return bool(cond)

    def counts(self) -> dict:
        return {s: sum(r["status"] == s for r in self.rows) for s in ("PASS", "WARN", "FAIL")}


def _labelish(columns) -> list[str]:
    return [c for c in columns if any(w in str(c).lower() for w in LABEL_WORDS)]


def check_config(c: Checks) -> CRIConfig | None:
    s = "config"
    try:
        cfg = CRIConfig.from_env()
    except Exception as exc:
        c.add(s, "configuration is valid", "FAIL", str(exc))
        return None
    c.ok(s, "configuration is valid", True, f"hash {cfg.config_hash}, weights {cfg.weight}, bands {cfg.bands}")
    c.ok(s, "no environment override of the Chapter 9 defaults", not cfg.overrides,
         f"overrides {dict(cfg.overrides)}; update .env or explain in the audit" if cfg.overrides else "", warn_only=True)
    w = cfg.effective_weights({x for x in COMPONENTS if x not in ("asset_criticality", "mitre_context")})
    c.ok(s, "effective weights sum to 1 without asset and MITRE", abs(sum(w.values()) - 1) < 1e-12,
         ", ".join(f"{k} {v:.3f}" for k, v in w.items()))
    return cfg


def check_calibration(c: Checks, args, processed: Path, cfg: CRIConfig):
    s = "calibration"
    try:
        cal = load_calibration(args.pin_path, args.models_dir, verify=True)
    except CalibrationUnavailableError as exc:
        c.add(s, "pinned calibration loads with sha256 verified", "FAIL", str(exc))
        return None
    c.ok(s, "pinned calibration loads with sha256 verified", True, cal.calibration_id)
    m = cal.model
    serving = resolve_serving_config()
    same = serving.served is not None and (serving.served.model_name, serving.served.registry_version) == (m["model_name"], m["registry_version"])
    c.ok(s, "fitted for the model served now (N29)", same,
         f"calibration {m['model_name']}:{m['registry_version']} ({m['model_version']}), served {serving.served} from {serving.source}")
    c.ok(s, "rarity scale matches the configuration", cal.maps.decades == cfg.rarity_decades,
         f"calibration D={cal.maps.decades}, config D={cfg.rarity_decades}")
    ref = pd.read_parquet(cal.reference_path)
    c.ok(s, "reference holds no label column (N5)", not _labelish(ref.columns), str(_labelish(ref.columns)))
    try:
        batch = chapter8_batch(processed, cal.meta["source_batch"]["batch_run_id"], None)
        served = batch.read(role="served", columns=["user_id", "date", "model_split", "role", "model_version", "anomaly_score"])
        val = served[served["model_split"] == "validation"].reset_index(drop=True)
        same_rows = len(val) == len(ref) and (val["user_id"].to_numpy() == ref["user_id"].astype("string").to_numpy()).all() \
            and (val["date"].to_numpy() == ref["date"].astype("string").to_numpy()).all()
        c.ok(s, "reference = the served model's validation rows of its batch", same_rows,
             f"{len(ref)} reference rows, {len(val)} validation rows in batch {batch.batch_run_id}")
        c.ok(s, "reference anomaly scores equal the batch's", same_rows and np.array_equal(
            val["anomaly_score"].to_numpy(dtype="float64"), ref[ANOMALY_STAT].to_numpy(dtype="float64")))
        c.ok(s, "batch model_version = calibration model_version", set(val["model_version"].unique()) == {m["model_version"]})
    except SourceError as exc:
        c.add(s, "reference = the served model's validation rows of its batch", "FAIL", str(exc))
    x = np.sort(ref[ANOMALY_STAT].to_numpy(dtype="float64"))
    r = cal.maps.apply(ANOMALY_STAT, x)
    distinct = np.r_[True, np.diff(x) > 0]
    c.ok(s, "rarity is monotone, strict across distinct reference values, in [0, 1]",
         bool((np.diff(r) >= 0).all() and (np.diff(r[distinct]) > 0).all() and r.min() >= 0 and r.max() <= 1),
         f"highest rarity on the reference {r.max():.4f}; ceiling log10(n+1)/D = {np.log10(len(x) + 1) / cal.maps.decades:.4f}")
    return cal


def check_risk(c: Checks, args, processed: Path, cfg: CRIConfig, cal) -> dict | None:
    s = "risk"
    try:
        run_dir = risk_run_dir(processed, args.cri_run_id, args.profile)
    except SourceError as exc:
        c.add(s, "risk run found", "FAIL", str(exc))
        return None
    meta = json.loads((run_dir / RISK_META).read_text(encoding="utf-8"))
    risk = pd.read_parquet(run_dir / RISK_OUTPUT)
    c.ok(s, "risk run found", True, f"{run_dir.name}, variant {meta['variant']}, {len(risk)} rows")
    expected = [*RISK_COLUMNS, "cri_run_id", "source_batch_run_id"]
    c.ok(s, "contract columns", list(risk.columns) == expected, f"extra/missing: {set(risk.columns) ^ set(expected)}")
    c.ok(s, "no label column (N5)", not _labelish(risk.columns), str(_labelish(risk.columns)))
    if cal is not None:
        c.ok(s, "calibration of the run = the pinned calibration", meta["calibration"]["calibration_id"] == cal.calibration_id,
             f"run {meta['calibration']['calibration_id']}, pin {cal.calibration_id}")
    c.ok(s, "the calibrated default configuration", bool(meta.get("is_calibrated_default")),
         f"variant {meta['variant']}, config {meta['config_hash']}, overrides {meta.get('config_overrides')}", warn_only=True)
    c.ok(s, "one model_version", risk["model_version"].nunique() == 1, str(list(risk["model_version"].unique()[:3])))

    batch = chapter8_batch(processed, meta["source_batch"]["batch_run_id"], None)
    served = batch.read(role="served", columns=["user_id", "date", "model_split", "anomaly_score"])
    if meta.get("rows_option") == "evaluation":
        served = served[served["model_split"] != "train"].reset_index(drop=True)
    keys_same = len(served) == len(risk) and (served["user_id"].to_numpy() == risk["user_id"].astype("string").to_numpy()).all() \
        and (served["date"].to_numpy() == risk["date"].astype("string").to_numpy()).all()
    c.ok(s, "one risk row per served batch row, same order", keys_same, f"{len(risk)} risk rows, {len(served)} served rows")
    c.ok(s, "anomaly score carried through unchanged (§14)", keys_same and np.array_equal(
        served["anomaly_score"].to_numpy(dtype="float64"), risk["anomaly_score"].to_numpy(dtype="float64")))
    c.ok(s, "model_split tags carried through (N31)", keys_same and (served["model_split"].to_numpy() == risk["model_split"].astype("string").to_numpy()).all())

    cri = risk["cri_score"].to_numpy(dtype="float64")
    c.ok(s, "cri_score finite and in [0, 100]", bool(np.isfinite(cri).all() and cri.min() >= 0 and cri.max() <= 100),
         f"min {cri.min():.3f}, max {cri.max():.3f}")
    pts = sum(risk[f"points_{x}"].to_numpy(dtype="float64") for x in COMPONENTS)
    c.ok(s, "points sum to cri_score", float(np.abs(pts - cri).max()) <= TOL, f"max diff {np.abs(pts - cri).max():.2e}")
    run_cfg = config_from_meta(meta)
    c.ok(s, "severity matches the configured bands", (severity_of(cri, run_cfg) == risk["severity"].to_numpy()).all())
    unavailable = meta.get("unavailable_components", {})
    for comp in unavailable:
        c.ok(s, f"{comp} unavailable: no value, no points, never invented",
             risk[f"component_{comp}"].isna().all() and (risk[f"points_{comp}"] == 0).all(), unavailable[comp])
    comps = {x: risk[f"component_{x}"].to_numpy(dtype="float64", na_value=np.nan) for x in COMPONENTS}
    again = combine(comps, {x for x in COMPONENTS if x not in unavailable}, run_cfg)
    c.ok(s, "recombining stored components reproduces cri_score", float(np.abs(again["cri"] - cri).max()) <= TOL)

    if cal is not None:
        engine = CRIEngine(run_cfg, cal)
        feats = read_feature_columns(Path(meta["features"]["path"]), risk[["user_id", "date"]])
        ctx = build_context(risk[["user_id", "date"]], feats, load_roles(processed), run_cfg.privileged_roles)
        if meta.get("mitre"):
            # Chapter 10 run: the recomputation joins the same enrichment run the batch joined
            from app.mitre.sources import mitre_run_dir, read_context

            mctx = read_context(mitre_run_dir(processed, meta["mitre"]["mitre_run_id"]), risk[["user_id", "date"]])
            ctx["mitre_context"] = mctx["mitre_context"].to_numpy(dtype="float64", na_value=np.nan)
        scores = risk[["user_id", "date", "model_split", "model_name", "model_version", "registry_version", "anomaly_score"]]
        fresh = engine.compute(scores, ctx)
        d = float(np.abs(fresh["cri_score"].to_numpy() - cri).max())
        c.ok(s, "a from-scratch recomputation reproduces every row", d <= 1e-12, f"max diff {d:.2e}")
        try:
            engine.check_model(risk["model_name"].iloc[0], "some-other-model-version")
            c.add(s, "scores from another model_version are refused (N29)", "FAIL", "no error raised")
        except CRIModelMismatchError:
            c.ok(s, "scores from another model_version are refused (N29)", True)
        try:
            engine.compute(scores.head(5).assign(role="shadow"), ctx.head(5))
            c.add(s, "shadow scores are refused (N32)", "FAIL", "no error raised")
        except CRIInputError:
            c.ok(s, "shadow scores are refused (N32)", True)

    summ = meta["summary"]
    beyond = sum(v.get("anomaly_beyond_reference", 0) for k, v in summ["by_model_split"].items() if k != "train")
    c.ok(s, "out-of-sample rows above the whole reference counted", True,
         f"{beyond} validation/test rows share the top rarity (resolution limit of the reference)")
    runlog = Path(os.getenv("CIRA_RUNLOG", str(repo_root() / "experiments" / "runlog.jsonl")))
    lines = [json.loads(x) for x in runlog.read_text(encoding="utf-8").splitlines() if x.strip()] if runlog.exists() else []
    c.ok(s, "runlog line (R8)", any(x.get("stage") == "chapter9_cri_batch" and x.get("cri_run_id") == run_dir.name for x in lines))
    c.ok(s, f"peak RSS under {RSS_TARGET_MB} MB", meta["peak_rss_mb"] < RSS_TARGET_MB, f"{meta['peak_rss_mb']} MB")
    return meta


def check_readout(c: Checks, args, meta: dict | None) -> None:
    s = "readout"
    path = Path(args.readout_path)
    if not path.exists():
        c.add(s, "validation readout present", "WARN", f"{path} not written yet; run `python -m app.cri.evaluate`")
        return
    r = json.loads(path.read_text(encoding="utf-8"))
    c.ok(s, "validation only (test is Chapter 16)", r.get("part") == "validation")
    if meta is not None:
        c.ok(s, "readout is of this risk run", r.get("cri_run_id") == meta["cri_run_id"], f"readout {r.get('cri_run_id')}")
    for h in r.get("harness", []):
        if h["ok"] is None:
            c.add(s, h["check"], "WARN", h["detail"])
        else:
            c.ok(s, h["check"], h["ok"], h["detail"])
    warns = r.get("guard", {}).get("warnings", [])
    if not warns:
        c.ok(s, f"{r.get('guard', {}).get('version')}: default CRI does no harm on validation", True)
    for w in warns:
        c.add(s, f"{r['guard']['version']}", "WARN", w)


def _parse_args(argv):
    root = repo_root()
    p = argparse.ArgumentParser(description="Verify Chapter 9 (CRI)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--cri-run-id", default=None)
    p.add_argument("--pin-path", default=str(resolve_pin_path()))
    p.add_argument("--models-dir", default=os.getenv("MODEL_PATH") or str(default_models_root()))
    p.add_argument("--readout-path", default=str(root / "experiments" / READOUT_FILE))
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter9"))
    p.add_argument("--no-readout", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    processed = Path(args.processed_dir)
    c = Checks()
    print("[verify chapter9]", flush=True)
    cfg = check_config(c)
    cal = check_calibration(c, args, processed, cfg) if cfg else None
    meta = check_risk(c, args, processed, cfg, cal) if cfg else None
    if not args.no_readout:
        check_readout(c, args, meta)
    counts = c.counts()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.results_dir) / f"verification_{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"profile": args.profile, "cri_run_id": None if meta is None else meta["cri_run_id"],
                               "counts": counts, "checks": c.rows}, indent=2), encoding="utf-8")
    append_experiment_runlog({"stage": "chapter9_verification", "profile": args.profile,
                              "cri_run_id": None if meta is None else meta["cri_run_id"],
                              "calibration_id": None if cal is None else cal.calibration_id,
                              "readout_checked": not args.no_readout, "pass": counts["PASS"], "warn": counts["WARN"],
                              "fail": counts["FAIL"], "peak_rss_mb": round(memory_rss_mb(), 1)})
    print(f"[verify chapter9] {counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL -> {out}", flush=True)
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
