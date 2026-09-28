"""Verify Chapter 8 before any served score is used.

Sections (each runs when its inputs exist; every check prints PASS, WARN or
FAIL; exit code 1 on any FAIL):

    candidate  a behaviour-only XGBoost run (--candidate-run-id): split,
               masquerade, class weight, static traits, registry, reload,
               same rows and matrix as the Chapter 6 reference, optional
               label-permutation test (--permutation-test)
    decision   the serving decision: rule unchanged, validation only,
               gates, reproducible from the score files, test read after it
    served     the served model loads through the service on CPU and
               reproduces its training-time scores; a tampered copy is refused
    batch      a batch scoring run (--batch-run-id, or the newest): schema,
               no labels, lineage columns, model_split tags, served scores
               equal the training-time scores on validation and test rows

Usage, from backend/ (same env vars as the runners):

    python ../scripts/verify_chapter8.py --profile mid --candidate-run-id <run> --permutation-test --no-decision
    python ../scripts/verify_chapter8.py --profile full --candidate-run-id <run> --permutation-test --no-decision
    python ../scripts/verify_chapter8.py --profile full                       # after select and batch

Writes ``experiments/results/chapter8/verification_<stamp>.json`` and one
``chapter8_verification`` runlog line. This is evaluation code: it reads
labels in memory, like the runners.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.runtime import apply_thread_caps  # noqa: E402

apply_thread_caps()

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import tempfile  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.evaluation.compare import load_reference_runs, reference_runs_for, _runlog_lines  # noqa: E402
from app.evaluation.labels import attach_labels, load_label_views  # noqa: E402
from app.evaluation.metrics import pr_auc  # noqa: E402
from app.evaluation.splitting import load_split, rows_for_split, time_split  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, repo_root  # noqa: E402
from app.scoring.batch import BATCH_COLUMNS, META_FILE, OUTPUT_FILE  # noqa: E402
from app.scoring.contracts import ModelPin, ScoringUnavailableError  # noqa: E402
from app.scoring.select import CANDIDATES, RULE, active_rule, collect, decide, gate  # noqa: E402
from app.scoring.service import AnomalyScoringService  # noqa: E402
from app.scoring.serving_config import ServingConfig, resolve_serving_config  # noqa: E402
from app.tabnet.dataset import file_sha256, load_feature_matrix  # noqa: E402
from app.tabnet.model_registry import ModelRegistry, RegistryError  # noqa: E402

LABEL_WORDS = ("malicious", "insider", "scenario", "label", "y_primary", "y_account", "is_masquerade", "target")
RSS_TARGET_MB = 10 * 1024
LABEL_FREE_BASELINES = ("rule_based", "isolation_forest", "lof", "lstm_autoencoder")
EXACT = 1e-12
# Re-scoring the same rows in a different batch composition moves TabNet's
# float32 matmuls in the last bits (measured: up to ~6e-6 on the score).
# Chapter 7's own batch-composition test allows 1e-5; the same tolerance is
# used here wherever the serving path re-scores rows. XGBoost scores each row
# independently and its reload check stays exact.
RESCORE_TOL = 1e-5


class Checks:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, section: str, name: str, status: str, detail: str = "") -> None:
        self.rows.append({"section": section, "check": name, "status": status, "detail": detail})
        print(f"  {status:<4} {section:<10} {name}" + (f"  -- {detail}" if detail else ""), flush=True)

    def ok(self, section, name, cond, detail="", warn_only=False) -> bool:
        self.add(section, name, "PASS" if cond else ("WARN" if warn_only else "FAIL"), detail)
        return bool(cond)

    def counts(self) -> dict:
        return {s: sum(r["status"] == s for r in self.rows) for s in ("PASS", "WARN", "FAIL")}


def _norm_keys(frame: pd.DataFrame) -> pd.DataFrame:
    out = frame.copy()
    out["user_id"] = out["user_id"].astype("string").str.strip().str.casefold()
    out["date"] = out["date"].astype("string")
    return out


def _training_scores(processed: Path, entry: dict) -> pd.DataFrame:
    chapter_dir = "chapter7" if entry["model_name"] == "tabnet" else "chapter8"
    path = processed / "scores" / chapter_dir / entry["run_id"] / f"{entry['model_name']}.parquet"
    return _norm_keys(pd.read_parquet(path))


def _max_diff_against(stored: pd.DataFrame, scored: pd.DataFrame) -> tuple[float, int]:
    j = stored.merge(scored[["user_id", "date", "anomaly_score"]], on=["user_id", "date"], suffixes=("_stored", "_now"))
    if not len(j):
        return float("inf"), 0
    return float(np.abs(j["anomaly_score_stored"].to_numpy() - j["anomaly_score_now"].to_numpy()).max()), len(j)


# ---------------------------------------------------------------------------

def check_candidate(c: Checks, args, processed: Path, runlog: list[dict]) -> None:
    S = "candidate"
    from app.scoring.gbdt_model import BehaviourGBDTDetector

    mpath = Path(args.results_dir) / args.candidate_run_id / "metrics.json"
    if not c.ok(S, "metrics.json exists", mpath.exists(), str(mpath)):
        return
    rep = json.loads(mpath.read_text(encoding="utf-8"))
    md = rep["models"]["gbdt"]["metadata"]
    c.ok(S, "profile matches", rep["profile"] == args.profile, rep["profile"])
    c.ok(S, "reportable flag follows N6", rep["reportable"] == (rep["profile"] != "dev"))
    c.ok(S, "no accuracy anywhere (N2)", "accuracy" not in json.dumps(rep).lower())
    excluded = rep["features"]["excluded_from_model"]
    c.ok(S, "static traits excluded (C8-2, N25)", bool(excluded) and all(x.startswith(("psych_", "peer_department_size")) for x in excluded),
         f"{len(excluded)} columns")
    c.ok(S, "no static trait among model inputs", md.get("static_inputs") == [], str(md.get("static_inputs")))
    c.ok(S, "model_version is a Chapter 8 version", md["model_version"].startswith("gbdt-chapter8-v1-"), md["model_version"])

    split = rep["split"]
    if split["mode"] == "user":
        f = Path(args.splits_dir) / Path(split["file"]).name
        c.ok(S, "split file loaded, not created (N11)", split.get("created_now") is False or rep["profile"] == "dev")
        c.ok(S, "split file unchanged since the run", f.exists() and file_sha256(f) == split.get("file_sha256"), f.name)
    tr = rep["training_rows"]
    c.ok(S, "masquerade days dropped from training rows (N13)",
         tr["train_masquerade_dropped"] == split["masquerade_rows_excluded"]["train"]
         and tr["validation_masquerade_dropped"] == split["masquerade_rows_excluded"]["validation"],
         f"train {tr['train_masquerade_dropped']}, validation {tr['validation_masquerade_dropped']}")
    imb = md["imbalance"]
    ratio = imb["train_negatives"] / imb["train_positives"]
    c.ok(S, "scale_pos_weight = negatives / positives on training rows (N2)",
         abs(imb["effective_positive_weight"] - ratio) < 1e-9 and imb["train_positives"] == split["positives_primary"]["train"],
         f"{imb['effective_positive_weight']:.3f}")

    line = next((r for r in runlog if r.get("stage") == "chapter8_gbdt_candidate" and r.get("run_id") == args.candidate_run_id), None)
    c.ok(S, "runlog line present (R8)", line is not None)

    reg = ModelRegistry(args.models_dir, "gbdt")
    try:
        entry = reg.resolve(args.candidate_run_id)
    except RegistryError as exc:
        c.add(S, "registered", "FAIL", str(exc))
        entry = None
    if entry is not None:
        c.ok(S, "registry artifact sha256 intact (N21)", reg.verify(entry) == [], str(reg.verify(entry)))
        det = BehaviourGBDTDetector.load(reg.artifact_dir(entry))
        det.use_cpu(2)
        fm = load_feature_matrix(processed, rep["profile"])
        stored = _training_scores(processed, entry)
        rows = fm.matrix.merge(stored[["user_id", "date"]], on=["user_id", "date"])
        now = rows[["user_id", "date"]].assign(anomaly_score=det.score(rows))
        diff, n = _max_diff_against(stored, now)
        trained_on = md.get("device_used") or "cpu"
        tol = EXACT if trained_on == "cpu" else RESCORE_TOL      # GPU and CPU predictors differ in the last bits
        c.ok(S, "reloaded artifact reproduces stored scores", n == len(stored) and diff <= tol,
             f"{n} rows, max diff {diff:.2e} (trained on {trained_on}, reloaded on cpu, tolerance {tol:g})")

    ref6 = reference_runs_for(load_reference_runs(args.ch6_references), rep["profile"], split["mode"]).get("gbdt") \
        if Path(args.ch6_references).exists() else None
    if ref6:
        p6 = processed / "scores" / "chapter6" / ref6 / "gbdt.parquet"
        if p6.exists():
            a = _norm_keys(pd.read_parquet(p6, columns=["user_id", "date", "split"])).sort_values(["split", "user_id", "date"]).reset_index(drop=True)
            b = _training_scores(processed, {"model_name": "gbdt", "run_id": args.candidate_run_id})[["user_id", "date", "split"]]
            b = b.sort_values(["split", "user_id", "date"]).reset_index(drop=True)
            c.ok(S, "same validation and test rows as the Chapter 6 reference (N18)", a.equals(b), f"{len(b)} rows")
            l6 = next((r for r in runlog if r.get("stage") == "chapter6_baseline" and r.get("run_id") == ref6 and r.get("model") == "gbdt"), None)
            c.ok(S, "same feature matrix as the Chapter 6 reference", l6 is not None and l6.get("feature_fingerprint") == rep["features"]["fingerprint"],
                 f"{None if l6 is None else l6.get('feature_fingerprint')} vs {rep['features']['fingerprint']}")
        else:
            c.add(S, "Chapter 6 reference score file", "WARN", f"{p6} not found; comparability not checked")

    if args.permutation_test:
        views = load_label_views(processed)
        fm = load_feature_matrix(processed, rep["profile"])
        lab = attach_labels(fm.keys, views)
        if split["mode"] == "user":
            assignment, _ = load_split(Path(args.splits_dir) / Path(split["file"]).name)
            rows = rows_for_split(fm.keys["user_id"], assignment)
        else:
            rows = time_split(fm.keys["date"], validation_start=split["validation_start"], test_start=split["test_start"])
        keep = ~lab["exclude_primary"].to_numpy()
        tr_ix, te_ix = np.flatnonzero((rows == "train") & keep), np.flatnonzero((rows == "test") & keep)
        y_te = lab["y_primary"].to_numpy()[te_ix]
        chance = float(y_te.mean())
        values = []
        for seed in (12345, 12346, 12347):
            y_tr = np.random.default_rng(seed).permutation(lab["y_primary"].to_numpy()[tr_ix])
            det = BehaviourGBDTDetector(seed=0, n_estimators=300, device="cpu", excluded_features=excluded)
            det.fit(fm.matrix.iloc[tr_ix].drop(columns=excluded).reset_index(drop=True), y_tr)
            values.append(pr_auc(y_te, det.score(fm.matrix.iloc[te_ix].reset_index(drop=True))))
        worst = max(v for v in values if v is not None)
        ref = label_free_reference(args, rep["profile"], split["mode"])
        status, detail = ch7_permutation_verdict()(worst, chance, ref)
        c.add("leakage", "XGBoost on shuffled labels stays near chance (3 shuffles, C7-8 rule)", status,
              detail + f"; all {[round(v, 4) for v in values]}")


def ch7_permutation_verdict():
    """Chapter 7's PASS / WARN / FAIL rule (deviation C7-8), loaded from its verifier so there is one definition."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_chapter7", Path(__file__).resolve().parent / "verify_chapter7.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.permutation_verdict


def label_free_reference(args, profile: str, split_mode: str) -> tuple[str, float] | None:
    """Best logged test PR-AUC of a label-free Chapter 6 reference baseline on these rows."""
    if not Path(args.ch6_references).exists():
        return None
    refs = reference_runs_for(load_reference_runs(args.ch6_references), profile, split_mode)
    best = None
    for line in _runlog_lines():
        model = line.get("model")
        if (line.get("stage") == "chapter6_baseline" and model in LABEL_FREE_BASELINES and refs.get(model) == line.get("run_id")
                and line.get("test_pr_auc") is not None and (best is None or line["test_pr_auc"] > best[1])):
            best = (model, float(line["test_pr_auc"]))
    return best


def check_decision(c: Checks, args, processed: Path) -> dict | None:
    S = "decision"
    path = Path(args.decision_path)
    if not c.ok(S, "decision file exists", path.exists(), str(path)):
        return None
    raw = path.read_bytes()
    d = json.loads(raw)
    rule = d["rule"]
    fixed = {k: v for k, v in RULE.items()}
    core = ("version", "criterion", "margin", "default", "served_profile", "text")
    c.ok(S, "rule unchanged from code (c8-serving-rule-v1)", all(rule.get(k) == fixed[k] for k in core))
    if rule.get("split_keys_overridden"):
        c.add(S, "rule split keys", "WARN", f"overridden to {rule['decisive']} / {rule['consistency']}: synthetic-test decision, never report it")
    else:
        c.ok(S, "rule split keys are the documented ones", rule["decisive"] == RULE["decisive"] and rule["consistency"] == RULE["consistency"])
    c.ok(S, "decided on validation only (N11)", d.get("part_used") == "validation")
    served = d["outcome"]["served"]
    c.ok(S, "served model is a pinned registry version (N21)", bool(served.get("registry_version", "").startswith("v")), str(served))
    c.ok(S, "served model passed every gate", d["gates"][served["model_name"]]["ok"], json.dumps(d["gates"][served["model_name"]]["checks"]))
    c.ok(S, "deviation recorded when XGBoost is served", (served["model_name"] == "gbdt") == (d["outcome"]["deviation"] == "C8-1"))

    # Reproduce: recompute the evidence from the score files and apply the rule again.
    ns = argparse.Namespace(processed_dir=str(processed), ch7_references=args.ch7_references, ch6_references=args.ch6_references,
                            models_dir=args.models_dir, seed=args.seed, decisive=rule["decisive"], consistency=",".join(rule["consistency"]))
    gbdt_runs = {k: v["run_id"] for k, v in d["candidates"]["gbdt"].items()}
    try:
        ev = collect(ns, "validation", gbdt_runs)
        pr = {k: {m: v["models"][m]["pr_auc"] for m in CANDIDATES} for k, v in ev.items()}
        stored = {k: {m: v["models"][m]["pr_auc"] for m in CANDIDATES} for k, v in d["evidence"].items()}
        same = all(abs(pr[k][m] - stored[k][m]) <= EXACT for k in stored for m in CANDIDATES)
        c.ok(S, "validation evidence reproduces from the score files", same, json.dumps(pr))
        regs = {m: ModelRegistry(args.models_dir, m) for m in CANDIDATES}
        gates = {m: gate(m, ev[rule["decisive"]]["_entries"][m], regs[m], rule["served_profile"])["ok"] for m in CANDIDATES}
        again = decide(pr, gates, rule=active_rule(ns))
        c.ok(S, "rule applied again gives the same served model", again["served"] == served["model_name"], again["reason"])
    except Exception as exc:     # noqa: BLE001 - any failure here means the decision cannot be reproduced
        c.add(S, "decision reproducible", "FAIL", f"{type(exc).__name__}: {exc}")

    readout = Path(args.test_readout_path)
    if readout.exists():
        r = json.loads(readout.read_text(encoding="utf-8"))
        c.ok(S, "test read after the decision, not before", r["read_at"] >= d["decided_at"], f"{d['decided_at']} -> {r['read_at']}")
        c.ok(S, "decision unchanged since test was read", r["decision_sha256"] == hashlib.sha256(raw).hexdigest())
        c.ok(S, "test readout harness reproduces every logged test PR-AUC",
             all(x["match"] for rows in r["harness_check"].values() for x in rows))
    else:
        c.add(S, "test readout", "WARN", "not read yet; run `python -m app.scoring.select --report-test` once for the write-up")
    return d


def check_served(c: Checks, args, processed: Path, decision: dict | None) -> AnomalyScoringService | None:
    S = "served"
    cfg = resolve_serving_config()
    if cfg.source == "env":
        c.add(S, "served model source", "WARN", "pinned by CIRA_SERVED_MODEL, not by the recorded decision")
    svc = AnomalyScoringService.load(cfg, allow_unreportable=args.allow_unreportable)
    if not c.ok(S, "served model loads through the service", svc.available, svc.unavailable_reason or ""):
        return None
    st = svc.status()
    if decision is not None and cfg.source == "decision_file":
        want = decision["outcome"]["served"]
        c.ok(S, "loaded model is the decided one", st["served"]["registry_version"] == want["registry_version"]
             and st["served"]["model_version"] == want["model_version"], f"{st['served']['model_name']} {st['served']['registry_version']}")
    c.ok(S, "served on CPU (HCEA §8)", st["served"]["device"] == "cpu")
    c.ok(S, "served model is behaviour-only", st["served"]["static_inputs"] == [])
    if cfg.shadows:
        c.ok(S, "shadow model loads", len(svc.shadows) == len(cfg.shadows), json.dumps(svc.shadow_load_errors), warn_only=True)

    entry = svc.served.entry
    stored = _training_scores(processed, entry)
    fm = load_feature_matrix(processed, entry["profile"])
    rows = fm.matrix.merge(stored[["user_id", "date"]], on=["user_id", "date"])
    diff, n = _max_diff_against(stored, svc.score_frame(rows))
    c.ok(S, "serving path reproduces training-time scores", n == len(stored) and diff <= RESCORE_TOL,
         f"{n} rows, max diff {diff:.2e} (tolerance {RESCORE_TOL:g})")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = Path(entry["artifact_dir"]) if Path(entry["artifact_dir"]).exists() else Path(args.models_dir) / entry["model_name"] / entry["registry_version"]
        shutil.copytree(src.parent, root / entry["model_name"])
        victim = next(p for p in sorted((root / entry["model_name"] / entry["registry_version"]).iterdir()) if p.name != "registry_entry.json")
        victim.write_bytes(victim.read_bytes() + b" ")
        bad = AnomalyScoringService.load(ServingConfig(ModelPin(entry["model_name"], entry["registry_version"]), (), root, "verify"))
        refused = not bad.available
        try:
            bad.score_event({})
            refused = False
        except ScoringUnavailableError:
            pass
        c.ok(S, "tampered artifact is refused, no score (§36)", refused, bad.unavailable_reason or "")
    return svc


def check_batch(c: Checks, args, processed: Path, svc: AnomalyScoringService | None) -> None:
    S = "batch"
    root = processed / "scores" / "chapter8"
    runs = sorted(p.name for p in root.iterdir() if p.is_dir() and p.name.endswith("-batch") and (p / META_FILE).exists()) if root.exists() else []
    run_id = args.batch_run_id or (runs[-1] if runs else None)
    if run_id is None:
        c.add(S, "batch run", "WARN", "no batch run yet; run `python -m app.scoring.batch --profile full`")
        return
    meta = json.loads((root / run_id / META_FILE).read_text(encoding="utf-8"))
    frame = pd.read_parquet(root / run_id / OUTPUT_FILE)
    c.ok(S, "columns are the batch contract", list(frame.columns) == list(BATCH_COLUMNS), str(list(frame.columns)))
    c.ok(S, "no label column in the score file (N5)", not any(w in col.lower() for col in frame.columns for w in LABEL_WORDS))
    s = frame["anomaly_score"].to_numpy()
    c.ok(S, "scores finite and in [0, 1] (N10)", np.isfinite(s).all() and ((s >= 0) & (s <= 1)).all())
    served = frame[frame["role"] == "served"]
    c.ok(S, "one served model_version and registry_version (§37)", served["model_version"].nunique() == 1 and served["registry_version"].nunique() == 1)
    if svc is not None and svc.available:
        c.ok(S, "batch was scored by the model now served", served["model_version"].iloc[0] == svc.served.model_version,
             f"{served['model_version'].iloc[0]} vs {svc.served.model_version}", warn_only=True)
    c.ok(S, "one row per user-day per role", not frame.duplicated(["user_id", "date", "role"]).any())
    fm = load_feature_matrix(processed, meta["profile"])
    if meta["rows_option"] == "all":
        c.ok(S, "every matrix row scored", len(served) == len(fm.matrix), f"{len(served)} of {len(fm.matrix)}")
    rec = meta["model_split"]
    keys = _norm_keys(served[["user_id", "date"]])
    if rec["mode"] == "user":
        assignment, _ = load_split(rec["file"])
        want = keys["user_id"].map(assignment).fillna("unassigned").to_numpy()
    else:
        want = time_split(keys["date"], validation_start=rec["validation_start"], test_start=rec["test_start"])
    c.ok(S, "model_split tags follow the served model's split (N31)", np.array_equal(served["model_split"].to_numpy(), want))
    if meta["summary"]["rows_by_model_split"].get("train"):
        c.add(S, "in-sample rows present", "PASS", f"{meta['summary']['rows_by_model_split']['train']} rows tagged train; never quote detection from them")
    entry = meta["served"]
    stored = _training_scores(processed, {"model_name": entry["model_name"], "run_id": entry["run_id"]})
    diff, n = _max_diff_against(stored, _norm_keys(served))
    c.ok(S, "batch scores equal training-time scores on validation and test rows", n == len(stored) and diff <= RESCORE_TOL,
         f"{n} rows, max diff {diff:.2e} (tolerance {RESCORE_TOL:g})")
    c.ok(S, "no saturated served score", meta["summary"]["saturated_served_scores"] == 0,
         str(meta["summary"]["saturated_served_scores"]), warn_only=True)
    line = next((r for r in _runlog_lines() if r.get("stage") == "chapter8_batch_scoring" and r.get("batch_run_id") == run_id), None)
    c.ok(S, "runlog line present (R8)", line is not None)
    c.ok(S, "peak RSS under the HCEA target", meta["peak_rss_mb"] < RSS_TARGET_MB, f"{meta['peak_rss_mb']} MB")
    c.ok(S, "scored the matrix the model was trained on", meta["features"]["same_matrix_as_training"], warn_only=True)


def main(argv=None) -> int:
    root = repo_root()
    p = argparse.ArgumentParser(description="Verify Chapter 8")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=("dev", "mid", "full"))
    p.add_argument("--candidate-run-id", default=None)
    p.add_argument("--permutation-test", action="store_true")
    p.add_argument("--no-decision", action="store_true", help="candidate checks only (before select has run)")
    p.add_argument("--batch-run-id", default=None)
    p.add_argument("--decision-path", default=os.getenv("CIRA_SERVING_DECISION", str(root / "experiments" / "chapter8_serving_decision.json")))
    p.add_argument("--test-readout-path", default=str(root / "experiments" / "chapter8_test_readout.json"))
    p.add_argument("--ch6-references", default=str(root / "experiments" / "chapter6_reference_runs.json"))
    p.add_argument("--ch7-references", default=str(root / "experiments" / "chapter7_reference_runs.json"))
    p.add_argument("--models-dir", default=os.getenv("MODEL_PATH", str(root / "models" / "saved_models")))
    p.add_argument("--splits-dir", default=str(root / "experiments" / "splits"))
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter8"))
    p.add_argument("--seed", type=int, default=int(os.getenv("CIRA_SEED", "42")))
    p.add_argument("--allow-unreportable", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args(argv)
    os.environ.setdefault("MODEL_PATH", args.models_dir)
    os.environ.setdefault("CIRA_SERVING_DECISION", args.decision_path)
    processed = Path(args.processed_dir)
    c = Checks()
    print("\nVerifying Chapter 8\n")
    if args.profile == "dev":
        c.add("run", "dev numbers are for debugging only", "WARN", "never report them (HCEA R10)")
    if args.candidate_run_id:
        check_candidate(c, args, processed, _runlog_lines())
    if not args.no_decision:
        decision = check_decision(c, args, processed)
        svc = check_served(c, args, processed, decision)
        check_batch(c, args, processed, svc)

    counts = c.counts()
    out_dir = Path(args.results_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"verification_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out.write_text(json.dumps({"args": {k: v for k, v in vars(args).items()}, "counts": counts, "checks": c.rows}, indent=2, default=str),
                   encoding="utf-8")
    append_experiment_runlog({"stage": "chapter8_verification", "profile": args.profile, "candidate_run_id": args.candidate_run_id,
                              "permutation_test": args.permutation_test, "decision_checked": not args.no_decision,
                              "batch_run_id": args.batch_run_id, **{k.lower(): v for k, v in counts.items()}})
    print(f"\n{counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL  ->  {out}")
    if counts["FAIL"]:
        print("NOT READY: fix every FAIL before any served score is used.")
    elif counts["WARN"]:
        print("No FAILs. Read every WARN and note in the audit why it is acceptable.")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
