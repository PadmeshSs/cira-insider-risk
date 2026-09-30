"""Chapter 11 end to end on a synthetic CERT tree, with real models:

Chapter 5 features + labels -> behaviour-only XGBoost (served) and TabNet
(shadow), both registered -> Chapter 8 batch with shadow -> Chapter 9
calibration -> Chapter 10 reference and enrichment -> CRI with MITRE ->
explain batch -> verifier -> validation readout (with the shadow mask view)
-> verifier again -> API health.

Unlike the Chapter 9 and 10 tests, the scores here come from trained models,
because TreeSHAP has to reproduce the margin of the model that scored.
"""
import importlib.util
import json
import os
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.cri import batch as cri_batch
from app.cri import calibrate as cri_calibrate
from app.explainability import batch as explain_batch
from app.explainability import evaluate as explain_evaluate
from app.explainability.sources import (
    ATTRIBUTIONS_OUTPUT,
    KERNEL_OUTPUT,
    SELECTION_OUTPUT,
    SUMMARY_OUTPUT,
    read_reasons,
)
from app.feature_engineering.pipeline import run_pipeline
from app.ingestion.ground_truth import build_insider_label_tables
from app.mitre import batch as mitre_batch
from app.mitre import calibrate as mitre_calibrate
from app.scoring import batch as score_batch
from app.scoring import gbdt_candidate
from app.tabnet.train import _parse_args as ch7_args
from app.tabnet.train import run as ch7_run
from fixtures import synthetic_ch6

REPO = Path(__file__).resolve().parents[3]
STATIC = "psych_,peer_department_size"


def _plant_http(raw: Path, users: list[str]) -> None:
    """Leak-site visits for two insiders and one benign user; a keylogger site for a scenario-3 insider."""
    http = pd.read_csv(raw / "http.csv", dtype=str, keep_default_na=False)
    plan = [(users[0], "wikileaks.org"), (users[5], "wikileaks.org"), (users[20], "pastebin.com"),
            (users[10], "keylogger.org")]
    days = [d for d in pd.date_range("2010-02-01", "2010-02-26", freq="D") if d.dayofweek < 5]
    rows = []
    for i, (u, host) in enumerate(plan):
        for k, d in enumerate(days[i::6][:3]):
            rows.append((f"{{P{i:03d}{k:03d}}}", f"{d:%m/%d/%Y} 22:{10 + k:02d}:00", u, "PC-0001", f"http://{host}/x{k}.html", "w"))
    both = pd.concat([http, pd.DataFrame(rows, columns=["id", "date", "user", "pc", "url", "content"])], ignore_index=True)
    order = pd.to_datetime(both["date"], format="%m/%d/%Y %H:%M:%S").argsort(kind="stable")
    both.iloc[order].to_csv(raw / "http.csv", index=False)


def _load_script(name):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _env(world) -> dict:
    return {"CIRA_RUNLOG": str(world["root"] / "runlog.jsonl"), "MODEL_PATH": str(world["models"]),
            "CIRA_SERVED_MODEL": "gbdt:v0001", "CIRA_SHADOW_MODEL": "tabnet:v0001",
            "CIRA_CRI_CALIBRATION": str(world["cri_pin"]), "CIRA_MITRE_REFERENCE": str(world["mitre_pin"])}


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("ch11")
    paths = synthetic_ch6.build(root)
    _plant_http(paths["raw"], paths["users"])
    processed = root / "processed"
    exp = root / "experiments"
    w = {"root": root, "processed": processed, "models": root / "models", "splits": root / "splits",
         "cri_pin": exp / "chapter9_cri_calibration.json", "mitre_pin": exp / "chapter10_mitre_reference.json",
         "readout": exp / "chapter11_validation_readout.json", "results": root / "r11"}
    mp = pytest.MonkeyPatch()
    for k, v in _env(w).items():
        mp.setenv(k, v)
    for k in [k for k in os.environ if k.startswith(("CRI_", "MITRE_"))]:
        mp.delenv(k)
    try:
        run_pipeline(paths["raw"], processed, profile="full", ground_truth_dir=paths["gt"])
        build_insider_label_tables(paths["gt"], processed)
        common = ["--processed-dir", str(processed), "--profile", "full", "--splits-dir", str(w["splits"]),
                  "--models-dir", str(w["models"])]
        w["gbdt"] = gbdt_candidate.run(gbdt_candidate._parse_args(common + ["--results-dir", str(root / "r8"), "--device", "cpu"]))
        w["tabnet"] = ch7_run(ch7_args(common + ["--checkpoint-dir", str(root / "ckpt"), "--results-dir", str(root / "r7"),
                                                 "--max-epochs", "3", "--batch-size", "512", "--virtual-batch-size", "128",
                                                 "--device", "cpu", "--exclude-features", STATIC]))
        w["batch"] = score_batch.run(score_batch._parse_args(["--processed-dir", str(processed), "--profile", "full",
                                                              "--with-shadow", "--splits-dir", str(w["splits"])]))
        cri = ["--processed-dir", str(processed), "--profile", "full", "--models-dir", str(w["models"]),
               "--pin-path", str(w["cri_pin"])]
        assert cri_calibrate.main(cri + ["--min-reference-rows", "50"]) == 0
        mitre_calibrate.run(mitre_calibrate._parse_args(["--processed-dir", str(processed), "--profile", "full",
                                                         "--splits-dir", str(w["splits"]), "--models-dir", str(w["models"]),
                                                         "--pin-path", str(w["mitre_pin"]), "--min-reference-rows", "50"]))
        m = mitre_batch.run(mitre_batch._parse_args(["--processed-dir", str(processed), "--profile", "full",
                                                     "--models-dir", str(w["models"]), "--pin-path", str(w["mitre_pin"])]))
        w["cri_plain"] = cri_batch.run(cri_batch._parse_args(cri))
        w["cri"] = cri_batch.run(cri_batch._parse_args(cri + ["--mitre-run-id", m["mitre_run_id"]]))
        w["mitre"] = m
    finally:
        mp.undo()
    return w


@pytest.fixture(autouse=True)
def _pins(world, monkeypatch):
    for k, v in _env(world).items():
        monkeypatch.setenv(k, v)
    for k in [k for k in os.environ if k.startswith(("CRI_", "MITRE_"))]:
        monkeypatch.delenv(k)


def _explain_args(world, *extra):
    return ["--processed-dir", str(world["processed"]), "--profile", "full", "--splits-dir", str(world["splits"]),
            "--max-bounded-rows", "40", "--n-background", "20", *extra]


@pytest.fixture(scope="module")
def run(world):
    mp = pytest.MonkeyPatch()
    for k, v in _env(world).items():
        mp.setenv(k, v)
    try:
        return explain_batch.run(explain_batch._parse_args(_explain_args(world)))
    finally:
        mp.undo()


def test_the_served_model_is_xgboost_and_the_shadow_tabnet(world):
    served = world["batch"]["served"]
    assert served["model_name"] == "gbdt" and served["static_inputs"] == []
    assert [s["model_name"] for s in world["batch"]["shadow"]] == ["tabnet"]


def test_explain_run_covers_every_scored_user_day(world, run):
    d = Path(run["outputs"][SUMMARY_OUTPUT]).parent
    summary = pd.read_parquet(d / SUMMARY_OUTPUT)
    scores = pd.read_parquet(world["batch"]["output"])
    served = scores[scores["role"] == "served"]
    assert len(summary) == len(served) and summary["method"].eq("treeshap").all()
    assert summary["model_version"].eq(world["batch"]["served"]["model_version"]).all()
    assert summary["additivity_error"].max() <= 1e-3
    assert np.abs(summary["raw_score"].to_numpy() - served["raw_score"].to_numpy()).max() <= 1e-4
    attr = pd.read_parquet(d / ATTRIBUTIONS_OUTPUT)
    assert attr.groupby(["user_id", "date"]).size().max() <= run["top_k"]
    assert not attr["is_static"].any()                                             # N25: not a model input
    assert not [c for c in [*summary.columns, *attr.columns] if any(w in c for w in ("label", "malicious", "scenario"))]
    assert run["shadow"].startswith("not loaded")                                  # N32
    lines = [json.loads(x) for x in (world["root"] / "runlog.jsonl").read_text().splitlines()]
    assert any(x.get("stage") == "chapter11_explain_batch" and x["explain_run_id"] == run["explain_run_id"] for x in lines)


def test_bounded_set_kernel_and_reasons(world, run):
    d = Path(run["outputs"][SUMMARY_OUTPUT]).parent
    sel = pd.read_parquet(d / SELECTION_OUTPUT)
    assert 0 < len(sel) <= 40 and set(sel["model_split"]) <= {"validation", "test"}      # N31
    assert run["risk_run"]["cri_run_id"] == world["cri"]["cri_run_id"] and run["risk_run"]["with_mitre"]
    k = run["kernel"]
    assert k["status"] == "done", k
    assert k["nsamples"] > k["n_inputs"] and k["n_background"] == 20
    split = json.loads(Path(k["background_split"]["file"]).read_text())["assignment"]
    assert all(split[u] == "train" for u, _d in k["background_keys"])            # training users only
    kern = pd.read_parquet(d / KERNEL_OUTPUT)
    assert len(kern) == len(sel) and kern["kernel_additivity_error"].max() < 1e-6
    reasons = read_reasons(d)
    assert len(reasons) == len(sel) and all(r["status"] == "complete" for r in reasons)
    for r in reasons:
        assert r["headline"]["model_name"] == "gbdt" and r["model"]["method"] == "treeshap"
        assert all(f["source"]["kind"] == "model" for f in r["model_factors"])
        assert all(c["source"]["kind"] == "cri" for c in r["context_factors"])
        assert r["attack_context"]["status"] in ("mapped", "unmapped", "not_evaluated")
    mapped = [r for r in reasons if r["attack_context"]["matches"]]
    assert mapped, "the planted leak-site and USB behaviour should map on some selected day"


def test_verifier_passes_before_and_after_the_readout(world, run, capsys):
    verify = _load_script("verify_chapter11")
    base = ["--processed-dir", str(world["processed"]), "--profile", "full", "--explain-run-id", run["explain_run_id"],
            "--readout-path", str(world["readout"]), "--results-dir", str(world["results"])]
    assert verify.main(base + ["--no-readout"]) == 0
    out = capsys.readouterr().out
    assert " 0 FAIL" in out and "TreeSHAP equals shap.TreeExplainer" in out

    readout = explain_evaluate.run(explain_evaluate._parse_args(
        ["--processed-dir", str(world["processed"]), "--profile", "full", "--explain-run-id", run["explain_run_id"],
         "--readout-path", str(world["readout"])]))
    assert readout["part"] == "validation" and readout["method"] == "treeshap"
    assert sum(b["days"] for b in readout["malicious_days_by_scenario"].values()) > 0
    view = readout["second_model_view"]
    assert view["available"] and "shadow" in view["label"] and view["model"]["role"] == "shadow"
    assert explain_evaluate.main(["--processed-dir", str(world["processed"]), "--profile", "full",
                                  "--readout-path", str(world["readout"])]) == 2          # written once
    assert verify.main(base) == 0
    assert " 0 FAIL" in capsys.readouterr().out


def test_readout_refuses_test(world, run):
    with pytest.raises(explain_evaluate.ReadoutRefused, match="validation only"):
        explain_evaluate.run(explain_evaluate._parse_args(["--processed-dir", str(world["processed"]), "--profile", "full",
                                                           "--part", "test", "--readout-path", str(world["root"] / "x.json")]))


def test_batch_refuses_when_the_served_model_did_not_score_the_batch(world, run, monkeypatch, capsys):
    monkeypatch.setenv("CIRA_SERVED_MODEL", "tabnet:v0001")                         # a rollback without a new batch
    monkeypatch.delenv("CIRA_SHADOW_MODEL")
    assert explain_batch.main(_explain_args(world, "--no-kernel")) == 2
    assert "Explanations come from the model that scored (N30)" in capsys.readouterr().err


def test_kernel_failure_degrades_without_blocking(world, run, tmp_path):
    """No split file for the background: TreeSHAP and the reasons are still written (§36)."""
    meta = explain_batch.run(explain_batch._parse_args(
        ["--processed-dir", str(world["processed"]), "--profile", "full", "--splits-dir", str(tmp_path),
         "--max-bounded-rows", "5"]))
    assert meta["kernel"]["status"] == "failed" and "split" in meta["kernel"]["reason"]
    assert meta["summary"]["reasons_written"] == meta["summary"]["bounded_rows"] > 0


def test_api_health_shows_the_explainer_for_the_served_model(world):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        body = client.get("/health").json()
    e = body["explainability"]
    assert e["status"] == "loaded" and e["method"] == "treeshap" and e["registry_version"] == "v0001"
    assert e["role"] == "served"
