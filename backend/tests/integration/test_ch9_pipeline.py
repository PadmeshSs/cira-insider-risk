"""Chapter 9 end to end on a synthetic CERT tree:

Chapter 5 features + LDAP -> labels -> a Chapter 8-shaped batch (served +
shadow rows, split tags) -> calibration -> CRI batch -> validation readout ->
verifier -> API health.

The batch is written directly rather than trained: Chapter 9 consumes
scores, and the Chapter 8 chain is already covered by its own integration
test. The fake served model is pinned through CIRA_SERVED_MODEL, the way a
rollback would be. Scores are built from labels here only because this is a
test fixture; no Chapter 9 module reads a label except evaluate.py.
"""
import importlib.util
import json
import os
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.cri import batch as cri_batch
from app.cri import calibrate, evaluate
from app.evaluation.labels import attach_labels, load_label_views
from app.feature_engineering.common import atomic_to_parquet
from app.feature_engineering.pipeline import run_pipeline
from app.ingestion.ground_truth import build_insider_label_tables
from app.scoring.batch import BATCH_COLUMNS
from app.tabnet.dataset import feature_fingerprint
from fixtures import synthetic_ch6

REPO = Path(__file__).resolve().parents[3]
SERVED = {"model_name": "gbdt", "registry_version": "v0003", "model_version": "gbdt-chapter8-v1-synthetic0001",
          "run_id": "synthetic-full-user", "profile": "full"}
BATCH_ID = "20260929T000000Z-full-batch"


def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("ch9")
    paths = synthetic_ch6.build(root)
    processed = root / "processed"
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(root / "runlog.jsonl"))
    try:
        run_pipeline(paths["raw"], processed, profile="full", ground_truth_dir=paths["gt"])
        build_insider_label_tables(paths["gt"], processed)
    finally:
        mp.undo()

    users = [u.casefold() for u in paths["users"]]
    ldap_path = processed / "context" / "ldap_user_month.parquet"
    ldap = pd.read_parquet(ldap_path)
    ldap.loc[ldap["user_id"].str.casefold() == users[13], "role"] = "ITAdmin"   # one benign validation admin
    atomic_to_parquet(ldap, ldap_path)

    split = {u: "train" for u in users}
    for i in (0, 5, 10, *range(13, 19)):
        split[users[i]] = "validation"
    for i in (1, 6, 11, *range(19, 25)):
        split[users[i]] = "test"

    features = processed / "features" / "user_day_full.parquet"
    m = pd.read_parquet(features, columns=["user_id", "date"])
    keys = pd.DataFrame({"user_id": m["user_id"].astype("string").str.casefold(), "date": m["date"].astype("string")})
    y = attach_labels(keys, load_label_views(processed))["y_primary"].to_numpy()
    rng = np.random.default_rng(9)
    served = _sigmoid(-9 + 8 * y + 1.5 * rng.normal(size=len(keys)))
    shadow = _sigmoid(-1 + 2 * y + rng.normal(size=len(keys)))
    tags = keys["user_id"].map(split).to_numpy(dtype=object)
    parts = []
    for role, s, pin in (("served", served, SERVED), ("shadow", shadow, {"model_name": "tabnet", "registry_version": "v0005",
                                                                            "model_version": "tabnet-chapter7-v1-synthetic"})):
        parts.append(pd.DataFrame({"user_id": keys["user_id"], "date": keys["date"], "model_split": tags, "role": role,
                                   "model_name": pin["model_name"], "model_version": pin["model_version"],
                                   "registry_version": pin["registry_version"], "raw_score": np.log(s / (1 - s)),
                                   "anomaly_score": s, "batch_run_id": BATCH_ID}))
    frame = pd.concat(parts, ignore_index=True)[list(BATCH_COLUMNS)]
    out = processed / "scores" / "chapter8" / BATCH_ID
    atomic_to_parquet(frame, out / "anomaly_scores.parquet")
    (out / "batch_meta.json").write_text(json.dumps({
        "chapter": 8, "batch_run_id": BATCH_ID, "profile": "full", "served": SERVED, "decision_sha256": None,
        "features": {"path": str(features), "fingerprint": feature_fingerprint(features)}}))
    return {"root": root, "processed": processed, "users": users, "split": split, "features": features,
            "pin": root / "experiments" / "chapter9_cri_calibration.json", "models": root / "models",
            "readout": root / "experiments" / "chapter9_validation_readout.json", "results": root / "r9"}


@pytest.fixture(autouse=True)
def _env(world, monkeypatch):
    monkeypatch.setenv("CIRA_RUNLOG", str(world["root"] / "runlog.jsonl"))
    monkeypatch.setenv("CIRA_SERVED_MODEL", "gbdt:v0003")
    monkeypatch.setenv("MODEL_PATH", str(world["models"]))
    monkeypatch.setenv("CIRA_CRI_CALIBRATION", str(world["pin"]))
    for k in [k for k in os.environ if k.startswith("CRI_")]:
        monkeypatch.delenv(k)


def _cal_args(world, *extra):
    return ["--processed-dir", str(world["processed"]), "--profile", "full", "--models-dir", str(world["models"]),
            "--pin-path", str(world["pin"]), "--min-reference-rows", "50", *extra]


def _run_args(world, *extra):
    return ["--processed-dir", str(world["processed"]), "--profile", "full", "--models-dir", str(world["models"]),
            "--pin-path", str(world["pin"]), *extra]


def _eval_args(world, *extra):
    return ["--processed-dir", str(world["processed"]), "--profile", "full", "--decision-path", str(world["root"] / "none.json"),
            "--readout-path", str(world["readout"]), "--results-dir", str(world["results"]), *extra]


def test_calibration_refuses_a_batch_from_another_model(world, monkeypatch, capsys):
    monkeypatch.setenv("CIRA_SERVED_MODEL", "tabnet:v0005")
    assert calibrate.main(_cal_args(world)) == 2
    assert "N29" in capsys.readouterr().err and not world["pin"].exists()


@pytest.fixture(scope="module")
def calibrated(world):
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(world["root"] / "runlog.jsonl"))
    mp.setenv("CIRA_SERVED_MODEL", "gbdt:v0003")
    try:
        assert calibrate.main(_cal_args(world)) == 0
    finally:
        mp.undo()
    pin = json.loads(world["pin"].read_text())
    cal_dir = world["models"] / "cri" / pin["current"]["calibration_id"]
    return {"pin": pin, "meta": json.loads((cal_dir / "calibration.json").read_text()),
            "reference": pd.read_parquet(cal_dir / "reference.parquet")}


def test_calibration_is_validation_only_and_label_free(world, calibrated):
    ref, meta = calibrated["reference"], calibrated["meta"]
    assert set(ref["user_id"].map(world["split"])) == {"validation"}
    assert not [c for c in ref.columns if any(w in c for w in ("malicious", "scenario", "label", "insider"))]
    assert meta["model"]["model_version"] == SERVED["model_version"] and meta["reference"]["part"] == "validation"
    rep = meta["report"]
    assert set(rep["served_score_quantiles_by_model_split"]) == {"train", "validation", "test"}
    sv = rep["served_vs_shadow"]
    assert sv["shadow_model"] == "tabnet:v0005" and sv["rows"] == len(ref) and -1 <= sv["spearman_rank_correlation"] <= 1
    assert rep["context_on_reference"]["privileged_users"] == 1
    assert abs(sum(rep["band_share_on_reference"]["default"].values()) - 1) < 1e-12
    assert calibrate.main(_cal_args(world)) == 2                      # a pin is never replaced silently


@pytest.fixture(scope="module")
def risk_run(world, calibrated):
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(world["root"] / "runlog.jsonl"))
    mp.setenv("CIRA_SERVED_MODEL", "gbdt:v0003")
    try:
        meta = cri_batch.run(cri_batch._parse_args(_run_args(world)))
    finally:
        mp.undo()
    return meta


def test_risk_batch(world, calibrated, risk_run):
    risk = pd.read_parquet(risk_run["output"])
    ch8 = pd.read_parquet(world["processed"] / "scores" / "chapter8" / BATCH_ID / "anomaly_scores.parquet")
    served = ch8[ch8["role"] == "served"]
    assert len(risk) == len(served) and set(risk["model_version"]) == {SERVED["model_version"]}
    np.testing.assert_array_equal(risk["anomaly_score"].to_numpy(), served["anomaly_score"].to_numpy())
    assert risk["cri_score"].between(0, 100).all() and risk_run["is_calibrated_default"]
    assert set(risk_run["unavailable_components"]) == {"asset_criticality", "mitre_context"}
    assert risk_run["effective_weights"]["anomaly"] == pytest.approx(0.60 / 0.90)
    assert set(risk_run["summary"]["daily_volume_out_of_sample"]) == {"validation", "test"}
    lines = [json.loads(x) for x in (world["root"] / "runlog.jsonl").read_text().splitlines()]
    assert any(x.get("stage") == "chapter9_cri_batch" and x["cri_run_id"] == risk_run["cri_run_id"] for x in lines)


def test_risk_batch_refuses_a_rollback_without_recalibration(world, calibrated, risk_run, monkeypatch, capsys):
    monkeypatch.setenv("CIRA_SERVED_MODEL", "tabnet:v0005")
    assert cri_batch.main(_run_args(world)) == 2
    assert "recalibrate" in capsys.readouterr().err


def test_risk_batch_refuses_a_different_matrix(world, calibrated, risk_run, capsys):
    st = world["features"].stat()
    os.utime(world["features"], (st.st_atime, st.st_mtime + 5))
    try:
        assert cri_batch.main(_run_args(world)) == 2
        assert "fingerprint" in capsys.readouterr().err
    finally:
        os.utime(world["features"], (st.st_atime, st.st_mtime))


@pytest.fixture(scope="module")
def readout(world, risk_run):
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(world["root"] / "runlog.jsonl"))
    try:
        r = evaluate.run(evaluate._parse_args(_eval_args(world, "--cri-run-id", risk_run["cri_run_id"])))
    finally:
        mp.undo()
    return r


def test_readout(world, risk_run, readout):
    r = readout
    assert r["part"] == "validation" and r["cri_run_id"] == risk_run["cri_run_id"] and r["positives"] > 0
    assert set(r["models"]) == {"anomaly_score", *(f"cri:{v}" for v in evaluate.VARIANTS)}
    assert r["models"]["cri:anomaly_only"]["pr_auc"] == pytest.approx(r["models"]["anomaly_score"]["pr_auc"], abs=1e-12)
    assert r["harness"][0]["ok"] is True and r["harness"][1]["ok"] is None     # no Chapter 8 evidence for synthetic rows
    assert r["guard"]["version"] == "c9-cri-guard-v1" and isinstance(r["guard"]["warnings"], list)
    assert "HIGH_or_above" in r["bands"]["cri:default"]


def test_readout_rules(world, readout, capsys):
    assert evaluate.main(_eval_args(world, "--part", "test")) == 2
    assert "Chapter 16" in capsys.readouterr().err
    assert evaluate.main(_eval_args(world)) == 2                       # written once
    assert "--supersede" in capsys.readouterr().err


def test_verifier_passes(world, calibrated, risk_run, readout):
    spec = importlib.util.spec_from_file_location("verify_chapter9", REPO / "scripts" / "verify_chapter9.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    code = mod.main(["--processed-dir", str(world["processed"]), "--profile", "full", "--cri-run-id", risk_run["cri_run_id"],
                     "--pin-path", str(world["pin"]), "--models-dir", str(world["models"]),
                     "--readout-path", str(world["readout"]), "--results-dir", str(world["results"])])
    assert code == 0
    report = json.loads(sorted(world["results"].glob("verification_*.json"))[-1].read_text())
    assert report["counts"]["FAIL"] == 0
    warns = [r for r in report["checks"] if r["status"] == "WARN"]
    assert all(r["section"] == "readout" for r in warns)               # only guard/harness notes, explained in the audit


def test_health_reports_the_cri_block(world, calibrated):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        body = client.get("/health").json()
    # the synthetic served model has no registry artifact, so there is no score to contextualise
    assert body["anomaly_model"]["status"] == "unavailable" and body["cri"]["status"] == "unavailable"
    assert body["cri"]["reason"]


# ---------------------------------------------------------------------------
# the one-command sign-off, on its own experiments / models / docs copies
# ---------------------------------------------------------------------------

def test_signoff_runs_green_and_finalize_waits_for_explanations(world, tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("signoff_chapter9", REPO / "scripts" / "signoff_chapter9.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    exp, docs, models = tmp_path / "experiments", tmp_path / "docs_root", tmp_path / "models"
    exp.mkdir()
    (exp / "chapter8_serving_decision.json").write_text(json.dumps({
        "rule": {"version": "c8-serving-rule-v1"},
        "outcome": {"served": SERVED, "shadow": {"model_name": "tabnet", "registry_version": "v0005"}}}))
    (docs / "docs" / "chapters").mkdir(parents=True)
    (docs / "README.md").write_text(mod.STATUS_PENDING + "\n")
    (docs / "docs" / "CARRY_FORWARD.md").write_text("| N38 Chapter 9 status | 9 (until retired) |\n\n" + mod.N38_HEADING + "text\n")
    (docs / "docs" / "chapters" / "chapter_9_cri.md").write_text(
        "# Chapter 9\n\nStatus: PARTIALLY IMPLEMENTED (synthetic only).\n\nReal runs (N38), not yet done:\n\n- [ ] one\n")
    monkeypatch.delenv("CIRA_CRI_CALIBRATION")
    common = ["--processed-dir", str(world["processed"]), "--models-dir", str(models), "--experiments-dir", str(exp),
              "--docs-root", str(docs), "--skip-tests", "--skip-health", "--min-reference-rows", "50", "--quiet",
              "--dotenv", str(tmp_path / "no.env")]

    assert mod.main(common) == 0
    state = json.loads((exp / "results" / "chapter9" / "signoff_state.json").read_text())
    assert state["green"] and state["verify"]["counts"]["FAIL"] == 0 and state["verify_with_readout"]["counts"]["FAIL"] == 0
    ref = json.loads((exp / "chapter9_reference_runs.json").read_text())
    assert ref["cri_run_id"] == state["cri_run_id"] and ref["calibration_id"] == state["calibration_id"]
    audit = docs / "docs" / "audits" / "chapter_9_audit.md"
    text = audit.read_text()
    assert "SKIPPED (tests-only flag" in text and "Served vs shadow" in text and "cri:default" in text

    assert mod.main(common) == 0                                   # a re-run skips finished steps
    state2 = json.loads((exp / "results" / "chapter9" / "signoff_state.json").read_text())
    assert state2["cri_run_id"] == state["cri_run_id"] and state2["calibration_id"] == state["calibration_id"]

    fin = ["--finalize", "--experiments-dir", str(exp), "--docs-root", str(docs), "--models-dir", str(models),
           "--dotenv", str(tmp_path / "no.env")]
    if mod.TO_EXPLAIN in text:
        assert mod.main(fin) == 1                                  # refuses while a WARN is unexplained
        audit.write_text(text.replace(mod.TO_EXPLAIN, "explained for the test"))
    assert mod.main(fin) == 0
    assert "IMPLEMENTED; calibrated for gbdt v0003" in (docs / "README.md").read_text()
    assert "RETIRED (chapter 9" in (docs / "docs" / "CARRY_FORWARD.md").read_text()
    chap = (docs / "docs" / "chapters" / "chapter_9_cri.md").read_text()
    assert "Status: IMPLEMENTED" in chap and "- [x] one" in chap


def test_signoff_never_supersedes_a_calibration_for_another_model(world, tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("signoff_chapter9", REPO / "scripts" / "signoff_chapter9.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    exp = tmp_path / "experiments"
    exp.mkdir()
    (exp / "chapter8_serving_decision.json").write_text(json.dumps({"outcome": {"served": SERVED}}))
    (exp / "chapter9_cri_calibration.json").write_text(json.dumps({"current": {
        "calibration_id": "old", "model": {"model_version": "tabnet-chapter7-v1-e03b3d0d3360"}, "source_batch_run_id": BATCH_ID}}))
    monkeypatch.delenv("CIRA_CRI_CALIBRATION")
    code = mod.main(["--processed-dir", str(world["processed"]), "--models-dir", str(tmp_path / "m"), "--experiments-dir",
                     str(exp), "--docs-root", str(tmp_path), "--skip-tests", "--skip-health", "--quiet",
                     "--dotenv", str(tmp_path / "no.env")])
    assert code == 1
    assert json.loads((exp / "chapter9_cri_calibration.json").read_text())["current"]["calibration_id"] == "old"


def test_signoff_refuses_cri_overrides_before_anything_runs(world, tmp_path, monkeypatch, capsys):
    """An old .env with the Chapter 1 placeholder weights must stop the sign-off (N37)."""
    spec = importlib.util.spec_from_file_location("signoff_chapter9", REPO / "scripts" / "signoff_chapter9.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    exp = tmp_path / "experiments"
    exp.mkdir()
    (exp / "chapter8_serving_decision.json").write_text(json.dumps({"outcome": {"served": SERVED}}))
    old_env = tmp_path / "old.env"
    old_env.write_text("CRI_WEIGHT_ANOMALY_SCORE=0.40\nCRI_WEIGHT_ASSET_CRITICALITY=0.15\n")
    monkeypatch.delenv("CIRA_CRI_CALIBRATION")
    for key in ("CRI_WEIGHT_ANOMALY_SCORE", "CRI_WEIGHT_ASSET_CRITICALITY"):
        monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv(key, "")        # registered with monkeypatch so load_dotenv's write is undone
        monkeypatch.delenv(key)
    code = mod.main(["--processed-dir", str(world["processed"]), "--models-dir", str(tmp_path / "m"), "--experiments-dir",
                     str(exp), "--docs-root", str(tmp_path), "--skip-tests", "--skip-health", "--quiet",
                     "--dotenv", str(old_env)])
    err = capsys.readouterr().err
    assert code == 1 and "CRI_WEIGHT_ANOMALY_SCORE" in err and ".env.example" in err
    assert not (exp / "chapter9_cri_calibration.json").exists() and not (tmp_path / "m").exists()
