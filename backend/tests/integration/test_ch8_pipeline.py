"""Chapter 8 end to end on a synthetic CERT tree:

features -> labels -> Chapter 6 XGBoost (reference) -> Chapter 7 TabNet
(user + time) -> behaviour-only XGBoost candidates -> serving decision on
validation -> test readout -> batch scoring -> API startup -> verifier.

The synthetic tree has one profile ("full"), so the rule's split keys are
overridden to full/user (decisive) and full/time (consistency) through the
hidden flags; the verifier must flag that with a WARN.
"""
import importlib.util
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.baselines.run import _parse_args as ch6_args
from app.baselines.run import run as ch6_run
from app.feature_engineering.pipeline import run_pipeline
from app.ingestion.ground_truth import build_insider_label_tables
from app.scoring import batch, gbdt_candidate, select
from app.tabnet.train import _parse_args as ch7_args
from app.tabnet.train import run as ch7_run
from fixtures import synthetic_ch6

REPO = Path(__file__).resolve().parents[3]
TIME = ["--time-validation-start", "2010-02-08", "--time-test-start", "2010-02-20"]
STATIC = "psych_,peer_department_size"


@pytest.fixture(scope="module")
def chain(tmp_path_factory):
    root = tmp_path_factory.mktemp("ch8")
    paths = synthetic_ch6.build(root)
    processed = root / "processed"
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(root / "runlog.jsonl"))
    try:
        run_pipeline(paths["raw"], processed, profile="full", ground_truth_dir=paths["gt"])
        build_insider_label_tables(paths["gt"], processed)
        common = ["--processed-dir", str(processed), "--profile", "full", "--splits-dir", str(root / "splits"),
                  "--models-dir", str(root / "models")]
        ch6 = ch6_run(ch6_args(common + ["--checkpoint-dir", str(root / "ckpt"), "--results-dir", str(root / "r6"), "--models", "rule_based,isolation_forest,gbdt"]))
        tab_args = common + ["--checkpoint-dir", str(root / "ckpt"), "--results-dir", str(root / "r7"), "--max-epochs", "3",
                             "--batch-size", "512", "--virtual-batch-size", "128", "--device", "cpu", "--exclude-features", STATIC]
        t_user = ch7_run(ch7_args(tab_args))
        t_time = ch7_run(ch7_args(tab_args + ["--split", "time", *TIME]))
        g_args = common + ["--results-dir", str(root / "r8"), "--device", "cpu"]
        g_user = gbdt_candidate.run(gbdt_candidate._parse_args(g_args))
        g_time = gbdt_candidate.run(gbdt_candidate._parse_args(g_args + ["--split", "time", *TIME]))
    finally:
        mp.undo()
    ch7_refs = root / "ch7_refs.json"
    ch7_refs.write_text(json.dumps({"runs": {
        "full/user": {"run_id": t_user["run_id"], "registry_version": t_user["registry"]["registry_version"]},
        "full/time": {"run_id": t_time["run_id"], "registry_version": t_time["registry"]["registry_version"]},
    }}))
    ch6_refs = root / "ch6_refs.json"
    ch6_refs.write_text(json.dumps({"runs": {"full/user": {m: ch6["run_id"] for m in ch6["models"]}}}))
    return {"root": root, "processed": processed, "ch6": ch6, "t_user": t_user, "t_time": t_time,
            "g_user": g_user, "g_time": g_time, "ch7_refs": ch7_refs, "ch6_refs": ch6_refs,
            "decision": root / "decision.json", "readout": root / "readout.json"}


def _select_args(chain, *extra):
    return ["--processed-dir", str(chain["processed"]), "--models-dir", str(chain["root"] / "models"),
            "--ch7-references", str(chain["ch7_refs"]), "--ch6-references", str(chain["ch6_refs"]),
            "--decision-path", str(chain["decision"]), "--test-readout-path", str(chain["readout"]),
            "--decisive", "full/user", "--consistency", "full/time", *extra]


@pytest.fixture(autouse=True)
def _env(chain, monkeypatch):
    monkeypatch.setenv("CIRA_RUNLOG", str(chain["root"] / "runlog.jsonl"))
    monkeypatch.setenv("MODEL_PATH", str(chain["root"] / "models"))
    monkeypatch.setenv("CIRA_SERVING_DECISION", str(chain["decision"]))
    monkeypatch.delenv("CIRA_SERVED_MODEL", raising=False)


def test_candidate_is_behaviour_only_and_registered(chain):
    r = chain["g_user"]
    md = r["models"]["gbdt"]["metadata"]
    assert r["chapter"] == 8 and r["split"]["created_now"] is False                   # the Chapter 6 split (N11)
    assert r["split"]["data_fingerprint"] == chain["ch6"]["split"]["data_fingerprint"]
    assert md["static_inputs"] == [] and all(c.startswith(("psych_", "peer_department_size")) for c in r["features"]["excluded_from_model"])
    assert md["model_version"].startswith("gbdt-chapter8-v1-") and r["registry"]["registry_version"] == "v0001"
    assert md["imbalance"]["effective_positive_weight"] == pytest.approx(
        md["imbalance"]["train_negatives"] / md["imbalance"]["train_positives"])
    scores = pd.read_parquet(md["scores_path"])
    assert list(scores.columns) == list(gbdt_candidate.SCORE_COLUMNS) and scores["anomaly_score"].between(0, 1).all()
    ch6_scores = pd.read_parquet(chain["ch6"]["models"]["gbdt"]["metadata"]["scores_path"])
    assert len(scores) == len(ch6_scores)                                              # same validation + test rows
    lines = [json.loads(x) for x in (chain["root"] / "runlog.jsonl").read_text().splitlines()]
    assert any(x.get("stage") == "chapter8_gbdt_candidate" and x["run_id"] == r["run_id"] for x in lines)


def test_candidate_console_shows_validation_only(chain, capsys):
    gbdt_candidate._print_summary(chain["g_user"], select_head(chain["g_user"]), (1, 5, 10))
    out = capsys.readouterr().out
    assert "validation  PR-AUC" in out and "test: written to metrics.json, not shown" in out


def select_head(report):
    from app.evaluation.metrics import headline

    return headline(report["models"]["gbdt"]["validation"], (1, 5, 10))


def test_test_readout_refused_before_a_decision(chain):
    assert not chain["decision"].exists()
    with pytest.raises(SystemExit, match="decide on validation first"):
        select.main(_select_args(chain, "--report-test"))


@pytest.fixture(scope="module")
def decided(chain):
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(chain["root"] / "runlog.jsonl"))
    try:
        assert select.main(_select_args(chain, "--gbdt", f"full/user={chain['g_user']['run_id']}",
                                        "--gbdt", f"full/time={chain['g_time']['run_id']}")) == 0
    finally:
        mp.undo()
    return json.loads(chain["decision"].read_text())


def test_decision_file(chain, decided):
    d = decided
    assert d["part_used"] == "validation" and d["rule"]["version"] == "c8-serving-rule-v1"
    assert d["rule"]["split_keys_overridden"] is True
    assert d["gates"]["tabnet"]["ok"] and d["gates"]["gbdt"]["ok"]
    ev = d["evidence"]["full/user"]
    assert set(ev["models"]) == {"tabnet", "gbdt", "gbdt_ch6_all_feat"}
    pr = {k: {m: v["models"][m]["pr_auc"] for m in ("tabnet", "gbdt")} for k, v in d["evidence"].items()}
    again = select.decide(pr, {"tabnet": True, "gbdt": True}, rule=d["rule"])
    served = d["outcome"]["served"]
    assert again["served"] == served["model_name"] and served["registry_version"].startswith("v")
    assert d["outcome"]["shadow"]["model_name"] != served["model_name"]
    assert (served["model_name"] == "gbdt") == (d["outcome"]["deviation"] == "C8-1")
    for key, run in (("full/user", chain["t_user"]), ("full/time", chain["t_time"])):          # validation rows only
        assert d["evidence"][key]["rows"] == run["split"]["rows"]["validation"]


def test_decision_is_made_once(chain, decided):
    with pytest.raises(SystemExit, match="exists"):
        select.main(_select_args(chain, "--gbdt", f"full/user={chain['g_user']['run_id']}",
                                 "--gbdt", f"full/time={chain['g_time']['run_id']}"))


@pytest.fixture(scope="module")
def readout(chain, decided):
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(chain["root"] / "runlog.jsonl"))
    try:
        assert select.main(_select_args(chain, "--report-test")) == 0
    finally:
        mp.undo()
    return json.loads(chain["readout"].read_text())


def test_test_readout_once_and_harness(chain, readout):
    assert readout["part"] == "test" and all(r["match"] for rows in readout["harness_check"].values() for r in rows)
    with pytest.raises(SystemExit, match="read once already"):
        select.main(_select_args(chain, "--report-test"))


@pytest.fixture(scope="module")
def batch_run(chain, decided):
    mp = pytest.MonkeyPatch()
    for k, v in {"CIRA_RUNLOG": chain["root"] / "runlog.jsonl", "MODEL_PATH": chain["root"] / "models",
                 "CIRA_SERVING_DECISION": chain["decision"]}.items():
        mp.setenv(k, str(v))
    mp.delenv("CIRA_SERVED_MODEL", raising=False)
    try:
        return batch.run(batch._parse_args(["--processed-dir", str(chain["processed"]), "--profile", "full", "--with-shadow",
                                            "--splits-dir", str(chain["root"] / "splits"), "--chunk-rows", "700"]))
    finally:
        mp.undo()


def test_batch_output(chain, decided, batch_run):
    frame = pd.read_parquet(batch_run["output"])
    matrix = pd.read_parquet(chain["processed"] / "features" / "user_day_full.parquet")
    assert list(frame.columns) == list(batch.BATCH_COLUMNS)
    served = frame[frame["role"] == "served"]
    assert len(served) == len(matrix) and (frame["role"] == "shadow").sum() == len(matrix)
    assert served["model_version"].nunique() == 1 and served["registry_version"].iloc[0] == decided["outcome"]["served"]["registry_version"]
    assert set(served["model_split"]) <= {"train", "validation", "test"} and (served["model_split"] == "train").any()
    assert not any(w in c for c in frame.columns for w in ("label", "malicious", "scenario", "insider"))
    # the serving path gives exactly the scores the training run stored (chunking and shadow change nothing)
    run = chain["g_user"] if decided["outcome"]["served"]["model_name"] == "gbdt" else chain["t_user"]
    name = decided["outcome"]["served"]["model_name"]
    stored = pd.read_parquet(run["models"][name]["metadata"]["scores_path"])
    stored["user_id"] = stored["user_id"].astype("string").str.strip().str.casefold()
    j = stored.merge(served, on=["user_id", "date"], suffixes=("_stored", "_batch"))
    # 1e-5: TabNet's float32 matmuls move in the last bits with batch composition (Chapter 7 uses the same tolerance)
    assert len(j) == len(stored) and np.abs(j["anomaly_score_stored"] - j["anomaly_score_batch"]).max() <= 1e-5
    assert (j["split"] == j["model_split"]).all()                                       # tags match the training split
    lines = [json.loads(x) for x in (chain["root"] / "runlog.jsonl").read_text().splitlines()]
    assert any(x.get("stage") == "chapter8_batch_scoring" and x["batch_run_id"] == batch_run["batch_run_id"] for x in lines)


def test_batch_refuses_without_a_model(chain, monkeypatch, capsys):
    out_root = chain["processed"] / "scores" / "chapter8"
    before = sorted(p.name for p in out_root.iterdir())
    monkeypatch.setenv("CIRA_SERVING_DECISION", str(chain["root"] / "missing.json"))
    code = batch.main(["--processed-dir", str(chain["processed"]), "--profile", "full", "--splits-dir", str(chain["root"] / "splits")])
    assert code == 2 and "no score written" in capsys.readouterr().err
    assert sorted(p.name for p in out_root.iterdir()) == before                         # nothing was written


def test_batch_refuses_a_changed_split_file(chain, decided, monkeypatch, tmp_path):
    split_src = chain["root"] / "splits"
    copy = tmp_path / "splits"
    copy.mkdir()
    for f in split_src.iterdir():
        data = json.loads(f.read_text())
        data["assignment"][next(iter(data["assignment"]))] = "test"
        (copy / f.name).write_text(json.dumps(data))
    code = batch.main(["--processed-dir", str(chain["processed"]), "--profile", "full", "--splits-dir", str(copy)])
    assert code == 2


def test_api_serves_the_decided_model(chain, decided):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        body = client.get("/health").json()
    m = body["anomaly_model"]
    assert body["status"] == "healthy" and m["source"] == "decision_file" and m["decision_rule"] == "c8-serving-rule-v1"
    assert m["served"]["registry_version"] == decided["outcome"]["served"]["registry_version"] and m["served"]["device"] == "cpu"
    assert len(m["shadow"]) == 1


def test_verifier_passes(chain, decided, readout, batch_run, capsys):
    spec = importlib.util.spec_from_file_location("verify_chapter8", REPO / "scripts" / "verify_chapter8.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    code = mod.main([
        "--processed-dir", str(chain["processed"]), "--profile", "full", "--candidate-run-id", chain["g_user"]["run_id"],
        "--permutation-test", "--decision-path", str(chain["decision"]), "--test-readout-path", str(chain["readout"]),
        "--ch6-references", str(chain["ch6_refs"]), "--ch7-references", str(chain["ch7_refs"]),
        "--models-dir", str(chain["root"] / "models"), "--splits-dir", str(chain["root"] / "splits"),
        "--results-dir", str(chain["root"] / "r8"), "--batch-run-id", batch_run["batch_run_id"],
    ])
    out = capsys.readouterr().out
    fails = [line for line in out.splitlines() if line.strip().startswith("FAIL")]
    assert code == 0, "\n".join(fails)
    assert "overridden to full/user" in out                                          # synthetic decision is flagged
    leak = [line for line in out.splitlines() if "leakage" in line]
    assert len(leak) == 1 and leak[0].split()[0] in ("PASS", "WARN")                 # C7-8 rule; WARN is explained, not hidden


def test_verifier_fails_a_decision_edited_after_the_fact(chain, decided, readout, batch_run, capsys):
    """Changing the rule in the decision file (here: margin 0.10 -> 0.0) must not pass."""
    spec = importlib.util.spec_from_file_location("verify_chapter8", REPO / "scripts" / "verify_chapter8.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    tampered = chain["root"] / "tampered_decision.json"
    d = json.loads(chain["decision"].read_text())
    d["rule"]["margin"] = 0.0
    tampered.write_text(json.dumps(d))
    code = mod.main([
        "--processed-dir", str(chain["processed"]), "--profile", "full", "--decision-path", str(tampered),
        "--test-readout-path", str(chain["readout"]), "--ch6-references", str(chain["ch6_refs"]),
        "--ch7-references", str(chain["ch7_refs"]), "--models-dir", str(chain["root"] / "models"),
        "--splits-dir", str(chain["root"] / "splits"), "--results-dir", str(chain["root"] / "r8"),
        "--batch-run-id", batch_run["batch_run_id"],
    ])
    fails = [line for line in capsys.readouterr().out.splitlines() if line.strip().startswith("FAIL")]
    assert code == 1
    assert any("rule unchanged" in line for line in fails) and any("decision unchanged since test was read" in line for line in fails)


def test_permutation_rule_is_chapter7s_and_still_fails_on_a_leak():
    spec = importlib.util.spec_from_file_location("verify_chapter8", REPO / "scripts" / "verify_chapter8.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    verdict = mod.ch7_permutation_verdict()
    ref = ("lstm_autoencoder", 0.0896)
    assert verdict(0.025, 0.0100, ref)[0] == "PASS"
    assert verdict(0.0388, 0.0100, ref)[0] == "WARN"
    assert verdict(0.20, 0.0100, ref)[0] == "FAIL"
