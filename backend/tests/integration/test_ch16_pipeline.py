"""Chapter 16 end to end on the synthetic CERT world of Chapter 15 (13 planted insiders, real models).

Chapters 5-12 are built by ``ch15_stack.build_world`` (no database needed). Then:

    Chapter 6 baselines -> reference files (as an operator records them, N18, N24)
    seed runs on the SAME split (two seeds, both configurations, both models)
    validation rehearsal -> test readout (pinned once) -> second write refused -> supersede keeps the old one
    report generated from the readout, byte-identical when regenerated

This proves the plumbing. Its numbers are synthetic and are never results (N72).
"""
import json
import sys
from pathlib import Path

import pytest

from app.baselines.run import _parse_args as baseline_args
from app.baselines.run import run as baseline_run
from app.evaluation import ablation, report, seeds

TESTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TESTS / "e2e"))
sys.path.insert(0, str(TESTS))
import ch15_stack  # noqa: E402

REPO = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("ch16")
    w = ch15_stack.build_world(root)
    exp = root / "experiments"
    exp.mkdir(exist_ok=True)
    with ch15_stack.pinned_env(root):
        b = baseline_run(baseline_args([
            "--processed-dir", str(w["processed"]), "--profile", "full", "--lstm-max-epochs", "2", "--device", "cpu",
            "--splits-dir", str(w["splits"]), "--results-dir", str(root / "r6"), "--models-dir", str(root / "models6"),
            "--checkpoint-dir", str(root / "ckpt6"), "--no-save-models"]))
    models = ["rule_based", "isolation_forest", "lof", "lstm_autoencoder", "gbdt"]
    (exp / "chapter6_reference_runs.json").write_text(json.dumps({"runs": {"full/user": {m: b["run_id"] for m in models}}}))
    t = w["tabnet"]
    (exp / "chapter7_reference_runs.json").write_text(json.dumps({"runs": {"full/user": {
        "run_id": t["run_id"], "registry_version": "v0001", "model_version": "tabnet-test"}}}))
    (exp / "chapter8_reference_runs.json").write_text(json.dumps({"gbdt_candidates": {"full/user": {
        "run_id": w["gbdt"]["run_id"], "registry_version": "v0001", "model_version": "gbdt-test"}}}))
    w["exp"] = exp
    with ch15_stack.pinned_env(root):
        seeds.run(seeds._parse_args([
            "--processed-dir", str(w["processed"]), "--profile", "full", "--seeds", "42,43",
            "--manifest", str(exp / seeds.MANIFEST_FILE), "--experiments-dir", str(exp), "--splits-dir", str(w["splits"]),
            "--models-dir", str(root / "models_seeds"), "--results-dir-tabnet", str(root / "rs_tabnet"),
            "--results-dir-gbdt", str(root / "rs_gbdt"), "--checkpoint-dir", str(root / "ckpt_seeds"),
            "--tabnet-args", "--max-epochs 3 --batch-size 512 --virtual-batch-size 128"]))
    return w


def _args(w, part, *extra):
    r = w["root"]
    return ablation._parse_args([
        "--processed-dir", str(w["processed"]), "--profile", "full", "--part", part, "--n-boot", "40",
        "--experiments-dir", str(w["exp"]), "--seed-manifest", str(w["exp"] / seeds.MANIFEST_FILE),
        "--readout-path", str(w["exp"] / "chapter16_test_readout.json"), "--results-dir", str(r / "r16"), *extra])


@pytest.fixture(scope="module")
def rehearsal(world):
    with ch15_stack.pinned_env(world["root"]):
        return ablation.run(_args(world, "validation"))


@pytest.fixture(scope="module")
def readout(world, rehearsal):
    with ch15_stack.pinned_env(world["root"]):
        return ablation.run(_args(world, "test"))


def test_seed_runs_use_the_saved_split_and_register_nothing(world):
    m = json.loads((world["exp"] / seeds.MANIFEST_FILE).read_text())
    assert m["split_seed"] == 42
    assert {"tabnet/behaviour/42", "gbdt/behaviour/42", "tabnet/behaviour/43", "tabnet/all_features/42",
            "gbdt/all_features/43"} <= set(m["runs"])
    assert m["runs"]["tabnet/behaviour/42"]["reference"] is True
    assert not list((world["root"] / "models_seeds").rglob("registry.jsonl"))          # N21: nothing registered
    assert not list(world["splits"].glob("user_split_full_seed43.json"))              # N78: no second split file


def test_validation_rehearsal_does_not_pin_a_readout(world, rehearsal):
    assert rehearsal["part"] == "validation"
    assert list((world["root"] / "r16").glob("*-validation-c16/readout_validation.json"))


def test_test_readout_is_pinned_and_complete(world, readout):
    path = world["exp"] / "chapter16_test_readout.json"
    assert json.loads(path.read_text())["run_id"] == readout["run_id"]
    for name in ("baseline:rule_based", "tabnet", "xgboost_served", "cri:no_mitre_context", "cri:default", "mitre_context"):
        assert name in readout["rankings"]
    assert [c["stage"] for c in readout["chain"]][-1] == "XGBoost + CRI + MITRE"
    assert set(readout["deviations"]) == {"C16-1", "C16-2", "C16-3"}
    assert readout["experiments"]["A_B_E3_seeds"]["available"] is True
    assert all(h["ok"] is not False for h in readout["harness"]), [h for h in readout["harness"] if h["ok"] is False]
    assert readout["guard"]["version"] == "c16-evaluation-guard-v1"


def test_every_metric_in_the_bible_list_is_present(readout):
    op = readout["rankings"]["xgboost_served"]["operating_by_budget"]["1"]
    for k in ("precision", "recall", "f1", "false_positive_rate", "tp", "fp", "fn", "tn"):
        assert k in op
    assert "coverage" in op and "review_load" in op["coverage"]
    s = readout["rankings"]["xgboost_served"]["summary"]
    assert s["pr_auc"] is not None and s["roc_auc_secondary"] is not None and "insiders_caught_at_1" in s
    assert "accuracy" not in json.dumps(readout)                                          # N2
    ci = readout["bootstrap"]["scores"]["xgboost_served"]["pr_auc"]
    assert ci["lo"] <= ci["point"] <= ci["hi"] or ci["lo"] is None


def test_paired_comparisons_and_seed_tests_exist(readout):
    metrics = {(p["a"], p["b"], p["metric"]) for p in readout["bootstrap"]["pairs"]}
    assert ("cri:default", "cri:no_mitre_context", "pr_auc") in metrics
    tests = readout["experiments"]["A_B_E3_seeds"]["paired_tests"]
    assert "A_tabnet_vs_xgboost_behaviour_n23" in tests
    t = tests["A_tabnet_vs_xgboost_behaviour_n23"]
    assert t["n_pairs"] == 2 and "min_attainable_p_two_sided" in t


def test_alert_queue_is_read_with_and_without_deduplication_and_both_orderings(readout):
    v = readout["experiments"]["E1_alert_queue"]["views"]
    assert set(v) >= {"policy_as_built", "policy_without_deduplication", "other_ordering",
                      "other_ordering_without_deduplication", "activity_rule"}
    assert v["policy_without_deduplication"]["suppressed_alerts"] == 0                       # N57
    assert v["policy_as_built"]["ordering"] != v["other_ordering"]["ordering"]               # N55
    cov = v["policy_as_built"]["coverage_by_scenario"]
    for b in cov.values():
        assert b["in_open_alert"] + b["only_in_suppressed_alert"] + b["in_no_alert"] == b["malicious_days"]   # N60


def test_second_test_write_is_refused_and_supersede_keeps_the_old_readout(world, readout):
    with ch15_stack.pinned_env(world["root"]):
        assert ablation.main([
            "--processed-dir", str(world["processed"]), "--profile", "full", "--part", "test", "--n-boot", "20",
            "--experiments-dir", str(world["exp"]), "--readout-path", str(world["exp"] / "chapter16_test_readout.json"),
            "--results-dir", str(world["root"] / "r16b")]) == 2
        again = ablation.run(_args(world, "test", "--supersede", "synthetic re-read in a test"))
    assert again["supersedes"]["previous"]["run_id"] == readout["run_id"]


def test_the_report_is_generated_from_the_readout_only(world, readout):
    path = world["exp"] / "chapter16_test_readout.json"
    pinned = json.loads(path.read_text())                      # the supersede test may have replaced it: read the file
    text = report.render(pinned, readout_sha256=report.sha256_of(path))
    again = report.render(json.loads(path.read_text()), readout_sha256=report.sha256_of(path))
    assert text == again
    assert pinned["run_id"] in text and "C16-1" in text and "probabilities of malice" in text.lower()
