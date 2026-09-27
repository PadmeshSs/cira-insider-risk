"""Chapter 7 end to end on a synthetic CERT tree: Chapter 5 features -> labels
-> Chapter 6 baselines (reference runs) -> TabNet -> registry -> comparison
with the same harness -> verifier."""
import importlib.util
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.baselines.run import _parse_args as ch6_args
from app.baselines.run import run as ch6_run
from app.evaluation.compare import chapter6_sources, chapter7_source, compare_sources, harness_check
from app.feature_engineering.pipeline import run_pipeline
from app.ingestion.ground_truth import build_insider_label_tables
from app.tabnet.infer import load_model
from app.tabnet.model_registry import ModelRegistry
from app.tabnet.train import _parse_args, _print_summary, run
from fixtures import synthetic_ch6

REPO = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("ch7")
    paths = synthetic_ch6.build(root)
    processed = root / "processed"
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(root / "runlog.jsonl"))
    try:
        run_pipeline(paths["raw"], processed, profile="full", ground_truth_dir=paths["gt"])
        build_insider_label_tables(paths["gt"], processed)
        common = ["--processed-dir", str(processed), "--profile", "full", "--splits-dir", str(root / "splits"),
                  "--models-dir", str(root / "models"), "--checkpoint-dir", str(root / "ckpt")]
        ch6 = ch6_run(ch6_args(common + ["--results-dir", str(root / "results6"), "--models", "rule_based,isolation_forest,gbdt"]))
        ch6_time = ch6_run(ch6_args(common + ["--results-dir", str(root / "results6"), "--models", "gbdt", "--split", "time",
                                              "--time-validation-start", "2010-02-08", "--time-test-start", "2010-02-20"]))
    finally:
        mp.undo()
    return {**paths, "root": root, "processed": processed, "common": common, "ch6": ch6, "ch6_time": ch6_time}


def _args(built, *extra):
    return _parse_args(built["common"] + ["--results-dir", str(built["root"] / "results7"), "--max-epochs", "3",
                                          "--batch-size", "512", "--virtual-batch-size", "128", "--device", "cpu", *extra])


@pytest.fixture(scope="module")
def user_run(built):
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    try:
        return run(_args(built))
    finally:
        mp.undo()


def test_runner_outputs(built, user_run):
    r = user_run
    assert r["chapter"] == 7 and r["reportable"] is True
    assert r["split"]["created_now"] is False                         # N11: the Chapter 6 split was loaded
    assert r["split"]["file_sha256"] and r["split"]["data_fingerprint"] == built["ch6"]["split"]["data_fingerprint"]
    block = r["models"]["tabnet"]
    for part in ("validation", "test"):
        p = block[part]["primary"]
        assert "accuracy" not in json.dumps(p)
        assert p["positives"] > 0 and p["pr_auc"] is not None and set(p["budgets"]) == {"1", "5", "10"}
    md = block["metadata"]
    assert md["imbalance"]["train_positives"] == r["split"]["positives_primary"]["train"]
    scores = pd.read_parquet(md["scores_path"])
    assert list(scores.columns) == ["user_id", "date", "split", "raw_score", "anomaly_score", "model_name", "model_version"]
    assert scores["anomaly_score"].between(0, 1).all() and scores["model_version"].nunique() == 1
    lines = [json.loads(x) for x in (built["root"] / "runlog.jsonl").read_text().splitlines()]
    mine = [x for x in lines if x.get("stage") == "chapter7_tabnet" and x["run_id"] == r["run_id"]]
    assert len(mine) == 1 and mine[0]["registry_version"] == r["registry"]["registry_version"]
    assert "test_recall_by_scenario_at_1" in mine[0] and "peak_rss_mb" in mine[0]


def test_console_shows_validation_only(user_run, capsys):
    """Test metrics are stored but never printed by the runner (N11)."""
    _print_summary(user_run, (1, 5, 10))
    out = capsys.readouterr().out
    assert any(line.startswith("validation") for line in out.splitlines())
    assert not any(line.startswith("test ") for line in out.splitlines())
    assert "test: written to metrics.json, not shown" in out
    assert user_run["models"]["tabnet"]["test"]["primary"]["pr_auc"] is not None      # still stored


def test_static_trait_ablation(built, user_run, monkeypatch, capsys):
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    r = run(_args(built, "--exclude-features", "psych_,peer_department_size", "--no-register"))
    md = r["models"]["tabnet"]["metadata"]
    dropped = r["features"]["excluded_from_model"]
    assert dropped and all(c.startswith(("psych_", "peer_department_size")) for c in dropped)
    assert md["config"]["excluded_features"] == dropped
    assert md["model_version"] != user_run["models"]["tabnet"]["metadata"]["model_version"]
    assert md["n_input_columns"] < user_run["models"]["tabnet"]["metadata"]["n_input_columns"]
    assert not any(f.startswith(("psych_", "peer_department_size")) for f, _ in md["top_features_by_mask"])
    assert "excluded from the model input" in capsys.readouterr().out
    lines = [json.loads(x) for x in (built["root"] / "runlog.jsonl").read_text().splitlines()]
    assert next(x for x in lines if x.get("run_id") == r["run_id"])["excluded_features"] == dropped
    with pytest.raises(SystemExit, match="no feature column starts with"):
        run(_args(built, "--exclude-features", "no_such_prefix_", "--no-register"))


def test_registry_entry_and_serving_load(built, user_run):
    r = user_run
    reg = ModelRegistry(built["root"] / "models")
    entry = reg.resolve(r["registry"]["registry_version"])
    assert entry["run_id"] == r["run_id"] and reg.verify(entry) == []
    assert entry["feature_schema"]["pipeline_version"] and entry["training_data"]["feature_fingerprint"] == r["features"]["fingerprint"]
    assert entry["imbalance"]["method"] == "class_weighted_loss"
    scorer = load_model("latest", registry_root=built["root"] / "models", profile="full")
    stored = pd.read_parquet(r["models"]["tabnet"]["metadata"]["scores_path"])
    test = stored[stored["split"] == "test"][["user_id", "date"]]
    matrix = pd.read_parquet(built["processed"] / "features" / "user_day_full.parquet")
    matrix["user_id"] = matrix["user_id"].astype("string").str.strip().str.casefold()
    matrix["date"] = matrix["date"].astype("string")
    frame = test.merge(matrix, on=["user_id", "date"], how="left")
    assert np.allclose(scorer.score(frame), stored.loc[stored["split"] == "test", "anomaly_score"].to_numpy(), atol=1e-6)


def test_second_run_resumes_and_gets_a_new_version(built, user_run, monkeypatch):
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    again = run(_args(built))
    md = again["models"]["tabnet"]["metadata"]
    assert md["completed_from_checkpoint"] is True
    assert again["registry"]["registry_version"] != user_run["registry"]["registry_version"]   # never overwritten
    a = pd.read_parquet(user_run["models"]["tabnet"]["metadata"]["scores_path"])
    b = pd.read_parquet(md["scores_path"])
    assert np.array_equal(a["anomaly_score"].to_numpy(), b["anomaly_score"].to_numpy())
    fresh = run(_args(built, "--fresh", "--no-register"))
    assert fresh["models"]["tabnet"]["metadata"]["resumed_from_epoch"] is None and fresh["registry"] is None


def test_same_harness_comparison_with_the_baselines(built, user_run, monkeypatch):
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    ch6 = built["ch6"]
    refs = {m: ch6["run_id"] for m in ch6["models"]}
    srcs = chapter6_sources(built["processed"], refs) + [chapter7_source(built["processed"], user_run["run_id"])]
    res = compare_sources(built["processed"], srcs, part="test", budgets=(1, 5, 10), seed=42, split_info=user_run["split"])
    assert set(res["models"]) == {"rule_based", "isolation_forest", "gbdt", "tabnet"}
    assert res["models"]["tabnet"]["metrics"]["primary"]["pr_auc"] == pytest.approx(user_run["models"]["tabnet"]["test"]["primary"]["pr_auc"])
    lines = [json.loads(x) for x in (built["root"] / "runlog.jsonl").read_text().splitlines()]
    checks = harness_check(res, srcs, lines)
    assert checks and all(c["match"] for c in checks)                 # harness reproduces every logged baseline number
    assert set(res["precision_ceiling"]) == {"1", "5", "10"}


def test_compare_cli_writes_its_output(built, user_run, monkeypatch, capsys):
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    from app.evaluation import compare

    refs = built["root"] / "refs_cli.json"
    ch6 = built["ch6"]
    refs.write_text(json.dumps({"runs": {"full/user": {m: ch6["run_id"] for m in ch6["models"]}}}))
    res = compare.main(["--processed-dir", str(built["processed"]), "--profile", "full", "--split", "user",
                        "--run-id", user_run["run_id"], "--references", str(refs), "--results-dir", str(built["root"] / "results7")])
    assert res["part"] == "validation" and "tabnet" in res["models"]
    assert (built["root"] / "results7" / user_run["run_id"] / "comparison_validation.json").exists()
    assert "per scenario" in capsys.readouterr().out
    lines = [json.loads(x) for x in (built["root"] / "runlog.jsonl").read_text().splitlines()]
    assert any(x.get("stage") == "chapter7_comparison" and x["run_id"] == user_run["run_id"] for x in lines)


def test_comparison_refuses_different_rows(built, user_run, monkeypatch):
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    from app.evaluation.compare import ComparisonError

    srcs = chapter6_sources(built["processed"], {"gbdt": built["ch6_time"]["run_id"]}) + [chapter7_source(built["processed"], user_run["run_id"])]
    with pytest.raises(ComparisonError, match="cannot be compared"):
        compare_sources(built["processed"], srcs, part="validation")


def test_time_split_run_reports_seen_and_new_insiders(built, monkeypatch):
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    r = run(_args(built, "--split", "time", "--time-validation-start", "2010-02-08", "--time-test-start", "2010-02-20", "--no-register"))
    srcs = chapter6_sources(built["processed"], {"gbdt": built["ch6_time"]["run_id"]}) + [chapter7_source(built["processed"], r["run_id"])]
    res = compare_sources(built["processed"], srcs, part="test", split_info=r["split"])
    assert "time_split" in res
    assert "pr_auc_new_insiders_only" in res["models"]["tabnet"]


def test_masquerade_rows_never_reach_training(built, monkeypatch):
    """The one masquerade account-day falls in train/validation here; it must be
    dropped from the rows TabNet fits and early-stops on (N13)."""
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    r = run(_args(built, "--split", "time", "--time-validation-start", "2010-03-01", "--time-test-start", "2010-03-03",
                  "--no-register", "--max-epochs", "1"))
    excl, tr = r["split"]["masquerade_rows_excluded"], r["training_rows"]
    assert excl["train"] + excl["validation"] == 1
    assert tr["train_masquerade_dropped"] == excl["train"] and tr["validation_masquerade_dropped"] == excl["validation"]
    imb = r["models"]["tabnet"]["metadata"]["imbalance"]
    assert imb["train_positives"] + imb["train_negatives"] == r["split"]["rows"]["train"] - excl["train"]


def test_inspect_scores_reads_a_chapter7_run(built, user_run, capsys):
    spec = importlib.util.spec_from_file_location("inspect_scores", REPO / "scripts" / "inspect_scores.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main(["--processed-dir", str(built["processed"]), "--profile", "full", "--run-id", user_run["run_id"],
              "--results-dir", str(built["root"] / "results7")])
    out = capsys.readouterr().out
    assert "=== tabnet" in out and "top features by mask" in out


def test_verifier_passes_on_the_run(built, user_run, monkeypatch):
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    spec = importlib.util.spec_from_file_location("verify_chapter7", REPO / "scripts" / "verify_chapter7.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    refs = built["root"] / "refs.json"
    ch6 = built["ch6"]
    refs.write_text(json.dumps({"runs": {"full/user": {m: ch6["run_id"] for m in ch6["models"]}}}))
    code = mod.main([
        "--processed-dir", str(built["processed"]), "--profile", "full", "--run-id", user_run["run_id"],
        "--results-dir", str(built["root"] / "results7"), "--splits-dir", str(built["root"] / "splits"),
        "--references", str(refs), "--runlog", str(built["root"] / "runlog.jsonl"),
        "--reload-models", "--permutation-test", "--permutation-epochs", "2", "--baselines",
    ])
    out = json.loads((built["root"] / "results7" / user_run["run_id"] / "verification.json").read_text())
    fails = [c for c in out["checks"] if c["status"] == "FAIL"]
    assert code == 0, fails
    leak = [c for c in out["checks"] if c["section"] == "leakage"]
    assert sum(c["check"].startswith("shuffled labels") for c in leak) == 3
    assert any(c["check"].startswith("untrained TabNet") for c in leak)
    assert any(c["check"].startswith("best label-free") for c in leak)
    assert leak[-1]["status"] in ("PASS", "WARN")
    assert "INFO" not in out["counts"]


def test_permutation_verdict_still_fails_on_a_leak():
    spec = importlib.util.spec_from_file_location("verify_chapter7", REPO / "scripts" / "verify_chapter7.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ref = ("lstm_autoencoder", 0.090)
    assert mod.permutation_verdict(0.025, 0.0100, ref)[0] == "PASS"       # under the Chapter 6 bar
    assert mod.permutation_verdict(0.0388, 0.0100, ref)[0] == "WARN"      # above it, inside the label-free range
    assert mod.permutation_verdict(0.20, 0.0100, ref)[0] == "FAIL"        # a leak-sized score
    assert mod.permutation_verdict(0.0388, 0.0100, None)[0] == "FAIL"     # no reference: the old rule holds
