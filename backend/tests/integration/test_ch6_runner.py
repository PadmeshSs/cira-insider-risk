"""Chapter 6 end to end on a synthetic CERT tree: Chapter 5 features ->
labels -> split -> all five baselines -> metrics, scores and runlog."""
import json

import pandas as pd
import pytest

from app.baselines import DETECTORS
from app.baselines.run import _parse_args, run
from app.feature_engineering.pipeline import run_pipeline
from app.ingestion.ground_truth import build_insider_label_tables
from fixtures import synthetic_ch6


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("ch6")
    paths = synthetic_ch6.build(root)
    processed = root / "processed"
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(root / "runlog.jsonl"))
    try:
        run_pipeline(paths["raw"], processed, profile="full", ground_truth_dir=paths["gt"])
        build_insider_label_tables(paths["gt"], processed)
    finally:
        mp.undo()
    return {**paths, "root": root, "processed": processed}


def _args(built, *extra):
    r = built["root"]
    return _parse_args([
        "--processed-dir", str(built["processed"]), "--profile", "full", "--lstm-max-epochs", "2",
        "--splits-dir", str(r / "splits"), "--results-dir", str(r / "results"),
        "--models-dir", str(r / "models"), "--checkpoint-dir", str(r / "ckpt"), *extra,
    ])


def test_user_split_run(built, monkeypatch):
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    report = run(_args(built))
    assert set(report["models"]) == set(DETECTORS)
    assert report["label_coverage"]["primary"]["unmatched"] == 0
    for name, block in report["models"].items():
        for split in ("validation", "test"):
            p = block[split]["primary"]
            assert "accuracy" not in json.dumps(p)
            assert p["positives"] > 0 and p["pr_auc"] is not None
            assert set(p["budgets"]) == {"1", "5", "10"}
        scores = pd.read_parquet(block["metadata"]["scores_path"])
        assert not {"y_primary", "is_malicious", "scenario", "label"} & set(scores.columns)   # N5
        assert scores["anomaly_score"].between(0, 1).all()
        assert scores["model_version"].nunique() == 1
    lines = [json.loads(x) for x in (built["root"] / "runlog.jsonl").read_text().splitlines()]
    ch6 = [x for x in lines if x.get("stage") == "chapter6_baseline" and x["run_id"] == report["run_id"]]
    assert {x["model"] for x in ch6} == set(DETECTORS)
    assert all("test_pr_auc" in x and "peak_rss_mb" in x for x in ch6)

    split = json.loads(open(report["split"]["file"]).read())
    assert set(split["assignment"].values()) <= {"train", "validation", "test"}

    # Second run re-uses the saved split instead of recomputing it.
    again = run(_args(built, "--models", "rule_based"))
    assert again["split"]["created_now"] is False


def test_time_split_run(built, monkeypatch):
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    report = run(_args(built, "--split", "time", "--time-validation-start", "2010-02-08", "--time-test-start", "2010-02-20",
                       "--models", "isolation_forest,lstm_autoencoder,gbdt"))
    assert report["split"]["rows"]["test"] > 0
    assert report["models"]["gbdt"]["test"]["primary"]["positives"] > 0


def test_masquerade_rows_are_excluded_and_counted(built, monkeypatch):
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    report = run(_args(built, "--models", "rule_based", "--split", "time",
                       "--time-validation-start", "2010-01-05", "--time-test-start", "2010-01-06"))
    total_excluded = sum(report["split"]["masquerade_rows_excluded"].values())
    assert total_excluded == 1


def test_dev_profile_with_date_window_runs_and_is_not_reportable(built, monkeypatch):
    """dev cuts the calendar, so insiders have label days outside the window.
    Those must be counted, not treated as missing (regression)."""
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    feats = built["processed"] / "features"
    full = pd.read_parquet(feats / "user_day_full.parquet")
    dev = full[(full["date"] >= "2010-01-18") & (full["date"] < "2010-02-27")]
    dev.to_parquet(feats / "user_day_dev.parquet", index=False)
    schema = json.loads((feats / "feature_schema_full.json").read_text())
    schema["profile"] = "dev"
    (feats / "feature_schema_dev.json").write_text(json.dumps(schema))
    args = _args(built, "--models", "rule_based,isolation_forest")
    args.profile = "dev"
    report = run(args)
    assert report["reportable"] is False
    cov = report["label_coverage"]["primary"]
    assert cov["unmatched"] == 0 and cov["outside_feature_window"] > 0


def test_full_profile_refuses_label_days_outside_the_window(built, monkeypatch, tmp_path):
    monkeypatch.setenv("CIRA_RUNLOG", str(built["root"] / "runlog.jsonl"))
    import shutil

    proc = tmp_path / "processed"
    shutil.copytree(built["processed"] / "labels", proc / "labels")
    (proc / "features").mkdir(parents=True)
    full = pd.read_parquet(built["processed"] / "features" / "user_day_full.parquet")
    full[full["date"] >= "2010-02-01"].to_parquet(proc / "features" / "user_day_full.parquet", index=False)
    shutil.copy(built["processed"] / "features" / "feature_schema_full.json", proc / "features" / "feature_schema_full.json")
    args = _args(built, "--models", "rule_based")
    args.processed_dir = str(proc)
    with pytest.raises(RuntimeError, match="outside the feature window"):
        run(args)
