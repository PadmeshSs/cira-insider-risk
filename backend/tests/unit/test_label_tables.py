"""Evaluation label tables are built from event-level answer files only."""
import pandas as pd
import pytest

from app.ingestion.ground_truth import build_insider_label_tables
from fixtures import synthetic_cert


def test_label_tables_from_answer_files(tmp_path):
    paths = synthetic_cert.build(tmp_path)
    summary = build_insider_label_tables(paths["gt"], tmp_path / "processed")
    assert summary["malicious_events"] == 3
    assert summary["insider_users"] == 1
    days = pd.read_parquet(tmp_path / "processed" / "labels" / "insider_user_days.parquet")
    assert sorted(days["date"].dt.strftime("%Y-%m-%d")) == ["2010-01-11", "2010-01-12"]
    assert set(days.columns) == {"user_id", "date", "scenario", "n_malicious_events", "is_malicious"}
    assert days["user_id"].unique().tolist() == [paths["users"][0].casefold()]


def test_label_tables_live_outside_feature_tree(tmp_path):
    paths = synthetic_cert.build(tmp_path)
    summary = build_insider_label_tables(paths["gt"], tmp_path / "processed")
    assert summary["output_dir"].endswith("labels")
    assert not (tmp_path / "processed" / "features").exists()


def test_missing_answer_folders_fail_loudly(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_insider_label_tables(tmp_path, tmp_path / "out")
