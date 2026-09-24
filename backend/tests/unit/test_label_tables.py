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


def test_masquerade_event_is_attributed_to_insider_and_flagged_on_account(tmp_path):
    """Scenario-3 style: insider U0000 acts through supervisor account U0005.

    Primary view credits the insider (filename identity); the account view
    keeps the supervisor's account-day and marks it is_masquerade = 1.
    """
    paths = synthetic_cert.build(tmp_path)
    insider, supervisor = paths["users"][0], paths["users"][5]
    answer = paths["gt"] / "r4.2-1" / f"r4.2-1-{insider}.csv"
    answer.write_text(
        answer.read_text(encoding="utf-8")
        + f"email,{{G4}},01/13/2010 09:00:00,{supervisor},PC-0099,alarming mass email\n",
        encoding="utf-8",
    )
    processed = tmp_path / "processed"
    summary = build_insider_label_tables(paths["gt"], processed)

    assert summary["insider_users"] == 1                       # roster identity, not 2
    assert summary["masquerade_events"] == 1
    assert summary["masquerade_accounts"] == [supervisor.casefold()]

    events = pd.read_parquet(processed / "labels" / "insider_events.parquet")
    row = events[events["event_id"] == "{G4}"].iloc[0]
    assert row["user_id"] == insider.casefold()
    assert row["event_user_id"] == supervisor.casefold()

    days = pd.read_parquet(processed / "labels" / "insider_user_days.parquet")
    assert set(days["user_id"]) == {insider.casefold()}
    assert "2010-01-13" in set(days["date"].dt.strftime("%Y-%m-%d"))

    acct = pd.read_parquet(processed / "labels" / "account_user_days.parquet")
    masq = acct[acct["is_masquerade"] == 1]
    assert len(masq) == 1
    assert masq.iloc[0]["account_user_id"] == supervisor.casefold()
    assert masq.iloc[0]["incident_user_id"] == insider.casefold()
    assert (acct.loc[acct["is_masquerade"] == 0, "account_user_id"] == insider.casefold()).all()


def test_answer_file_for_user_not_in_roster_is_rejected(tmp_path):
    paths = synthetic_cert.build(tmp_path)
    (paths["gt"] / "r4.2-1" / "r4.2-1-NOTREAL1.csv").write_text(
        "logon,{X1},01/11/2010 22:01:02,NOTREAL1,PC-0001,Logon\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="does not appear in insiders.csv"):
        build_insider_label_tables(paths["gt"], tmp_path / "processed")
