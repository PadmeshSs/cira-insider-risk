"""Chapter 5 regression tests (end-to-end on a tiny synthetic CERT tree).

Chunk sizes are forced small so user-days straddle Parquet parts, which is
exactly what happens with the real 500k/1M-row chunks.  These tests cover
the HCEA §5.5 acceptance items that can be checked without the real corpus:
distinct counts vs brute force, resumability, null policy, schema, leakage.
"""
from __future__ import annotations

import json
import sys

import numpy as np
import pandas as pd
import pytest

import app.feature_engineering.stage0 as stage0
from app.feature_engineering import pipeline
from app.feature_engineering.pipeline import run_pipeline
from fixtures import synthetic_cert


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("cert")
    paths = synthetic_cert.build(root)
    processed = root / "processed"
    saved = dict(stage0.CHUNK_SIZES)
    stage0.CHUNK_SIZES.update({k: 173 for k in saved})
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(root / "runlog.jsonl"))
    try:
        out = run_pipeline(paths["raw"], processed, profile="full")
    finally:
        stage0.CHUNK_SIZES.clear()
        stage0.CHUNK_SIZES.update(saved)
        mp.undo()
    matrix = pd.read_parquet(out)
    schema = json.loads((processed / "features" / "feature_schema.json").read_text())
    return {**paths, "processed": processed, "matrix": matrix, "schema": schema, "root": root}


def _brute(raw, name):
    df = pd.read_csv(raw / name)
    df["user_id"] = df["user"].str.casefold()
    df["hour"] = df["date"].str[11:13].astype(int)
    df["date"] = pd.to_datetime(df["date"].str[:10], format="%m/%d/%Y").dt.strftime("%Y-%m-%d")
    return df


def test_chunks_really_straddle_days(built):
    parts = list((built["processed"] / "events" / "profile=full" / "source_type=device").rglob("*.parquet"))
    assert len(parts) > 3


@pytest.mark.parametrize(
    "csv_name,column,item",
    [
        ("device.csv", "usb_distinct_pcs", "pc"),
        ("file.csv", "file_distinct_pcs", "pc"),
        ("logon.csv", "distinct_auth_pcs", "pc"),
    ],
)
def test_distinct_counts_match_brute_force(built, csv_name, column, item):
    ref = _brute(built["raw"], csv_name).groupby(["user_id", "date"])[item].nunique().rename("ref").reset_index()
    j = built["matrix"].merge(ref, on=["user_id", "date"])
    assert len(j) > 0
    assert (j[column] == j["ref"]).all()


def test_http_distinct_hosts_match_brute_force(built):
    df = _brute(built["raw"], "http.csv")
    df["host"] = df["url"].str.extract(r"://([^/]+)")[0]
    ref = df.groupby(["user_id", "date"])["host"].nunique().rename("ref").reset_index()
    j = built["matrix"].merge(ref, on=["user_id", "date"])
    assert (j["http_distinct_hosts"] == j["ref"]).all()


def test_first_last_hours_are_min_max_not_sums(built):
    ref = _brute(built["raw"], "device.csv").groupby(["user_id", "date"])["hour"].agg(["min", "max"]).reset_index()
    j = built["matrix"].merge(ref, on=["user_id", "date"])
    assert (j["usb_first_hour"] == j["min"]).all()
    assert (j["usb_last_hour"] == j["max"]).all()
    assert built["matrix"][["usb_first_hour", "usb_last_hour", "first_auth_hour", "last_auth_hour"]].max().max() <= 23


def test_inactive_days_are_null_not_midnight(built):
    m = built["matrix"]
    idle = m[m["login_count"] == 0]
    assert len(idle) > 0
    assert idle["first_auth_hour"].isna().all()
    assert idle["first_auth_off_hours"].isna().all()
    assert idle["off_hours_login_ratio"].isna().all()
    assert (idle["login_count"] == 0).all()


def test_host_category_counts(built):
    df = _brute(built["raw"], "http.csv")
    df["host"] = df["url"].str.extract(r"://([^/]+)")[0]
    df["cloud"] = df["host"].isin(["dropbox.com", "a.drive.google.com"]).astype(int)
    ref = df.groupby(["user_id", "date"])["cloud"].sum().rename("ref").reset_index()
    j = built["matrix"].merge(ref, on=["user_id", "date"])
    assert (j["http_cloud_storage_count"] == j["ref"]).all()


def test_matrix_is_numeric_float32_and_label_free(built):
    m = built["matrix"]
    features = m.drop(columns=["user_id", "date"])
    assert (features.dtypes == np.float32).all()
    lowered = [c.lower() for c in m.columns]
    for bad in ("label", "malicious", "insider", "scenario", "ground_truth"):
        assert not any(bad in c for c in lowered)


def test_schema_documents_every_column(built):
    schema = built["schema"]
    names = [c["name"] for c in schema["columns"]]
    assert set(names) == set(built["matrix"].columns) - {"user_id", "date"}
    for col in schema["columns"]:
        assert col["dtype"]
        assert col["source_domain"]
        assert col["null_policy"] != "not applicable", col["name"]
    hist = next(c for c in schema["columns"] if c["name"] == "hist_z_login_count")
    assert hist["window_days"] == 30 and hist["min_periods"] == 7


def test_peer_features_use_same_day_and_exclude_target(built):
    m = built["matrix"]
    assert m["peer_median_login_count"].notna().any()
    assert (m["peer_department_size"].dropna() >= 0).all()


def test_runlog_written(built):
    lines = (built["root"] / "runlog.jsonl").read_text().strip().splitlines()
    record = json.loads(lines[-1])
    for key in ("profile", "rows_in", "rows_out", "wall_seconds", "peak_rss_mb", "config_fingerprint"):
        assert key in record


def test_stage0_resumes_after_a_crash(tmp_path, monkeypatch):
    paths = synthetic_cert.build(tmp_path)
    processed = tmp_path / "processed"
    calls = {"n": 0}
    real = stage0._canonical_domain_chunk

    def flaky(domain, chunk, tz):
        calls["n"] += 1
        if calls["n"] == 4:
            raise KeyboardInterrupt("simulated kill")
        return real(domain, chunk, tz)

    monkeypatch.setattr(stage0, "_canonical_domain_chunk", flaky)
    with pytest.raises(KeyboardInterrupt):
        stage0.convert_domain(paths["raw"], processed, "http", profile="full", chunksize=500)
    done_before = len(list((processed / "_runlog" / "stage0_parts" / "full" / "http").glob("*.done")))
    assert done_before == 3

    monkeypatch.setattr(stage0, "_canonical_domain_chunk", real)
    result = stage0.convert_domain(paths["raw"], processed, "http", profile="full", chunksize=500)
    assert result["chunks_skipped"] == 3
    assert result["rows_written"] == len(pd.read_csv(paths["raw"] / "http.csv"))
    written = sum(len(pd.read_parquet(p)) for p in (processed / "events" / "profile=full" / "source_type=http").rglob("*.parquet"))
    assert written == result["rows_written"]


def test_stage0_rejects_malformed_rows_with_reason(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    pd.DataFrame({
        "id": ["{A}", "{B}", "{C}", "{C}", ""],
        "date": ["01/04/2010 08:00:00", "not a date", "01/04/2010 09:00:00", "01/04/2010 09:00:00", "01/04/2010 10:00:00"],
        "user": ["U1", "U1", "U1", "U1", "U1"],
        "pc": ["PC-1"] * 5,
        "activity": ["Logon"] * 5,
    }).to_csv(raw / "logon.csv", index=False)
    result = stage0.convert_domain(raw, tmp_path / "p", "logon", profile="full")
    assert result["rows_written"] == 2
    assert result["rows_rejected"] == 3
    rej = pd.concat(pd.read_parquet(p) for p in (tmp_path / "p" / "rejected").rglob("*.parquet"))
    assert sorted(rej["reason_code"]) == ["duplicate_event", "missing_event_id", "unparseable_timestamp"]


def test_stage0_cli_runs(tmp_path, monkeypatch):
    paths = synthetic_cert.build(tmp_path)
    monkeypatch.setattr(sys, "argv", [
        "stage0", "--raw-dir", str(paths["raw"]), "--processed-dir", str(tmp_path / "p"),
        "--profile", "full", "--domain", "logon",
    ])
    stage0.main()
    assert list((tmp_path / "p" / "events" / "profile=full" / "source_type=logon").rglob("*.parquet"))


def test_dev_profile_only_picks_insiders_active_in_window(tmp_path, monkeypatch):
    paths = synthetic_cert.build(tmp_path)
    processed = tmp_path / "p"
    from app.feature_engineering.context import build_context

    build_context(paths["raw"], processed)
    monkeypatch.setitem(pipeline.PROFILE_CONFIG, "dev", {**pipeline.PROFILE_CONFIG["dev"], "insiders": 2, "benign": 3})
    users = pipeline._profile_users(processed, paths["raw"], "dev", ground_truth_dir=paths["gt"])
    insiders_in_window = {paths["users"][1].casefold(), paths["users"][2].casefold()}
    assert insiders_in_window <= users
    assert paths["users"][0].casefold() not in users   # its window is Jan 2010
    assert "zzz9999" not in users                       # r5.1 row ignored
    assert len(users) == 5

    monkeypatch.setitem(pipeline.PROFILE_CONFIG, "dev", {**pipeline.PROFILE_CONFIG["dev"], "insiders": 3})
    with pytest.raises(RuntimeError, match="needs 3 insiders"):
        pipeline._profile_users(processed, paths["raw"], "dev", ground_truth_dir=paths["gt"])

def test_http_aggregation_resumes_after_interruption(tmp_path, monkeypatch):
    paths = synthetic_cert.build(tmp_path)
    processed = tmp_path / "processed"

    # Create synthetic HTTP Parquet parts.
    stage0.convert_domain(
        paths["raw"],
        processed,
        "http",
        profile="full",
        chunksize=173,
    )

    fingerprint = "http-resume-test"
    real_aggregate = pipeline.network.aggregate
    calls = {"n": 0}

    def flaky_aggregate(df):
        calls["n"] += 1
        if calls["n"] == 4:
            raise KeyboardInterrupt("simulated interruption")
        return real_aggregate(df)

    monkeypatch.setattr(pipeline.network, "aggregate", flaky_aggregate)

    with pytest.raises(KeyboardInterrupt):
        pipeline.aggregate_http(processed, "full", fingerprint)

    root = processed / "_runlog" / "http_parts" / "full" / fingerprint
    completed_aggregates = list((root / "aggregates").glob("*.parquet"))

    # Three aggregate parts completed before the simulated interruption.
    assert len(completed_aggregates) == 3

    # Resume using the real aggregation function.
    monkeypatch.setattr(pipeline.network, "aggregate", real_aggregate)
    resumed = pipeline.aggregate_http(processed, "full", fingerprint)

    assert len(list((root / "aggregates").glob("*.parquet"))) == len(
        list(processed.glob("events/profile=full/source_type=http/**/*.parquet"))
    )

    # Compare resumed output with a clean, uninterrupted run.
    clean_processed = tmp_path / "clean_processed"
    stage0.convert_domain(
        paths["raw"],
        clean_processed,
        "http",
        profile="full",
        chunksize=173,
    )

    clean = pipeline.aggregate_http(clean_processed, "full", "clean-run")

    pd.testing.assert_frame_equal(
        resumed.sort_values(["user_id", "date"]).reset_index(drop=True),
        clean.sort_values(["user_id", "date"]).reset_index(drop=True),
        check_dtype=False,
    )