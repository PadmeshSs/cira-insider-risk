"""Unit tests for Chapter 5 sub-domains that previously had none."""
import numpy as np
import pandas as pd

from app.feature_engineering import application, file_activity, temporal
from app.feature_engineering.common import categorize_hosts, combine_rule
from app.feature_engineering.network import aggregate as http_aggregate
from app.feature_engineering.peer_group import add_peer_features, leave_one_out_median


def _rows(**extra):
    base = {
        "event_id": ["1", "2", "3"],
        "date_day": pd.to_datetime(["2010-01-04"] * 3),
        "hour": [8, 20, 9],
        "weekday": [0, 0, 0],
        "user_id": ["u1"] * 3,
        "device_id": ["pc1", "pc2", "pc1"],
    }
    base.update(extra)
    return pd.DataFrame(base)


def test_file_activity_extension_counts_and_off_hours():
    out = file_activity.aggregate(_rows(file_extension=["zip", "exe", "weird"]))
    row = out.iloc[0]
    assert row.file_event_count == 3
    assert row.file_zip_count == 1 and row.file_exe_count == 1
    assert row.file_other_ext_count == 1
    assert row.file_archive_or_executable_count == 2
    assert row.file_off_hours_events == 1
    assert row.file_distinct_pcs == 2


def test_application_family_emits_no_fabricated_columns():
    out = application.aggregate(pd.DataFrame())
    assert list(out.columns) == ["user_id", "date"]
    assert out.empty


def test_temporal_nulls_absence_and_rolls_without_current_day():
    df = pd.DataFrame({
        "user_id": ["u1"] * 4,
        "date": pd.date_range("2010-01-01", periods=4),
        "first_auth_hour": [8.0, np.nan, 22.0, 9.0],
        "last_auth_hour": [17.0, np.nan, 23.0, 9.0],
        "auth_event_count": [2, 0, 2, 1],
        "http_request_count": [5, 0, 0, 3],
    })
    out = temporal.add_temporal(df)
    assert out["first_auth_off_hours"].tolist()[0] == 0
    assert np.isnan(out["first_auth_off_hours"].tolist()[1])
    assert out["first_auth_off_hours"].tolist()[2] == 1
    assert out["total_event_count"].tolist() == [7, 0, 2, 4]
    assert out["is_active_day"].tolist() == [1, 0, 1, 1]
    rolled = out["rolling_7d_event_count"].tolist()
    assert np.isnan(rolled[0])                   # no prior day
    assert rolled[1] == 7 and rolled[3] == 9     # current day excluded
    assert out["auth_active_span_hours"].tolist()[0] == 9


def test_combine_rules():
    assert combine_rule("usb_first_hour") == "min"
    assert combine_rule("first_auth_hour") == "min"
    assert combine_rule("usb_last_hour") == "max"
    assert combine_rule("http_x_flag") == "max"
    assert combine_rule("login_count") == "sum"


def test_host_categories_match_exact_or_subdomain_only():
    hosts = pd.Series(["drive.google.com", "x.drive.google.com", "google.com", "notdropbox.com", "dropbox.com"])
    flags = categorize_hosts(hosts, {"cloud": ("drive.google.com", "dropbox.com")})
    assert flags["cloud"].tolist() == [1, 1, 0, 0, 1]


def test_http_category_counts_are_additive_columns():
    df = _rows(host=["dropbox.com", "cnn.com", "dropbox.com"])
    out = http_aggregate(df, {"cloud_storage": ("dropbox.com",)})
    assert out.iloc[0].http_cloud_storage_count == 2
    assert out.iloc[0].http_request_count == 3


def test_leave_one_out_median_matches_brute_force():
    rng = np.random.default_rng(0)
    for _ in range(50):
        n = int(rng.integers(1, 25))
        v = pd.Series(rng.integers(0, 5, n).astype(float))
        g = pd.Series(rng.integers(0, 3, n))
        got = leave_one_out_median(v, g)
        for i in range(n):
            peers = v[(g == g[i]) & (v.index != i)]
            exp = peers.median() if len(peers) else np.nan
            assert (np.isnan(exp) and np.isnan(got[i])) or np.isclose(exp, got[i])


def test_peer_group_compares_same_day_not_whole_month():
    # u2's huge value on Jan 20 must not affect u1's Jan 10 peer median.
    df = pd.DataFrame({
        "user_id": ["u1", "u2", "u1", "u2"],
        "date": pd.to_datetime(["2010-01-10", "2010-01-10", "2010-01-20", "2010-01-20"]),
        "login_count": [1.0, 2.0, 1.0, 999.0],
    })
    ldap = pd.DataFrame({
        "user_id": ["u1", "u2"], "department": ["d", "d"], "functional_unit": ["f", "f"],
        "snapshot_month": pd.to_datetime(["2010-01-01", "2010-01-01"]),
    })
    out, _ = add_peer_features(df, ldap)
    jan10_u1 = out[(out.user_id == "u1") & (out.date == "2010-01-10")].iloc[0]
    assert jan10_u1.peer_median_login_count == 2.0


def test_peer_group_separates_same_department_name_in_other_functional_unit():
    df = pd.DataFrame({
        "user_id": ["u1", "u2"], "date": pd.to_datetime(["2010-01-10"] * 2), "login_count": [1.0, 5.0],
    })
    ldap = pd.DataFrame({
        "user_id": ["u1", "u2"], "department": ["1 - Sales", "1 - Sales"], "functional_unit": ["A", "B"],
        "snapshot_month": pd.to_datetime(["2010-01-01"] * 2),
    })
    out, _ = add_peer_features(df, ldap)
    assert out["peer_median_login_count"].isna().all()


def test_feature_package_never_imports_ground_truth():
    import ast
    from pathlib import Path

    import app.feature_engineering as fe

    for path in Path(fe.__file__).parent.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert "ground_truth" not in (node.module or ""), path.name
            if isinstance(node, ast.Import):
                assert all("ground_truth" not in a.name for a in node.names), path.name
