import pandas as pd
import numpy as np

from app.feature_engineering.authentication import aggregate as auth_aggregate
from app.feature_engineering.email import aggregate as email_aggregate
from app.feature_engineering.historical_baseline import add_baselines
from app.feature_engineering.network import aggregate as http_aggregate
from app.feature_engineering.peer_group import add_peer_features
from app.feature_engineering.usb import aggregate as usb_aggregate


def base_rows():
    return pd.DataFrame({
        "event_id": ["1", "2", "3", "4"],
        "timestamp": pd.to_datetime(["2010-01-01 08:00", "2010-01-01 20:00", "2010-01-02 09:00", "2010-01-02 10:00"], utc=True),
        "date_day": pd.to_datetime(["2010-01-01"]*2 + ["2010-01-02"]*2),
        "hour": [8, 20, 9, 10],
        "weekday": [4, 4, 5, 5],
        "user_id": ["u1"]*4,
        "device_id": ["pc1", "pc2", "pc1", "pc3"],
        "activity": ["logon", "logoff", "logon", "logoff"],
    })


def test_authentication_counts_and_off_hours():
    out = auth_aggregate(base_rows())
    row = out[out.date.eq(pd.Timestamp("2010-01-01"))].iloc[0]
    assert row.login_count == 1
    assert row.logoff_count == 1
    assert row.off_hours_login_ratio == 0


def test_usb_counts():
    df = base_rows().assign(activity=["connect", "disconnect", "connect", "disconnect"])
    out = usb_aggregate(df)
    assert out.usb_connect_count.sum() == 2
    assert out.usb_disconnect_count.sum() == 2


def test_email_external_ratio_uses_directory_membership():
    df = pd.DataFrame({
        "event_id": ["1", "2"], "date_day": pd.to_datetime(["2010-01-01", "2010-01-01"]),
        "hour": [8, 20], "weekday": [4, 4], "user_id": ["u1", "u1"], "device_id": ["pc1", "pc1"],
        "to": ["u2@example.com", "external@other.com"], "cc": ["", ""], "bcc": ["", ""],
        "from": ["u1@example.com", "u1@example.com"], "size": [100, 200], "attachments": [1, 0],
    })
    out = email_aggregate(df, {"u1@example.com": "u1", "u2@example.com": "u2"})
    assert out.iloc[0].emails_sent == 2
    assert out.iloc[0].email_external_recipient_count == 1
    assert np.isclose(out.iloc[0].external_email_ratio, 0.5)


def test_http_distinct_hosts():
    df = pd.DataFrame({
        "event_id": ["1", "2", "3"], "date_day": pd.to_datetime(["2010-01-01"]*3),
        "hour": [8, 8, 20], "weekday": [4, 4, 4], "user_id": ["u1"]*3, "device_id": ["pc1"]*3,
        "host": ["a.example", "a.example", "b.example"],
    })
    out = http_aggregate(df)
    assert out.iloc[0].http_request_count == 3
    assert out.iloc[0].http_distinct_hosts == 2


def test_history_excludes_current_day():
    df = pd.DataFrame({"user_id": ["u1"]*8, "date": pd.date_range("2010-01-01", periods=8), "login_count": [1,2,1,2,1,2,1,10]})
    out, meta = add_baselines(df, columns=["login_count"], window=30, min_periods=7)
    assert pd.isna(out.loc[6, "hist_z_login_count"])
    assert out.loc[7, "hist_z_login_count"] > 0
    assert meta["hist_z_login_count"]["min_periods"] == 7


def test_peer_deviation_excludes_target_and_uses_same_month_department():
    df = pd.DataFrame({
        "user_id": ["u1", "u2"],
        "date": pd.to_datetime(["2010-01-15"] * 2),
        "login_count": [10, 20],
    })

    ldap = pd.DataFrame({
        "user_id": ["u1", "u2"],
        "department": ["eng", "eng"],
        "role": ["x", "x"],
        "snapshot_month": pd.to_datetime(
            ["2010-01-01"] * 2
        ),
    })

    out, meta = add_peer_features(df, ldap)

    medians = dict(
        zip(
            out["user_id"],
            out["peer_median_login_count"],
        )
    )

    deviations = dict(
        zip(
            out["user_id"],
            out["peer_dev_login_count"],
        )
    )

    assert medians["u1"] == 20
    assert medians["u2"] == 10

    assert deviations["u1"] == -10
    assert deviations["u2"] == 10

    assert out["peer_department_size"].tolist() == [1.0, 1.0]

    assert meta["peer_dev_login_count"]["peer_excludes_target"] is True