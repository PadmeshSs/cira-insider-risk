"""In-memory label join (N1, N5)."""
import pandas as pd

from app.evaluation.labels import (
    attach_labels,
    insider_scenarios,
    label_coverage,
    load_label_views,
)
from app.ingestion.ground_truth import build_insider_label_tables
from fixtures import synthetic_ch6


def test_views_join_and_masquerade_flag(tmp_path):
    paths = synthetic_ch6.build(tmp_path, n_users=30)
    processed = tmp_path / "processed"
    build_insider_label_tables(paths["gt"], processed)
    views = load_label_views(processed)
    assert views.primary["user_id"].nunique() == 13
    assert insider_scenarios(views) == paths["insiders"]

    masq = views.account[views.account["is_masquerade"] == 1].iloc[0]
    assert masq["user_id"] == paths["supervisor"]
    ins = views.primary.iloc[0]
    keys = pd.DataFrame({
        "user_id": pd.array([masq["user_id"], ins["user_id"], "nobody"], dtype="string"),
        "date": pd.array([masq["date"], ins["date"], "2010-01-05"], dtype="string"),
    }, index=[10, 11, 12])
    lab = attach_labels(keys, views)
    assert lab.index.tolist() == [10, 11, 12]
    assert lab["y_primary"].tolist() == [0, 1, 0]
    assert lab["exclude_primary"].tolist() == [True, False, False]
    assert lab["y_account"].tolist() == [1, 1, 0]

    cov = label_coverage(keys, views)
    # keys hold one day per user, so the insider's other malicious days are
    # outside the feature window (dev-style), not missing.
    assert cov["primary"]["unmatched"] == 0
    assert cov["primary"]["outside_feature_window"] == 2


def test_coverage_flags_a_missing_day_inside_the_window(tmp_path):
    paths = synthetic_ch6.build(tmp_path, n_users=30)
    processed = tmp_path / "processed"
    build_insider_label_tables(paths["gt"], processed)
    views = load_label_views(processed)
    user = views.primary["user_id"].iloc[0]
    days = sorted(views.primary.loc[views.primary["user_id"] == user, "date"])
    span = pd.date_range(days[0], days[-1], freq="D").strftime("%Y-%m-%d")
    keep = [d for d in span if d != days[1]]                     # drop one malicious day from the middle
    keys = pd.DataFrame({"user_id": pd.array([user] * len(keep), dtype="string"), "date": pd.array(keep, dtype="string")})
    cov = label_coverage(keys, views)["primary"]
    assert cov["unmatched"] == 1 and cov["outside_feature_window"] == 0


def test_label_frame_is_separate_from_features(tmp_path):
    """attach_labels returns a new frame; it never adds columns to the keys."""
    paths = synthetic_ch6.build(tmp_path, n_users=30)
    processed = tmp_path / "processed"
    build_insider_label_tables(paths["gt"], processed)
    keys = pd.DataFrame({"user_id": pd.array(["u0000"], dtype="string"), "date": pd.array(["2010-01-05"], dtype="string")})
    before = list(keys.columns)
    attach_labels(keys, load_label_views(processed))
    assert list(keys.columns) == before
