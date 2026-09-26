"""User split rules (CARRY_FORWARD N3)."""
import json

import numpy as np
import pandas as pd
import pytest

from app.evaluation.splitting import (
    SPLITS,
    assert_user_disjoint,
    assign_user_splits,
    load_or_create_split,
    rows_for_split,
    time_split,
)

INSIDERS = {**{f"s1_{i:02d}": 1 for i in range(30)}, **{f"s2_{i:02d}": 2 for i in range(30)}, **{f"s3_{i:02d}": 3 for i in range(10)}}
BENIGN_MID = [f"b{i:04d}" for i in range(180)]
BENIGN_FULL = [f"b{i:04d}" for i in range(930)]


def test_each_user_in_exactly_one_split_and_scenarios_stratified():
    users = list(INSIDERS) + BENIGN_MID
    a = assign_user_splits(users, INSIDERS, seed=42)
    assert set(a) == {u.casefold() for u in users}
    assert set(a.values()) <= set(SPLITS)
    for scenario, total, expected in ((1, 30, (18, 6, 6)), (2, 30, (18, 6, 6)), (3, 10, (6, 2, 2))):
        members = [u for u, s in INSIDERS.items() if s == scenario]
        got = tuple(sum(a[u] == split for u in members) for split in SPLITS)
        assert got == expected, (scenario, got)


def test_split_is_stable_between_mid_and_full_populations():
    mid = assign_user_splits(list(INSIDERS) + BENIGN_MID, INSIDERS, seed=42)
    full = assign_user_splits(list(INSIDERS) + BENIGN_FULL, INSIDERS, seed=42)
    assert all(full[u] == s for u, s in mid.items())


def test_seed_changes_assignment_and_same_seed_reproduces():
    users = list(INSIDERS) + BENIGN_MID
    assert assign_user_splits(users, INSIDERS, seed=42) == assign_user_splits(users, INSIDERS, seed=42)
    assert assign_user_splits(users, INSIDERS, seed=42) != assign_user_splits(users, INSIDERS, seed=7)


def test_saved_split_has_no_per_user_labels(tmp_path):
    users = list(INSIDERS) + BENIGN_MID
    path = tmp_path / "split.json"
    load_or_create_split(path, users, INSIDERS, seed=42, profile="mid")
    payload = json.loads(path.read_text())
    assert set(payload["assignment"].values()) <= set(SPLITS)          # only split names per user
    assert "scenario" not in json.dumps(payload["assignment"])
    assert payload["counts"]["test"]["insiders_by_scenario"] == {"1": 6, "2": 6, "3": 2}


def test_saved_split_mismatch_is_an_error_not_an_overwrite(tmp_path):
    path = tmp_path / "split.json"
    load_or_create_split(path, list(INSIDERS) + BENIGN_MID, INSIDERS, seed=42, profile="mid")
    with pytest.raises(RuntimeError, match="does not match"):
        load_or_create_split(path, list(INSIDERS) + BENIGN_MID[:100], INSIDERS, seed=42, profile="mid")
    _, _, created = load_or_create_split(path, list(INSIDERS) + BENIGN_MID[:100], INSIDERS, seed=42, profile="mid", rebuild=True)
    assert created


def test_rows_follow_their_user_and_disjointness_is_checked():
    a = {"a": "train", "b": "test"}
    users = pd.Series(["a", "a", "b"], dtype="string")
    split = rows_for_split(users, a)
    assert split.tolist() == ["train", "train", "test"]
    assert_user_disjoint(users, split)
    with pytest.raises(AssertionError):
        assert_user_disjoint(users, np.array(["train", "test", "test"]))
    with pytest.raises(RuntimeError):
        rows_for_split(pd.Series(["zzz"], dtype="string"), a)


def test_time_split_orders_by_date():
    dates = pd.Series(["2010-12-31", "2011-01-01", "2011-01-31", "2011-02-01"], dtype="string")
    assert time_split(dates, validation_start="2011-01-01", test_start="2011-02-01").tolist() == [
        "train", "validation", "validation", "test"]
    with pytest.raises(ValueError):
        time_split(dates, validation_start="2011-02-01", test_start="2011-01-01")
