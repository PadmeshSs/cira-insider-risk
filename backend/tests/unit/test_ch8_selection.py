"""The Chapter 8 serving rule (c8-serving-rule-v1), as a pure function."""
import pytest

from app.scoring.select import RULE, DecisionError, decide

OK = {"tabnet": True, "gbdt": True}


def pr(full, mid_user, mid_time):
    return {"full/user": {"tabnet": full[0], "gbdt": full[1]},
            "mid/user": {"tabnet": mid_user[0], "gbdt": mid_user[1]},
            "mid/time": {"tabnet": mid_time[0], "gbdt": mid_time[1]}}


def test_rule_constants_are_the_documented_ones():
    assert RULE["version"] == "c8-serving-rule-v1" and RULE["margin"] == 0.10 and RULE["default"] == "tabnet"
    assert RULE["decisive"] == "full/user" and RULE["consistency"] == ["mid/user", "mid/time"]
    assert RULE["criterion"] == "validation PR-AUC, primary view" and RULE["served_profile"] == "full"


def test_xgboost_served_only_when_clearly_and_consistently_ahead():
    out = decide(pr((0.75, 0.92), (0.73, 0.92), (0.95, 0.99)), OK)
    assert out["served"] == "gbdt" and out["shadow"] == "tabnet" and out["deviation"] == "C8-1"
    assert out["difference"] == pytest.approx(0.17)


def test_inside_the_margin_the_default_stands():
    out = decide(pr((0.75, 0.84), (0.73, 0.92), (0.95, 0.99)), OK)
    assert out["served"] == "tabnet" and out["shadow"] == "gbdt" and out["deviation"] is None
    assert "not above" in out["reason"]
    assert decide(pr((0.75, 0.85), (0.7, 0.9), (0.9, 0.95)), OK)["served"] == "tabnet"     # exactly 0.10 is not > 0.10


def test_inconsistent_evidence_keeps_the_default():
    out = decide(pr((0.60, 0.90), (0.73, 0.92), (0.99, 0.95)), OK)
    assert out["served"] == "tabnet" and "mid/time" in out["reason"]
    missing = pr((0.60, 0.90), (0.73, 0.92), (None, 0.95))
    assert decide(missing, OK)["served"] == "tabnet"


def test_tabnet_ahead_is_served():
    assert decide(pr((0.80, 0.50), (0.8, 0.5), (0.9, 0.8)), OK)["served"] == "tabnet"


def test_gates_override_the_numbers():
    out = decide(pr((0.9, 0.5), (0.9, 0.5), (0.9, 0.5)), {"tabnet": False, "gbdt": True})
    assert out["served"] == "gbdt" and out["shadow"] is None and "tabnet failed a gate" in out["reason"]
    out = decide(pr((0.5, 0.9), (0.5, 0.9), (0.5, 0.9)), {"tabnet": True, "gbdt": False})
    assert out["served"] == "tabnet" and out["shadow"] is None
    with pytest.raises(DecisionError):
        decide(pr((0.5, 0.9), (0.5, 0.9), (0.5, 0.9)), {"tabnet": False, "gbdt": False})


def test_missing_decisive_evidence_is_an_error():
    with pytest.raises(DecisionError):
        decide({"mid/user": {"tabnet": 0.5, "gbdt": 0.9}}, OK)
