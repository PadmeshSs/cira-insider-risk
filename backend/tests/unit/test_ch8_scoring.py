"""Chapter 8 serving path: contract, adapters, service, failure modes (Bible Ch8, HCEA §8)."""
import ast
import json
import shutil
from pathlib import Path

import numpy as np
import pytest

from app.scoring.adapters import GBDTAdapter, TabNetAdapter, load_adapter
from app.scoring.contracts import (
    SCORE_FRAME_COLUMNS,
    STATIC_TRAIT_PREFIXES,
    ModelPin,
    ScoringFailedError,
    ScoringInputError,
    ScoringUnavailableError,
    stable_sigmoid,
    static_inputs,
    vector_to_frame,
)
from app.scoring.gbdt_model import BehaviourGBDTDetector
from app.scoring.service import AnomalyScoringService
from app.scoring.serving_config import ServingConfig, resolve_serving_config
from app.tabnet.model_registry import ModelRegistry
from fixtures import synthetic_matrix

NULLABLE = list(synthetic_matrix.NULLABLE)
FAST_TABNET = dict(n_d=8, n_a=8, n_steps=3, max_epochs=3, patience=10, batch_size=128, virtual_batch_size=64,
                   device="cpu", nullable_columns=NULLABLE)


def _label(frame):
    return (frame["http_leak_paste_count"] >= 5).astype("int8").to_numpy()


@pytest.fixture(scope="module")
def data():
    m = synthetic_matrix.build(n_users=16, n_days=90)
    m["psych_openness"] = np.float32(30.0)                    # a static trait the served models must not see
    train = m[m["user_id"] < "u0011"].reset_index(drop=True)
    test = m[m["user_id"] >= "u0011"].reset_index(drop=True)
    return train, test


def _entry(model_version, profile="full", reportable=True):
    return {"model_version": model_version, "run_id": f"run-{model_version}", "profile": profile,
            "reportable": reportable, "split": {"mode": "user"}}


@pytest.fixture(scope="module")
def registry(data, tmp_path_factory):
    """One TabNet and one XGBoost, both behaviour-only, registered like the runners do."""
    from app.tabnet.train import TabNetDetector

    train, test = data
    root = tmp_path_factory.mktemp("registry")
    fit_train = train.drop(columns=["psych_openness"])
    tab = TabNetDetector(seed=0, **FAST_TABNET).fit(fit_train, _label(train), validation=test.drop(columns=["psych_openness"]),
                                                   y_validation=_label(test))
    gb = BehaviourGBDTDetector(seed=0, device="cpu", n_estimators=60, excluded_features=["psych_openness"])
    gb.fit(fit_train, _label(train), validation=test.drop(columns=["psych_openness"]), y_validation=_label(test))
    e_tab = ModelRegistry(root, "tabnet").register(lambda d: tab.save(d), _entry(tab.model_version))
    e_gb = ModelRegistry(root, "gbdt").register(lambda d: gb.save(d), _entry(gb.model_version))
    e_dev = ModelRegistry(root, "gbdt").register(lambda d: gb.save(d), _entry(gb.model_version, profile="dev", reportable=False))
    return {"root": root, "tabnet": tab, "gbdt": gb, "e_tab": e_tab, "e_gb": e_gb, "e_dev": e_dev}


def _service(registry, served="tabnet", shadow="gbdt"):
    pins = {"tabnet": ModelPin("tabnet", registry["e_tab"]["registry_version"]),
            "gbdt": ModelPin("gbdt", registry["e_gb"]["registry_version"])}
    cfg = ServingConfig(pins[served], (pins[shadow],) if shadow else (), registry["root"], "test")
    return AnomalyScoringService.load(cfg)


# --- contract ---------------------------------------------------------------

def test_pins_refuse_latest_and_bad_names():
    assert ModelPin.parse("gbdt:v0003") == ModelPin("gbdt", "v0003")
    for bad in ("tabnet:latest", "tabnet:3", "lof:v0001", "tabnet"):
        with pytest.raises(ValueError):
            ModelPin.parse(bad)


def test_sigmoid_and_static_prefixes_match_chapter7():
    from app.tabnet.dataset import STATIC_TRAIT_PREFIXES as ch7
    from app.tabnet.infer import sigmoid

    z = np.array([-800.0, -40.0, -1.0, 0.0, 1.0, 40.0, 800.0])
    assert np.array_equal(stable_sigmoid(z), sigmoid(z))
    assert STATIC_TRAIT_PREFIXES == ch7
    assert static_inputs(["psych_openness", "usb_event_count", "peer_department_size"]) == ["peer_department_size", "psych_openness"]


def test_excluded_columns_rule_matches_chapter7(data):
    from app.scoring.gbdt_candidate import excluded_columns as ch8
    from app.tabnet.train import excluded_columns as ch7

    train, _ = data
    assert ch8(train, "psych_,usb_") == ch7(train, "psych_,usb_")
    with pytest.raises(SystemExit):
        ch8(train, "no_such_prefix_")


def test_vector_to_frame_distinguishes_null_from_missing():
    f = vector_to_frame({"a": None, "b": True, "c": 3}, ["a", "b", "c"])
    assert np.isnan(f.loc[0, "a"]) and f.loc[0, "b"] == 1.0 and f.loc[0, "c"] == 3.0
    with pytest.raises(ScoringInputError, match="missing"):
        vector_to_frame({"a": 1.0}, ["a", "b"])
    with pytest.raises(ScoringInputError, match="non-numeric"):
        vector_to_frame({"a": "high"}, ["a"])


# --- the behaviour-only XGBoost ---------------------------------------------

def test_gbdt_score_is_sigmoid_of_margin_and_uses_best_iteration(registry, data):
    _, test = data
    gb = registry["gbdt"]
    raw, s = gb.scores(test)
    assert np.array_equal(s, stable_sigmoid(raw)) and ((s >= 0) & (s <= 1)).all()
    assert np.abs(s - gb.model.predict_proba(gb._x(test))[:, 1]).max() < 1e-6
    best = gb.info["best_iteration"]
    margin_best = gb.model.predict(gb._x(test), output_margin=True, iteration_range=(0, best + 1))
    assert np.allclose(raw, margin_best)
    assert gb.model_version.startswith("gbdt-chapter8-v1-")
    assert "psych_openness" not in gb.input_columns and gb.metadata()["static_inputs"] == []


def test_gbdt_round_trip_is_exact(registry, data, tmp_path):
    _, test = data
    registry["gbdt"].save(tmp_path / "m")
    back = BehaviourGBDTDetector.load(tmp_path / "m")
    back.use_cpu(2)
    assert np.array_equal(back.score(test), registry["gbdt"].score(test))
    assert back.model_version == registry["gbdt"].model_version


# --- adapters ---------------------------------------------------------------

def test_adapters_load_pinned_versions_on_cpu(registry, data):
    _, test = data
    tab = load_adapter(ModelPin("tabnet", registry["e_tab"]["registry_version"]), registry["root"])
    gb = load_adapter(ModelPin("gbdt", registry["e_gb"]["registry_version"]), registry["root"])
    assert isinstance(tab, TabNetAdapter) and isinstance(gb, GBDTAdapter)
    assert np.array_equal(stable_sigmoid(tab.raw_score(test)), registry["tabnet"].score(test))
    assert np.array_equal(stable_sigmoid(gb.raw_score(test)), registry["gbdt"].score(test))
    for a in (tab, gb):
        d = a.describe()
        assert d["device"] == "cpu" and d["static_inputs"] == [] and d["profile"] == "full"
    assert tab.scorer.device == "cpu"


def test_adapter_refusals(registry, tmp_path):
    with pytest.raises(ScoringUnavailableError, match="is not a registered"):
        load_adapter(ModelPin("gbdt", "v0999"), registry["root"])
    with pytest.raises(ScoringUnavailableError, match="not reportable"):
        load_adapter(ModelPin("gbdt", registry["e_dev"]["registry_version"]), registry["root"])
    assert load_adapter(ModelPin("gbdt", registry["e_dev"]["registry_version"]), registry["root"], allow_unreportable=True)
    # a tampered artifact is never loaded
    root = tmp_path / "copy"
    shutil.copytree(registry["root"], root)
    victim = root / "gbdt" / registry["e_gb"]["registry_version"] / "columns.txt"
    victim.write_text(victim.read_text() + "\nextra_column")
    with pytest.raises(ScoringUnavailableError, match="sha256"):
        load_adapter(ModelPin("gbdt", registry["e_gb"]["registry_version"]), root)


# --- service ----------------------------------------------------------------

def test_score_frame_long_format_with_lineage(registry, data):
    _, test = data
    svc = _service(registry)
    out = svc.score_frame(test)
    assert list(out.columns) == list(SCORE_FRAME_COLUMNS) and len(out) == len(test)
    assert (out["role"] == "served").all() and out["model_version"].nunique() == 1
    assert out["registry_version"].iloc[0] == registry["e_tab"]["registry_version"]
    assert np.array_equal(out["anomaly_score"].to_numpy(), registry["tabnet"].score(test))
    both = svc.score_frame(test, include_shadow=True)
    assert len(both) == 2 * len(test) and set(both["role"]) == {"served", "shadow"}
    served = both[both["role"] == "served"]["anomaly_score"].to_numpy()
    assert np.array_equal(served, out["anomaly_score"].to_numpy())          # shadow changes nothing served


def test_score_event_equals_batch_row(registry, data):
    _, test = data
    svc = _service(registry, served="gbdt", shadow=None)
    row = test.iloc[7]
    result = svc.score_event(row.to_dict(), user_id=row["user_id"], date=row["date"])
    batch = svc.score_frame(test.iloc[[7]])
    assert result.anomaly_score == batch["anomaly_score"].iloc[0]
    assert result.model_version == registry["gbdt"].model_version and result.role == "served"
    assert result.registry_version == registry["e_gb"]["registry_version"] and result.user_id == row["user_id"]


def test_input_errors_are_explicit(registry, data):
    _, test = data
    svc = _service(registry)
    col = svc.input_columns[0]
    with pytest.raises(ScoringInputError, match="missing"):
        svc.score_frame(test.drop(columns=[col]))
    bad = test.copy()
    bad.loc[0, col] = np.inf
    with pytest.raises(ScoringInputError, match="infinite"):
        svc.score_frame(bad)
    with pytest.raises(ScoringInputError, match="user_id"):
        svc.score_frame(test.drop(columns=["user_id"]))
    nulls = test.copy()
    nulls[NULLABLE[0]] = np.nan                                             # deliberate nulls are fine (N4)
    assert np.isfinite(svc.score_frame(nulls)["anomaly_score"]).all()
    assert svc.score_frame(test.assign(unrelated_extra=1.0)).shape[0] == len(test)


def test_unavailable_service_never_scores(registry, data):
    _, test = data
    cfg = ServingConfig(ModelPin("tabnet", "v0999"), (), registry["root"], "test")
    svc = AnomalyScoringService.load(cfg)
    assert not svc.available and svc.status()["status"] == "unavailable" and "v0999" in svc.status()["reason"]
    with pytest.raises(ScoringUnavailableError):
        svc.score_frame(test)
    with pytest.raises(ScoringUnavailableError):
        svc.score_event(test.iloc[0].to_dict())
    empty = AnomalyScoringService.load(ServingConfig(None, (), registry["root"], "none", problem="nothing configured"))
    assert empty.status()["reason"] == "nothing configured"


def test_inference_failure_is_an_error_not_a_score(registry, data, monkeypatch):
    _, test = data
    svc = _service(registry, shadow=None)
    monkeypatch.setattr(svc.served, "raw_score", lambda frame: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(ScoringFailedError, match="boom"):
        svc.score_frame(test)
    monkeypatch.setattr(svc.served, "raw_score", lambda frame: np.full(len(frame), np.nan))
    with pytest.raises(ScoringFailedError, match="non-finite"):
        svc.score_frame(test)


def test_broken_shadow_never_blocks_serving(registry, data, monkeypatch):
    _, test = data
    svc = _service(registry)
    monkeypatch.setattr(svc.shadows[0], "raw_score", lambda frame: (_ for _ in ()).throw(RuntimeError("shadow down")))
    out = svc.score_frame(test, include_shadow=True)
    assert (out["role"] == "served").all() and svc.shadow_score_failures == 1
    cfg = ServingConfig(ModelPin("tabnet", registry["e_tab"]["registry_version"]), (ModelPin("gbdt", "v0999"),), registry["root"], "test")
    svc2 = AnomalyScoringService.load(cfg)
    assert svc2.available and "gbdt:v0999" in svc2.status()["shadow_load_errors"]


# --- configuration ----------------------------------------------------------

def test_serving_config_resolution(tmp_path):
    env = {"MODEL_PATH": str(tmp_path), "CIRA_SERVING_DECISION": str(tmp_path / "none.json")}
    cfg = resolve_serving_config(env)
    assert cfg.served is None and "no serving decision" in cfg.problem
    cfg = resolve_serving_config({**env, "CIRA_SERVED_MODEL": "gbdt:v0002", "CIRA_SHADOW_MODEL": "tabnet:v0005"})
    assert cfg.source == "env" and cfg.served == ModelPin("gbdt", "v0002") and cfg.shadows == (ModelPin("tabnet", "v0005"),)
    assert resolve_serving_config({**env, "CIRA_SERVED_MODEL": "tabnet:latest"}).problem
    decision = tmp_path / "d.json"
    decision.write_text(json.dumps({"rule": {"version": "r"}, "outcome": {
        "served": {"model_name": "tabnet", "registry_version": "v0005"}, "shadow": None}}))
    cfg = resolve_serving_config({**env, "CIRA_SERVING_DECISION": str(decision)})
    assert cfg.source == "decision_file" and cfg.served == ModelPin("tabnet", "v0005") and cfg.shadows == () and cfg.decision_rule == "r"
    decision.write_text("{not json")
    assert "unreadable" in resolve_serving_config({**env, "CIRA_SERVING_DECISION": str(decision)}).problem


# --- API lifespan (HCEA §8: load once at startup) ---------------------------

def test_api_starts_degraded_without_a_model(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.delenv("CIRA_SERVED_MODEL", raising=False)
    monkeypatch.setenv("CIRA_SERVING_DECISION", str(tmp_path / "missing.json"))
    with TestClient(app) as client:
        body = client.get("/health").json()
    assert body["status"] == "degraded" and body["anomaly_model"]["status"] == "unavailable"
    assert body["anomaly_model"]["served"] is None and "missing.json" in body["anomaly_model"]["reason"]
    assert "anomaly_score" not in body["anomaly_model"] and "raw_score" not in body["anomaly_model"]


def test_api_loads_the_pinned_model_once(registry, monkeypatch):
    from fastapi.testclient import TestClient

    import app.main as main
    import app.scoring.service as service_mod

    calls = []
    real = service_mod.AnomalyScoringService.load.__func__

    def counting(cls, config, **kw):
        calls.append(config)
        return real(cls, config, **kw)

    monkeypatch.setattr(service_mod.AnomalyScoringService, "load", classmethod(counting))
    monkeypatch.setenv("MODEL_PATH", str(registry["root"]))
    monkeypatch.setenv("CIRA_SERVED_MODEL", f"gbdt:{registry['e_gb']['registry_version']}")
    with TestClient(main.app) as client:
        for _ in range(3):
            body = client.get("/health").json()
    assert len(calls) == 1
    assert body["status"] == "healthy" and body["anomaly_model"]["served"]["model_version"] == registry["gbdt"].model_version
    assert body["anomaly_model"]["source"] == "env"


# --- label isolation (N5) ---------------------------------------------------

SERVING_MODULES = ("__init__", "contracts", "gbdt_model", "adapters", "serving_config", "service", "batch")
OFFLINE_MODULES = ("gbdt_candidate", "select")


def test_serving_modules_never_import_labels_or_offline_code():
    import app.scoring as pkg

    for name in SERVING_MODULES:
        tree = ast.parse((Path(pkg.__file__).parent / f"{name}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mods = [("." * node.level) + (node.module or "")]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            else:
                continue
            for m in mods:
                assert "ground_truth" not in m and "evaluation.labels" not in m and "evaluation.compare" not in m, (name, m)
                assert not any(m.endswith(off) for off in OFFLINE_MODULES), (name, m)
