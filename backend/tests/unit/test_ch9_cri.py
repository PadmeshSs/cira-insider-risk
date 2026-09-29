"""Chapter 9 CRI: configuration, rarity, context, engine, calibration files (Bible Ch9)."""
import ast
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.cri.calibration import (
    ANOMALY_STAT,
    DEFINITION_VERSION,
    HISTORICAL_STAT,
    CalibrationUnavailableError,
    LoadedCalibration,
    exceedance,
    fit_maps,
    load_calibration,
    rarity,
    save_calibration,
    sorted_reference,
)
from app.cri.config import COMPONENTS, DEFAULT_WEIGHTS, CRIConfig, CRIConfigError
from app.cri.context import build_context, historical_statistic, user_context
from app.cri.engine import RISK_COLUMNS, CRIEngine, CRIInputError, CRIModelMismatchError, combine, severity_of
from app.cri.runtime import CRIRuntime

MODEL = {"model_name": "gbdt", "model_version": "gbdt-chapter8-v1-aaaaaaaaaaaa", "registry_version": "v0003"}
BASE = ("anomaly", "historical_deviation", "peer_deviation", "user_context")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _frames(n=400, seed=0, users=20):
    rng = np.random.default_rng(seed)
    keys = pd.DataFrame({"user_id": [f"u{i % users:03d}" for i in range(n)],
                         "date": pd.date_range("2010-06-01", periods=n // users + 1).strftime("%Y-%m-%d")
                         .to_numpy()[np.arange(n) // users]})
    feats = pd.DataFrame({
        "hist_z_login_count": rng.normal(0, 1, n), "hist_z_usb_connect_count": rng.normal(0, 1, n),
        "peer_dev_login_count": rng.normal(0, 2, n), "peer_dev_emails_sent": rng.normal(0, 5, n),
    })
    early = rng.random(n) < 0.1                                       # fewer than 7 prior days: every z is null
    feats.loc[early, ["hist_z_login_count", "hist_z_usb_connect_count"]] = np.nan
    roles = pd.DataFrame({"user_id": [f"u{i:03d}" for i in range(users)], "month": "2010-06",
                          "role": ["ITAdmin" if i == 0 else "Salesman" for i in range(users)]})
    roles = pd.concat([roles, roles.assign(month="2010-07")], ignore_index=True)
    scores = keys.assign(role="served", **MODEL, anomaly_score=1 / (1 + np.exp(-rng.normal(-6, 3, n))))
    return keys, feats, roles, scores


def _calibration(ref_scores, ctx, decades=5.0):
    reference = pd.DataFrame({"user_id": ref_scores["user_id"], "date": ref_scores["date"],
                              ANOMALY_STAT: ref_scores["anomaly_score"].to_numpy(),
                              HISTORICAL_STAT: ctx["historical_statistic"].to_numpy(dtype="float64"),
                              **{c: ctx[c].to_numpy(dtype="float64") for c in ctx.columns if c.startswith("peer_pos__")}})
    meta = {"calibration_id": "test-cri", "model": dict(MODEL), "definition_version": DEFINITION_VERSION,
            "rarity_decades": decades, "reference": {"part": "validation", "rows": len(reference)},
            "config_at_calibration": {"config_hash": CRIConfig().config_hash}}
    return reference, meta, LoadedCalibration(meta=meta, maps=fit_maps(reference, decades), pin={}, reference_path=Path())


@pytest.fixture()
def world():
    keys, feats, roles, scores = _frames()
    ctx = build_context(keys, feats, roles, ("ITAdmin",))
    reference, meta, cal = _calibration(scores, ctx)
    return {"keys": keys, "feats": feats, "roles": roles, "scores": scores, "ctx": ctx,
            "reference": reference, "meta": meta, "engine": CRIEngine(CRIConfig(), cal)}


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

def test_defaults_and_effective_weights():
    cfg = CRIConfig()
    assert cfg.weight == DEFAULT_WEIGHTS and not cfg.overrides
    w = cfg.effective_weights(set(BASE))
    assert set(w) == set(BASE) and sum(w.values()) == pytest.approx(1.0)
    assert w["anomaly"] == pytest.approx(0.60 / 0.90)                # asset (0) and MITRE (unavailable) left out
    w2 = cfg.effective_weights(set(COMPONENTS))
    assert "mitre_context" in w2 and "asset_criticality" not in w2   # weight 0 is never active
    assert 100 * w["anomaly"] < 75                                    # anomaly alone cannot reach CRITICAL


def test_env_overrides_are_recorded_not_silent():
    cfg = CRIConfig.from_env({"CRI_WEIGHT_ANOMALY_SCORE": "0.40", "CRI_SEVERITY_HIGH_MAX": "70"})
    assert cfg.weight["anomaly"] == 0.40 and cfg.bands == (24, 49, 70)
    assert dict(cfg.overrides) == {"CRI_WEIGHT_ANOMALY_SCORE": "0.40", "CRI_SEVERITY_HIGH_MAX": "70"}
    assert cfg.config_hash != CRIConfig().config_hash
    assert CRIConfig.from_env({}).config_hash == CRIConfig().config_hash


@pytest.mark.parametrize("env", [
    {"CRI_WEIGHT_ANOMALY_SCORE": "0"},
    {"CRI_WEIGHT_PEER_DEVIATION": "-0.1"},
    {"CRI_SEVERITY_LOW_MAX": "60"},
    {"CRI_DISABLED_COMPONENTS": "anomaly"},
    {"CRI_DISABLED_COMPONENTS": "nonsense"},
    {"CRI_WEIGHT_USER_CONTEXT": "abc"},
])
def test_invalid_configuration_is_refused(env):
    with pytest.raises(CRIConfigError):
        CRIConfig.from_env(env)


def test_variants_and_hash():
    cfg = CRIConfig()
    only = cfg.variant("anomaly_only")
    assert only.effective_weights(set(COMPONENTS)) == {"anomaly": 1.0}
    assert cfg.variant("default").config_hash == cfg.config_hash
    assert cfg.variant("no_peer_deviation").config_hash != cfg.config_hash
    with pytest.raises(CRIConfigError):
        cfg.variant("no_such_variant")


def test_band_boundaries():
    cfg = CRIConfig()
    got = severity_of(np.array([0.0, 24.99, 25.0, 49.99, 50.0, 74.99, 75.0, 100.0]), cfg)
    assert got.tolist() == ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]


# ---------------------------------------------------------------------------
# rarity
# ---------------------------------------------------------------------------

def test_rarity_bounds_monotone_and_ceiling():
    ref = sorted_reference(np.r_[np.arange(999, dtype=float), np.nan])
    assert len(ref) == 999
    x = np.array([-5.0, 0.0, 500.0, 998.0, 5000.0, np.nan])
    p = exceedance(x, ref)
    assert p[0] == 1.0 and p[1] == 1.0 and p[4] == pytest.approx(1 / 1000)
    r = rarity(x, ref, 5.0)
    assert r[0] == 0.0 and np.isnan(r[-1])
    assert r[4] == pytest.approx(np.log10(1000) / 5)                 # capped by the reference size
    assert (np.diff(r[:5]) >= 0).all() and r[3] < r[4]
    dense = rarity(np.sort(ref), ref, 5.0)
    assert (np.diff(dense) > 0).all()                                # strict across distinct reference values
    assert rarity(np.array([1e9]), ref, 2.0)[0] == 1.0               # D smaller than log10(n+1): cap at 1


def test_anomaly_only_ranks_exactly_like_the_score(world):
    only = world["engine"].compute_variants(world["scores"], world["ctx"], ["anomaly_only"])["anomaly_only"]
    s, c = world["scores"]["anomaly_score"].to_numpy(), only["cri_score"].to_numpy()
    order = np.argsort(s, kind="mergesort")
    assert (np.diff(c[order]) >= 0).all()
    assert pd.Series(s).rank().equals(pd.Series(c).rank())


# ---------------------------------------------------------------------------
# context
# ---------------------------------------------------------------------------

def test_historical_statistic_takes_the_largest_rise_only():
    f = pd.DataFrame({"hist_z_a": [2.0, -3.0, np.nan, np.nan], "hist_z_b": [5.0, -1.0, 1.5, np.nan]})
    stat, top = historical_statistic(f, ["hist_z_a", "hist_z_b"])
    assert stat[0] == 5.0 and top[0] == "b"
    assert stat[1] == 0.0 and top[1] is None                         # a drop is not risk
    assert stat[2] == 1.5 and np.isnan(stat[3]) and top[3] is None


def test_user_context_is_point_in_time_and_casefolded():
    keys = pd.DataFrame({"user_id": ["U000", "u001", "u000", "u002"], "date": ["2010-06-03", "2010-06-03", "2010-08-01", "2010-06-03"]})
    roles = pd.DataFrame({"user_id": ["u000", "u001", "u000"], "month": ["2010-06", "2010-06", "2010-07"],
                          "role": ["itadmin", "Salesman", "ITAdmin"]})
    value, role = user_context(keys, roles, ("ITAdmin",))
    assert value[0] == 1.0 and value[1] == 0.0
    assert np.isnan(value[2]) and role[2] is None                   # no August snapshot: never borrowed from July
    assert np.isnan(value[3])


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------

def test_compute_contract_and_arithmetic(world):
    risk = world["engine"].compute(world["scores"], world["ctx"])
    assert list(risk.columns) == list(RISK_COLUMNS)
    np.testing.assert_array_equal(risk["anomaly_score"].to_numpy(), world["scores"]["anomaly_score"].to_numpy())
    pts = sum(risk[f"points_{c}"] for c in COMPONENTS)
    assert np.allclose(pts, risk["cri_score"], atol=1e-12) and risk["cri_score"].between(0, 100).all()
    assert risk["component_asset_criticality"].isna().all() and (risk["points_asset_criticality"] == 0).all()
    assert risk["component_mitre_context"].isna().all() and (risk["points_mitre_context"] == 0).all()
    missing_hist = risk["component_historical_deviation"].isna()
    assert missing_hist.any() and (risk.loc[missing_hist, "points_historical_deviation"] == 0).all()
    assert risk.loc[missing_hist, "missing_components"].str.contains("historical_deviation").all()
    priv = risk["role"] == "ITAdmin"
    assert (risk.loc[priv, "component_user_context"] == 1).all() and (risk.loc[~priv, "component_user_context"] == 0).all()
    assert set(risk["cri_version"]) == {"chapter9-v1"} and set(risk["calibration_id"]) == {"test-cri"}


def test_a_null_component_is_not_reweighted(world):
    ctx = world["ctx"].copy()
    ctx["historical_statistic"] = np.nan
    risk = world["engine"].compute(world["scores"], ctx)
    w = CRIConfig().effective_weights(set(BASE))
    assert np.allclose(risk["points_anomaly"], 100 * w["anomaly"] * risk["component_anomaly"])


def test_supplied_mitre_and_asset_enter_the_formula(world):
    ctx = world["ctx"].assign(mitre_context=0.0, asset_criticality=np.nan)
    ctx.loc[0, "mitre_context"] = 1.0
    risk = world["engine"].compute(world["scores"], ctx)
    cfg = CRIConfig()
    avail = {*BASE, "mitre_context", "asset_criticality"}
    assert risk.loc[0, "points_mitre_context"] == pytest.approx(100 * cfg.effective_weights(avail)["mitre_context"])
    bad = world["ctx"].assign(asset_criticality=1.5)
    with pytest.raises(CRIInputError):
        world["engine"].compute(world["scores"], bad)


def test_refusals(world):
    e, s, ctx = world["engine"], world["scores"], world["ctx"]
    with pytest.raises(CRIModelMismatchError, match="N29"):
        e.compute(s.assign(model_version="tabnet-chapter7-v1-e03b3d0d3360", model_name="tabnet"), ctx)
    with pytest.raises(CRIInputError, match="N32"):
        e.compute(s.assign(role="shadow"), ctx)
    nan = s.copy()
    nan.loc[3, "anomaly_score"] = np.nan
    with pytest.raises(CRIInputError, match="no score, no CRI"):
        e.compute(nan, ctx)
    with pytest.raises(CRIInputError, match="aligned"):
        e.compute(s, ctx.iloc[::-1].reset_index(drop=True))
    mixed = s.copy()
    mixed.loc[0, "model_version"] = "other"
    with pytest.raises(CRIModelMismatchError):
        e.compute(mixed, ctx)


def test_variants_only_recombine(world):
    out = world["engine"].compute_variants(world["scores"], world["ctx"], ["default", "no_user_context"])
    d, nu = out["default"], out["no_user_context"]
    for c in COMPONENTS:
        pd.testing.assert_series_equal(d[f"component_{c}"], nu[f"component_{c}"])
    assert (nu["points_user_context"] == 0).all() and set(nu["cri_variant"]) == {"no_user_context"}
    comps = {c: d[f"component_{c}"].to_numpy() for c in COMPONENTS}
    again = combine(comps, set(BASE), CRIConfig())
    assert np.allclose(again["cri"], d["cri_score"])


def test_compute_event_matches_the_frame(world):
    i = 7
    row = world["engine"].compute(world["scores"], world["ctx"]).iloc[i]
    score = {**MODEL, "anomaly_score": float(world["scores"]["anomaly_score"].iloc[i]), "role": "served",
             "user_id": world["keys"]["user_id"].iloc[i], "date": world["keys"]["date"].iloc[i]}
    role = world["roles"].set_index("user_id").loc[score["user_id"], "role"].iloc[0]
    one = world["engine"].compute_event(score, world["feats"].iloc[i].to_dict(), role)
    assert one["cri_score"] == pytest.approx(row["cri_score"], abs=1e-12) and one["severity"] == row["severity"]


# ---------------------------------------------------------------------------
# calibration files and runtime
# ---------------------------------------------------------------------------

def test_save_load_tamper_and_supersede(tmp_path, world):
    models, pin = tmp_path / "models", tmp_path / "pin.json"
    meta = {**world["meta"], "created_at": "2026-09-29T00:00:00+00:00", "source_batch": {"batch_run_id": "b1"}}
    save_calibration(meta, world["reference"], models_root=models, pin_path=pin)
    cal = load_calibration(pin, models)
    assert cal.calibration_id == "test-cri" and cal.model["model_version"] == MODEL["model_version"]
    with pytest.raises(FileExistsError, match="--supersede"):
        save_calibration({**meta, "calibration_id": "test-cri-2"}, world["reference"], models_root=models, pin_path=pin)
    save_calibration({**meta, "calibration_id": "test-cri-2"}, world["reference"], models_root=models, pin_path=pin,
                     supersede_reason="served model changed")
    p = json.loads(pin.read_text())
    assert p["current"]["calibration_id"] == "test-cri-2" and p["superseded"][0]["calibration_id"] == "test-cri"
    ref = models / "cri" / "test-cri-2" / "reference.parquet"
    world["reference"].assign(anomaly_score=0.5).to_parquet(ref, index=False)
    with pytest.raises(CalibrationUnavailableError, match="modified"):
        load_calibration(pin, models)


class _Served:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Service:
    def __init__(self, served):
        self.served = served


def test_runtime_reports_why_it_is_unavailable(tmp_path, world):
    rt = CRIRuntime.load(_Service(None), pin_path=tmp_path / "none.json", models_root=tmp_path)
    assert not rt.available and "no CRI calibration" in rt.status()["reason"]
    models, pin = tmp_path / "models", tmp_path / "pin.json"
    meta = {**world["meta"], "created_at": "x", "source_batch": {"batch_run_id": "b1"}}
    save_calibration(meta, world["reference"], models_root=models, pin_path=pin)
    tab = _Served(model_name="tabnet", model_version="tabnet-chapter7-v1-e03b3d0d3360", registry_version="v0005")
    rt = CRIRuntime.load(_Service(tab), pin_path=pin, models_root=models)       # a rollback without recalibration
    assert not rt.available and "N29" in rt.status()["reason"]
    ok = CRIRuntime.load(_Service(_Served(**MODEL)), pin_path=pin, models_root=models)
    assert ok.available and ok.status()["calibration"]["model_version"] == MODEL["model_version"]
    from app.cri.engine import CRIUnavailableError

    with pytest.raises(CRIUnavailableError, match="N29"):
        CRIRuntime.load(_Service(tab), pin_path=pin, models_root=models).engine()


# ---------------------------------------------------------------------------
# label isolation
# ---------------------------------------------------------------------------

SERVING_MODULES = ("config", "calibration", "context", "assets", "engine", "sources", "runtime", "batch", "calibrate")


def test_serving_modules_never_import_labels_or_the_readout():
    import app.cri as pkg

    for name in SERVING_MODULES:
        tree = ast.parse((Path(pkg.__file__).parent / f"{name}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mods = [(("." * node.level) + (node.module or ""))]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            else:
                continue
            for m in mods:
                assert "ground_truth" not in m and "evaluation.labels" not in m and "evaluation.metrics" not in m, (name, m)
                assert "evaluation.compare" not in m and not m.endswith("evaluate"), (name, m)


def test_env_example_matches_the_code_defaults():
    """.env.example must not ship an override of the Chapter 9 defaults (N37)."""
    env = {}
    for line in (Path(__file__).resolve().parents[3] / ".env.example").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    cfg = CRIConfig.from_env(env)
    assert not cfg.overrides and cfg.config_hash == CRIConfig().config_hash
