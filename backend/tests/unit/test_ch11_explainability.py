"""Chapter 11 explainability: describer, TreeSHAP, masks, KernelSHAP, selection, reasons, runtime (Bible Ch11, D-5)."""
import ast
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.explainability import features as F
from app.explainability.attributions import (
    ATTRIBUTION_COLUMNS,
    Attributions,
    ExplanationFailedError,
    ExplanationUnavailableError,
    explainer_for,
    row_summary,
    top_k_long,
)
from app.explainability.reason_builder import (
    GENERIC_PHRASES,
    ExplanationInputError,
    build_explanation,
    jsonable,
    validate_explanation,
)
from app.explainability.runtime import ExplainRuntime
from app.explainability.selection import per_day_top_k, select_rows
from app.explainability.shap_explainer import KernelCorroborator, TreeShapExplainer, auto_nsamples, shap_tree_cross_check
from app.explainability.tabnet_masks import TabNetMaskExplainer
from app.feature_engineering.historical_baseline import DEFAULT_BASELINES
from app.feature_engineering.peer_group import PEER_FEATURES
from app.scoring.adapters import load_adapter
from app.scoring.contracts import ModelPin
from app.scoring.gbdt_model import BehaviourGBDTDetector
from app.scoring.service import AnomalyScoringService
from app.scoring.serving_config import ServingConfig
from app.tabnet.model_registry import ModelRegistry
from fixtures import synthetic_matrix

NULLABLE = list(synthetic_matrix.NULLABLE)
FAST_TABNET = dict(n_d=8, n_a=8, n_steps=3, max_epochs=3, patience=10, batch_size=128, virtual_batch_size=64,
                   device="cpu", nullable_columns=NULLABLE)
SERVING = ("features", "attributions", "shap_explainer", "tabnet_masks", "reason_builder", "selection", "sources",
           "runtime", "batch")


def _label(frame):
    return ((frame["http_leak_paste_count"] >= 4) & (frame["file_event_count"] >= 2)).astype("int8").to_numpy()


@pytest.fixture(scope="module")
def data():
    m = synthetic_matrix.build(n_users=16, n_days=90)
    train = m[m["user_id"] < "u0011"].reset_index(drop=True)
    test = m[m["user_id"] >= "u0011"].reset_index(drop=True)
    return train, test


@pytest.fixture(scope="module")
def registry(data, tmp_path_factory):
    """A behaviour-only XGBoost that early-stops well before its last tree, and a small TabNet, registered."""
    from app.tabnet.train import TabNetDetector

    train, test = data
    root = tmp_path_factory.mktemp("registry11")
    gb = BehaviourGBDTDetector(seed=0, device="cpu", n_estimators=300, learning_rate=0.3, early_stopping_rounds=5)
    gb.fit(train, _label(train), validation=test, y_validation=_label(test))
    tab = TabNetDetector(seed=0, **FAST_TABNET).fit(train, _label(train), validation=test, y_validation=_label(test))
    entry = {"run_id": "r", "profile": "full", "reportable": True, "split": {"mode": "user"}}
    e_gb = ModelRegistry(root, "gbdt").register(lambda d: gb.save(d), {**entry, "model_version": gb.model_version})
    e_tab = ModelRegistry(root, "tabnet").register(lambda d: tab.save(d), {**entry, "model_version": tab.model_version})
    return {"root": root,
            "gbdt": load_adapter(ModelPin("gbdt", e_gb["registry_version"]), root),
            "tabnet": load_adapter(ModelPin("tabnet", e_tab["registry_version"]), root)}


# --- describer (N4, N9, N22) ----------------------------------------------------------

def _chapter5_columns() -> list[str]:
    cols = [c for c in F.BASE]
    for b in DEFAULT_BASELINES:
        cols += [f"hist_z_{b}", f"hist_abs_z_{b}"]
    for b in PEER_FEATURES:
        cols += [f"peer_median_{b}", f"peer_dev_{b}", f"peer_abs_dev_{b}"]
    return cols


def test_every_chapter5_column_is_described_without_unsupported_claims():
    cols = _chapter5_columns()
    assert F.undescribed(cols) == []
    assert {c: F.forbidden_in(F.describe(c).label) for c in cols if F.forbidden_in(F.describe(c).label)} == {}
    assert F.describe("no_such_column").described is False


def test_static_traits_and_calendar_columns_are_marked():
    assert F.describe("psych_openness").static and F.describe("peer_department_size").static
    assert not F.describe("peer_dev_login_count").static
    assert F.describe("is_weekend").calendar and F.describe("day_of_week").calendar


def test_values_in_words_and_nulls_by_meaning():
    assert F.value_text("first_auth_hour", 23.0) == "23:00"
    assert F.value_text("off_hours_login_ratio", 0.5) == "50%"
    assert F.value_text("hist_z_usb_connect_count", 4.2) == "4.2 standard deviations above their usual level"
    assert F.value_text("peer_dev_file_event_count", -3.0) == "3 below the peers' median"
    assert F.value_text("day_of_week", 6.0) == "Sunday" and F.value_text("new_device_flag", 1.0) == "yes"
    assert F.value_text("file_event_count", 14.0) == "14"
    for col in ("first_auth_hour", "off_hours_login_ratio", "hist_z_login_count", "peer_dev_login_count"):
        text = F.value_text(col, np.nan)
        assert text.startswith("no value") and "0" not in text           # a null is never shown as zero (N4)
    assert F.describe_value("file_event_count", 14) == "files copied to removable media: 14"


# --- TreeSHAP on the served XGBoost ------------------------------------------------------

def test_treeshap_adds_up_to_the_served_margin(registry, data):
    _, test = data
    ex = explainer_for(registry["gbdt"])
    assert isinstance(ex, TreeShapExplainer) and ex.method == "treeshap"
    a = ex.explain(test)
    margin = registry["gbdt"].raw_score(test)
    assert np.allclose(a.values.sum(axis=1) + a.expected_value, margin, atol=1e-4)
    assert a.additivity_error.max() < 1e-4 and a.features == registry["gbdt"].input_columns


def test_treeshap_uses_the_early_stopping_iteration(registry, data):
    """Without the best iteration a raw Booster uses every tree and the contributions stop adding up."""
    _, test = data
    ex = explainer_for(registry["gbdt"])
    n_trees = ex.booster.num_boosted_rounds()
    assert ex.best_iteration is not None and ex.best_iteration + 1 < n_trees       # the fixture early-stopped
    ex.iteration_range = (0, 0)                                                     # "all trees": the bug it guards
    with pytest.raises(ExplanationFailedError, match="does not reproduce the served margin"):
        ex.explain(test)


def test_treeshap_is_chunk_invariant_and_matches_shap(registry, data):
    _, test = data
    full = explainer_for(registry["gbdt"]).explain(test)
    small = explainer_for(registry["gbdt"], chunk_rows=37).explain(test)
    assert np.array_equal(full.values, small.values)
    r = shap_tree_cross_check(registry["gbdt"], test.iloc[:200], Attributions(
        keys=full.keys.iloc[:200], features=full.features, values=full.values[:200], method="treeshap",
        raw_score=full.raw_score[:200], model=full.model))
    assert r["ok"] is True, r["detail"]


def test_top_k_long_takes_values_from_the_raw_row(registry, data):
    _, test = data
    a = explainer_for(registry["gbdt"]).explain(test.iloc[:50])
    long = top_k_long(a, test.iloc[:50], 5)
    assert list(long.columns) == list(ATTRIBUTION_COLUMNS)
    assert (long["contribution"] != 0).all() and long["rank"].between(1, 5).all()
    assert set(long["direction"]) <= {"raises", "lowers"}
    first = long.iloc[0]
    raw = test.set_index(["user_id", "date"]).loc[(first["user_id"], first["date"]), first["feature"]]
    assert first["feature_value"] == pytest.approx(float(raw), nan_ok=True)          # N22: raw matrix value
    s = row_summary(a)
    i = int(np.argmax(np.where(a.values[0] > 0, a.values[0], -np.inf)))
    assert s["top_feature"].iloc[0] == a.features[i] and not s["static_in_top5"].any()


def test_explainer_follows_the_model_that_scored(registry):
    assert isinstance(explainer_for(registry["tabnet"]), TabNetMaskExplainer)
    assert explainer_for(registry["gbdt"], role="shadow").model["role"] == "shadow"

    class Other:
        model_name = "lof"

    with pytest.raises(ExplanationUnavailableError):
        explainer_for(Other())


# --- TabNet masks ----------------------------------------------------------------

def test_tabnet_masks_are_shares_grouped_per_base_feature(registry, data):
    _, test = data
    ex = explainer_for(registry["tabnet"], chunk_rows=64)
    a = ex.explain(test.iloc[:200])
    assert a.method == "tabnet_mask" and not a.signed
    assert not any(f.startswith("isnull__") for f in a.features)                    # value + indicator summed (N22)
    assert set(NULLABLE) <= set(a.features)
    sums = a.values.sum(axis=1)
    assert np.allclose(sums[sums > 0], 1.0) and (a.values >= 0).all()
    again = explainer_for(registry["tabnet"], chunk_rows=500).explain(test.iloc[:200])
    assert np.allclose(a.values, again.values, atol=1e-6)                           # chunking changes nothing
    long = top_k_long(a, test.iloc[:200], 3)
    assert set(long["direction"]) == {"attends"}                                    # a mask has no direction


# --- KernelSHAP corroboration and the deletion check (D-5) -------------------------------

def test_kernel_corroboration_refuses_underdetermined_nsamples(registry, data):
    train, _ = data
    m = len(registry["gbdt"].input_columns)
    assert auto_nsamples(m) == 2 * m + 2048
    with pytest.raises(ValueError, match="underdetermined"):
        KernelCorroborator(registry["gbdt"], train, nsamples=m)


def test_kernel_corroboration_on_xgboost(registry, data):
    train, test = data
    rows = test.iloc[:6].reset_index(drop=True)
    primary = explainer_for(registry["gbdt"]).explain(rows)
    corr = KernelCorroborator(registry["gbdt"], train, n_background=20, seed=3)
    assert corr.describe()["n_background"] == 20 and len(corr.describe()["background_keys"]) == 20
    out = corr.corroborate(rows, primary)
    assert len(out) == 6 and out["kernel_additivity_error"].max() < 1e-6
    assert out["top5_overlap"].between(0, 1).all()
    again = KernelCorroborator(registry["gbdt"], train, n_background=20, seed=3).corroborate(rows, primary)
    pd.testing.assert_frame_equal(out, again)                                       # seeded: reproducible
    has = out["deletion_k"] > 0
    assert (out.loc[has, "deletion_drop_top"].notna()).all()


def test_kernel_corroboration_on_tabnet_uses_kmeans_background(registry, data):
    train, test = data
    rows = test.iloc[:3].reset_index(drop=True)
    primary = explainer_for(registry["tabnet"]).explain(rows)
    corr = KernelCorroborator(registry["tabnet"], train.iloc[:400], n_background=10, nsamples=300, seed=1)
    assert "kmeans" in corr.describe()["background"]
    out = corr.corroborate(rows, primary)
    assert len(out) == 3 and out["sign_agreement"].isna().all()                     # masks are unsigned


# --- selection (N31, N39, N40) ---------------------------------------------------------

def _risk(n_days=4, users=("a", "b", "c")):
    rows = []
    for d in range(n_days):
        for i, u in enumerate(users):
            rows.append({"user_id": u, "date": f"2011-01-0{d + 1}", "model_split": ["train", "validation", "test"][i],
                         "anomaly_score": 0.1 * (i + 1) + d / 100, "cri_score": 10.0 * (3 - i),
                         "severity": "LOW"})
    return pd.DataFrame(rows)


def test_selection_is_label_free_and_out_of_sample_only():
    risk = _risk()
    risk.loc[0, "severity"] = "HIGH"                                                # a train row: never selected
    sel, info = select_rows(risk, top_k_per_day=1)
    assert set(sel["model_split"]) <= {"validation", "test"}
    assert sel["by_anomaly"].sum() == 4 and sel["by_cri"].sum() == 4               # c tops anomaly, b tops CRI
    assert info["candidates"] == 8 and info["truncated"] == 0
    capped, info2 = select_rows(risk, top_k_per_day=1, max_rows=3)
    assert info2["truncated"] == 5 and set(capped["model_split"]) == {"test"}         # test users first (N31)


def test_per_day_top_k_breaks_ties_by_user():
    f = pd.DataFrame({"user_id": ["b", "a", "c"], "date": ["d1"] * 3, "s": [1.0, 1.0, 0.5]})
    assert per_day_top_k(f, "s", 1).tolist() == [False, True, False]


# --- the analyst explanation (§18, N22, N30, N32, N34, N45) -----------------------------

MODEL = {"method": "treeshap", "model_name": "gbdt", "model_version": "gbdt-v", "registry_version": "v0003",
         "role": "served", "anomaly_score": 0.97, "raw_score": 3.4, "expected_value": -5.0,
         "factors": [{"feature": "file_event_count", "contribution": 2.1, "feature_value": 14.0},
                     {"feature": "psych_openness", "contribution": 0.9, "feature_value": 30.0},
                     {"feature": "hist_z_usb_connect_count", "contribution": 1.2, "feature_value": 4.2},
                     {"feature": "first_auth_hour", "contribution": 0.4, "feature_value": np.nan},
                     {"feature": "emails_sent", "contribution": -0.3, "feature_value": 2.0}]}
RISK = {"model_version": "gbdt-v", "anomaly_score": 0.97, "cri_score": 57.3, "severity": "HIGH",
        "points_anomaly": 40.0, "points_historical_deviation": 9.1, "points_peer_deviation": 0.0,
        "points_user_context": 0.0, "points_mitre_context": 8.2, "points_asset_criticality": 0.0,
        "historical_top_feature": "usb_connect_count", "peer_top_feature": None, "role": "Salesman",
        "cri_run_id": "cri-1", "calibration_id": "cal-1", "cri_config_hash": "h"}
MITRE = {"mitre_status": "mapped", "mitre_context": 0.8, "mitre_unmapped_behaviours": "job_search",
         "matches": [{"rule_id": "R01_removable_media_copy", "technique_id": "T1052.001",
                      "technique_name": "Exfiltration Over Physical Medium: Exfiltration over USB",
                      "tactic": "exfiltration", "tactic_name": "Exfiltration", "evidence": "observed",
                      "trigger_column": "file_event_count", "trigger_value": 14.0, "strength": 0.5},
                     {"rule_id": "R02_leak_site_access", "technique_id": "T1567",
                      "technique_name": "Exfiltration Over Web Service", "tactic": "exfiltration",
                      "tactic_name": "Exfiltration", "evidence": "indicated", "trigger_column": "http_leak_paste_count",
                      "trigger_value": 3.0, "strength": 0.4}]}


def _expl(**kw):
    args = dict(model=MODEL, risk=RISK, mitre=MITRE, features_row={"hist_z_usb_connect_count": 4.2},
                unavailable_components={"asset_criticality": "CERT r4.2 has no asset inventory"})
    args.update(kw)
    return build_explanation("u1", "2011-01-03", **args)


def test_explanation_has_three_traced_sections():
    e = _expl()
    assert e["status"] == "complete" and e["headline"]["severity"] == "HIGH"
    assert [f["feature"] for f in e["model_factors"]] == ["file_event_count", "hist_z_usb_connect_count", "first_auth_hour"]
    assert all(f["source"]["kind"] == "model" and f["source"]["model_version"] == "gbdt-v" for f in e["model_factors"])
    assert e["model_factors"][2]["value_text"].startswith("no value")                # a null stays a null
    assert [f["feature"] for f in e["model_factors_lowering"]] == ["emails_sent"]
    assert {c["component"] for c in e["context_factors"]} == {"historical_deviation", "mitre_context"}
    assert all(c["source"]["kind"] == "cri" for c in e["context_factors"])
    assert [m["technique_id"] for m in e["attack_context"]["matches"]] == ["T1052.001", "T1567"]
    t = e["text"]
    assert t.startswith("HIGH RISK") and "Primary contributing factors" in t
    assert "not model reasons" in t and "not a reason the model scored this day" in t
    assert "Not available: asset criticality" in t
    assert not any(p in t.lower() for p in GENERIC_PHRASES)
    assert validate_explanation(e, model=MODEL, risk=RISK, mitre=MITRE) == []


def test_static_trait_is_suppressed_never_a_reason():
    e = _expl()
    assert "psych_openness" not in [f["feature"] for f in e["model_factors"]]
    assert e["suppressed"][0]["feature"] == "psych_openness" and "N22" in e["suppressed"][0]["reason"]


def test_indicated_match_is_worded_as_a_visit_and_unmapped_is_listed():
    e = _expl()
    leak = [m for m in e["attack_context"]["matches"] if m["evidence"] == "indicated"][0]
    assert "not what was sent or received" in leak["text"]
    assert "upload" not in leak["text"].lower() and "exfiltrated" not in leak["text"].lower()
    assert e["attack_context"]["unmapped_behaviours"][0]["behaviour"] == "job_search"
    assert "job_search: considered, no ATT&CK technique" in e["text"]


def test_shadow_and_mismatched_inputs_are_refused():
    with pytest.raises(ExplanationInputError, match="served"):
        _expl(model={**MODEL, "role": "shadow"})
    with pytest.raises(ExplanationInputError, match="one explanation, one score"):
        _expl(risk={**RISK, "model_version": "tabnet-v"})
    with pytest.raises(ExplanationInputError, match="disagree"):
        _expl(risk={**RISK, "anomaly_score": 0.5})


def test_tampering_is_caught_by_validation():
    e = _expl()
    bad = dict(e, model_factors=[dict(e["model_factors"][0], contribution=9.9)])
    assert any("differs from its attribution" in p for p in validate_explanation(bad, model=MODEL, risk=RISK, mitre=MITRE))
    bad = dict(e, context_factors=[dict(e["context_factors"][0], points=99.0)])
    assert any("points differ" in p for p in validate_explanation(bad, model=MODEL, risk=RISK, mitre=MITRE))
    bad = dict(e, text=e["text"] + "\nThe model predicted high risk.")
    assert any("generic" in p for p in validate_explanation(bad, model=MODEL, risk=RISK, mitre=MITRE))
    ghost = dict(MITRE, matches=[])
    assert any("not in the enrichment run" in p for p in validate_explanation(e, model=MODEL, risk=RISK, mitre=ghost))


def test_missing_model_part_is_deferred_not_invented():
    e = _expl(model=None, model_unavailable_reason="explainer not loaded")
    assert e["status"] == "model_explanation_deferred" and e["model_factors"] == []
    assert "Model explanation not available: explainer not loaded" in e["text"]
    assert e["headline"]["anomaly_score"] == 0.97                                    # the score and context stand
    e = _expl(risk=None, risk_unavailable_reason="no calibration")
    assert e["text"].startswith("RISK NOT CONTEXTUALISED") and e["unavailable"]["cri"] == "no calibration"


def test_mask_explanation_is_worded_as_attention():
    m = {**MODEL, "method": "tabnet_mask", "factors": [{"feature": "usb_connect_count", "contribution": 0.4,
                                                          "feature_value": 3.0}]}
    e = _expl(model=m)
    assert "attention" in e["model_factors"][0]["text"] and "raised" not in e["model_factors"][0]["text"]
    assert e["model_factors_lowering"] == []


def test_jsonable_turns_nan_into_null():
    assert jsonable({"a": np.float64("nan"), "b": [np.int64(3)]}) == {"a": None, "b": [3]}


# --- runtime and API (§36) --------------------------------------------------------------

def test_runtime_unavailable_without_a_served_model():
    rt = ExplainRuntime.load(None)
    assert not rt.available and rt.status()["status"] == "unavailable"
    with pytest.raises(ExplanationUnavailableError):
        rt.explainer()


def test_runtime_explains_one_event(registry, data):
    _, test = data
    cfg = ServingConfig(ModelPin("gbdt", registry["gbdt"].registry_version), (), registry["root"], "test")
    service = AnomalyScoringService.load(cfg)
    rt = ExplainRuntime.load(service)
    assert rt.available and rt.status()["method"] == "treeshap" and "N32" in rt.status()["shadow"]
    row = test.iloc[5]
    vec = {c: (None if pd.isna(row[c]) else float(row[c])) for c in service.input_columns}
    out = rt.explain_event(vec, user_id=row["user_id"], date=row["date"])
    assert out["status"] == "complete" and out["model"]["method"] == "treeshap"
    assert out["headline"]["anomaly_score"] == pytest.approx(service.score_event(vec).anomaly_score)
    assert out["headline"]["severity"] is None and "cri" in out["unavailable"]


def test_api_health_has_an_explainability_block(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.delenv("CIRA_SERVED_MODEL", raising=False)
    monkeypatch.setenv("CIRA_SERVING_DECISION", str(tmp_path / "missing.json"))
    with TestClient(app) as client:
        body = client.get("/health").json()
    assert body["explainability"]["status"] == "unavailable"
    assert "no anomaly model is served" in body["explainability"]["reason"]


# --- isolation (N5, N32) ---------------------------------------------------------------

def test_serving_modules_never_import_labels_or_the_readout():
    import app.explainability as pkg

    for name in SERVING:
        tree = ast.parse((Path(pkg.__file__).parent / f"{name}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mods = [((".") * node.level) + (node.module or "")]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            else:
                continue
            for m in mods:
                assert "ground_truth" not in m and "evaluation.labels" not in m and "evaluation.metrics" not in m, (name, m)
                assert not m.endswith("evaluate"), (name, m)
