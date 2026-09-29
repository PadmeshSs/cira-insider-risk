"""Chapter 10 end to end on a synthetic CERT tree:

Chapter 5 features + LDAP -> labels -> shared split file -> a Chapter 8-shaped
batch (served + shadow) -> Chapter 9 calibration -> MITRE reference -> MITRE
enrichment run -> CRI with MITRE -> validation readout (with the served /
shadow disagreement view) -> both verifiers -> API health.

Leak-site and keylogger-site visits are planted in the raw HTTP log before
the Chapter 5 pipeline runs, on insiders and on one benign user, so every
rule has something to fire on and a benign user carries a mapped technique
too. Scores are built from labels only because this is a test fixture; no
Chapter 10 serving module reads a label.
"""
import importlib.util
import json
import os
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.cri import batch as cri_batch
from app.cri import calibrate as cri_calibrate
from app.evaluation.labels import attach_labels, load_label_views
from app.evaluation.splitting import SPLIT_VERSION
from app.feature_engineering.common import atomic_to_parquet
from app.feature_engineering.pipeline import run_pipeline
from app.ingestion.ground_truth import build_insider_label_tables
from app.mitre import batch as mitre_batch
from app.mitre import calibrate as mitre_calibrate
from app.mitre import evaluate as mitre_evaluate
from app.mitre.sources import CONTEXT_OUTPUT, MATCHES_OUTPUT
from app.scoring.batch import BATCH_COLUMNS
from app.tabnet.dataset import feature_fingerprint
from fixtures import synthetic_ch6

REPO = Path(__file__).resolve().parents[3]
SERVED = {"model_name": "gbdt", "registry_version": "v0003", "model_version": "gbdt-chapter8-v1-synthetic0001",
          "run_id": "synthetic-full-user", "profile": "full"}
BATCH_ID = "20260929T000000Z-full-batch"


def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))


def _plant_http(raw: Path, users: list[str]) -> None:
    """Leak-site visits for two scenario-1 insiders and one benign user; a keylogger site for a scenario-3 insider."""
    http = pd.read_csv(raw / "http.csv", dtype=str, keep_default_na=False)
    plan = [(users[0], "wikileaks.org"), (users[5], "wikileaks.org"), (users[20], "pastebin.com"),
            (users[10], "keylogger.org")]
    days = [d for d in pd.date_range("2010-02-01", "2010-02-26", freq="D") if d.dayofweek < 5]
    rows = []
    for i, (u, host) in enumerate(plan):
        for k, d in enumerate(days[i::6][:3]):
            rows.append((f"{{P{i:03d}{k:03d}}}", f"{d:%m/%d/%Y} 22:{10 + k:02d}:00", u, "PC-0001", f"http://{host}/x{k}.html", "w"))
    add = pd.DataFrame(rows, columns=["id", "date", "user", "pc", "url", "content"])
    both = pd.concat([http, add], ignore_index=True)
    order = pd.to_datetime(both["date"], format="%m/%d/%Y %H:%M:%S").argsort(kind="stable")
    both.iloc[order].to_csv(raw / "http.csv", index=False)


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("ch10")
    paths = synthetic_ch6.build(root)
    _plant_http(paths["raw"], paths["users"])
    processed = root / "processed"
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(root / "runlog.jsonl"))
    try:
        run_pipeline(paths["raw"], processed, profile="full", ground_truth_dir=paths["gt"])
        build_insider_label_tables(paths["gt"], processed)
    finally:
        mp.undo()

    users = [u.casefold() for u in paths["users"]]
    split = {u: "train" for u in users}
    for i in (0, 5, 10, *range(13, 19), 20):
        split[users[i]] = "validation"
    for i in (1, 6, 11, *range(21, 27)):
        split[users[i]] = "test"
    splits = root / "experiments" / "splits"
    splits.mkdir(parents=True)
    (splits / "user_split_full_seed42.json").write_text(json.dumps(
        {"version": SPLIT_VERSION, "profile": "full", "seed": 42, "assignment": split}), encoding="utf-8")

    features = processed / "features" / "user_day_full.parquet"
    m = pd.read_parquet(features, columns=["user_id", "date"])
    keys = pd.DataFrame({"user_id": m["user_id"].astype("string").str.casefold(), "date": m["date"].astype("string")})
    y = attach_labels(keys, load_label_views(processed))["y_primary"].to_numpy()
    rng = np.random.default_rng(10)
    served = _sigmoid(-9 + 8 * y + 1.5 * rng.normal(size=len(keys)))
    shadow = _sigmoid(-1 + 2 * y + rng.normal(size=len(keys)))
    tags = keys["user_id"].map(split).to_numpy(dtype=object)
    parts = []
    for role, s, pin in (("served", served, SERVED), ("shadow", shadow, {"model_name": "tabnet", "registry_version": "v0005",
                                                                            "model_version": "tabnet-chapter7-v1-synthetic"})):
        parts.append(pd.DataFrame({"user_id": keys["user_id"], "date": keys["date"], "model_split": tags, "role": role,
                                   "model_name": pin["model_name"], "model_version": pin["model_version"],
                                   "registry_version": pin["registry_version"], "raw_score": np.log(s / (1 - s)),
                                   "anomaly_score": s, "batch_run_id": BATCH_ID}))
    out = processed / "scores" / "chapter8" / BATCH_ID
    atomic_to_parquet(pd.concat(parts, ignore_index=True)[list(BATCH_COLUMNS)], out / "anomaly_scores.parquet")
    (out / "batch_meta.json").write_text(json.dumps({
        "chapter": 8, "batch_run_id": BATCH_ID, "profile": "full", "served": SERVED, "decision_sha256": None,
        "features": {"path": str(features), "fingerprint": feature_fingerprint(features)}}))
    exp = root / "experiments"
    return {"root": root, "processed": processed, "users": users, "split": split, "features": features, "splits": splits,
            "models": root / "models", "cri_pin": exp / "chapter9_cri_calibration.json",
            "mitre_pin": exp / "chapter10_mitre_reference.json", "readout": exp / "chapter10_validation_readout.json",
            "results": root / "r10"}


@pytest.fixture(autouse=True)
def _env(world, monkeypatch):
    monkeypatch.setenv("CIRA_RUNLOG", str(world["root"] / "runlog.jsonl"))
    monkeypatch.setenv("CIRA_SERVED_MODEL", "gbdt:v0003")
    monkeypatch.setenv("MODEL_PATH", str(world["models"]))
    monkeypatch.setenv("CIRA_CRI_CALIBRATION", str(world["cri_pin"]))
    monkeypatch.setenv("CIRA_MITRE_REFERENCE", str(world["mitre_pin"]))
    for k in [k for k in os.environ if k.startswith(("CRI_", "MITRE_"))]:
        monkeypatch.delenv(k)


def _mitre_cal_args(world, *extra):
    return ["--processed-dir", str(world["processed"]), "--profile", "full", "--splits-dir", str(world["splits"]),
            "--models-dir", str(world["models"]), "--pin-path", str(world["mitre_pin"]), "--min-reference-rows", "50", *extra]


def _mitre_run_args(world, *extra):
    return ["--processed-dir", str(world["processed"]), "--profile", "full", "--models-dir", str(world["models"]),
            "--pin-path", str(world["mitre_pin"]), *extra]


def _cri_args(world, *extra):
    return ["--processed-dir", str(world["processed"]), "--profile", "full", "--models-dir", str(world["models"]),
            "--pin-path", str(world["cri_pin"]), *extra]


def _load_script(name):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def chain(world):
    """Chapter 9 calibration, MITRE reference, enrichment run, CRI with and without MITRE."""
    mp = pytest.MonkeyPatch()
    for k, v in (("CIRA_RUNLOG", str(world["root"] / "runlog.jsonl")), ("CIRA_SERVED_MODEL", "gbdt:v0003"),
                 ("MODEL_PATH", str(world["models"])), ("CIRA_CRI_CALIBRATION", str(world["cri_pin"])),
                 ("CIRA_MITRE_REFERENCE", str(world["mitre_pin"]))):
        mp.setenv(k, v)
    try:
        assert cri_calibrate.main(_cri_args(world, "--min-reference-rows", "50")) == 0
        ref = mitre_calibrate.run(mitre_calibrate._parse_args(_mitre_cal_args(world)))
        run = mitre_batch.run(mitre_batch._parse_args(_mitre_run_args(world)))
        plain = cri_batch.run(cri_batch._parse_args(_cri_args(world)))
        with_mitre = cri_batch.run(cri_batch._parse_args(_cri_args(world, "--mitre-run-id", run["mitre_run_id"])))
    finally:
        mp.undo()
    return {"ref": ref, "run": run, "plain": plain, "with_mitre": with_mitre}


def test_reference_is_model_free_and_validation_only(world, chain):
    meta = chain["ref"]["meta"]
    assert meta["reference"]["part"] == "validation" and meta["attack_version"] == "19.2"
    ref_dir = world["models"] / "mitre" / meta["reference_id"]
    frame = pd.read_parquet(ref_dir / "reference.parquet")
    assert set(frame["user_id"].map(world["split"])) == {"validation"}
    assert not [c for c in frame.columns if any(w in c for w in ("score", "model", "label", "malicious", "scenario"))]
    rules = meta["report"]["rules"]
    assert rules["R03_cloud_storage_access"]["fires_on_share_of_reference"] > 0.2        # dropbox is everyday here
    assert rules["R02_leak_site_access"]["strength_of_one_event"] > rules["R03_cloud_storage_access"]["strength_of_one_event"]
    assert mitre_calibrate.main(_mitre_cal_args(world)) == 2                              # a pin is never replaced silently


def test_enrichment_run(world, chain):
    run = chain["run"]
    d = Path(run["outputs"]["context"]).parent
    ctx, matches = pd.read_parquet(d / CONTEXT_OUTPUT), pd.read_parquet(d / MATCHES_OUTPUT)
    m = pd.read_parquet(world["features"], columns=["user_id"])
    assert len(ctx) == len(m) and run["model_free"] is True
    assert set(ctx["mitre_status"]) <= {"mapped", "unmapped", "not_evaluated"}
    assert set(matches["rule_id"]) == {"R01_removable_media_copy", "R02_leak_site_access", "R03_cloud_storage_access",
                                       "R04_attack_tool_site_access"}
    benign = world["users"][20]
    leak = matches[matches["rule_id"] == "R02_leak_site_access"]
    assert benign in set(leak["user_id"])                                    # a benign user maps too: this is context, not a verdict
    assert (ctx.loc[ctx["mitre_status"] == "unmapped", "mitre_context"] == 0).all()
    assert ctx["mitre_unmapped_behaviours"].notna().any()
    lines = [json.loads(x) for x in (world["root"] / "runlog.jsonl").read_text().splitlines()]
    assert any(x.get("stage") == "chapter10_mitre_batch" and x["mitre_run_id"] == run["mitre_run_id"] for x in lines)


def test_cri_with_and_without_mitre(world, chain):
    plain, wm = chain["plain"], chain["with_mitre"]
    assert "mitre_context" in plain["unavailable_components"] and plain["mitre"] is None
    assert "mitre_context" not in wm["unavailable_components"] and wm["mitre"]["mitre_run_id"] == chain["run"]["mitre_run_id"]
    assert wm["effective_weights"]["anomaly"] == pytest.approx(0.60) and plain["effective_weights"]["anomaly"] == pytest.approx(0.60 / 0.90)
    assert wm["formula_hash"] != plain["formula_hash"] and wm["config_hash"] == plain["config_hash"]
    assert wm["cri_run_id"].endswith("-mitre")
    a, b = pd.read_parquet(plain["output"]), pd.read_parquet(wm["output"])
    np.testing.assert_array_equal(a["anomaly_score"].to_numpy(), b["anomaly_score"].to_numpy())   # §14: untouched
    assert (b["points_mitre_context"] >= 0).all() and (b["points_mitre_context"] > 0).any()


def test_a_rollback_does_not_touch_mitre(world, chain, monkeypatch):
    """N42: the enrichment is model-free, so serving TabNet changes nothing in it."""
    monkeypatch.setenv("CIRA_SERVED_MODEL", "tabnet:v0005")
    from app.mitre.runtime import MitreRuntime

    rt = MitreRuntime.load(pin_path=world["mitre_pin"], models_root=world["models"])
    assert rt.available and rt.status()["reference"]["reference_id"] == chain["ref"]["meta"]["reference_id"]
    assert cri_batch.main(_cri_args(world, "--with-mitre")) == 2              # the CRI still refuses (N29)


def test_mitre_batch_refuses_a_different_matrix(world, chain, capsys):
    st = world["features"].stat()
    os.utime(world["features"], (st.st_atime, st.st_mtime + 5))
    try:
        assert mitre_batch.main(_mitre_run_args(world)) == 2
        assert "fingerprint" in capsys.readouterr().err
    finally:
        os.utime(world["features"], (st.st_atime, st.st_mtime))


@pytest.fixture(scope="module")
def readout(world, chain):
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(world["root"] / "runlog.jsonl"))
    try:
        args = ["--processed-dir", str(world["processed"]), "--profile", "full", "--cri-run-id",
                chain["with_mitre"]["cri_run_id"], "--decision-path", str(world["root"] / "none.json"),
                "--chapter9-readout", str(world["root"] / "none9.json"), "--readout-path", str(world["readout"]),
                "--results-dir", str(world["results"])]
        return mitre_evaluate.run(mitre_evaluate._parse_args(args)), args
    finally:
        mp.undo()


def test_readout_and_disagreement_view(world, chain, readout):
    r, _ = readout
    assert r["part"] == "validation" and r["positives"] > 0 and r["mitre"]["mitre_run_id"] == chain["run"]["mitre_run_id"]
    assert set(r["models"]) == {"anomaly_score", "cri:anomaly_only", "cri:no_mitre_context", "cri:default", "mitre_context"}
    assert r["models"]["cri:anomaly_only"]["pr_auc"] == pytest.approx(r["models"]["anomaly_score"]["pr_auc"], abs=1e-12)
    h = {x["check"]: x["ok"] for x in r["harness"]}
    assert h["recombining stored components reproduces the stored cri_score"] is True
    assert h["cri:no_mitre_context equals the Chapter 9 readout's cri:default"] is None     # no Chapter 9 readout here
    v = r["disagreement_view"]
    assert v["shadow_model"] == "tabnet:v0005" and v["budget"] == "daily top-1"
    for cells in v["by_scenario"].values():
        assert set(cells) == {"both", "served_only", "shadow_only", "neither"}
        assert all(c["mitre_mapped"] <= c["days"] for c in cells.values())
    total = sum(c["days"] for cells in v["by_scenario"].values() for c in cells.values())
    assert total == r["positives"]
    assert 0 < r["rule_rates"]["benign_mapped_share"] < 1 and r["guard"]["version"] == "c10-mitre-guard-v1"
    assert "N41" in r["disclosure"]


def test_readout_rules(world, readout, capsys):
    _, args = readout
    assert mitre_evaluate.main([*args, "--part", "test"]) == 2
    assert "ablation D" in capsys.readouterr().err
    assert mitre_evaluate.main(args) == 2                                     # written once
    assert "--supersede" in capsys.readouterr().err


def test_verifiers_pass(world, chain, readout):
    v10 = _load_script("verify_chapter10")
    code = v10.main(["--processed-dir", str(world["processed"]), "--profile", "full", "--mitre-run-id",
                     chain["run"]["mitre_run_id"], "--cri-run-id", chain["with_mitre"]["cri_run_id"],
                     "--pin-path", str(world["mitre_pin"]), "--models-dir", str(world["models"]),
                     "--readout-path", str(world["readout"]), "--results-dir", str(world["results"])])
    assert code == 0
    report = json.loads(sorted(world["results"].glob("verification_*.json"))[-1].read_text())
    assert report["counts"]["FAIL"] == 0
    assert all(x["section"] in ("readout", "run") for x in report["checks"] if x["status"] == "WARN")

    v9 = _load_script("verify_chapter9")                                      # the Chapter 9 verifier accepts a MITRE run
    code = v9.main(["--processed-dir", str(world["processed"]), "--profile", "full", "--cri-run-id",
                    chain["with_mitre"]["cri_run_id"], "--pin-path", str(world["cri_pin"]), "--models-dir",
                    str(world["models"]), "--results-dir", str(world["root"] / "r9"), "--no-readout"])
    assert code == 0


def test_health_reports_mitre_loaded_without_a_served_model(world, chain):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        body = client.get("/health").json()
    assert body["anomaly_model"]["status"] == "unavailable"          # no registry artifact in the synthetic world
    assert body["mitre"]["status"] == "loaded" and body["mitre"]["table"]["attack_version"] == "19.2"
    assert body["mitre"]["reference"]["reference_id"] == chain["ref"]["meta"]["reference_id"]
