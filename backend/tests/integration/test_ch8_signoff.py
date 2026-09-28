"""The Chapter 8 sign-off script, end to end, on a synthetic tree with the
real profile layout (mid and full), so the rule's own split keys are used.

Builds Chapters 5-7 the way the real repository has them (reference run
files, TabNet registry v0001-v0003), then runs scripts/signoff_chapter8.py
exactly as a person would: every step in its own process. The permutation
test is skipped here (it is covered by test_ch8_pipeline) and so is the
pytest step (this is inside pytest).
"""
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from app.baselines.run import _parse_args as ch6_args
from app.baselines.run import run as ch6_run
from app.feature_engineering.pipeline import run_pipeline
from app.ingestion.ground_truth import build_insider_label_tables
from app.tabnet.train import _parse_args as ch7_args
from app.tabnet.train import run as ch7_run
from fixtures import synthetic_ch6

REPO = Path(__file__).resolve().parents[3]
TIME = ["--time-validation-start", "2010-02-08", "--time-test-start", "2010-02-20"]
STATIC = "psych_,peer_department_size"


def _signoff():
    spec = importlib.util.spec_from_file_location("signoff_chapter8", REPO / "scripts" / "signoff_chapter8.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("signoff")
    paths = synthetic_ch6.build(root)
    processed, exp, models = root / "processed", root / "experiments", root / "models"
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(exp / "runlog.jsonl"))
    # The synthetic tree has 19 benign users; mid keeps every insider and 12 of them,
    # so mid is a strict subset of full, as on CERT (all 70 insiders + 180 benign).
    import app.feature_engineering.pipeline as pipeline

    mp.setitem(pipeline.PROFILE_CONFIG, "mid", {**pipeline.PROFILE_CONFIG["mid"], "benign": 12})
    try:
        for profile in ("mid", "full"):
            run_pipeline(paths["raw"], processed, profile=profile, ground_truth_dir=paths["gt"])
        build_insider_label_tables(paths["gt"], processed)
        ch6, ch7 = {}, {}
        for profile, split in (("mid", "user"), ("mid", "time"), ("full", "user")):
            common = ["--processed-dir", str(processed), "--profile", profile, "--splits-dir", str(exp / "splits"),
                      "--models-dir", str(models), "--checkpoint-dir", str(root / "ckpt")] + (["--split", "time", *TIME] if split == "time" else [])
            r6 = ch6_run(ch6_args(common + ["--results-dir", str(exp / "results" / "chapter6"), "--models", "rule_based,gbdt"]))
            r7 = ch7_run(ch7_args(common + ["--results-dir", str(exp / "results" / "chapter7"), "--max-epochs", "3", "--batch-size", "512",
                                            "--virtual-batch-size", "128", "--device", "cpu", "--exclude-features", STATIC]))
            ch6[f"{profile}/{split}"] = {m: r6["run_id"] for m in r6["models"]}
            ch7[f"{profile}/{split}"] = {"run_id": r7["run_id"], "registry_version": r7["registry"]["registry_version"],
                                         "model_version": r7["models"]["tabnet"]["metadata"]["model_version"]}
    finally:
        mp.undo()
    (exp / "chapter6_reference_runs.json").write_text(json.dumps({"runs": ch6}))
    (exp / "chapter7_reference_runs.json").write_text(json.dumps({"runs": ch7}))
    docs = root / "docs_root"
    for rel in ("README.md", "docs/CARRY_FORWARD.md", "docs/chapters/chapter_8_scoring.md"):
        (docs / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, docs / rel)
    args = ["--processed-dir", str(processed), "--models-dir", str(models), "--experiments-dir", str(exp),
            "--docs-root", str(docs), "--skip-tests", "--skip-permutation", "--quiet"]
    return {"root": root, "processed": processed, "exp": exp, "models": models, "docs": docs, "args": args}


@pytest.fixture(autouse=True)
def _env(world, monkeypatch):
    monkeypatch.setenv("CIRA_RUNLOG", str(world["exp"] / "runlog.jsonl"))
    monkeypatch.setenv("CIRA_SERVED_MODEL", "tabnet:v0001")        # must be ignored by the sign-off


@pytest.fixture(scope="module")
def first_run(world):
    mp = pytest.MonkeyPatch()
    mp.setenv("CIRA_RUNLOG", str(world["exp"] / "runlog.jsonl"))
    try:
        code = _signoff().main(world["args"])
    finally:
        mp.undo()
    state = json.loads((world["exp"] / "results" / "chapter8" / "signoff_state.json").read_text())
    return code, state


def test_signoff_goes_green(world, first_run):
    code, state = first_run
    assert code == 0 and state["green"] is True, json.dumps(state, indent=1)[:3000]
    exp = world["exp"]
    decision = json.loads((exp / "chapter8_serving_decision.json").read_text())
    assert decision["rule"]["version"] == "c8-serving-rule-v1" and "split_keys_overridden" not in decision["rule"]
    assert set(decision["evidence"]) == {"full/user", "mid/user", "mid/time"}
    assert (exp / "chapter8_test_readout.json").exists()
    ref = json.loads((exp / "chapter8_reference_runs.json").read_text())
    assert set(ref["gbdt_candidates"]) == {"mid/user", "mid/time", "full/user"}
    assert ref["decision"]["served"] == decision["outcome"]["served"]
    assert state["health"]["ok"] and state["health"]["source"] == "decision_file"
    assert state["final_verification"]["counts"]["FAIL"] == 0
    assert all(v["counts"]["FAIL"] == 0 for v in state["candidate_verification"].values())


def test_time_candidate_uses_the_chapter7_dates(world, first_run):
    run_id = first_run[1]["candidates"]["mid/time"]
    metrics = json.loads((world["exp"] / "results" / "chapter8" / run_id / "metrics.json").read_text())
    assert metrics["split"]["validation_start"] == "2010-02-08" and metrics["split"]["test_start"] == "2010-02-20"


def test_audit_draft_holds_only_run_outputs(world, first_run):
    audit = (world["docs"] / "docs" / "audits" / "chapter_8_audit.md").read_text()
    decision = json.loads((world["exp"] / "chapter8_serving_decision.json").read_text())
    served = decision["outcome"]["served"]
    assert f"{served['model_name']} {served['registry_version']}" in audit
    for k in ("mid/user", "mid/time", "full/user"):
        assert first_run[1]["candidates"][k] in audit
    n_warn = sum(len(v["warn"]) for v in first_run[1]["candidate_verification"].values()) + len(first_run[1]["final_verification"]["warn"])
    assert audit.count("TO EXPLAIN") == n_warn


def test_rerun_skips_finished_steps_and_stays_green(world, first_run, capsys):
    runlog = world["exp"] / "runlog.jsonl"
    stages = lambda: [json.loads(x)["stage"] for x in runlog.read_text().splitlines() if x.strip()]  # noqa: E731
    before = stages()
    assert _signoff().main(world["args"]) == 0
    after = stages()[len(before):]
    assert "chapter8_gbdt_candidate" not in after and "chapter8_serving_decision" not in after
    assert "chapter8_test_readout" not in after and "chapter8_batch_scoring" not in after
    assert after.count("chapter8_verification") == 1                                  # only the final check re-runs


def test_finalize_needs_every_warn_explained(world, first_run):
    audit = world["docs"] / "docs" / "audits" / "chapter_8_audit.md"
    audit.write_text(audit.read_text() + "\n- extra: `WARN x`  \n  TO EXPLAIN: why.\n")
    assert _signoff().main(world["args"] + ["--finalize"]) == 1
    text = "\n".join(line.replace("TO EXPLAIN: why this is acceptable.", "Acceptable: reviewed.").replace("TO EXPLAIN: why.", "Reviewed.")
                     for line in audit.read_text().splitlines())
    audit.write_text(text)
    assert _signoff().main(world["args"] + ["--finalize"]) == 0
    served = json.loads((world["exp"] / "chapter8_serving_decision.json").read_text())["outcome"]["served"]
    cf = (world["docs"] / "docs" / "CARRY_FORWARD.md").read_text()
    assert "| N27 Chapter 8 status (RETIRED) | - |" in cf and "RETIRED (chapter 8, runs verified" in cf
    readme = (world["docs"] / "README.md").read_text()
    assert f"IMPLEMENTED; serving {served['model_name']} {served['registry_version']}" in readme
    chap = (world["docs"] / "docs" / "chapters" / "chapter_8_scoring.md").read_text()
    assert "Status: IMPLEMENTED" in chap and "- [ ] " not in chap
    assert "generated by scripts/signoff_chapter8.py" not in audit.read_text()


def test_red_run_reports_and_stops(world, tmp_path):
    args = list(world["args"])
    args[args.index("--processed-dir") + 1] = str(tmp_path / "nowhere")
    assert _signoff().main(args) == 1
