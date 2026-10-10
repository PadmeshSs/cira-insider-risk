"""Chapter 16 building blocks on toy data."""
import json
from types import SimpleNamespace

import numpy as np
import pytest

from app.evaluation import report, seeds
from app.evaluation.bootstrap import cluster_bootstrap, paired_wilcoxon, seed_summary
from app.evaluation.operating import confusion, operating_point, risk_coverage


def test_operating_point_matches_hand_counts_and_masquerade_rows_are_out():
    y = np.array([1, 1, 0, 0, 0, 0, 1, 0])
    a = np.array([1, 0, 1, 0, 0, 0, 1, 1])
    excl = np.array([0, 0, 0, 0, 0, 0, 0, 1])
    op = operating_point(y, a, excl)
    assert (op["tp"], op["fp"], op["fn"], op["tn"]) == (2, 1, 1, 3)
    assert op["precision"] == pytest.approx(2 / 3) and op["recall"] == pytest.approx(2 / 3)
    assert op["f1"] == pytest.approx(2 / 3) and op["false_positive_rate"] == pytest.approx(1 / 4)
    assert "accuracy" not in op                                                           # N2
    assert confusion(y, a)["fp"] == 2                                                     # without the exclusion


def test_f1_is_zero_not_none_when_alerts_exist_and_none_are_right():
    op = operating_point([1, 0], [0, 1])
    assert op["f1"] == 0.0 and operating_point([0, 0], [0, 0])["f1"] is None


def test_risk_coverage_is_printed_with_its_review_load():
    rc = risk_coverage([1, 1, 0, 0], [1, 0, 1, 0])
    assert rc["coverage"] == 0.5 and rc["review_load"] == 0.5


def _toy(seed=0, users=40, days=60, insiders=6):
    rng = np.random.default_rng(seed)
    u = np.repeat([f"u{i}" for i in range(users)], days)
    y = np.zeros(users * days, bool)
    for i in range(insiders):
        y[i * days + 10:i * days + 14] = True
    return u, y, rng


def test_bootstrap_separates_a_good_ranking_from_a_weak_one_and_is_deterministic():
    u, y, rng = _toy()
    good, weak = rng.random(len(y)) + 2 * y, rng.random(len(y)) + 0.3 * y
    args = (u, y, np.zeros(len(y), bool), {"good": good, "weak": weak})
    kw = dict(pairs=[("good", "weak")], n_boot=120, seed=3)
    a, b = cluster_bootstrap(*args, **kw), cluster_bootstrap(*args, **kw)
    assert a == b
    pair = next(p for p in a["pairs"] if p["metric"] == "pr_auc")
    assert pair["lo"] > 0 and pair["interval_excludes_zero"] and pair["p_two_sided"] < 0.05
    ci = a["scores"]["weak"]["pr_auc"]
    assert ci["lo"] <= ci["point"] <= ci["hi"]


def test_bootstrap_resamples_users_not_rows():
    u, y, rng = _toy(users=10, insiders=3)
    s = rng.random(len(y))
    wide = cluster_bootstrap(u, y, np.zeros(len(y), bool), {"s": s}, n_boot=150, seed=1)["scores"]["s"]["pr_auc"]
    rows = np.random.default_rng(1)
    boots = []
    for _ in range(150):                                     # a (wrong) row bootstrap for comparison
        i = rows.integers(0, len(y), len(y))
        from sklearn.metrics import average_precision_score
        boots.append(average_precision_score(y[i], s[i]))
    narrow = np.quantile(boots, [0.975]) - np.quantile(boots, [0.025])
    assert (wide["hi"] - wide["lo"]) > narrow[0]


def test_masks_use_the_fixed_queue_and_masquerade_rows_carry_no_weight():
    u, y, _ = _toy(users=12, insiders=4)
    mask = y.copy()
    excl = np.zeros(len(y), bool)
    excl[:5] = True
    out = cluster_bootstrap(u, y, excl, {"s": y.astype(float)}, {"m": mask}, n_boot=60, seed=2)
    assert out["masks"]["m"]["recall"]["point"] == 1.0 and out["masks"]["m"]["precision"]["point"] == 1.0
    assert out["insiders"] == 4


def test_wilcoxon_says_when_it_cannot_reach_significance():
    five = paired_wilcoxon([.5, .6, .7, .8, .9], [.4, .5, .6, .7, .8])
    assert five["min_attainable_p_two_sided"] == pytest.approx(0.0625) and "cannot show significance" in five["note"]
    six = paired_wilcoxon([.5, .6, .7, .8, .9, 1.0], [.4, .5, .6, .7, .8, .9])
    assert six["p_two_sided"] < 0.05 and "note" not in six
    assert paired_wilcoxon([1, 1], [1, 1])["p_two_sided"] == 1.0


def test_seed_summary_ignores_missing():
    assert seed_summary([0.2, None, 0.4])["n"] == 2 and seed_summary([])["n"] == 0


def test_seed_plan_has_six_seeds_two_configs_two_models_and_distinct_cells():
    cells = seeds.plan()
    assert len(cells) == 6 * 2 * 2 and len({c.key for c in cells}) == len(cells)
    with pytest.raises(ValueError):
        seeds.plan(seeds=(42, 42))
    with pytest.raises(ValueError):
        seeds.plan(models=("lstm",))


def test_seed_commands_pass_the_split_seed_separately_and_never_register():
    for cell in seeds.plan(seeds=(43,)):
        argv = seeds.argv_for(cell, processed="/p", profile="full", split_seed=42)
        assert argv[argv.index("--seed") + 1] == "43" and argv[argv.index("--split-seed") + 1] == "42"
        assert "--no-register" in argv or seeds.runner_for(cell) == "baseline"
        if cell.model == "gbdt" and cell.config == "all_features":
            assert seeds.runner_for(cell) == "baseline" and "--no-save-models" in argv
        elif cell.config == "behaviour":
            assert argv[argv.index("--exclude-features") + 1] == "psych_,peer_department_size"


def test_split_seed_defaults_to_seed_in_all_three_runners():
    from app.baselines import run as b
    from app.scoring import gbdt_candidate as g
    from app.tabnet import train as t

    for mod in (b, g, t):
        assert mod.split_seed(SimpleNamespace(seed=42, split_seed=None)) == 42
        assert mod.split_seed(SimpleNamespace(seed=43, split_seed=42)) == 42
        assert mod.split_seed(SimpleNamespace(seed=7)) == 7


def test_reference_cells_come_from_the_recorded_reference_files(tmp_path):
    (tmp_path / "chapter7_reference_runs.json").write_text(json.dumps(
        {"runs": {"full/user": {"run_id": "R7", "registry_version": "v0005", "model_version": "t"}}}))
    (tmp_path / "chapter8_reference_runs.json").write_text(json.dumps(
        {"gbdt_candidates": {"full/user": {"run_id": "R8", "registry_version": "v0003", "model_version": "g"}}}))
    refs = seeds.reference_cells(tmp_path, "full", "user")
    assert refs["tabnet/behaviour/42"]["run_id"] == "R7" and refs["gbdt/behaviour/42"]["reference"] is True


def test_manifest_write_is_atomic_and_round_trips(tmp_path):
    m = seeds.new_manifest("full", "user", (42, 43), 42)
    path = tmp_path / "m.json"
    seeds.write_manifest(path, m)
    assert seeds.read_manifest(path) == m and not list(tmp_path.glob("*.tmp"))


def test_the_report_builder_has_no_input_but_the_readout():
    import inspect
    assert list(inspect.signature(report.render).parameters) == ["r", "readout_sha256"]


def test_a_chapter16_module_never_uses_the_wall_clock_for_run_ids():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "app" / "evaluation"
    for f in ("ablation.py", "seeds.py"):
        assert "datetime.now" not in (root / f).read_text().replace("datetime.now(timezone.utc).isoformat", "")   # N74
