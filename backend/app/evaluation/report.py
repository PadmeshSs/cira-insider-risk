"""Render the Chapter 16 evaluation report from the pinned readout, and from nothing else.

"No number in the final report lacks a corresponding logged experiment" (Bible Chapter 16) is enforced by
construction: ``render`` takes the readout dict and the readout's sha256, formats values from it, and has no
other input. ``scripts/verify_chapter16.py`` regenerates the report and requires it to equal the committed
file byte for byte, so a hand-edited number is a FAIL.

Wording rules carried from the notes: scores are ranking scores, never probabilities (N20); the headline is
mostly scenario 2 (N15); a synthetic readout is labelled and never a result (N72).

Usage, from backend/:

    python -m app.evaluation.report                      # experiments/chapter16_test_readout.json -> experiments/chapter16_evaluation_report.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from app.feature_engineering.common import repo_root

REPORT_FILE = "chapter16_evaluation_report.md"


def sha256_of(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _f(v, nd=3) -> str:
    return "-" if v is None else (f"{v:.{nd}f}" if isinstance(v, (int, float)) else str(v))


def _ci(ci: dict | None) -> str:
    return "-" if not ci or ci.get("lo") is None else f"{_f(ci['lo'])} to {_f(ci['hi'])}"


def _scen(d: dict | None) -> str:
    return ", ".join(f"s{k} {v}" for k, v in (d or {}).items()) or "-"


def _table(head: list[str], rows: list[list]) -> list[str]:
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return out + [""]


def render(r: dict, *, readout_sha256: str) -> str:
    L: list[str] = []
    p = r["population"]
    lin = r["lineage"]
    L += [f"# Chapter 16 evaluation report ({r['part']}, profile {r['profile']})", "",
          f"Generated from `experiments/chapter16_test_readout.json` (sha256 `{readout_sha256}`), run `{r['run_id']}`, "
          f"written {r['written_at']}. Every number below is read from that file; none is typed in.", ""]
    if not r.get("reportable") or r["part"] != "test":
        L += ["> This readout is not reportable (profile or part). Do not quote it as a result (N6, N72).", ""]
    L += ["Population: " + f"{p['rows']} user-days of {p['users']} users, {p['positives']} malicious user-days "
          f"(chance PR-AUC {_f(p['chance_pr_auc'], 4)}), scenario days {_scen(p['scenario_days'])}. "
          "Scores are ranking scores, not probabilities of malice (N20). The headline is mostly scenario 2 (N15).", "",
          f"Lineage: risk run `{lin['risk_run_id']}`, alert run `{lin['alert_run_id']}` (policy `{lin['alert_policy_hash']}`), "
          f"explain run `{lin.get('explain_run_id')}`, calibration `{lin.get('calibration_id')}`, CRI config `{lin.get('cri_config_hash')}`, "
          f"MITRE run `{lin.get('mitre_run_id')}`.", ""]

    L += ["## Comparison chain", "",
          f"Best baseline, chosen on validation before test was read: `{r['baseline_choice']['best']}`.", ""]
    L += _table(["Stage", "Ranking", "PR-AUC", "95% interval", "Recall@1", "Insiders caught@1"],
                [[c["stage"], f"`{c['ranking']}`", _f(c["pr_auc"]), _ci(c["pr_auc_ci"]), _f(c["recall_at_1"]),
                  c["insiders_caught_at_1"]] for c in r["chain"]])

    L += ["## All rankings", ""]
    rows = []
    for n, x in r["rankings"].items():
        s = x["summary"]
        o1 = x["operating_by_budget"]["1"]
        rows.append([f"`{n}`" + (" (validation-informed)" if x.get("validation_informed") else ""), _f(s["pr_auc"]),
                     _ci(r["bootstrap"]["scores"][n]["pr_auc"]), _f(s["roc_auc_secondary"]), _f(o1["precision"]),
                     _f(o1["recall"]), _f(o1["f1"]), _f(o1["false_positive_rate"], 5),
                     _f(o1["coverage"]["coverage"]), _f(o1["coverage"]["review_load"], 5), s["insiders_caught_at_1"],
                     s["insiders_caught_at_5"], _scen(s["days_by_scenario_at_1"])])
    L += _table(["Ranking", "PR-AUC", "95% interval", "ROC-AUC (secondary)", "P@1", "R@1", "F1@1", "FPR@1",
                 "Risk coverage@1", "Review load@1", "Caught@1", "Caught@5", "Days@1 by scenario"], rows)
    L += ["Risk coverage is defined in `app/evaluation/operating.py` (deviation C16-3) and printed with the review load.", ""]

    L += ["## Paired comparisons (user-clustered bootstrap)", "",
          f"{r['bootstrap']['n_boot']} replicates, seed {r['bootstrap']['seed']}; {r['bootstrap']['method']}.", ""]
    L += _table(["A", "B", "Metric", "A - B", "95% interval", "p (approx.)"],
                [[f"`{q['a']}`", f"`{q['b']}`", q["metric"], _f(q["point_difference"]),
                  "-" if q["lo"] is None else f"{_f(q['lo'])} to {_f(q['hi'])}", _f(q["p_two_sided"], 4)]
                 for q in r["bootstrap"]["pairs"] if q["metric"] in ("pr_auc", "recall", "insiders_caught_share")])

    ab = r["experiments"]["A_B_E3_seeds"]
    L += ["## Experiments A and B: training seeds", ""]
    if ab.get("available"):
        L += _table(["Model / configuration", "Seeds", "Min", "Median", "Max", "Mean", "Std"],
                    [[k, v.get("n"), _f(v.get("min")), _f(v.get("median")), _f(v.get("max")), _f(v.get("mean")), _f(v.get("std"))]
                     for k, v in ab["seed_summary_pr_auc"].items()])
        L += _table(["Paired test", "Pairs", "Mean difference", "Wins / losses / ties", "p (Wilcoxon)", "Smallest attainable p"],
                    [[k, t["n_pairs"], _f(t["mean_difference"]), f"{t['wins']}/{t['losses']}/{t['ties']}",
                      _f(t.get("p_two_sided"), 4), _f(t["min_attainable_p_two_sided"], 4)]
                     for k, t in ab["paired_tests"].items()])
        for k, t in ab["paired_tests"].items():
            if t.get("note"):
                L.append(f"- {k}: {t['note']}")
        L += ["", f"Experiment E3 (cost of the interpretability constraint, all features minus behaviour-only, mean PR-AUC over seeds): "
              f"TabNet {_f(ab['E3_interpretability_cost']['tabnet'])}, XGBoost {_f(ab['E3_interpretability_cost']['xgboost'])}.", ""]
    else:
        L += [f"Not computed: {ab.get('reason')}", ""]

    L += ["## Experiment C: the CRI and its leave-one-out variants", ""]
    rows = []
    for n in r["experiments"]["C"]["rankings"]:
        x = r["rankings"][n]
        b = x.get("bands", {}).get("HIGH_or_above")
        rows.append([f"`{n}`", _f(x["summary"]["pr_auc"]), x["summary"]["insiders_caught_at_1"],
                     "-" if not b else f"{b['alerts']} alerts, precision {_f(b['precision'])}, recall {_f(b['recall'])}, "
                     f"caught {b['per_user']['caught']}/{b['per_user']['insiders']}"])
    L += _table(["Ranking", "PR-AUC", "Caught@1", "Band HIGH or above"], rows)

    D = r["experiments"]["D"]
    L += ["## Experiment D: MITRE context", "", D["disclosure"] + ".", "",
          f"Share of benign test user-days carrying a mapped technique: {_f(D['benign_and_rules']['benign_mapped_share'])} "
          f"of {D['benign_and_rules']['benign_user_days']}.", ""]
    L += _table(["Scenario", "Cell", "Days", "Mapped", "CRI default @1", "CRI without MITRE @1"],
                [[s, c, v["days"], v["mitre_mapped"], v["cri_default_at_1"], v["cri_no_mitre_at_1"]]
                 for s, cells in D["served_shadow_disagreement_at_top1"].items() for c, v in cells.items()])

    E1 = r["experiments"]["E1_alert_queue"]
    L += ["## Experiment E1: the alert queue", "", E1["population"]["note"] + ".", ""]
    rows = []
    for n, v in E1["views"].items():
        if n == "activity_rule":
            continue
        rows.append([n, v.get("ordering"), v["open_alerts"], v["suppressed_alerts"], _f(v["alert_precision"]),
                     _scen({k: f"{x['caught']}/{x['insiders']}" for k, x in v["insiders_caught_by_scenario"].items()}),
                     _scen({k: f"{x['in_open_alert']} open, {x['only_in_suppressed_alert']} suppressed only, {x['in_no_alert']} none "
                            f"of {x['malicious_days']}" for k, x in v["coverage_by_scenario"].items()})])
    L += _table(["View", "Ordering", "Open", "Suppressed", "Alert precision", "Insiders caught", "Malicious days"], rows)
    a = E1["views"]["activity_rule"]
    L += [f"Activity rule: {a['dates_with_a_changed_slot']} of {a['dates_in_part']} dates had a changed top-{a['top_k_per_day']} "
          f"slot ({a['user_days_whose_slot_changed']} user-days, {a['of_which_malicious']} malicious). "
          f"Open alerts never above LOW on the CRI: {E1['open_alerts_never_above_low']['count']} of "
          f"{E1['open_alerts_never_above_low']['of_open_alerts']}.", ""]

    E2 = r["experiments"]["E2_explanations"]
    L += ["## Experiment E2: explanations", ""]
    if E2.get("malicious_days_by_scenario"):
        L += _table(["Scenario", "Days", "Top factors", "Calendar-led share"],
                    [[s, b["days"], ", ".join(f"{k} {v}" for k, v in list(b["top_factor_counts"].items())[:4]),
                      _f(b["top_factor_is_calendar_share"])] for s, b in E2["malicious_days_by_scenario"].items()])
        fa = E2["false_alarms_at_top1"]
        L += [f"False alarms at top-1: {fa['days']} days; leading factors {', '.join(f'{k} {v}' for k, v in list(fa['top_factor_counts'].items())[:4])}. "
              f"Integrity: {E2['integrity']['rows']} rows, max additivity error {_f(E2['integrity']['max_additivity_error'], 6)}, "
              f"{E2['integrity']['rows_with_static_trait_in_top5']} with a static trait in the top five.", ""]
        sv = E2["second_model_view"]
        if sv.get("available"):
            L += [sv["label"] + ".", ""]
            L += _table(["Scenario", "Days", "Mean top-5 Jaccard with TreeSHAP", "Top mask factors"],
                        [[s, b.get("days"), _f(b.get("mean_top5_jaccard_with_treeshap")),
                          ", ".join(f"{k} {v}" for k, v in list((b.get("mask_top_factor_counts") or {}).items())[:3])]
                         for s, b in sv["by_scenario"].items()])
    else:
        L += [f"Not computed: {E2.get('reason')}", ""]

    if r.get("secondary_splits"):
        L += ["## Other splits (Chapter 7 harness)", ""]
        for k, v in r["secondary_splits"].items():
            if v.get("available") is False:
                L += [f"- {k}: not computed ({v['reason']})"]
                continue
            L += [f"### {k}", ""]
            L += _table(["Model", "PR-AUC", "Caught@1"] + (["PR-AUC on new insiders"] if "time_split" in v else []),
                        [[m, _f(e["metrics"]["primary"]["pr_auc"]),
                          f"{e['metrics']['primary']['budgets']['1']['per_user']['caught']}/"
                          f"{e['metrics']['primary']['budgets']['1']['per_user']['insiders']}"]
                         + ([_f(e.get("pr_auc_new_insiders_only"))] if "time_split" in v else [])
                         for m, e in v["models"].items()])

    L += ["## Harness checks", ""]
    L += _table(["Check", "Result", "Detail"], [[h["check"], "PASS" if h["ok"] else ("n/a" if h["ok"] is None else "FAIL"),
                                                 h["detail"]] for h in r["harness"]])
    L += [f"## Guard {r['guard']['version']}", ""]
    L += [f"- WARN: {w}" for w in r["guard"]["warnings"]] or ["No warning."]
    L += ["", "## Deviations", ""] + [f"- {k}: {v}" for k, v in r["deviations"].items()]
    L += ["", "## Disclosures", ""] + [f"- {d}" for d in r["disclosures"]]
    L += ["", "## Caveats", ""] + [f"- {c}" for c in r["caveats"]]
    return "\n".join(L).rstrip() + "\n"


def main(argv=None) -> int:
    root = repo_root()
    ap = argparse.ArgumentParser(description="Render the Chapter 16 report from the pinned readout")
    ap.add_argument("--readout", default=str(root / "experiments" / "chapter16_test_readout.json"))
    ap.add_argument("--out", default=str(root / "experiments" / REPORT_FILE))
    a = ap.parse_args(argv)
    path = Path(a.readout)
    if not path.exists():
        print(f"no readout at {path}; run `python -m app.evaluation.ablation --part test` first", file=sys.stderr)
        return 2
    text = render(json.loads(path.read_text(encoding="utf-8")), readout_sha256=sha256_of(path))
    Path(a.out).write_text(text, encoding="utf-8")
    print(f"written: {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
