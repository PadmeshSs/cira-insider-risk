"""Choose the served model on validation, record why (Chapter 8, N26, N28).

The rule below was written before any behaviour-only XGBoost number existed
(docs/chapters/chapter_8_scoring.md, "The serving rule"). It is applied
mechanically; this module has no option that changes it, and the rule is
copied into the decision file so the verifier can tell if it was edited.

Rule c8-serving-rule-v1
    Candidates: the adopted TabNet (experiments/chapter7_reference_runs.json)
    and the behaviour-only XGBoost (app.scoring.gbdt_candidate), one run of
    each per profile/split, scored on identical validation rows.

    Gates, for the full-profile artifact that would be served. A candidate
    that fails one cannot be served:
        registered and sha256-verified (N21); reportable (N6); trained on
        the full profile; no static per-user trait among its inputs (N25).

    Criterion: validation PR-AUC, primary view (N1, N2).
        d = PR-AUC(XGBoost) - PR-AUC(TabNet) on full / user validation.
        Serve XGBoost only if d > 0.10 and XGBoost is also ahead on mid /
        user and mid / time validation. Otherwise serve TabNet.

    Why TabNet is the default: the Bible names it the primary model, and
    Chapter 11 is planned around its masks. The burden of proof sits with
    the deviation. Why 0.10: it is the epoch-to-epoch swing of TabNet's
    validation PR-AUC measured in Chapter 7, the same threshold the
    static-trait ablation used; a smaller gap cannot be told apart from
    TabNet's selection noise. Validation favours TabNet if anything, because
    its early stopping keeps a noisy peak (N26), so an XGBoost win under
    this rule is not an artefact of that optimism.

    The candidate not served becomes the shadow model (N32).

Test is not read to decide. ``--report-test`` reads it once, afterwards, for
the write-up, and refuses to run before a decision exists or a second time.

Offline module: reads labels in memory through app.evaluation.compare.

Usage, from backend/:

    python -m app.scoring.select --gbdt full/user=<run id> --gbdt mid/user=<run id> --gbdt mid/time=<run id>
    python -m app.scoring.select --report-test
"""
from __future__ import annotations

from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

from app.evaluation.compare import (  # noqa: E402
    ComparisonError,
    ScoreSource,
    compare_sources,
    harness_check,
    load_reference_runs,
    print_table,
    reference_runs_for,
    _runlog_lines,
)
from app.feature_engineering.common import append_experiment_runlog, repo_root  # noqa: E402
from app.tabnet.model_registry import ModelRegistry, RegistryError  # noqa: E402

from .contracts import static_inputs  # noqa: E402
from .serving_config import DECISION_FILE  # noqa: E402

RULE = {
    "version": "c8-serving-rule-v1",
    "criterion": "validation PR-AUC, primary view",
    "decisive": "full/user",
    "consistency": ["mid/user", "mid/time"],
    "margin": 0.10,
    "default": "tabnet",
    "served_profile": "full",
    "text": ("Serve XGBoost only if its validation PR-AUC exceeds TabNet's by more than 0.10 on full/user "
             "and it is also ahead on mid/user and mid/time; otherwise serve TabNet. A candidate that fails a "
             "gate (registered + sha256, reportable, full profile, behaviour-only) cannot be served."),
}
CANDIDATES = ("tabnet", "gbdt")
TEST_READOUT_FILE = "chapter8_test_readout.json"
CH6_REFERENCE_LABEL = "gbdt_ch6_all_feat"   # the Chapter 6 reference, all features (N18)


class DecisionError(RuntimeError):
    """No servable model, or the evidence is incomplete."""


# ---------------------------------------------------------------------------
# The rule, as a pure function
# ---------------------------------------------------------------------------

def decide(pr_auc: dict[str, dict[str, float | None]], gates: dict[str, bool], *, rule: dict = RULE) -> dict:
    """Apply the serving rule to validation PR-AUCs and gate results.

    ``pr_auc[split_key][model]`` for split keys like "full/user".
    Returns {"served", "shadow", "reason", "deviation", "difference", "consistency"}.
    """
    eligible = [m for m in CANDIDATES if gates.get(m)]
    if not eligible:
        raise DecisionError("no candidate passes the gates; nothing can be served")
    decisive = rule["decisive"]
    tab, gb = (pr_auc.get(decisive) or {}).get("tabnet"), (pr_auc.get(decisive) or {}).get("gbdt")
    d = None if tab is None or gb is None else gb - tab
    consistency = {}
    for key in rule["consistency"]:
        t, g = (pr_auc.get(key) or {}).get("tabnet"), (pr_auc.get(key) or {}).get("gbdt")
        consistency[key] = None if t is None or g is None else g - t

    if len(eligible) == 1:
        served = eligible[0]
        other = next(m for m in CANDIDATES if m != served)
        return {"served": served, "shadow": None, "difference": d, "consistency": consistency,
                "reason": f"{other} failed a gate; {served} is the only servable candidate",
                "deviation": "C8-1" if served != "tabnet" else None}
    if d is None:
        raise DecisionError(f"no validation PR-AUC for both candidates on {decisive}")
    ahead_everywhere = all(v is not None and v > 0 for v in consistency.values())
    if d > rule["margin"] and ahead_everywhere:
        served = "gbdt"
        reason = (f"XGBoost leads by {d:.3f} on {decisive} validation PR-AUC (> {rule['margin']}) and is ahead on "
                  + ", ".join(f"{k} ({v:+.3f})" for k, v in consistency.items()))
    else:
        served = rule["default"]
        if d <= rule["margin"]:
            reason = f"difference {d:+.3f} on {decisive} is not above the {rule['margin']} margin; the default ({served}) stands"
        else:
            missing = [k for k, v in consistency.items() if v is None]
            behind = [k for k, v in consistency.items() if v is not None and v <= 0]
            reason = (f"XGBoost leads by {d:.3f} on {decisive} but is not ahead everywhere "
                      f"(behind: {behind or 'none'}, missing: {missing or 'none'}); the default ({served}) stands")
    return {"served": served, "shadow": next(m for m in CANDIDATES if m != served), "difference": d,
            "consistency": consistency, "reason": reason, "deviation": "C8-1" if served != "tabnet" else None}


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

def _input_columns(model_name: str, artifact_dir: Path) -> list[str]:
    if model_name == "tabnet":
        prep = json.loads((artifact_dir / "preprocessor.json").read_text(encoding="utf-8"))
        return list(prep["imputer"]["columns"])
    return (artifact_dir / "columns.txt").read_text(encoding="utf-8").splitlines()


def gate(model_name: str, entry: dict, registry: ModelRegistry, served_profile: str) -> dict:
    problems = registry.verify(entry)
    cols = _input_columns(model_name, registry.artifact_dir(entry)) if not problems else []
    checks = {
        "sha256_verified": not problems,
        "reportable": bool(entry.get("reportable")),
        "trained_on_served_profile": entry.get("profile") == served_profile,
        "behaviour_only": not problems and not static_inputs(cols),
    }
    return {"ok": all(checks.values()), "checks": checks, "problems": problems, "static_inputs": static_inputs(cols),
            "n_input_columns": len(cols)}


def _pin(entry: dict) -> dict:
    return {k: entry.get(k) for k in ("model_name", "registry_version", "model_version", "run_id", "profile")}


def _summary(metrics: dict) -> dict:
    p = metrics["primary"]
    b1 = p["budgets"].get("1") or {}
    return {
        "pr_auc": p["pr_auc"], "roc_auc_secondary": p["roc_auc_secondary"],
        "recall_at_1": b1.get("recall"), "insiders_caught_at_1": f"{b1['per_user']['caught']}/{b1['per_user']['insiders']}" if b1 else None,
        "caught_by_scenario_at_1": {s: f"{v['caught']}/{v['insiders']}" for s, v in (b1.get("per_user") or {}).get("by_scenario", {}).items()},
        "recall_by_scenario_at_1": {s: f"{v['alerted']}/{v['positives']}" for s, v in b1.get("recall_by_scenario", {}).items()},
    }


def collect(args: argparse.Namespace, part: str, gbdt_runs: dict[str, str]) -> dict:
    """Score-file evidence per split key, for the given part."""
    processed = Path(args.processed_dir)
    ch7 = load_reference_runs(args.ch7_references)
    ch6 = load_reference_runs(args.ch6_references) if Path(args.ch6_references).exists() else {"runs": {}}
    tab_reg, gb_reg = ModelRegistry(args.models_dir, "tabnet"), ModelRegistry(args.models_dir, "gbdt")
    out = {}
    rule = active_rule(args)
    for key in [rule["decisive"], *rule["consistency"]]:
        tab_ref = (ch7.get("runs") or {}).get(key)
        if not tab_ref:
            raise DecisionError(f"no reference TabNet run for {key} in {args.ch7_references}")
        if key not in gbdt_runs:
            raise DecisionError(f"no XGBoost candidate run given for {key}; pass --gbdt {key}=<run id>")
        gb_entry = gb_reg.resolve(gbdt_runs[key])
        tab_entry = tab_reg.resolve(tab_ref["registry_version"])
        sources = [
            ScoreSource("tabnet", 7, tab_ref["run_id"], "tabnet", processed / "scores" / "chapter7" / tab_ref["run_id"] / "tabnet.parquet"),
            ScoreSource("gbdt", 8, gbdt_runs[key], "gbdt", processed / "scores" / "chapter8" / gbdt_runs[key] / "gbdt.parquet"),
        ]
        ref6 = reference_runs_for(ch6, *key.split("/")).get("gbdt")
        ref6_path = processed / "scores" / "chapter6" / str(ref6) / "gbdt.parquet"
        if ref6 and ref6_path.exists():
            sources.append(ScoreSource(CH6_REFERENCE_LABEL, 6, ref6, "gbdt", ref6_path))
        result = compare_sources(processed, sources, part=part, seed=args.seed)
        out[key] = {
            "rows": result["rows"], "positives": result["positives"], "chance_pr_auc": result["chance_pr_auc"],
            "precision_ceiling": result["precision_ceiling"],
            "runs": {"tabnet": _pin(tab_entry), "gbdt": _pin(gb_entry), **({CH6_REFERENCE_LABEL: {"run_id": ref6}} if len(sources) == 3 else {})},
            "models": {label: {"model_version": e["model_version"], **_summary(e["metrics"])} for label, e in result["models"].items()},
            "_result": result, "_sources": sources, "_entries": {"tabnet": tab_entry, "gbdt": gb_entry},
        }
    return out


def active_rule(args: argparse.Namespace) -> dict:
    """The rule. The hidden --decisive / --consistency flags exist only for the
    synthetic tests (one profile); using them marks the decision, and the
    verifier will not pass such a decision silently."""
    rule = dict(RULE)
    if getattr(args, "decisive", None) and args.decisive != RULE["decisive"]:
        rule["decisive"] = args.decisive
        rule["split_keys_overridden"] = True
    if getattr(args, "consistency", None) is not None:
        keys = [k for k in args.consistency.split(",") if k]
        if keys != RULE["consistency"]:
            rule["consistency"] = keys
            rule["split_keys_overridden"] = True
    return rule


def _public(evidence: dict) -> dict:
    return {k: {kk: vv for kk, vv in v.items() if not kk.startswith("_")} for k, v in evidence.items()}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    root = repo_root()
    p = argparse.ArgumentParser(description="CIRA Chapter 8: choose the served model on validation")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--gbdt", action="append", default=[], metavar="PROFILE/SPLIT=RUN_ID",
                   help="behaviour-only XGBoost candidate run for one profile/split; repeat for each")
    p.add_argument("--report-test", action="store_true", help="after the decision: read test once, for the write-up")
    p.add_argument("--supersede", default=None, metavar="REASON", help="replace an existing decision, keeping it on record")
    p.add_argument("--decision-path", default=os.getenv("CIRA_SERVING_DECISION", str(root / "experiments" / DECISION_FILE)))
    p.add_argument("--test-readout-path", default=str(root / "experiments" / TEST_READOUT_FILE))
    p.add_argument("--ch7-references", default=str(root / "experiments" / "chapter7_reference_runs.json"))
    p.add_argument("--ch6-references", default=str(root / "experiments" / "chapter6_reference_runs.json"))
    p.add_argument("--models-dir", default=os.getenv("MODEL_PATH", str(root / "models" / "saved_models")))
    p.add_argument("--seed", type=int, default=int(os.getenv("CIRA_SEED", "42")))
    p.add_argument("--decisive", default=None, help=argparse.SUPPRESS)       # synthetic tests only
    p.add_argument("--consistency", default=None, help=argparse.SUPPRESS)    # synthetic tests only
    return p.parse_args(argv)


def _gbdt_runs(values: list[str]) -> dict[str, str]:
    out = {}
    for v in values:
        key, sep, run_id = v.partition("=")
        if not sep or "/" not in key or not run_id:
            raise SystemExit(f"--gbdt expects PROFILE/SPLIT=RUN_ID, got {v!r}")
        out[key.strip()] = run_id.strip()
    return out


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def make_decision(args: argparse.Namespace) -> dict:
    rule = active_rule(args)
    decision_path = Path(args.decision_path)
    previous = None
    if decision_path.exists():
        if not args.supersede:
            raise SystemExit(f"{decision_path} exists. A decision is made once; pass --supersede \"<reason>\" to replace it on record.")
        previous = json.loads(decision_path.read_text(encoding="utf-8"))
    gbdt_runs = _gbdt_runs(args.gbdt)
    evidence = collect(args, "validation", gbdt_runs)
    decisive = evidence[rule["decisive"]]
    registries = {"tabnet": ModelRegistry(args.models_dir, "tabnet"), "gbdt": ModelRegistry(args.models_dir, "gbdt")}
    gates = {m: gate(m, decisive["_entries"][m], registries[m], rule["served_profile"]) for m in CANDIDATES}
    pr = {k: {m: v["models"][m]["pr_auc"] for m in CANDIDATES} for k, v in evidence.items()}
    outcome = decide(pr, {m: g["ok"] for m, g in gates.items()}, rule=rule)

    for key, ev in evidence.items():
        print(f"\n=== {key} (validation) ===")
        print_table(ev["_result"])
    served_entry = decisive["_entries"][outcome["served"]]
    shadow_entry = decisive["_entries"][outcome["shadow"]] if outcome["shadow"] and gates[outcome["shadow"]]["ok"] else None
    payload = {
        "chapter": 8,
        "decided_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "part_used": "validation",
        "rule": rule,
        "candidates": {m: {k: ev["runs"][m] for k, ev in evidence.items()} for m in CANDIDATES},
        "gates": gates,
        "evidence": _public(evidence),
        "outcome": {
            "served": _pin(served_entry),
            "shadow": None if shadow_entry is None else _pin(shadow_entry),
            "reason": outcome["reason"],
            "difference_decisive": outcome["difference"],
            "difference_consistency": outcome["consistency"],
            "deviation": outcome["deviation"],
        },
        "superseded": ([] if previous is None else [*previous.get("superseded", []),
                                                     {**{k: previous.get(k) for k in ("decided_at", "rule", "outcome")},
                                                      "superseded_because": args.supersede}]),
    }
    _atomic_json(decision_path, payload)
    append_experiment_runlog({
        "stage": "chapter8_serving_decision", "rule": rule["version"], "part": "validation",
        "served": f"{payload['outcome']['served']['model_name']}:{payload['outcome']['served']['registry_version']}",
        "shadow": None if shadow_entry is None else f"{shadow_entry['model_name']}:{shadow_entry['registry_version']}",
        "difference_decisive": outcome["difference"], "difference_consistency": outcome["consistency"],
        "validation_pr_auc": pr, "gates_ok": {m: g["ok"] for m, g in gates.items()},
        "deviation": outcome["deviation"], "superseded": bool(previous), "decision_path": str(decision_path),
    })
    print(f"\nSERVED: {payload['outcome']['served']['model_name']} {payload['outcome']['served']['registry_version']} "
          f"({payload['outcome']['served']['model_version']})")
    print(f"reason: {outcome['reason']}")
    print(f"written: {decision_path}  (commit it; the API and the batch job read it)")
    return payload


def report_test(args: argparse.Namespace) -> dict:
    decision_path, readout_path = Path(args.decision_path), Path(args.test_readout_path)
    if not decision_path.exists():
        raise SystemExit("no decision yet: decide on validation first. Test is read after the decision, never before (N11).")
    if readout_path.exists():
        raise SystemExit(f"{readout_path} exists: test has been read once already. It is not read again.")
    decision_bytes = decision_path.read_bytes()
    decision = json.loads(decision_bytes)
    args.decisive, args.consistency = decision["rule"]["decisive"], ",".join(decision["rule"]["consistency"])
    gbdt_runs = {k: v["run_id"] for k, v in decision["candidates"]["gbdt"].items()}
    print("Reading TEST once, for the write-up. Nothing may be changed because of it (N11).")
    evidence = collect(args, "test", gbdt_runs)
    runlog = _runlog_lines()
    harness = {}
    for key, ev in evidence.items():
        print(f"\n=== {key} (test) ===")
        print_table(ev["_result"])
        rows = harness_check(ev["_result"], ev["_sources"], runlog)
        for m in CANDIDATES:        # the registry entry holds each candidate's test PR-AUC from training time
            logged = ((ev["_entries"][m].get("metrics") or {}).get("test") or {}).get("pr_auc")
            now = ev["models"][m]["pr_auc"]
            rows.append({"model": m, "logged_test_pr_auc": logged, "recomputed_test_pr_auc": now,
                         "match": logged is not None and now is not None and abs(now - logged) <= 1e-9})
        harness[key] = rows
    payload = {
        "chapter": 8, "read_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "part": "test",
        "decision_sha256": hashlib.sha256(decision_bytes).hexdigest(), "decision_outcome": decision["outcome"],
        "evidence": _public(evidence), "harness_check": harness,
    }
    _atomic_json(readout_path, payload)
    append_experiment_runlog({
        "stage": "chapter8_test_readout", "decision_sha256": payload["decision_sha256"],
        "test_pr_auc": {k: {m: e["pr_auc"] for m, e in ev["models"].items()} for k, ev in evidence.items()},
        "harness_ok": all(r["match"] for rows in harness.values() for r in rows),
    })
    print(f"\nwritten: {readout_path}")
    return payload


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.report_test:
            report_test(args)
        else:
            make_decision(args)
    except (DecisionError, ComparisonError, RegistryError) as exc:
        print(f"chapter8 selection stopped: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
