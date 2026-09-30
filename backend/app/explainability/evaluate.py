"""Validation readout of the explanations (Chapter 11, N15, N23, N30, N32).

Offline module: joins labels in memory through app.evaluation, like
app.mitre.evaluate. Never imported by a serving module (N5).

What it answers, on the served model's validation user-days only
    1. What explains malicious days, per scenario. For every malicious
       validation day: the top raising factor and the domains of the top three
       (logon, device, file, email, http, temporal, historical_baseline,
       peer_group). If the served model is right for the right reasons, the
       factors should be behaviour the scenario describes, not the calendar.
    2. What the analyst would see on false alarms: benign days that were in
       the served model's daily top-1, and their top factors.
    3. A second model's view (N30, N32). The case for TabNet was always its
       masks (N23). For the same malicious days, the shadow TabNet's grouped
       masks are computed here and compared with XGBoost's TreeSHAP: top-1
       mask feature per scenario and the overlap of the two top-5 sets. This
       view is labelled as the shadow's, lives only in this readout, and never
       reaches an alert, a queue or an analyst explanation.

Guard c11-explain-guard-v1 (WARN only; explained in the audit)
    * any user-day whose served explanation has a static trait in its top 5;
    * any scenario whose most frequent top factor on malicious days is a
      calendar column (day_of_week, is_weekend).
    A WARN never changes the model, the explainer or a description.

Rules
    * Validation only; ``--part test`` is refused. Test-set explanations are
      Chapter 16's.
    * Written once; ``--supersede "<reason>"`` keeps the old readout inside.

Usage, from backend/:

    python -m app.explainability.evaluate --profile full
"""
from __future__ import annotations

from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
from collections import Counter  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.evaluation.labels import attach_labels, load_label_views  # noqa: E402
from app.evaluation.metrics import daily_top_k  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, repo_root  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, load_feature_matrix  # noqa: E402

from .attributions import ExplanationFailedError, ExplanationUnavailableError, explainer_for  # noqa: E402
from .features import CALENDAR_COLUMNS, describe  # noqa: E402
from .sources import ATTRIBUTIONS_OUTPUT, SUMMARY_OUTPUT, ExplainSourceError, aligned, explain_run_dir, read_meta  # noqa: E402

READOUT_FILE = "chapter11_validation_readout.json"
GUARD = {
    "version": "c11-explain-guard-v1",
    "warn_if": ["a static trait in the top 5 of any served explanation (N22)",
                "a calendar column is the most frequent top factor of a scenario's malicious days"],
    "effect": "WARN to be explained in docs/audits/chapter_11_audit.md; never changes the model or the explainer",
}
SCENARIOS = (1, 2, 3)


class ReadoutRefused(RuntimeError):
    """Nothing was written."""


def top_raising(attr: pd.DataFrame, n: int) -> dict[tuple[str, str], list[str]]:
    """(user_id, date) -> the first ``n`` raising features, strongest first."""
    a = attr[attr["contribution"] > 0].sort_values(["user_id", "date", "rank"], kind="mergesort")
    return {k: g["feature"].head(n).tolist() for k, g in a.groupby(["user_id", "date"], sort=False)}


def _describe_days(keys: pd.DataFrame, tops: dict) -> dict:
    lists = [tops.get((str(u), str(d)), []) for u, d in zip(keys["user_id"], keys["date"])]
    first = [x[0] for x in lists if x]
    domains = Counter(describe(f).domain for x in lists for f in x[:3])
    total = sum(domains.values())
    return {
        "days": len(lists),
        "no_raising_factor": sum(1 for x in lists if not x),
        "top_factor_counts": dict(Counter(first).most_common(8)),
        "top_factor_is_calendar_share": (sum(f in CALENDAR_COLUMNS for f in first) / len(first)) if first else None,
        "top3_domain_share": {k: round(v / total, 4) for k, v in domains.most_common()} if total else {},
    }


def _shadow_view(processed: Path, fm, keys_by_scenario: dict, tree_tops: dict) -> dict:
    """Shadow TabNet masks on the same malicious days (N30: a clearly labelled second model's view)."""
    from app.scoring.adapters import load_adapter
    from app.scoring.contracts import ScoringUnavailableError
    from app.scoring.serving_config import resolve_serving_config

    cfg = resolve_serving_config()
    pins = [p for p in cfg.shadows if p.model_name == "tabnet"]
    if not pins:
        return {"available": False, "reason": "no TabNet shadow in the serving configuration"}
    try:
        adapter = load_adapter(pins[0], cfg.registry_root)
        ex = explainer_for(adapter, role="shadow")
    except (ScoringUnavailableError, ExplanationUnavailableError) as exc:
        return {"available": False, "reason": str(exc)}
    out = {"available": True, "label": "SECOND MODEL'S VIEW (shadow TabNet masks); never shown to an analyst (N30, N32)",
           "model": ex.model, "by_scenario": {}}
    for s, keys in keys_by_scenario.items():
        if keys.empty:
            continue
        frame = aligned(fm.matrix, keys, "the feature matrix")
        try:
            attr = ex.explain(frame)
        except ExplanationFailedError as exc:
            out["by_scenario"][str(s)] = {"error": str(exc)}
            continue
        order = np.argsort(-attr.values, axis=1, kind="stable")[:, :5]
        names = np.asarray(attr.features, dtype=object)
        mask_top = [list(names[r]) for r in order]
        jac = []
        for (u, d), m in zip(zip(keys["user_id"].astype(str), keys["date"].astype(str)), mask_top):
            t = set(tree_tops.get((u, d), [])[:5])
            if t:
                jac.append(len(t & set(m)) / len(t | set(m)))
        out["by_scenario"][str(s)] = {
            "days": int(len(keys)),
            "mask_top_factor_counts": dict(Counter(m[0] for m in mask_top).most_common(8)),
            "mean_top5_jaccard_with_treeshap": float(np.mean(jac)) if jac else None,
        }
    return out


def _parse_args(argv):
    root = repo_root()
    p = argparse.ArgumentParser(description="CIRA Chapter 11 validation readout (reads labels)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--explain-run-id", default=None)
    p.add_argument("--part", default="validation")
    p.add_argument("--readout-path", default=str(root / "experiments" / READOUT_FILE))
    p.add_argument("--no-shadow", action="store_true", help="skip the shadow TabNet mask view")
    p.add_argument("--seed", type=int, default=int(os.getenv("CIRA_SEED", "42")))
    p.add_argument("--supersede", default=None, metavar="REASON")
    return p.parse_args(argv)


def run(args) -> dict:
    if args.part != "validation":
        raise ReadoutRefused("validation only; test-set explanations are read in Chapter 16")
    path = Path(args.readout_path)
    previous = None
    if path.exists():
        if not args.supersede:
            raise ReadoutRefused(f"{path} exists: the readout is written once (use --supersede \"<reason>\")")
        previous = json.loads(path.read_text(encoding="utf-8"))
    processed = Path(args.processed_dir)
    run_dir = explain_run_dir(processed, args.explain_run_id, args.profile)
    meta = read_meta(run_dir)
    summary = pd.read_parquet(run_dir / SUMMARY_OUTPUT)
    val = summary[summary["model_split"] == "validation"].reset_index(drop=True)
    if val.empty:
        raise ReadoutRefused(f"explain run {run_dir.name} has no validation rows")
    attr = pd.read_parquet(run_dir / ATTRIBUTIONS_OUTPUT)
    attr = attr.merge(val[["user_id", "date"]], on=["user_id", "date"])
    labels = attach_labels(val[["user_id", "date"]], load_label_views(processed))
    y = labels["y_primary"].to_numpy()
    scen = labels["scenario_primary"].to_numpy()
    excl = labels["exclude_primary"].to_numpy().astype(bool)
    tops = top_raising(attr, 5)

    by_scenario, keys_by_scenario = {}, {}
    for s in SCENARIOS:
        keys = val.loc[(y == 1) & (scen == s), ["user_id", "date"]].reset_index(drop=True)
        keys_by_scenario[s] = keys
        by_scenario[str(s)] = _describe_days(keys, tops)
    top1 = daily_top_k(val["date"], val["anomaly_score"].to_numpy(dtype="float64"), 1, seed=args.seed)
    false_alarm_keys = val.loc[top1 & (y == 0) & ~excl, ["user_id", "date"]]
    false_alarms = _describe_days(false_alarm_keys, tops)

    shadow = {"available": False, "reason": "--no-shadow"}
    if not args.no_shadow:
        fm = load_feature_matrix(processed, args.profile)
        shadow = _shadow_view(processed, fm, keys_by_scenario, tops)

    warnings = []
    n_static = int(summary["static_in_top5"].sum())
    if n_static:
        warnings.append(f"{n_static} served explanations have a static trait in their top 5 (N22)")
    for s, block in by_scenario.items():
        counts = block["top_factor_counts"]
        if counts and next(iter(counts)) in CALENDAR_COLUMNS:
            warnings.append(f"scenario {s}: the most frequent top factor on malicious days is {next(iter(counts))}")
    readout = {
        "chapter": 11, "part": "validation", "view": "primary (N1); masquerade account-days excluded from benign",
        "explain_run_id": run_dir.name, "served": meta.get("served"), "method": (meta.get("explainer") or {}).get("method"),
        "malicious_days_by_scenario": by_scenario,
        "false_alarms_at_top1": {"definition": "benign validation days in the served model's daily top-1 (seeded tie-break)",
                                 **false_alarms},
        "second_model_view": shadow,
        "guard": {**GUARD, "warnings": warnings},
        "caveats": ["one seed, validation only (N26); six scenario-1 insiders cannot settle a scenario claim (N15)",
                    "a factor that matches a public scenario description is partly by construction of the dataset (N41)"],
        "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if previous is not None:
        readout["supersedes"] = {"reason": args.supersede, "previous": previous}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(readout, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)
    append_experiment_runlog({"stage": "chapter11_validation_readout", "explain_run_id": run_dir.name,
                              "profile": args.profile, "guard_warnings": len(warnings), "output": str(path)})
    for s, b in by_scenario.items():
        print(f"[readout] scenario {s}: {b['days']} malicious validation days; top factors {b['top_factor_counts']}", flush=True)
    print(f"[readout] false alarms at top-1: {false_alarms['days']}; top factors {false_alarms['top_factor_counts']}", flush=True)
    for w in warnings:
        print(f"[readout] WARN {GUARD['version']}: {w}", flush=True)
    print(f"[readout] written: {path}", flush=True)
    return readout


def main(argv=None) -> int:
    args = _parse_args(argv)
    try:
        run(args)
    except (ReadoutRefused, ExplainSourceError) as exc:
        print(f"chapter11 readout refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
