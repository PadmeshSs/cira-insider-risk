"""Compare detectors on identical rows with one harness (Bible Ch7 acceptance).

Chapter 7 must be benchmarked against the Chapter 6 baselines "using the same
evaluation harness". This module does that without re-running any baseline:
it reads the stored score files of the reference runs (N18, listed in
``experiments/chapter6_reference_runs.json``) and of a Chapter 7 run, checks
that they cover exactly the same (user, date) rows, joins labels in memory,
and computes every metric with ``app.evaluation.metrics.evaluate_scores`` using
the same budgets and the same tie-break seed.

What it adds on top of the per-run metrics
    * a harness check: for the test part, each baseline's recomputed PR-AUC
      must equal the ``test_pr_auc`` its run logged in
      ``experiments/runlog.jsonl``; a mismatch means the harness or the data
      changed and nothing may be compared (N18);
    * a feature-fingerprint check between the Chapter 7 run and the
      baselines (a different matrix makes the comparison meaningless);
    * chance level (the positive rate) and the precision ceiling of each
      daily budget (N17);
    * recall and insiders caught per scenario next to every headline (N15);
    * for the time split, PR-AUC on insiders never seen in training plus
      all benign users, per model (N16).

Validation is the default part. ``--part test`` is for the write-up, once
per model; choosing anything after reading test turns test into a second
validation set (N11).

Bootstrap confidence intervals and significance tests stay in Chapter 16
(deviation C6-2).

Usage, from backend/:
    python -m app.evaluation.compare --profile mid --split user --run-id <chapter 7 run id>
    python -m app.evaluation.compare --profile full --split user --run-id <id> --part test
"""
from __future__ import annotations

from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.evaluation.labels import attach_labels, load_label_views  # noqa: E402
from app.evaluation.metrics import DEFAULT_BUDGETS, evaluate_scores, pr_auc  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, repo_root  # noqa: E402

REFERENCE_FILE = "chapter6_reference_runs.json"
HARNESS_TOLERANCE = 1e-9


class ComparisonError(RuntimeError):
    """The sources cannot be compared (different rows, harness drift)."""


@dataclass(frozen=True)
class ScoreSource:
    label: str
    chapter: int
    run_id: str
    model: str
    path: Path


def load_reference_runs(path: str | Path | None = None) -> dict:
    path = Path(path) if path else repo_root() / "experiments" / REFERENCE_FILE
    return json.loads(path.read_text(encoding="utf-8"))


def reference_runs_for(refs: dict, profile: str, split: str) -> dict[str, str]:
    """model -> run id of the reported Chapter 6 run, or {} if none exists."""
    return dict(refs.get("runs", {}).get(f"{profile}/{split}", {}))


def chapter6_sources(processed: str | Path, runs: dict[str, str]) -> list[ScoreSource]:
    root = Path(processed) / "scores" / "chapter6"
    return [ScoreSource(model, 6, rid, model, root / rid / f"{model}.parquet") for model, rid in runs.items()]


def chapter7_source(processed: str | Path, run_id: str, model: str = "tabnet") -> ScoreSource:
    return ScoreSource(model, 7, run_id, model, Path(processed) / "scores" / "chapter7" / run_id / f"{model}.parquet")


def _load_part(src: ScoreSource, part: str) -> pd.DataFrame:
    if not src.path.exists():
        raise ComparisonError(f"score file for {src.label} ({src.run_id}) not found: {src.path}")
    sc = pd.read_parquet(src.path, columns=["user_id", "date", "split", "anomaly_score", "model_version"])
    sc = sc[sc["split"] == part].copy()
    sc["user_id"] = sc["user_id"].astype("string").str.strip().str.casefold()
    sc["date"] = sc["date"].astype("string")
    if sc.duplicated(["user_id", "date"]).any():
        raise ComparisonError(f"{src.path} has duplicate (user_id, date) rows in {part}")
    return sc.sort_values(["user_id", "date"], kind="mergesort").reset_index(drop=True)


def _precision_ceiling(dates: pd.Series, y: np.ndarray, keep: np.ndarray, budgets) -> dict[str, float | None]:
    """Best precision a perfect ranker could reach at each daily budget."""
    per_day = pd.Series((y.astype(bool) & keep).astype(int), index=dates.to_numpy()).groupby(level=0).sum()
    rows_per_day = pd.Series(np.ones(len(y), dtype=int), index=dates.to_numpy()).groupby(level=0).sum()
    out = {}
    for k in budgets:
        alerts = int(np.minimum(rows_per_day.to_numpy(), k).sum())
        out[str(k)] = float(np.minimum(per_day.to_numpy(), k).sum() / alerts) if alerts else None
    return out


def compare_sources(
    processed: str | Path,
    sources: list[ScoreSource],
    *,
    part: str = "validation",
    budgets=DEFAULT_BUDGETS,
    seed: int = 42,
    split_info: dict | None = None,
) -> dict:
    if part not in ("validation", "test"):
        raise ValueError("part must be validation or test")
    if not sources:
        raise ComparisonError("nothing to compare")
    frames = {s.label: _load_part(s, part) for s in sources}
    first = sources[0].label
    keys = frames[first][["user_id", "date"]]
    for label, fr in frames.items():
        same = len(fr) == len(keys) and (fr["user_id"].to_numpy() == keys["user_id"].to_numpy()).all() \
            and (fr["date"].to_numpy() == keys["date"].to_numpy()).all()
        if not same:
            raise ComparisonError(
                f"{label} scores {len(fr)} {part} rows, {first} scores {len(keys)}; the runs did not use the same "
                "split or matrix, so they cannot be compared (N11, N18)"
            )

    views = load_label_views(processed)
    labels = attach_labels(keys, views)
    y = labels["y_primary"].to_numpy()
    keep = ~labels["exclude_primary"].to_numpy()

    seen: set[str] = set()
    if split_info and split_info.get("mode") == "time":
        cut = split_info.get("validation_start")
        seen = set(views.primary.loc[views.primary["date"] < cut, "user_id"])
    is_seen = keys["user_id"].isin(seen).to_numpy()

    result = {
        "part": part,
        "rows": int(len(keys)),
        "users": int(keys["user_id"].nunique()),
        "positives": int(y[keep].sum()),
        "chance_pr_auc": float(y[keep].mean()) if keep.any() else None,
        "precision_ceiling": _precision_ceiling(keys["date"], y, keep, budgets),
        "budgets": list(budgets),
        "seed": seed,
        "models": {},
    }
    if seen:
        new = keep & ~is_seen
        result["time_split"] = {
            "insiders_seen_in_training": sorted(set(keys["user_id"].to_numpy()[(y == 1) & is_seen])),
            "insiders_new": sorted(set(keys["user_id"].to_numpy()[(y == 1) & ~is_seen])),
            "chance_new_insiders_only": float(y[new].mean()) if new.any() else None,
        }
    for src in sources:
        s = frames[src.label]["anomaly_score"].to_numpy(dtype="float64")
        m = evaluate_scores(keys, s, labels, budgets=budgets, seed=seed)
        entry = {
            "chapter": src.chapter,
            "run_id": src.run_id,
            "model_version": str(frames[src.label]["model_version"].iloc[0]) if len(s) else None,
            "metrics": m,
        }
        if seen:
            new = keep & ~is_seen
            entry["pr_auc_new_insiders_only"] = pr_auc(y[new], s[new])
        result["models"][src.label] = entry
    return result


def _runlog_lines(path: str | Path | None = None) -> list[dict]:
    path = Path(path or os.getenv("CIRA_RUNLOG", str(repo_root() / "experiments" / "runlog.jsonl")))
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def harness_check(result: dict, sources: list[ScoreSource], runlog: list[dict]) -> list[dict]:
    """Recomputed test PR-AUC of each Chapter 6 source vs the logged value."""
    rows = []
    if result["part"] != "test":
        return rows
    for src in sources:
        if src.chapter != 6:
            continue
        line = next((r for r in runlog if r.get("stage") == "chapter6_baseline" and r.get("run_id") == src.run_id
                     and r.get("model") == src.model), None)
        now = result["models"][src.label]["metrics"]["primary"]["pr_auc"]
        logged = None if line is None else line.get("test_pr_auc")
        ok = logged is not None and now is not None and abs(now - logged) <= HARNESS_TOLERANCE
        rows.append({"model": src.label, "run_id": src.run_id, "logged_test_pr_auc": logged,
                     "recomputed_test_pr_auc": now, "match": ok})
    return rows


def fingerprint_check(runlog: list[dict], sources: list[ScoreSource], feature_fp: str | None) -> list[dict]:
    rows = []
    for src in sources:
        if src.chapter != 6:
            continue
        line = next((r for r in runlog if r.get("stage") == "chapter6_baseline" and r.get("run_id") == src.run_id
                     and r.get("model") == src.model), None)
        fp = None if line is None else line.get("feature_fingerprint")
        rows.append({"model": src.label, "run_id": src.run_id, "baseline_fingerprint": fp,
                     "chapter7_fingerprint": feature_fp, "match": fp is not None and fp == feature_fp})
    return rows


def _f(v, nd=3) -> str:
    return "n/a" if v is None else f"{v:.{nd}f}"


def print_table(result: dict) -> None:
    budgets = result["budgets"]
    print(f"\n{result['part']}: {result['rows']} rows, {result['users']} users, {result['positives']} malicious user-days, "
          f"chance PR-AUC {_f(result['chance_pr_auc'], 4)}")
    print("precision ceiling per daily budget: " + ", ".join(f"top-{k} {_f(v)}" for k, v in result["precision_ceiling"].items()))
    head = f"{'model':<18}{'PR-AUC':>8}{'ROC-AUC*':>10}" + "".join(f"{f'R@{k}':>8}{f'caught@{k}':>11}" for k in budgets)
    print(head)
    for label, e in result["models"].items():
        p = e["metrics"]["primary"]
        row = f"{label:<18}{_f(p['pr_auc']):>8}{_f(p['roc_auc_secondary']):>10}"
        for k in budgets:
            b = p["budgets"][str(k)]
            row += f"{_f(b['recall']):>8}{b['per_user']['caught']:>6}/{b['per_user']['insiders']:<4}"
        print(row)
    k = budgets[0]
    print(f"\nper scenario at top-{k} (recall days; insiders caught)  N15")
    for label, e in result["models"].items():
        b = e["metrics"]["primary"]["budgets"][str(k)]
        rec = ", ".join(f"s{s} {v['alerted']}/{v['positives']}" for s, v in b["recall_by_scenario"].items())
        cau = ", ".join(f"s{s} {v['caught']}/{v['insiders']}" for s, v in b["per_user"]["by_scenario"].items())
        print(f"  {label:<18}{rec:<40}{cau}")
    if "time_split" in result:
        t = result["time_split"]
        print(f"\ntime split (N16): {len(t['insiders_seen_in_training'])} insiders seen in training, "
              f"{len(t['insiders_new'])} new; chance on new + benign {_f(t['chance_new_insiders_only'], 4)}")
        for label, e in result["models"].items():
            print(f"  {label:<18} PR-AUC on new insiders + benign: {_f(e.get('pr_auc_new_insiders_only'))}")
    print("\n* ROC-AUC is secondary (N2). At mid, read top-1: top-5 saturates per-user detection (N17).")


def _latest_ch7_run(results_dir: Path, profile: str, split: str) -> str:
    runs = sorted(p.name for p in results_dir.iterdir() if p.is_dir() and f"-{profile}-{split}-" in p.name
                  and (p / "metrics.json").exists()) if results_dir.exists() else []
    if not runs:
        raise SystemExit(f"no Chapter 7 run under {results_dir} for profile={profile} split={split}")
    return runs[-1]


def main(argv: list[str] | None = None) -> dict:
    root = repo_root()
    p = argparse.ArgumentParser(description="Compare TabNet with the reference Chapter 6 runs")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "mid"), choices=("dev", "mid", "full"))
    p.add_argument("--split", default="user", choices=("user", "time"))
    p.add_argument("--run-id", default=None, help="Chapter 7 run; defaults to the newest for profile/split")
    p.add_argument("--part", default="validation", choices=("validation", "test"))
    p.add_argument("--references", default=str(root / "experiments" / REFERENCE_FILE))
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter7"))
    p.add_argument("--baselines-only", action="store_true", help="compare the reference baselines without a Chapter 7 run")
    args = p.parse_args(argv)
    if args.profile == "dev":
        print("dev profile: debugging only, never report these numbers (N6).")
    if args.part == "test":
        print("Reading TEST. For the write-up only; do not change any design choice after this (N11).")

    results_dir = Path(args.results_dir)
    refs = reference_runs_for(load_reference_runs(args.references), args.profile, args.split)
    sources = chapter6_sources(args.processed_dir, refs)
    report, feature_fp, split_info, seed, budgets = None, None, {"mode": args.split}, 42, DEFAULT_BUDGETS
    if not args.baselines_only:
        run_id = args.run_id or _latest_ch7_run(results_dir, args.profile, args.split)
        report = json.loads((results_dir / run_id / "metrics.json").read_text(encoding="utf-8"))
        if report["profile"] != args.profile or report["split"]["mode"] != args.split:
            raise SystemExit(f"{run_id} is {report['profile']}/{report['split']['mode']}, not {args.profile}/{args.split}")
        feature_fp, split_info = report["features"]["fingerprint"], report["split"]
        seed, budgets = report["seed"], tuple(report["budgets"])
        sources.append(chapter7_source(args.processed_dir, run_id))
    if not refs:
        print(f"No reference Chapter 6 runs recorded for {args.profile}/{args.split}; nothing to compare against.")
    if split_info.get("mode") == "time" and "validation_start" not in split_info:
        split_info = {"mode": "time", "validation_start": "2011-01-01", "test_start": "2011-02-01"}

    result = compare_sources(args.processed_dir, sources, part=args.part, budgets=budgets, seed=seed, split_info=split_info)
    runlog = _runlog_lines()
    result["harness_check"] = harness_check(result, sources, runlog)
    result["fingerprint_check"] = fingerprint_check(runlog, sources, feature_fp) if feature_fp else []
    print_table(result)
    for row in result["harness_check"]:
        print(f"  harness {'PASS' if row['match'] else 'FAIL'}  {row['model']}: logged {row['logged_test_pr_auc']}, "
              f"recomputed {row['recomputed_test_pr_auc']}")
    for row in result["fingerprint_check"]:
        if not row["match"]:
            print(f"  WARNING {row['model']} ({row['run_id']}) was run on feature matrix {row['baseline_fingerprint']}, "
                  f"TabNet on {row['chapter7_fingerprint']}: not the same matrix")

    if report is not None:
        out = results_dir / report["run_id"] / f"comparison_{args.part}.json"
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        print(f"\nwritten: {out}")
        append_experiment_runlog({
            "stage": "chapter7_comparison", "run_id": report["run_id"], "profile": args.profile, "split_mode": args.split,
            "part": args.part, "rows": result["rows"], "positives": result["positives"],
            "pr_auc": {m: e["metrics"]["primary"]["pr_auc"] for m, e in result["models"].items()},
            "harness_ok": all(r["match"] for r in result["harness_check"]) if result["harness_check"] else None,
            "same_feature_matrix": all(r["match"] for r in result["fingerprint_check"]) if result["fingerprint_check"] else None,
        })
    return result


if __name__ == "__main__":
    main()
