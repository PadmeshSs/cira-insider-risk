"""Chapter 16 seed runs: the same split, other model seeds (N26, N78).

N26 says one run per configuration cannot separate TabNet configurations and asks Chapter 16 to run several
seeds per model before claiming more than "XGBoost ranks higher". This module trains them, by calling the
production entry points (``app.tabnet.train`` and ``app.scoring.gbdt_candidate``) exactly as an operator
would, and records what it made in ``experiments/chapter16_seed_runs.json``.

Two configurations, because experiments A and B differ only in the input columns:

    behaviour     ``--exclude-features psych_,peer_department_size``   (the adopted models, N25)
    all_features  no exclusion                                        (the static / contextual columns too)

and two models (TabNet, XGBoost), so the manifest has model x configuration x seed cells.

Rules
    * Every cell loads the SAME saved user split: the model seed is ``--seed``, the split's seed is
      ``--split-seed`` (default 42). Without that separation ``--seed 43`` would build a different split
      and nothing could be compared (N11).
    * XGBoost / all_features is trained by the Chapter 6 baseline runner, because ``gbdt_candidate`` only trains the
      behaviour-only serving candidate (C8-2); that runner sees every column, like the reported baseline.
    * Nothing is registered (``--no-register``): the registry is append-only and the served model is pinned
      by a decision (N21, N28). Seed runs write score files and metrics only, under their own run ids from
      ``app.core.run_stamp`` (N74).
    * The reported runs are the seed-42 cells of the ``behaviour`` configuration. They are recorded as
      ``reference`` entries, not retrained (N24).
    * Resumable: a finished cell is skipped, so a crash or a thermal pause loses at most one fit.
    * Test is not read here. Each run's own metrics.json contains a test block, as every training run has
      since Chapter 6; nothing in this module prints or selects on it.

Usage, from backend/ (full profile; about two hours on the development machine, see the Chapter 7 audit
for the per-fit time):

    python -m app.evaluation.seeds --profile full
    python -m app.evaluation.seeds --profile full --seeds 42,43,44,45,46,47 --models gbdt      # XGBoost only
"""
from __future__ import annotations

from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import shlex  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

from app.feature_engineering.common import repo_root  # noqa: E402

PLAN_VERSION = "c16-seed-plan-v1"
MANIFEST_FILE = "chapter16_seed_runs.json"
DEFAULT_SEEDS = (42, 43, 44, 45, 46, 47)          # six: the smallest n where a Wilcoxon test can reach p < 0.05
SPLIT_SEED = 42
STATIC = "psych_,peer_department_size"
CONFIGS = {"behaviour": STATIC, "all_features": ""}
MODELS = ("tabnet", "gbdt")


@dataclass(frozen=True)
class Cell:
    model: str
    config: str
    seed: int

    @property
    def key(self) -> str:
        return f"{self.model}/{self.config}/{self.seed}"


def plan(seeds=DEFAULT_SEEDS, models=MODELS, configs=tuple(CONFIGS)) -> list[Cell]:
    unknown = [m for m in models if m not in MODELS] + [c for c in configs if c not in CONFIGS]
    if unknown:
        raise ValueError(f"unknown model or configuration: {unknown}")
    if len(set(seeds)) != len(tuple(seeds)):
        raise ValueError("seeds must be distinct")
    return [Cell(m, c, int(s)) for m in models for c in configs for s in seeds]


def reference_cells(experiments: Path, profile: str, split: str) -> dict[str, dict]:
    """The reported seed-42 behaviour-only runs (N24, Chapter 8 reference file), as manifest entries."""
    out: dict[str, dict] = {}
    f7 = experiments / "chapter7_reference_runs.json"
    f8 = experiments / "chapter8_reference_runs.json"
    if f7.exists():
        r = (json.loads(f7.read_text(encoding="utf-8")).get("runs") or {}).get(f"{profile}/{split}")
        if r:
            out["tabnet/behaviour/42"] = {"run_id": r["run_id"], "model_version": r.get("model_version"),
                                          "registry_version": r.get("registry_version"), "reference": True,
                                          "source": "experiments/chapter7_reference_runs.json"}
    if f8.exists():
        r = (json.loads(f8.read_text(encoding="utf-8")).get("gbdt_candidates") or {}).get(f"{profile}/{split}")
        if r:
            out["gbdt/behaviour/42"] = {"run_id": r["run_id"], "model_version": r.get("model_version"),
                                        "registry_version": r.get("registry_version"), "reference": True,
                                        "source": "experiments/chapter8_reference_runs.json"}
    return out


def runner_for(cell: Cell) -> str:
    """Which production entry point trains a cell.

    ``gbdt_candidate`` refuses to train anything but the behaviour-only serving candidate (C8-2), so the
    all-features XGBoost is the Chapter 6 baseline runner with ``--models gbdt`` (it sees every Chapter 5 column).
    """
    if cell.model == "tabnet":
        return "tabnet"
    return "gbdt_candidate" if cell.config == "behaviour" else "baseline"


def argv_for(cell: Cell, *, processed: str, profile: str, split_seed: int, splits_dir: str | None = None,
             results_dir: str | None = None, models_dir: str | None = None, extra: list[str] | None = None) -> list[str]:
    """The command line of one cell. The model seed and the split seed are separate arguments (N78)."""
    argv = ["--processed-dir", str(processed), "--profile", profile, "--split", "user", "--seed", str(cell.seed),
            "--split-seed", str(split_seed), "--device", "cpu"]
    if runner_for(cell) == "baseline":
        argv += ["--models", "gbdt", "--no-save-models"]
    else:
        argv += ["--exclude-features", CONFIGS[cell.config], "--no-register", "--tag", f"c16-{cell.config}-s{cell.seed}"]
    if splits_dir:
        argv += ["--splits-dir", str(splits_dir)]
    if results_dir:
        argv += ["--results-dir", str(results_dir)]
    if models_dir:
        argv += ["--models-dir", str(models_dir)]
    return argv + list(extra or [])


def new_manifest(profile: str, split: str, seeds, split_seed: int) -> dict:
    return {"version": PLAN_VERSION, "profile": profile, "split": split, "split_seed": int(split_seed),
            "seeds": [int(s) for s in seeds], "configs": dict(CONFIGS), "models": list(MODELS), "runs": {},
            "note": "seed runs are not registered and never served (N21, N28); score files only"}


def read_manifest(path: Path) -> dict | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def write_manifest(path: Path, manifest: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _run_cell(cell: Cell, argv: list[str]) -> dict:
    if cell.model == "tabnet":
        from app.tabnet import train

        report = train.run(train._parse_args(argv))
        meta = report["models"]["tabnet"]["metadata"]
    elif runner_for(cell) == "baseline":
        from app.baselines import run as baselines

        report = baselines.run(baselines._parse_args(argv))
        meta = report["models"]["gbdt"]["metadata"]
    else:
        from app.scoring import gbdt_candidate

        report = gbdt_candidate.run(gbdt_candidate._parse_args(argv))
        meta = report["models"]["gbdt"]["metadata"]
    return {"run_id": report["run_id"], "model_version": meta.get("model_version"), "scores_path": meta["scores_path"],
            "seed": cell.seed, "reference": False, "wall_seconds": report.get("wall_seconds")}


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    root = repo_root()
    p = argparse.ArgumentParser(description="CIRA Chapter 16 seed runs (experiments A and B)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=("mid", "full"))
    p.add_argument("--seeds", default=",".join(str(s) for s in DEFAULT_SEEDS))
    p.add_argument("--split-seed", type=int, default=SPLIT_SEED)
    p.add_argument("--models", default=",".join(MODELS))
    p.add_argument("--configs", default=",".join(CONFIGS))
    p.add_argument("--manifest", default=str(root / "experiments" / MANIFEST_FILE))
    p.add_argument("--experiments-dir", default=str(root / "experiments"))
    p.add_argument("--splits-dir", default=str(root / "experiments" / "splits"))
    p.add_argument("--models-dir", default=os.getenv("MODEL_PATH", str(root / "models" / "saved_models")))
    p.add_argument("--results-dir-tabnet", default=str(root / "experiments" / "results" / "chapter16" / "seed_runs_tabnet"))
    p.add_argument("--results-dir-gbdt", default=str(root / "experiments" / "results" / "chapter16" / "seed_runs_gbdt"))
    p.add_argument("--checkpoint-dir", default=str(root / "models" / "checkpoints"))
    p.add_argument("--tabnet-args", default="", help="extra TabNet arguments, e.g. a short budget in tests (never for a reported run)")
    p.add_argument("--pause-seconds", type=float, default=0.0, help="rest between fits (thermal notes, HCEA §16)")
    p.add_argument("--dry-run", action="store_true", help="print the cells and their command lines, train nothing")
    return p.parse_args(argv)


def run(args: argparse.Namespace) -> dict:
    split = "user"
    seeds = [int(s) for s in str(args.seeds).split(",") if s.strip()]
    models = tuple(m.strip() for m in args.models.split(",") if m.strip())
    configs = tuple(c.strip() for c in args.configs.split(",") if c.strip())
    cells = plan(seeds, models, configs)
    path = Path(args.manifest)
    manifest = read_manifest(path) or new_manifest(args.profile, split, seeds, args.split_seed)
    if (manifest["profile"], manifest["split_seed"]) != (args.profile, args.split_seed):
        raise SystemExit(f"{path} is for profile={manifest['profile']} split_seed={manifest['split_seed']}; refusing to mix runs")
    manifest["seeds"] = sorted(set(manifest["seeds"]) | set(seeds))
    refs = reference_cells(Path(args.experiments_dir), args.profile, split)
    for k, v in refs.items():
        manifest["runs"].setdefault(k, v)

    todo = [c for c in cells if c.key not in manifest["runs"]]
    print(f"[seeds] {len(cells)} cells planned, {len(cells) - len(todo)} already recorded, {len(todo)} to train", flush=True)
    for i, cell in enumerate(todo, 1):
        extra = shlex.split(args.tabnet_args) + ["--checkpoint-dir", args.checkpoint_dir] if cell.model == "tabnet" else []
        results = args.results_dir_tabnet if cell.model == "tabnet" else args.results_dir_gbdt
        if runner_for(cell) == "baseline":
            extra = ["--checkpoint-dir", args.checkpoint_dir]
        argv = argv_for(cell, processed=args.processed_dir, profile=args.profile, split_seed=args.split_seed,
                        splits_dir=args.splits_dir, results_dir=results, models_dir=args.models_dir, extra=extra)
        print(f"[seeds] ({i}/{len(todo)}) {cell.key}: {' '.join(argv)}", flush=True)
        if args.dry_run:
            continue
        t0 = time.perf_counter()
        record = _run_cell(cell, argv)
        record["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        manifest["runs"][cell.key] = record
        write_manifest(path, manifest)             # after every fit: a crash loses at most one
        print(f"[seeds] {cell.key} -> {record['run_id']} in {time.perf_counter() - t0:.0f} s", flush=True)
        if args.pause_seconds and i < len(todo):
            time.sleep(args.pause_seconds)
    if not args.dry_run:
        write_manifest(path, manifest)
    return manifest


def main(argv: list[str] | None = None) -> int:
    run(_parse_args(argv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
