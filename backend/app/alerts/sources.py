"""Where alert runs live, and reading them (label-free, N5).

Layout of one run: ``<processed>/alerts/chapter12/<alert_run_id>/``
    alerts.parquet          one row per alert (open and suppressed)
    alert_members.parquet   one row per member user-day, with its triggers
    alert_reasons.parquet   one row per explanation item (model / cri / mitre), N50
    explanations.jsonl      the full Chapter 11 explanation of every member day
    demo_sample.parquet     the D-6 demo sample keys (c12-demo-sample-v1)
    alert_meta.json         lineage, policy, summary
    loads/                  one ``load_<stamp>.json`` per load that committed
"""
from __future__ import annotations

import json
from pathlib import Path

ALERTS_OUTPUT = "alerts.parquet"
MEMBERS_OUTPUT = "alert_members.parquet"
REASONS_OUTPUT = "alert_reasons.parquet"
EXPLANATIONS_OUTPUT = "explanations.jsonl"
DEMO_OUTPUT = "demo_sample.parquet"
ALERT_META = "alert_meta.json"
LOADS_DIR = "loads"
REQUIRED = (ALERTS_OUTPUT, MEMBERS_OUTPUT, REASONS_OUTPUT, EXPLANATIONS_OUTPUT, DEMO_OUTPUT, ALERT_META)


class AlertSourceError(RuntimeError):
    """A required alert run is missing or incomplete."""


def runs_root(processed: str | Path) -> Path:
    return Path(processed) / "alerts" / "chapter12"


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def alert_run_dir(processed: str | Path, run_id: str | None, profile: str | None = None) -> Path:
    root = runs_root(processed)
    if run_id:
        path = root / run_id
    else:
        runs = [d for d in sorted(root.iterdir()) if (d / ALERT_META).exists()
                and (profile is None or _read(d / ALERT_META).get("profile") == profile)] if root.exists() else []
        if not runs:
            raise AlertSourceError(f"no Chapter 12 alert run for profile={profile!r} under {root}")
        path = runs[-1]                               # run ids start with a UTC timestamp
    for f in REQUIRED:
        if not (path / f).exists():
            raise AlertSourceError(f"alert run {path.name} is incomplete (missing {f})")
    return path


def read_meta(run_dir: Path) -> dict:
    return _read(run_dir / ALERT_META)


def read_explanations(run_dir: Path) -> list[dict]:
    text = (run_dir / EXPLANATIONS_OUTPUT).read_text(encoding="utf-8")
    return [json.loads(x) for x in text.splitlines() if x.strip()]


def load_records(run_dir: Path) -> list[dict]:
    d = run_dir / LOADS_DIR
    return [_read(p) for p in sorted(d.glob("load_*.json"))] if d.exists() else []
