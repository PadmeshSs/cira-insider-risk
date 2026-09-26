"""Rule-based floor baseline (Bible Ch6 step 1).

Fixed presence rules over Chapter 5 feature columns. The score of a
user-day is the fraction of rules that fire, which is already in [0, 1].

Provenance of the rules. They are generic insider-risk indicators (activity
outside working hours, removable media, job-search browsing, consumer cloud
storage / leak sites, hacking-tool sites, archive or executable files, new
machines). They overlap with the published CERT scenario descriptions, which
makes this floor, if anything, optimistic. Thresholds are "> 0" everywhere
and were not tuned against labels; ``fit`` never sees labels.

Only signals CERT r4.2 actually contains are used (N9): there are no failed
logins, upload events, byte volumes or process logs here.

Expect many tied scores. The metrics module breaks ties at the daily budget
with a seeded random key, not by user id.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import numpy as np
import pandas as pd

from .base import BaselineDetector

RULE_SET_VERSION = "rules-v1"


@dataclass(frozen=True)
class Rule:
    name: str
    columns: tuple[str, ...]
    description: str
    fires: Callable[[pd.DataFrame], np.ndarray]


def _any_positive(*cols: str) -> Callable[[pd.DataFrame], np.ndarray]:
    def f(frame: pd.DataFrame) -> np.ndarray:
        total = np.zeros(len(frame), dtype="float64")
        for c in cols:
            total += frame[c].fillna(0).to_numpy(dtype="float64")
        return total > 0

    return f


RULES: tuple[Rule, ...] = (
    Rule("off_hours_logon", ("off_hours_logins",), "at least one logon before 07:00 or from 19:00", _any_positive("off_hours_logins")),
    Rule("weekend_logon", ("weekend_logins",), "at least one logon on Saturday or Sunday", _any_positive("weekend_logins")),
    Rule("off_hours_usb", ("usb_off_hours_events",), "removable-media activity outside working hours", _any_positive("usb_off_hours_events")),
    Rule("new_machine", ("new_device_count",), "logon to a PC not seen before for this user", _any_positive("new_device_count")),
    Rule("job_search_sites", ("http_job_search_count",), "visits to job-search hosts", _any_positive("http_job_search_count")),
    Rule(
        "cloud_storage_or_leak_sites",
        ("http_cloud_storage_count", "http_leak_paste_count"),
        "visits to consumer cloud-storage or leak/paste hosts (visits only; r4.2 has no upload events)",
        _any_positive("http_cloud_storage_count", "http_leak_paste_count"),
    ),
    Rule("hacking_tool_sites", ("http_hacking_tools_count",), "visits to hacking-tool / keylogger hosts", _any_positive("http_hacking_tools_count")),
    Rule(
        "archive_or_executable_files",
        ("file_archive_or_executable_count",),
        "file activity on .zip or .exe files",
        _any_positive("file_archive_or_executable_count"),
    ),
)


class RuleBasedDetector(BaselineDetector):
    name = "rule_based"
    calibrate = False

    def __init__(self, *, seed: int = 42, **config) -> None:
        config.setdefault("rule_set_version", RULE_SET_VERSION)
        config.setdefault("rules", [r.name for r in RULES])
        super().__init__(seed=seed, **config)
        self._rules = [r for r in RULES if r.name in set(self.config["rules"])]
        self.train_fire_rates: dict[str, float] = {}

    def _check_columns(self, frame: pd.DataFrame) -> None:
        missing = sorted({c for r in self._rules for c in r.columns} - set(frame.columns))
        if missing:
            raise KeyError(f"rule baseline needs columns not in the matrix: {missing}")

    def fired(self, frame: pd.DataFrame) -> pd.DataFrame:
        """One boolean column per rule; reusable for explanations later."""
        self._check_columns(frame)
        return pd.DataFrame({r.name: r.fires(frame) for r in self._rules}, index=frame.index)

    def _fit(self, train, y, validation, y_validation) -> None:
        fired = self.fired(train)
        # Label-blind description of how noisy each rule is on training rows.
        self.train_fire_rates = {k: float(v) for k, v in fired.mean().items()}

    def _raw_score(self, frame: pd.DataFrame, **_) -> np.ndarray:
        return self.fired(frame).to_numpy().mean(axis=1).astype("float64")

    def _extra_metadata(self) -> dict:
        return {
            "rules": [{"name": r.name, "columns": list(r.columns), "description": r.description} for r in self._rules],
            "train_fire_rates": self.train_fire_rates,
        }

    def _save_artifacts(self, directory: Path) -> dict:
        return {}

    def _load_artifacts(self, directory: Path, meta: dict) -> None:
        self.train_fire_rates = dict(meta.get("train_fire_rates", {}))
