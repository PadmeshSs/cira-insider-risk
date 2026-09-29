"""Rarity reference for rule strength, and the pin (N33, N42).

Why grade at all
    Some mapped behaviours are everyday on CERT: many users copy files to
    removable media on ordinary days (R01). A flat "technique matched = 1"
    would add the same MITRE points to thousands of benign user-days and
    tell the analyst nothing. So a match is graded by how unusual its
    triggering activity is, on the same rarity scale the CRI already uses
    (``app.cri.calibration``, D = CRI_RARITY_DECADES):

        stage 1  strength_r = rarity(intensity_r)            per rule, against the
                                                             reference values of that column
        stage 2  mitre_context = rarity(max_r strength_r)    against the reference
                                                             distribution of that maximum

    Stage 2 exists for the reason the peer component has it: a maximum over
    several rules is larger than any one of them by construction. A user-day
    where no rule fired has every strength at 0, so ``mitre_context`` = 0
    exactly (N33: 0 = no mapped technique). A user-day whose rule columns are
    all null gets null (not evaluated).

The reference: validation user-days of the shared user split
    The same users every model is validated on (N11), taken from the split
    file, not from a model's batch. That keeps the MITRE layer model-free:
    XGBoost and TabNet are validated on identical users, so the reference
    does not change when the served model changes, and a rollback needs no
    MITRE refit. Train rows are not used (the reference should be out of
    sample like Chapter 9's) and test rows stay unread (N11). No label is
    read; the split file holds only user -> split.

The pin
    ``experiments/chapter10_mitre_reference.json`` (committed) names the
    reference id and the sha256 of ``reference.parquet`` and
    ``reference.json`` under ``models/saved_models/mitre/<reference_id>/``
    (gitignored). Loading verifies both, and refuses a reference fitted for
    another ruleset, ATT&CK table or definition. A pin is replaced only with
    a reason; the old entry is kept.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

import numpy as np
import pandas as pd

from app.cri.calibration import file_sha256, rarity, sorted_reference
from app.feature_engineering.common import repo_root

from .mapping_rules import RULES, RULESET_VERSION, ruleset_hash

PIN_FILE = "chapter10_mitre_reference.json"
REFERENCE_FILE = "reference.parquet"
META_FILE = "reference.json"
DEFINITION_VERSION = "c10-mitre-rarity-v1"
STRENGTH_STAT = "mitre_strength_max"


class MitreReferenceUnavailableError(RuntimeError):
    """No usable MITRE reference: missing, modified, or fitted for other rules."""


def default_pin_path() -> Path:
    return repo_root() / "experiments" / PIN_FILE


def default_models_root() -> Path:
    return repo_root() / "models" / "saved_models"


def resolve_pin_path(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    return Path(env.get("CIRA_MITRE_REFERENCE") or default_pin_path())


@dataclass
class MitreMaps:
    """Sorted reference values per rule column (stage 1) and of the maximum (stage 2)."""

    decades: float
    columns: dict[str, np.ndarray] = field(default_factory=dict)
    strength_max: np.ndarray | None = None

    def rule_strength(self, rule, values: np.ndarray) -> np.ndarray:
        """Stage 1 for one rule: rarity where the rule fired, 0 where it did not, NaN where null."""
        v = np.asarray(values, dtype="float64")
        if rule.intensity_column not in self.columns:
            raise MitreReferenceUnavailableError(f"reference has no values for {rule.intensity_column!r}")
        fired = np.isfinite(v) & (v > 0)
        r = rarity(np.where(np.isfinite(v), v, 0.0), self.columns[rule.intensity_column], self.decades)
        return np.where(~np.isfinite(v), np.nan, np.where(fired, r, 0.0))

    def strengths(self, frame: pd.DataFrame) -> np.ndarray:
        """[n x rules] stage-1 strengths in RULES order."""
        return np.column_stack([
            self.rule_strength(r, frame[r.intensity_column].to_numpy(dtype="float64", na_value=np.nan)) for r in RULES
        ])

    @staticmethod
    def max_strength(block: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """(max over evaluable rules, index of that rule); NaN / -1 where nothing was evaluable."""
        all_nan = np.isnan(block).all(axis=1)
        filled = np.where(np.isnan(block), -1.0, block)
        idx = filled.argmax(axis=1)
        stat = np.where(all_nan, np.nan, filled[np.arange(len(block)), idx])
        return stat, np.where(all_nan, -1, idx)

    def context(self, stat: np.ndarray) -> np.ndarray:
        """Stage 2: mitre_context in [0, 1]; NaN stays NaN."""
        if self.strength_max is None or len(self.strength_max) == 0:
            raise MitreReferenceUnavailableError("reference has no stage-2 distribution")
        s = np.asarray(stat, dtype="float64")
        out = rarity(np.where(np.isnan(s), 0.0, s), self.strength_max, self.decades)
        return np.where(np.isnan(s), np.nan, out)


def fit_maps(reference: pd.DataFrame, decades: float) -> MitreMaps:
    maps = MitreMaps(decades=float(decades))
    for r in RULES:
        if r.intensity_column not in reference.columns:
            raise MitreReferenceUnavailableError(f"reference frame lacks {r.intensity_column!r}")
        maps.columns[r.intensity_column] = sorted_reference(reference[r.intensity_column])
        if len(maps.columns[r.intensity_column]) == 0:
            raise MitreReferenceUnavailableError(f"no finite reference values for {r.intensity_column!r}")
    stat, _ = maps.max_strength(maps.strengths(reference))
    maps.strength_max = sorted_reference(stat)
    return maps


@dataclass
class LoadedReference:
    meta: dict
    maps: MitreMaps
    pin: dict
    reference_path: Path

    @property
    def reference_id(self) -> str:
        return self.meta["reference_id"]

    def describe(self) -> dict:
        return {
            "reference_id": self.reference_id,
            "definition_version": self.meta.get("definition_version"),
            "ruleset_version": self.meta.get("ruleset_version"),
            "ruleset_hash": self.meta.get("ruleset_hash"),
            "attack_version": self.meta.get("attack_version"),
            "reference_part": self.meta.get("reference", {}).get("part"),
            "reference_rows": self.meta.get("reference", {}).get("rows"),
            "rarity_decades": self.maps.decades,
            "features_fingerprint": self.meta.get("features", {}).get("fingerprint"),
        }


def load_reference(pin_path: str | Path | None = None, models_root: str | Path | None = None, *,
                   verify: bool = True, table=None) -> LoadedReference:
    pin_path = Path(pin_path) if pin_path else resolve_pin_path()
    if not pin_path.exists():
        raise MitreReferenceUnavailableError(
            f"no MITRE reference at {pin_path}; run `python -m app.mitre.calibrate`")
    try:
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
        current = pin["current"]
        ref_id = current["reference_id"]
    except (ValueError, KeyError, TypeError) as exc:
        raise MitreReferenceUnavailableError(f"unreadable MITRE reference pin {pin_path}: {exc}") from exc
    root = Path(models_root) if models_root else Path(os.getenv("MODEL_PATH") or default_models_root())
    ref_dir = root / "mitre" / ref_id
    ref_path, meta_path = ref_dir / REFERENCE_FILE, ref_dir / META_FILE
    if not ref_path.exists() or not meta_path.exists():
        raise MitreReferenceUnavailableError(f"MITRE reference {ref_id} files not found under {ref_dir}")
    if verify:
        for path, key in ((ref_path, "reference_sha256"), (meta_path, "meta_sha256")):
            digest = file_sha256(path)
            if digest != current.get(key):
                raise MitreReferenceUnavailableError(
                    f"{path.name} of MITRE reference {ref_id} has sha256 {digest[:12]}, the pin records "
                    f"{str(current.get(key))[:12]}; refusing a modified reference")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("definition_version") != DEFINITION_VERSION:
        raise MitreReferenceUnavailableError(
            f"reference {ref_id} uses definition {meta.get('definition_version')!r}, this code {DEFINITION_VERSION!r}")
    if meta.get("ruleset_hash") != ruleset_hash():
        raise MitreReferenceUnavailableError(
            f"reference {ref_id} was fitted for ruleset {meta.get('ruleset_version')} ({meta.get('ruleset_hash')}), "
            f"the code has {RULESET_VERSION} ({ruleset_hash()}); a changed rule needs a refit")
    if table is not None and meta.get("table_sha256") != table.table_sha256:
        raise MitreReferenceUnavailableError(
            f"reference {ref_id} was fitted with technique table {str(meta.get('table_sha256'))[:12]}, "
            f"the loaded table is {table.table_sha256[:12]}")
    reference = pd.read_parquet(ref_path)
    maps = fit_maps(reference, meta["rarity_decades"])
    return LoadedReference(meta=meta, maps=maps, pin=pin, reference_path=ref_path)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def save_reference(meta: dict, reference: pd.DataFrame, *, models_root: Path, pin_path: Path,
                   supersede_reason: str | None = None) -> dict:
    """Write reference + meta under models_root/mitre/<id>/ and point the pin at them.

    A reference directory is never replaced; an existing pin only with a reason.
    """
    ref_id = meta["reference_id"]
    ref_dir = models_root / "mitre" / ref_id
    if ref_dir.exists():
        raise FileExistsError(f"{ref_dir} exists; a reference is never overwritten")
    previous = None
    if pin_path.exists():
        previous = json.loads(pin_path.read_text(encoding="utf-8"))
        if not supersede_reason:
            raise FileExistsError(
                f"{pin_path} already pins MITRE reference {previous.get('current', {}).get('reference_id')}; "
                "pass --supersede \"<reason>\" to replace it (the old entry is kept)")
    ref_dir.mkdir(parents=True)
    ref_path = ref_dir / REFERENCE_FILE
    tmp = ref_path.with_name(ref_path.name + ".tmp")
    reference.to_parquet(tmp, index=False)
    tmp.replace(ref_path)
    _atomic_write(ref_dir / META_FILE, json.dumps(meta, indent=2, default=str))
    current = {
        "reference_id": ref_id,
        "created_at": meta["created_at"],
        "ruleset_version": meta["ruleset_version"],
        "ruleset_hash": meta["ruleset_hash"],
        "attack_version": meta["attack_version"],
        "table_sha256": meta["table_sha256"],
        "reference_rows": meta["reference"]["rows"],
        "reference_sha256": file_sha256(ref_path),
        "meta_sha256": file_sha256(ref_dir / META_FILE),
        "definition_version": meta["definition_version"],
        "features_fingerprint": meta["features"]["fingerprint"],
    }
    pin = {
        "chapter": 10,
        "description": ("The MITRE rarity reference in use (N42). Model-free: fitted on validation users of the "
                        "shared split, never on a model's scores. Replace only with "
                        "`python -m app.mitre.calibrate --supersede \"<reason>\"`."),
        "current": current,
        "superseded": ([] if previous is None else [*previous.get("superseded", []),
                                                     {**previous.get("current", {}), "superseded_because": supersede_reason}]),
    }
    _atomic_write(pin_path, json.dumps(pin, indent=2, default=str))
    return pin
