"""Rarity scale and the pinned CRI calibration (N29, N33).

Why a calibration at all
    XGBoost and TabNet put their anomaly scores in [0, 1], but on very
    different scales. The served XGBoost's full-profile batch has a median
    score of 8e-8, a 99th percentile of 5e-4 and a 99.9th percentile of
    0.99999 (docs/audits/chapter_8_audit.md). A weighted sum over the raw
    score would make the anomaly term almost binary, and the same severity
    thresholds would mean something else for the shadow TabNet. N29 already
    says the thresholds belong to one model_version.

What rarity is
    For a value x and a reference sample of n values,

        p(x)      = (#{reference >= x} + 1) / (n + 1)        exceedance probability
        rarity(x) = min(1, log10(1 / p(x)) / D)              D = CRI_RARITY_DECADES (5)

    0 means "as common as the bulk of the reference", 1 means "rarer than
    1 in 10**D". The map is monotone non-decreasing in x, and strictly
    increasing across distinct reference values, so the anomaly component
    alone ranks user-days exactly like the anomaly score does on the
    reference rows (N10: any map must be monotone). Values above the whole
    reference share the top value 1/(n + 1): that is a real resolution limit
    of a finite reference, counted in the batch meta as "beyond reference".

    D is fixed rather than log10(n + 1) so a band means the same exceedance
    probability for every model and profile. A small reference simply cannot
    certify extreme rarity: with n = 89,018 (full validation) the maximum is
    log10(89,019) / 5 = 0.99.

The reference
    The served model's validation user-days from its Chapter 8 batch:
    out-of-sample (the model never saw their labels, unlike train rows, N31),
    and not test (test stays unread, N11). The calibration reads split tags
    only, never labels. The extreme tail of the pooled batch is where a
    supervised model's in-sample training insiders sit, which is why neither
    all rows nor train rows are used.

The pin
    ``experiments/chapter9_cri_calibration.json`` (committed) names the
    calibration id, the model it was fitted for and the sha256 of the
    reference file under ``models/saved_models/cri/<calibration_id>/``
    (gitignored, like model artifacts). Loading verifies the sha256; the
    engine refuses scores from any other model_version.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

import numpy as np
import pandas as pd

from app.feature_engineering.common import repo_root

PIN_FILE = "chapter9_cri_calibration.json"
REFERENCE_FILE = "reference.parquet"
META_FILE = "calibration.json"
DEFINITION_VERSION = "c9-rarity-v1"
ANOMALY_STAT = "anomaly_score"
HISTORICAL_STAT = "historical_statistic"
PEER_STAT = "peer_statistic"
PEER_POS_PREFIX = "peer_pos__"


class CalibrationUnavailableError(RuntimeError):
    """No usable calibration: missing, tampered, or fitted for another model."""


def default_pin_path() -> Path:
    return repo_root() / "experiments" / PIN_FILE


def default_models_root() -> Path:
    return repo_root() / "models" / "saved_models"


def resolve_pin_path(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    return Path(env.get("CIRA_CRI_CALIBRATION") or default_pin_path())


def file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Rarity
# ---------------------------------------------------------------------------

def sorted_reference(values) -> np.ndarray:
    v = np.asarray(values, dtype="float64")
    v = v[np.isfinite(v)]
    return np.sort(v, kind="mergesort")


def exceedance(x, reference_sorted: np.ndarray) -> np.ndarray:
    """(#{ref >= x} + 1) / (n + 1); NaN where x is NaN."""
    x = np.asarray(x, dtype="float64")
    n = len(reference_sorted)
    ge = n - np.searchsorted(reference_sorted, np.where(np.isnan(x), 0.0, x), side="left")
    p = (ge + 1.0) / (n + 1.0)
    return np.where(np.isnan(x), np.nan, p)


def rarity(x, reference_sorted: np.ndarray, decades: float) -> np.ndarray:
    if len(reference_sorted) == 0:
        raise CalibrationUnavailableError("empty reference: rarity is undefined")
    p = exceedance(x, reference_sorted)
    with np.errstate(invalid="ignore"):
        r = np.log10(1.0 / p) / float(decades)
    return np.where(np.isnan(p), np.nan, np.clip(r, 0.0, 1.0))


def beyond_reference(x, reference_sorted: np.ndarray) -> np.ndarray:
    """True where x is above every reference value (rarity at its ceiling)."""
    x = np.asarray(x, dtype="float64")
    return np.isfinite(x) & (x > reference_sorted[-1]) if len(reference_sorted) else np.zeros(len(x), dtype=bool)


@dataclass
class RarityMaps:
    """Sorted reference samples, one per statistic, and the scale D."""

    decades: float
    references: dict[str, np.ndarray] = field(default_factory=dict)

    def apply(self, name: str, x) -> np.ndarray:
        if name not in self.references:
            raise CalibrationUnavailableError(f"calibration has no reference for {name!r}")
        return rarity(x, self.references[name], self.decades)

    def beyond(self, name: str, x) -> np.ndarray:
        return beyond_reference(x, self.references[name])

    def peer_columns(self) -> list[str]:
        return sorted(k[len(PEER_POS_PREFIX):] for k in self.references if k.startswith(PEER_POS_PREFIX))

    def peer_statistic(self, positives: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        """Max over peer columns of per-column rarity, and which column gave it.

        ``positives`` holds the positive part of each ``peer_dev_<feature>``
        (columns named by feature). Stage 1 of the two-stage peer component:
        the raw deviations have different units (logins, emails, hosts), so
        each is first put on the rarity scale; stage 2 (in the engine) takes
        the rarity of this maximum, because a maximum over several columns
        is larger than any one of them by construction.
        """
        cols = self.peer_columns()
        if not cols:
            n = len(positives)
            return np.full(n, np.nan), np.full(n, None, dtype=object)
        block = np.column_stack([self.apply(PEER_POS_PREFIX + c, positives[c].to_numpy(dtype="float64")) for c in cols])
        all_nan = np.isnan(block).all(axis=1)
        filled = np.where(np.isnan(block), -1.0, block)
        idx = filled.argmax(axis=1)
        stat = np.where(all_nan, np.nan, filled[np.arange(len(block)), idx])
        top = np.where(all_nan, None, np.asarray(cols, dtype=object)[idx])
        return stat, top


def fit_maps(reference: pd.DataFrame, decades: float) -> RarityMaps:
    """Build every rarity map from a reference frame (see ``build_reference``)."""
    maps = RarityMaps(decades=float(decades))
    for col in reference.columns:
        if col == ANOMALY_STAT or col == HISTORICAL_STAT or col.startswith(PEER_POS_PREFIX):
            maps.references[col] = sorted_reference(reference[col])
    if ANOMALY_STAT not in maps.references or len(maps.references[ANOMALY_STAT]) == 0:
        raise CalibrationUnavailableError("the reference has no anomaly scores")
    positives = pd.DataFrame({c: reference[PEER_POS_PREFIX + c] for c in maps.peer_columns()}, index=reference.index)
    stat, _ = maps.peer_statistic(positives)
    maps.references[PEER_STAT] = sorted_reference(stat)
    return maps


# ---------------------------------------------------------------------------
# Loading and saving
# ---------------------------------------------------------------------------

@dataclass
class LoadedCalibration:
    meta: dict
    maps: RarityMaps
    pin: dict
    reference_path: Path

    @property
    def calibration_id(self) -> str:
        return self.meta["calibration_id"]

    @property
    def model(self) -> dict:
        return self.meta["model"]

    def describe(self) -> dict:
        m = self.model
        return {
            "calibration_id": self.calibration_id,
            "definition_version": self.meta.get("definition_version"),
            "model_name": m.get("model_name"),
            "model_version": m.get("model_version"),
            "registry_version": m.get("registry_version"),
            "reference_part": self.meta.get("reference", {}).get("part"),
            "reference_rows": self.meta.get("reference", {}).get("rows"),
            "rarity_decades": self.maps.decades,
            "config_hash_at_calibration": (self.meta.get("config_at_calibration") or {}).get("config_hash"),
        }


def load_calibration(pin_path: str | Path | None = None, models_root: str | Path | None = None,
                     *, verify: bool = True) -> LoadedCalibration:
    pin_path = Path(pin_path) if pin_path else resolve_pin_path()
    if not pin_path.exists():
        raise CalibrationUnavailableError(
            f"no CRI calibration at {pin_path}; run `python -m app.cri.calibrate` for the served model")
    try:
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
        current = pin["current"]
        cal_id = current["calibration_id"]
    except (ValueError, KeyError, TypeError) as exc:
        raise CalibrationUnavailableError(f"unreadable calibration pin {pin_path}: {exc}") from exc
    root = Path(models_root) if models_root else Path(os.getenv("MODEL_PATH") or default_models_root())
    cal_dir = root / "cri" / cal_id
    ref_path, meta_path = cal_dir / REFERENCE_FILE, cal_dir / META_FILE
    if not ref_path.exists() or not meta_path.exists():
        raise CalibrationUnavailableError(f"calibration {cal_id} files not found under {cal_dir}")
    if verify:
        for path, key in ((ref_path, "reference_sha256"), (meta_path, "meta_sha256")):
            digest = file_sha256(path)
            if digest != current.get(key):
                raise CalibrationUnavailableError(
                    f"{path.name} of calibration {cal_id} has sha256 {digest[:12]}, the pin records "
                    f"{str(current.get(key))[:12]}; refusing a modified calibration")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("definition_version") != DEFINITION_VERSION:
        raise CalibrationUnavailableError(
            f"calibration {cal_id} uses definition {meta.get('definition_version')!r}, this code {DEFINITION_VERSION!r}")
    reference = pd.read_parquet(ref_path)
    maps = fit_maps(reference, meta["rarity_decades"])
    return LoadedCalibration(meta=meta, maps=maps, pin=pin, reference_path=ref_path)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def save_calibration(meta: dict, reference: pd.DataFrame, *, models_root: Path, pin_path: Path,
                     supersede_reason: str | None = None) -> dict:
    """Write reference + meta under models_root/cri/<id>/ and point the pin at them.

    A calibration directory is never replaced. An existing pin is replaced
    only with a reason, and the old entry is kept inside the new pin.
    """
    cal_id = meta["calibration_id"]
    cal_dir = models_root / "cri" / cal_id
    if cal_dir.exists():
        raise FileExistsError(f"{cal_dir} exists; a calibration is never overwritten")
    previous = None
    if pin_path.exists():
        previous = json.loads(pin_path.read_text(encoding="utf-8"))
        if not supersede_reason:
            raise FileExistsError(
                f"{pin_path} already pins calibration {previous.get('current', {}).get('calibration_id')}; "
                "pass --supersede \"<reason>\" to replace it (the old entry is kept)")
    cal_dir.mkdir(parents=True)
    ref_path = cal_dir / REFERENCE_FILE
    tmp = ref_path.with_name(ref_path.name + ".tmp")
    reference.to_parquet(tmp, index=False)
    tmp.replace(ref_path)
    _atomic_write(cal_dir / META_FILE, json.dumps(meta, indent=2, default=str))
    current = {
        "calibration_id": cal_id,
        "created_at": meta["created_at"],
        "model": meta["model"],
        "source_batch_run_id": meta["source_batch"]["batch_run_id"],
        "reference_rows": meta["reference"]["rows"],
        "reference_sha256": file_sha256(ref_path),
        "meta_sha256": file_sha256(cal_dir / META_FILE),
        "definition_version": meta["definition_version"],
        "config_hash_at_calibration": meta["config_at_calibration"]["config_hash"],
    }
    pin = {
        "chapter": 9,
        "description": ("The CRI calibration in use (N29, N33). Engine and API refuse scores from any other "
                        "model_version. Replace only with `python -m app.cri.calibrate --supersede \"<reason>\"`."),
        "current": current,
        "superseded": ([] if previous is None else [*previous.get("superseded", []),
                                                     {**previous.get("current", {}), "superseded_because": supersede_reason}]),
    }
    _atomic_write(pin_path, json.dumps(pin, indent=2, default=str))
    return pin
