"""Every ranking Chapter 16 compares, loaded from stored runs and aligned on one set of user-days.

Nothing is trained or scored here. The rankings come from files earlier chapters wrote:

    baseline:*            Chapter 6 reference runs (N18), score files under <processed>/scores/chapter6/
    tabnet                Chapter 7 reference run (N24), the shadow model since C8-1
    xgboost_served        the served model's anomaly score, from the Chapter 9/10 risk run
    cri:no_mitre_context  the Chapter 9 formula, recombined from the stored components (HCEA §9)
    cri:default           the configured CRI with MITRE context (Chapter 10)
    cri:no_*              Chapter 9 leave-one-out variants (MITRE off), recombined
    cri:no_peer_deviation+no_user_context
                          the variant that looked better on VALIDATION (N40). It is read here and not
                          adopted; the readout labels it validation-informed.
    mitre_context         the MITRE component alone, as a ranking (not a detector, N42)

Every ranking is for ONE part (validation or test) of the served model's split. A baseline file that does
not cover exactly the same (user, date) rows is a refusal, not a silent inner join (N11, N18).

The comparison chain in the Bible is Baseline -> TabNet -> TabNet + CRI -> TabNet + CRI + MITRE. The CRI is
calibrated for the served model's validation rows (N33) and the shadow's scores never feed it (N32), so the
chain here ends in the served XGBoost: baselines -> TabNet (shadow) -> XGBoost -> XGBoost + CRI ->
XGBoost + CRI + MITRE. This is deviation C16-1, stated in every readout.

Reads labels (in memory, through app.evaluation.labels) and is never imported by a serving module (N5).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from app.cri.config import COMPONENTS, CRIConfig
from app.cri.engine import combine
from app.cri.sources import RISK_META, RISK_OUTPUT
from app.evaluation import compare
from app.evaluation.labels import attach_labels, load_label_views
from app.evaluation.metrics import pr_auc
from app.feature_engineering.common import repo_root
from app.mitre.sources import mitre_run_dir, read_context
from app.tabnet.dataset import file_sha256

BASELINES = ("rule_based", "isolation_forest", "lof", "lstm_autoencoder", "gbdt")
BASELINE_LABEL = {"gbdt": "gbdt_all_features"}          # the Chapter 6 XGBoost saw every Chapter 5 column
CRI_VARIANTS = {
    # name -> components switched off on top of the configured CRI, applied to the with-MITRE risk run
    "cri:default": (),
    "cri:no_mitre_context": ("no_mitre_context",),
    "cri:no_historical_deviation": ("no_mitre_context", "no_historical_deviation"),
    "cri:no_peer_deviation": ("no_mitre_context", "no_peer_deviation"),
    "cri:no_user_context": ("no_mitre_context", "no_user_context"),
    "cri:no_peer_deviation+no_user_context": ("no_mitre_context", "no_peer_deviation", "no_user_context"),
}
VALIDATION_INFORMED = ("cri:no_peer_deviation+no_user_context",)
BAND_VARIANTS = tuple(CRI_VARIANTS)
SERVED = "xgboost_served"
SHADOW = "tabnet"
CHAIN = (
    ("baseline (best on validation)", "{best_baseline}"),
    ("TabNet (shadow, behaviour-only)", SHADOW),
    ("XGBoost (served, behaviour-only)", SERVED),
    ("XGBoost + CRI", "cri:no_mitre_context"),
    ("XGBoost + CRI + MITRE", "cri:default"),
)


class RankingError(RuntimeError):
    """The stored runs cannot be compared as given."""


@dataclass
class Population:
    """The user-days of one part, with everything the readout needs aligned to them."""

    part: str
    profile: str
    processed: Path
    keys: pd.DataFrame
    labels: pd.DataFrame
    risk: pd.DataFrame
    risk_dir: Path
    risk_meta: dict
    config: CRIConfig
    available: set[str]
    components: dict[str, np.ndarray]
    mitre: pd.DataFrame
    provenance: dict = field(default_factory=dict)

    @property
    def y(self) -> np.ndarray:
        return self.labels["y_primary"].to_numpy()

    @property
    def exclude(self) -> np.ndarray:
        return self.labels["exclude_primary"].to_numpy().astype(bool)

    @property
    def scenario(self) -> np.ndarray:
        return self.labels["scenario_primary"].to_numpy()

    @property
    def users(self) -> np.ndarray:
        return self.keys["user_id"].astype(str).to_numpy()

    @property
    def dates(self) -> pd.Series:
        return self.keys["date"].astype(str)


def newest_risk_run_with_mitre(processed: Path, profile: str) -> Path:
    root = processed / "risk" / "chapter9"
    found = []
    for d in sorted(root.iterdir()) if root.exists() else []:
        m = d / RISK_META
        if not m.exists():
            continue
        meta = json.loads(m.read_text(encoding="utf-8"))
        if meta.get("profile") == profile and meta.get("mitre") and meta.get("variant") == "default" \
                and not meta.get("config", {}).get("disabled"):
            found.append(d)
    if not found:
        raise RankingError(f"no default CRI run with MITRE for profile={profile!r} under {root}; run "
                           "`python -m app.cri.batch --profile <p> --with-mitre` first")
    return found[-1]


def _config_from_meta(meta: dict) -> CRIConfig:
    from app.cri.evaluate import config_from_meta

    return config_from_meta(meta)


def load_population(processed: str | Path, profile: str, part: str, *, cri_run_id: str | None = None) -> Population:
    if part not in ("validation", "test"):
        raise RankingError("part must be validation or test (train rows are in-sample, N31)")
    processed = Path(processed)
    run_dir = processed / "risk" / "chapter9" / cri_run_id if cri_run_id else newest_risk_run_with_mitre(processed, profile)
    meta = json.loads((run_dir / RISK_META).read_text(encoding="utf-8"))
    if not meta.get("mitre"):
        raise RankingError(f"risk run {run_dir.name} was made without MITRE")
    if meta.get("variant") != "default" or meta.get("config", {}).get("disabled"):
        raise RankingError(f"risk run {run_dir.name} is not the default variant; variants are recombined from it")
    risk = pd.read_parquet(run_dir / RISK_OUTPUT)
    risk = risk[risk["model_split"].astype(str) == part].copy()
    risk["user_id"] = risk["user_id"].astype("string").str.strip().str.casefold()
    risk["date"] = risk["date"].astype("string")
    risk = risk.sort_values(["user_id", "date"], kind="mergesort").reset_index(drop=True)
    if risk.empty:
        raise RankingError(f"risk run {run_dir.name} has no {part} rows")
    keys = risk[["user_id", "date"]].copy()
    mitre_dir = mitre_run_dir(processed, meta["mitre"]["mitre_run_id"])
    mitre = read_context(mitre_dir, keys, ["mitre_status", "mitre_context", "mitre_rules"])
    views = load_label_views(processed)
    labels = attach_labels(keys, views)
    available = {c for c in COMPONENTS if c not in meta.get("unavailable_components", {})}
    if "mitre_context" not in available:
        raise RankingError("the risk run lists mitre_context as unavailable")
    comps = {c: risk[f"component_{c}"].to_numpy(dtype="float64", na_value=np.nan) for c in COMPONENTS}
    prov = {
        "risk_run_id": run_dir.name,
        "risk_scores_sha256": file_sha256(run_dir / RISK_OUTPUT),
        "cri_config_hash": meta.get("config_hash"),
        "calibration_id": (meta.get("calibration") or {}).get("calibration_id"),
        "served": meta.get("served"),
        "mitre_run_id": meta["mitre"]["mitre_run_id"],
        "labels": "primary view (N1); masquerade account-days neither hit nor false alarm",
    }
    return Population(part, profile, processed, keys, labels, risk, run_dir, meta, _config_from_meta(meta), available,
                      comps, mitre, prov)


def cri_variant_outputs(pop: Population) -> dict[str, dict]:
    """name -> combine() output for every CRI variant, recombined from the stored components (HCEA §9)."""
    out = {}
    for name, steps in CRI_VARIANTS.items():
        cfg = pop.config
        for step in steps:
            cfg = cfg.variant(step)
        out[name] = combine(pop.components, pop.available, cfg)
    stored = pop.risk["cri_score"].to_numpy(dtype="float64")
    diff = float(np.abs(stored - out["cri:default"]["cri"]).max())
    if diff > 1e-9:
        raise RankingError(f"recombining the stored components does not reproduce the stored cri_score "
                           f"(max difference {diff:.2e}); the risk run and this code disagree")
    return out


def _aligned_scores(src: compare.ScoreSource, pop: Population) -> np.ndarray:
    frame = compare._load_part(src, pop.part)
    same = len(frame) == len(pop.keys) and (frame["user_id"].to_numpy() == pop.keys["user_id"].astype(str).to_numpy()).all() \
        and (frame["date"].to_numpy() == pop.keys["date"].astype(str).to_numpy()).all()
    if not same:
        raise RankingError(f"{src.label} ({src.run_id}) scores {len(frame)} {pop.part} rows and the served model's risk run "
                           f"has {len(pop.keys)}; they did not use the same split or matrix (N11, N18)")
    return frame["anomaly_score"].to_numpy(dtype="float64")


def reference_sources(processed: Path, profile: str, split: str, experiments: Path | None = None) -> list[compare.ScoreSource]:
    """The reported Chapter 6 baselines and the Chapter 7 TabNet of one profile/split (N18, N24)."""
    exp = experiments or repo_root() / "experiments"
    refs6 = compare.load_reference_runs(exp / compare.REFERENCE_FILE)
    runs6 = compare.reference_runs_for(refs6, profile, split)
    if not runs6:
        raise RankingError(f"no Chapter 6 reference runs for {profile}/{split} in {exp / compare.REFERENCE_FILE}")
    refs7 = json.loads((exp / "chapter7_reference_runs.json").read_text(encoding="utf-8"))
    r7 = (refs7.get("runs") or {}).get(f"{profile}/{split}")
    if not r7:
        raise RankingError(f"no Chapter 7 reference run for {profile}/{split}")
    sources = compare.chapter6_sources(processed, runs6)
    sources.append(compare.chapter7_source(processed, r7["run_id"]))
    return sources


def baseline_choice_on_validation(processed: Path, profile: str, split: str = "user",
                                  experiments: Path | None = None) -> dict:
    """The best Chapter 6 baseline by VALIDATION PR-AUC (primary view). Chosen before test is read (N11).

    Ties go to the first name in ``BASELINES``. The whole table is stored with the readout.
    """
    sources = [s for s in reference_sources(processed, profile, split, experiments) if s.chapter == 6]
    views = load_label_views(processed)
    table = {}
    for src in sources:
        frame = compare._load_part(src, "validation")
        lab = attach_labels(frame[["user_id", "date"]], views)
        keep = ~lab["exclude_primary"].to_numpy().astype(bool)
        table[src.label] = pr_auc(lab["y_primary"].to_numpy()[keep], frame["anomaly_score"].to_numpy(dtype="float64")[keep])
    scored = {k: v for k, v in table.items() if v is not None}
    if not scored:
        raise RankingError("no baseline has a defined validation PR-AUC")
    order = {name: i for i, name in enumerate(BASELINES)}
    best = sorted(scored, key=lambda k: (-scored[k], order.get(k, 99)))[0]
    return {"rule": "highest validation PR-AUC among the Chapter 6 reference baselines, primary view",
            "validation_pr_auc": table, "best": best}


def build_rankings(pop: Population, *, experiments: Path | None = None, split: str = "user") -> tuple[dict, dict]:
    """(scores, provenance): every ranking as a float64 array aligned with ``pop.keys``."""
    scores: dict[str, np.ndarray] = {}
    prov: dict[str, dict] = {}
    for src in reference_sources(pop.processed, pop.profile, split, experiments):
        name = SHADOW if src.chapter == 7 else f"baseline:{BASELINE_LABEL.get(src.label, src.label)}"
        scores[name] = _aligned_scores(src, pop)
        prov[name] = {"chapter": src.chapter, "run_id": src.run_id, "path": str(src.path), "sha256": file_sha256(src.path)}
    scores[SERVED] = pop.risk["anomaly_score"].to_numpy(dtype="float64")
    prov[SERVED] = {"chapter": 8, "risk_run_id": pop.risk_dir.name, "model": (pop.risk_meta.get("served") or {})}
    for name, out in cri_variant_outputs(pop).items():
        scores[name] = out["cri"]
        prov[name] = {"chapter": 9 if name != "cri:default" else 10, "risk_run_id": pop.risk_dir.name,
                      "effective_weights": out["weights"], "validation_informed": name in VALIDATION_INFORMED}
    scores["mitre_context"] = np.nan_to_num(pop.mitre["mitre_context"].to_numpy(dtype="float64", na_value=np.nan), nan=0.0)
    prov["mitre_context"] = {"chapter": 10, "mitre_run_id": pop.provenance["mitre_run_id"],
                             "note": "the MITRE component alone, not a detector; rows not evaluated are ranked as 0"}
    for n, s in scores.items():
        if len(s) != len(pop.keys) or not np.isfinite(s).all():
            raise RankingError(f"ranking {n!r} is not finite and aligned with the population")
    return scores, prov


def mapped_mask(pop: Population) -> np.ndarray:
    return (pop.mitre["mitre_status"].astype(str) == "mapped").to_numpy()
