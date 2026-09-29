"""CRI configuration: weights, severity bands, ablation variants (Bible Ch9 step 1).

Everything here is configuration, not a constant buried in the engine. The
defaults below were written before any CRI number existed on CERT r4.2 and
are not tuned on labels in Chapter 9 (N37). Environment variables override
them; every override is reported (``CRIConfig.overrides``), recorded in the
batch meta and flagged by the verifier, so an old ``.env`` can never change
the formula silently.

Components (Architecture §15)
    anomaly               the served model's anomaly score, as rarity
    historical_deviation  largest rise above the user's own 30-day baseline
    peer_deviation        largest rise above the same-day department median
    user_context          1 for a privileged LDAP role, else 0 (a policy prior)
    asset_criticality     criticality of assets touched; CERT r4.2 has none
    mitre_context         Chapter 10 enrichment, joined with `app.cri.batch --with-mitre`

Why these default weights
    The anomaly score is the only input validated against labels (Chapters
    6-8), so it carries 0.60. The context components are priors nobody has
    validated on this data yet, and together they carry less than the
    anomaly score. With MITRE and asset criticality unavailable the weights
    are renormalised over what is available (0.60 / 0.90 = 0.667 for the
    anomaly score). A consequence worth stating: the anomaly score alone
    tops out at about 66 (HIGH); a CRITICAL needs corroborating context.

Severity bands (Architecture §15): 0-24 LOW, 25-49 MEDIUM, 50-74 HIGH,
75-100 CRITICAL. On the float score a band starts at its lower integer: 24.99
is LOW, 25.0 is MEDIUM.

Ablation hooks (Bible Ch9 acceptance, HCEA §9): ``config.variant(name)``
switches components off by configuration. The engine recombines stored
components, so every variant is a cheap recomputation over one scored
matrix, never a pipeline re-run.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field, replace
from typing import Mapping

COMPONENTS = (
    "anomaly",
    "historical_deviation",
    "peer_deviation",
    "user_context",
    "asset_criticality",
    "mitre_context",
)
DEFAULT_WEIGHTS = {
    "anomaly": 0.60,
    "historical_deviation": 0.15,
    "peer_deviation": 0.10,
    "user_context": 0.05,
    "asset_criticality": 0.00,
    "mitre_context": 0.10,
}
ENV_WEIGHT = {
    "anomaly": "CRI_WEIGHT_ANOMALY_SCORE",
    "historical_deviation": "CRI_WEIGHT_HISTORICAL_DEVIATION",
    "peer_deviation": "CRI_WEIGHT_PEER_DEVIATION",
    "user_context": "CRI_WEIGHT_USER_CONTEXT",
    "asset_criticality": "CRI_WEIGHT_ASSET_CRITICALITY",
    "mitre_context": "CRI_WEIGHT_MITRE_CONTEXT",
}
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
DEFAULT_BANDS = (24, 49, 74)               # upper integer of LOW, MEDIUM, HIGH
ENV_BANDS = ("CRI_SEVERITY_LOW_MAX", "CRI_SEVERITY_MEDIUM_MAX", "CRI_SEVERITY_HIGH_MAX")
# ITAdmin is the only r4.2 LDAP role whose name implies administrative
# access. Chosen from the role name, not from who the insiders are; see the
# scenario-3 caveat in docs/chapters/chapter_9_cri.md (N36).
DEFAULT_PRIVILEGED_ROLES = ("ITAdmin",)
# Rarity is measured in decades of exceedance probability and capped at 1:
# 1.0 means "rarer than 1 in 10**5 reference user-days". Fixed, so a band
# means the same thing for every model and profile (see calibration.py).
DEFAULT_RARITY_DECADES = 5.0

ABLATIONS: dict[str, tuple[str, ...]] = {
    "default": (),
    "anomaly_only": ("historical_deviation", "peer_deviation", "user_context", "asset_criticality", "mitre_context"),
    "no_historical_deviation": ("historical_deviation",),
    "no_peer_deviation": ("peer_deviation",),
    "no_user_context": ("user_context",),
    "no_mitre_context": ("mitre_context",),
}


class CRIConfigError(ValueError):
    """The configuration cannot produce a valid CRI."""


def _float(env: Mapping[str, str], key: str, default: float) -> float:
    raw = env.get(key)
    if raw is None or str(raw).strip() == "":
        return float(default)
    try:
        return float(raw)
    except ValueError as exc:
        raise CRIConfigError(f"{key}={raw!r} is not a number") from exc


def _int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    if raw is None or str(raw).strip() == "":
        return int(default)
    try:
        return int(raw)
    except ValueError as exc:
        raise CRIConfigError(f"{key}={raw!r} is not an integer") from exc


def _names(raw: str | None) -> tuple[str, ...]:
    return tuple(x.strip() for x in (raw or "").split(",") if x.strip())


@dataclass(frozen=True)
class CRIConfig:
    weights: tuple[tuple[str, float], ...] = tuple(DEFAULT_WEIGHTS.items())
    bands: tuple[int, int, int] = DEFAULT_BANDS
    privileged_roles: tuple[str, ...] = DEFAULT_PRIVILEGED_ROLES
    rarity_decades: float = DEFAULT_RARITY_DECADES
    disabled: frozenset[str] = frozenset()
    variant_name: str = "default"
    overrides: tuple[tuple[str, str], ...] = field(default=(), compare=False)

    def __post_init__(self) -> None:
        w = dict(self.weights)
        unknown = set(w) - set(COMPONENTS)
        if unknown:
            raise CRIConfigError(f"unknown CRI component(s) {sorted(unknown)}")
        if set(w) != set(COMPONENTS):
            raise CRIConfigError(f"weights must name every component {COMPONENTS}")
        bad = {k: v for k, v in w.items() if not (v >= 0.0) or v != v}
        if bad:
            raise CRIConfigError(f"weights must be finite and >= 0, got {bad}")
        if w["anomaly"] <= 0.0:
            raise CRIConfigError("the anomaly weight must be > 0: a CRI is a contextualised anomaly score (§15)")
        if "anomaly" in self.disabled:
            raise CRIConfigError("the anomaly component cannot be disabled")
        unknown_off = set(self.disabled) - set(COMPONENTS)
        if unknown_off:
            raise CRIConfigError(f"cannot disable unknown component(s) {sorted(unknown_off)}")
        lo, mid, hi = self.bands
        if not (0 <= lo < mid < hi < 100):
            raise CRIConfigError(f"severity maxima must satisfy 0 <= LOW < MEDIUM < HIGH < 100, got {self.bands}")
        if not (self.rarity_decades > 0):
            raise CRIConfigError("CRI_RARITY_DECADES must be > 0")

    # --- construction -----------------------------------------------------
    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "CRIConfig":
        env = os.environ if env is None else env
        weights = {c: _float(env, ENV_WEIGHT[c], DEFAULT_WEIGHTS[c]) for c in COMPONENTS}
        bands = tuple(_int(env, k, d) for k, d in zip(ENV_BANDS, DEFAULT_BANDS))
        roles = _names(env.get("CRI_PRIVILEGED_ROLES")) if env.get("CRI_PRIVILEGED_ROLES") is not None else DEFAULT_PRIVILEGED_ROLES
        decades = _float(env, "CRI_RARITY_DECADES", DEFAULT_RARITY_DECADES)
        disabled = frozenset(_names(env.get("CRI_DISABLED_COMPONENTS")))

        overrides: list[tuple[str, str]] = []
        for c in COMPONENTS:
            if weights[c] != DEFAULT_WEIGHTS[c]:
                overrides.append((ENV_WEIGHT[c], str(env.get(ENV_WEIGHT[c]))))
        for k, got, want in zip(ENV_BANDS, bands, DEFAULT_BANDS):
            if got != want:
                overrides.append((k, str(got)))
        if tuple(roles) != DEFAULT_PRIVILEGED_ROLES:
            overrides.append(("CRI_PRIVILEGED_ROLES", ",".join(roles)))
        if decades != DEFAULT_RARITY_DECADES:
            overrides.append(("CRI_RARITY_DECADES", str(decades)))
        if disabled:
            overrides.append(("CRI_DISABLED_COMPONENTS", ",".join(sorted(disabled))))
        return cls(tuple(weights.items()), bands, tuple(roles), decades, disabled,
                   "default" if not disabled else "custom", tuple(overrides))

    def variant(self, name: str) -> "CRIConfig":
        """The same configuration with one ablation applied (Chapter 16 hook)."""
        if name not in ABLATIONS:
            raise CRIConfigError(f"unknown CRI variant {name!r}; known: {sorted(ABLATIONS)}")
        return replace(self, disabled=frozenset(self.disabled) | frozenset(ABLATIONS[name]), variant_name=name)

    # --- derived ----------------------------------------------------------
    @property
    def weight(self) -> dict[str, float]:
        return dict(self.weights)

    def effective_weights(self, available: set[str] | frozenset[str]) -> dict[str, float]:
        """Weights of enabled, available, non-zero components, renormalised to sum 1.

        A component that this deployment cannot provide (asset criticality on
        CERT, MITRE before Chapter 10) is taken out of the formula. It is not
        imputed. Per-row nulls of an available component are handled by the
        engine (they contribute 0).
        """
        w = self.weight
        active = {c: w[c] for c in COMPONENTS if c in available and c not in self.disabled and w[c] > 0}
        if "anomaly" not in active:
            raise CRIConfigError("the anomaly component must be available and weighted")
        total = sum(active.values())
        return {c: v / total for c, v in active.items()}

    def band_edges(self) -> tuple[int, int, int]:
        """Lower bounds of MEDIUM, HIGH and CRITICAL on the 0-100 scale."""
        lo, mid, hi = self.bands
        return (lo + 1, mid + 1, hi + 1)

    def to_dict(self) -> dict:
        return {
            "weights": self.weight,
            "severity_maxima": {"LOW": self.bands[0], "MEDIUM": self.bands[1], "HIGH": self.bands[2], "CRITICAL": 100},
            "privileged_roles": list(self.privileged_roles),
            "rarity_decades": self.rarity_decades,
            "disabled": sorted(self.disabled),
            "variant": self.variant_name,
        }

    @property
    def config_hash(self) -> str:
        body = self.to_dict()
        body.pop("variant")      # the variant name is a label; the content decides the hash
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:12]

    @property
    def definition(self) -> dict:
        """The parts that change what a component means, not how it is weighted.

        A calibration is valid only for the definition it was fitted with.
        """
        return {"rarity_decades": self.rarity_decades}
