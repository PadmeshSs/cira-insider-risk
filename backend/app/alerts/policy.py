"""The alert policy, c12-alert-policy-v1 (Bible Ch12, N39, N40, N46).

Fixed before any alert number existed. Every value is recorded in the alert
run's meta with its hash, and a value that differs from the default is listed
as an override (the verifier WARNs on it). It is configured by command-line
flags of ``python -m app.alerts.batch``, never by ``.env``, so an environment
variable can never change an alert silently (same reasoning as C11 and N37).

Which user-days trigger (N39: the policy says which view it uses)
    band      the CRI severity is HIGH or CRITICAL. A global threshold; it
              can be quiet on some days and busy on others.
    top_k     the user-day is among the day's top ``top_k_per_day`` by the
              queue ordering score. A per-day budget an analyst can work.
    A user-day triggers if either holds. With ``require_activity`` (default
    on) a user-day with no recorded event (``total_event_count == 0``) cannot
    take a top-k slot: the daily budget otherwise fires on every calendar day,
    including weekends when nobody did anything, and gives the slot to
    whoever is least quiet among the idle. The band trigger is unaffected.
    This rule was added while building the chapter, after the synthetic
    chain produced a top-1 alert on a day with no events; no CERT number
    informed it. Both views are recorded per member
    day (``by_band``, ``by_top_k``) and reported separately, so neither hides
    the other.

Queue ordering (N40, N46: chosen explicitly, both views reported)
    ``anomaly_score``: the served model's score orders the queue and picks
    the daily top-k; the CRI score and band are shown next to it as context.
    Reason: on full / user validation the anomaly score has the highest
    PR-AUC (0.915 against 0.694 for the CRI and 0.557 for the CRI with MITRE),
    while no ordering dominates on insiders caught at top-1. This choice was
    made after those validation readouts existed, so it is recorded as
    validation-informed. The batch reports what the ``cri_score`` ordering
    would have triggered, label-free, and the readout reads both.

Correlation and deduplication (§17)
    correlation_gap_days  two triggered days of one user belong to one alert
                          if they are at most this many calendar days apart
                          (3: Friday to Monday is one incident)
    max_span_days         an alert never spans more than this many calendar
                          days (14), so a user who triggers every day for a
                          month becomes several alerts, not one endless one
    cooldown_days         a new alert of the same user that starts at most
                          this many days after an open alert ends, with a
                          pattern already seen in it, is suppressed (7)

Ties inside a day are broken by a seeded random key, the same algorithm as
``app.evaluation.metrics.daily_top_k``, copied here so serving code never
imports the evaluation package (N5).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, fields

import numpy as np
import pandas as pd

POLICY_VERSION = "c12-alert-policy-v1"
ORDERINGS = ("anomaly_score", "cri_score")
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
TRIGGER_COLUMNS = ("by_band", "by_top_k")


class AlertPolicyError(ValueError):
    """The policy values are not usable."""


@dataclass(frozen=True)
class AlertPolicy:
    band_severities: tuple[str, ...] = ("HIGH", "CRITICAL")
    top_k_per_day: int = 1
    ordering: str = "anomaly_score"
    correlation_gap_days: int = 3
    max_span_days: int = 14
    cooldown_days: int = 7
    tie_break_seed: int = 42
    require_activity: bool = True

    def __post_init__(self) -> None:
        bad = [s for s in self.band_severities if s not in SEVERITY_RANK]
        if bad:
            raise AlertPolicyError(f"unknown severities {bad}")
        if self.ordering not in ORDERINGS:
            raise AlertPolicyError(f"ordering must be one of {ORDERINGS}")
        if self.top_k_per_day < 0:
            raise AlertPolicyError("top_k_per_day must be >= 0 (0 = band only)")
        if not self.band_severities and self.top_k_per_day == 0:
            raise AlertPolicyError("the policy triggers nothing: no band and no daily top-k")
        if self.correlation_gap_days < 0 or self.max_span_days < 1 or self.cooldown_days < 0:
            raise AlertPolicyError("gap >= 0, span >= 1 and cooldown >= 0 days")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["band_severities"] = list(self.band_severities)
        return {"version": POLICY_VERSION, **d}

    @property
    def policy_hash(self) -> str:
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True).encode()).hexdigest()[:12]

    def overrides(self, default: "AlertPolicy | None" = None) -> dict:
        """Values that differ from the fixed defaults (the seed follows CIRA_SEED and is not an override)."""
        base = default or AlertPolicy(tie_break_seed=self.tie_break_seed)
        out = {}
        for f in fields(self):
            a, b = getattr(self, f.name), getattr(base, f.name)
            if a != b:
                out[f.name] = list(a) if isinstance(a, tuple) else a
        return out

    @classmethod
    def from_dict(cls, d: dict) -> "AlertPolicy":
        if d.get("version") not in (None, POLICY_VERSION):
            raise AlertPolicyError(f"policy version {d.get('version')!r} is not {POLICY_VERSION}")
        kw = {f.name: d[f.name] for f in fields(cls) if f.name in d}
        if "band_severities" in kw:
            kw["band_severities"] = tuple(kw["band_severities"])
        return cls(**kw)


def daily_top_k(dates: pd.Series, scores: np.ndarray, k: int, *, seed: int) -> np.ndarray:
    """The k highest scores on each calendar day; ties broken by a seeded random key."""
    s = np.asarray(scores, dtype="float64")
    if k < 1 or len(s) == 0:
        return np.zeros(len(s), dtype=bool)
    if not np.isfinite(s).all():
        raise AlertPolicyError("scores must be finite to rank a day")
    rng = np.random.default_rng(seed)
    frame = pd.DataFrame({"d": pd.Series(dates).astype("string").to_numpy(), "s": -s,
                          "t": rng.random(len(s)), "i": np.arange(len(s))})
    frame = frame.sort_values(["d", "s", "t"], kind="mergesort")
    rank = frame.groupby("d", sort=False).cumcount().to_numpy()
    mask = np.zeros(len(s), dtype=bool)
    mask[frame["i"].to_numpy()[rank < k]] = True
    return mask


ACTIVITY_COLUMN = "total_event_count"


def triggers(risk: pd.DataFrame, policy: AlertPolicy, activity: np.ndarray | None = None) -> pd.DataFrame:
    """``risk`` (user_id, date, severity, anomaly_score, cri_score) -> by_band, by_top_k, triggered.

    Ranking is over every row passed in (the monitored population of the
    run), restricted to rows with recorded activity when the policy requires
    it; ``activity`` is the Chapter 5 ``total_event_count`` aligned to ``risk``.
    """
    need = ("user_id", "date", "severity", "anomaly_score", "cri_score")
    missing = [c for c in need if c not in risk.columns]
    if missing:
        raise AlertPolicyError(f"triggers need {missing}")
    by_band = risk["severity"].astype(str).isin(policy.band_severities).to_numpy()
    eligible = np.ones(len(risk), dtype=bool)
    if policy.require_activity:
        if activity is None:
            raise AlertPolicyError(f"the policy requires activity: pass {ACTIVITY_COLUMN} aligned to the rows")
        a = np.asarray(activity, dtype="float64")
        eligible = np.nan_to_num(a, nan=0.0) > 0
    by_top_k = np.zeros(len(risk), dtype=bool)
    idx = np.flatnonzero(eligible)
    by_top_k[idx] = daily_top_k(risk["date"].iloc[idx], risk[policy.ordering].to_numpy(dtype="float64")[idx],
                                policy.top_k_per_day, seed=policy.tie_break_seed)
    return pd.DataFrame({"by_band": by_band, "by_top_k": by_top_k, "triggered": by_band | by_top_k},
                        index=risk.index)
