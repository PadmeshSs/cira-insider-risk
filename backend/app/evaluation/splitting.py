"""Leakage-safe splits (CARRY_FORWARD N3, HCEA §7.5).

User split (primary)
    Every user's rows go to exactly one of train / validation / test.
    Insiders are spread across the splits stratified by scenario. Benign users
    are assigned by a seeded hash threshold. Both rules depend only on the
    seed and the user id, never on which other users are present, so a user
    lands in the same split under the mid and the full profile. That lets a
    mid result and a full result be compared user for user.

    The assignment is saved as JSON under ``experiments/splits/`` so every
    model (baselines now, TabNet in Chapter 7) reads the same split instead
    of recomputing one. The file holds user -> split plus aggregate counts.
    It does not hold any per-user label or scenario.

Time split (secondary check)
    Train on earlier days, validate on a later window, test on the last
    months. Users appear in several splits by design; no row from the future
    is used to fit a model. Insider activity clusters in time, so this check
    shows whether a model depends on seeing the same period it is tested on.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

SPLIT_VERSION = "ch6-user-split-v1"
SPLITS = ("train", "validation", "test")
DEFAULT_FRACTIONS = (0.6, 0.2, 0.2)


def _unit_hash(seed: int, user_id: str) -> float:
    """Deterministic value in [0, 1) from (seed, user)."""
    digest = hashlib.sha256(f"{seed}:{user_id}".encode("utf-8")).hexdigest()
    return int(digest[:15], 16) / float(16**15)


def _allocate(n: int, fractions: tuple[float, float, float]) -> list[int]:
    """Largest-remainder allocation of n items to the three splits."""
    raw = [n * f for f in fractions]
    counts = [math.floor(x) for x in raw]
    order = sorted(range(3), key=lambda i: (-(raw[i] - counts[i]), i))
    for i in order[: n - sum(counts)]:
        counts[i] += 1
    return counts


def _check_fractions(fractions: Iterable[float]) -> tuple[float, float, float]:
    f = tuple(float(x) for x in fractions)
    if len(f) != 3 or any(x < 0 for x in f) or not math.isclose(sum(f), 1.0, abs_tol=1e-9):
        raise ValueError(f"fractions must be three non-negative numbers summing to 1, got {f}")
    return f  # type: ignore[return-value]


def assign_user_splits(
    users: Iterable[str],
    insider_scenarios: dict[str, int],
    *,
    seed: int,
    fractions: Iterable[float] = DEFAULT_FRACTIONS,
) -> dict[str, str]:
    """Return ``user_id -> split`` for every user in ``users``."""
    f = _check_fractions(fractions)
    population = sorted({str(u).strip().casefold() for u in users})
    scen = {str(u).strip().casefold(): int(s) for u, s in insider_scenarios.items()}
    assignment: dict[str, str] = {}

    # Insiders: exact stratification per scenario. The ordering inside a
    # scenario is by seeded hash, so it does not depend on the population.
    for scenario in sorted(set(scen.values())):
        members = sorted((u for u, s in scen.items() if s == scenario), key=lambda u: (_unit_hash(seed, u), u))
        counts = _allocate(len(members), f)
        cursor = 0
        for split, count in zip(SPLITS, counts):
            for u in members[cursor : cursor + count]:
                assignment[u] = split
            cursor += count

    # Benign users: hash threshold, stable across profiles.
    edges = (f[0], f[0] + f[1])
    for u in population:
        if u in scen:
            continue
        h = _unit_hash(seed, u)
        assignment[u] = SPLITS[0] if h < edges[0] else SPLITS[1] if h < edges[1] else SPLITS[2]

    # Only return users that are actually in the population; insiders absent
    # from the matrix are reported by the caller, not invented here.
    return {u: assignment[u] for u in population}


def split_summary(assignment: dict[str, str], insider_scenarios: dict[str, int]) -> dict:
    scen = {str(u).casefold(): int(s) for u, s in insider_scenarios.items()}
    out = {}
    for split in SPLITS:
        members = [u for u, s in assignment.items() if s == split]
        by_scenario: dict[str, int] = {}
        for u in members:
            if u in scen:
                by_scenario[str(scen[u])] = by_scenario.get(str(scen[u]), 0) + 1
        out[split] = {
            "users": len(members),
            "insiders": sum(by_scenario.values()),
            "insiders_by_scenario": dict(sorted(by_scenario.items())),
        }
    return out


def save_split(
    path: str | Path,
    assignment: dict[str, str],
    insider_scenarios: dict[str, int],
    *,
    seed: int,
    fractions: Iterable[float],
    profile: str,
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": SPLIT_VERSION,
        "profile": profile,
        "seed": int(seed),
        "fractions": dict(zip(SPLITS, _check_fractions(fractions))),
        "method": (
            "insiders: per-scenario largest-remainder allocation over a seeded-hash order; "
            "benign: seeded-hash threshold. Population-independent, so mid and full agree on shared users."
        ),
        "counts": split_summary(assignment, insider_scenarios),
        "assignment": dict(sorted(assignment.items())),
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    os.replace(tmp, path)
    return path


def load_split(path: str | Path) -> tuple[dict[str, str], dict]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("version") != SPLIT_VERSION:
        raise ValueError(f"{path}: split version {payload.get('version')!r}, expected {SPLIT_VERSION!r}")
    return dict(payload["assignment"]), {k: v for k, v in payload.items() if k != "assignment"}


def load_or_create_split(
    path: str | Path,
    users: Iterable[str],
    insider_scenarios: dict[str, int],
    *,
    seed: int,
    fractions: Iterable[float] = DEFAULT_FRACTIONS,
    profile: str,
    rebuild: bool = False,
) -> tuple[dict[str, str], dict, bool]:
    """Load the saved split, or create it on first use.

    Returns (assignment, meta, created). A saved split that no longer matches
    what the rule would produce (different users, seed or fractions) is an
    error, not something to overwrite quietly.
    """
    path = Path(path)
    expected = assign_user_splits(users, insider_scenarios, seed=seed, fractions=fractions)
    if path.exists() and not rebuild:
        stored, meta = load_split(path)
        if stored != expected:
            only_stored = sorted(set(stored) - set(expected))[:5]
            only_now = sorted(set(expected) - set(stored))[:5]
            changed = sorted(u for u in set(stored) & set(expected) if stored[u] != expected[u])[:5]
            raise RuntimeError(
                f"Saved split {path} does not match the current population/seed. "
                f"only in file: {only_stored}; only now: {only_now}; moved: {changed}. "
                "Re-run with --rebuild-split if this change is intended, and note it in the write-up."
            )
        return stored, meta, False
    save_split(path, expected, insider_scenarios, seed=seed, fractions=fractions, profile=profile)
    _, meta = load_split(path)
    return expected, meta, True


def rows_for_split(user_ids: pd.Series, assignment: dict[str, str]) -> np.ndarray:
    """Split name for every row; raises if a row's user is unassigned."""
    users = user_ids.astype("string").str.strip().str.casefold()
    mapped = users.map(assignment)
    if mapped.isna().any():
        missing = sorted(set(users[mapped.isna()]))[:5]
        raise RuntimeError(f"Rows for users not in the split assignment: {missing}")
    return mapped.astype(str).to_numpy()


def time_split(dates: pd.Series, *, validation_start: str, test_start: str) -> np.ndarray:
    """Split name per row from its date (``YYYY-MM-DD``)."""
    vs, ts = pd.Timestamp(validation_start), pd.Timestamp(test_start)
    if not vs < ts:
        raise ValueError(f"validation_start {validation_start} must be before test_start {test_start}")
    d = pd.to_datetime(dates.astype("string"))
    out = np.where(d < vs, SPLITS[0], np.where(d < ts, SPLITS[1], SPLITS[2]))
    return out.astype(str)


def assert_user_disjoint(user_ids: pd.Series, split: np.ndarray) -> None:
    frame = pd.DataFrame({"u": user_ids.astype("string").to_numpy(), "s": split})
    per_user = frame.groupby("u")["s"].nunique()
    leaked = per_user[per_user > 1]
    if len(leaked):
        raise AssertionError(f"Users present in more than one split: {list(leaked.index[:5])}")
