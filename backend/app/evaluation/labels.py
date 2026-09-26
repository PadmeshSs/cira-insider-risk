"""Evaluation-only access to the CERT r4.2 label tables.

Label tables are built by ``scripts/build_labels.py`` under
``<processed>/labels/``. They are read here and joined to feature keys in
memory. The joined frame is never written back to disk next to features
(CARRY_FORWARD N5).

Two views exist (CARRY_FORWARD N1):

* primary  ``insider_user_days.parquet``: keyed by the incident insider.
  Headline metrics use this view.
* account  ``account_user_days.parquet``: keyed by the account the event was
  logged under. In r4.2 scenario 3 the insider uses a supervisor's keylogged
  credentials, so some malicious account-days belong to a supervisor who is
  not an insider. Those rows carry ``is_masquerade = 1``.

Primary evaluation excludes masquerade account-days from the negative set:
they are neither a true positive nor a false positive.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

PRIMARY_FILE = "insider_user_days.parquet"
ACCOUNT_FILE = "account_user_days.parquet"


@dataclass(frozen=True)
class LabelViews:
    """Positive user-days only. ``date`` is a ``YYYY-MM-DD`` string."""

    primary: pd.DataFrame   # user_id, date, scenario
    account: pd.DataFrame   # user_id (account), date, scenario, is_masquerade, incident_user_id


def _norm_user(s: pd.Series) -> pd.Series:
    return s.astype("string").str.strip().str.casefold()


def _norm_date(s: pd.Series) -> pd.Series:
    return pd.to_datetime(s).dt.strftime("%Y-%m-%d").astype("string")


def load_label_views(processed_dir: str | Path) -> LabelViews:
    root = Path(processed_dir) / "labels"
    primary_path, account_path = root / PRIMARY_FILE, root / ACCOUNT_FILE
    for path in (primary_path, account_path):
        if not path.exists():
            raise FileNotFoundError(
                f"Label table missing: {path}. Run `python scripts/build_labels.py` first."
            )

    prim = pd.read_parquet(primary_path, columns=["user_id", "date", "scenario", "is_malicious"])
    prim = prim[prim["is_malicious"] == 1].copy()
    prim["user_id"] = _norm_user(prim["user_id"])
    prim["date"] = _norm_date(prim["date"])
    prim["scenario"] = prim["scenario"].astype("int8")
    prim = prim[["user_id", "date", "scenario"]]
    if prim.duplicated(["user_id", "date"]).any():
        raise ValueError(f"{primary_path} has duplicate (user_id, date) rows")

    acct = pd.read_parquet(
        account_path,
        columns=["account_user_id", "date", "incident_user_id", "scenario", "is_masquerade", "is_malicious"],
    )
    acct = acct[acct["is_malicious"] == 1].rename(columns={"account_user_id": "user_id"}).copy()
    acct["user_id"] = _norm_user(acct["user_id"])
    acct["incident_user_id"] = _norm_user(acct["incident_user_id"])
    acct["date"] = _norm_date(acct["date"])
    acct["scenario"] = acct["scenario"].astype("int8")
    acct["is_masquerade"] = acct["is_masquerade"].astype("int8")
    acct = acct[["user_id", "date", "scenario", "is_masquerade", "incident_user_id"]]
    if acct.duplicated(["user_id", "date"]).any():
        raise ValueError(f"{account_path} has duplicate (account, date) rows")

    return LabelViews(primary=prim.reset_index(drop=True), account=acct.reset_index(drop=True))


def attach_labels(keys: pd.DataFrame, views: LabelViews) -> pd.DataFrame:
    """Labels aligned 1:1 with ``keys`` (same index, same order).

    Returned columns:
      y_primary         1 if the user was acting maliciously that day
      scenario_primary  1-3 for positives, 0 otherwise
      exclude_primary   True for masquerade account-days (N1 rule 2)
      y_account         1 if the account's activity included malicious events
      scenario_account  1-3 for account-view positives, 0 otherwise
    """
    k = pd.DataFrame(
        {
            "user_id": _norm_user(keys["user_id"]).to_numpy(),
            "date": keys["date"].astype("string").to_numpy(),
            "_pos": np.arange(len(keys)),
        }
    )
    p = views.primary.assign(y_primary=np.int8(1)).rename(columns={"scenario": "scenario_primary"})
    a = views.account[["user_id", "date", "scenario", "is_masquerade"]].assign(y_account=np.int8(1)).rename(
        columns={"scenario": "scenario_account"}
    )
    out = k.merge(p, on=["user_id", "date"], how="left", validate="many_to_one")
    out = out.merge(a, on=["user_id", "date"], how="left", validate="many_to_one")
    out = out.sort_values("_pos")

    y_primary = out["y_primary"].fillna(0).astype("int8").to_numpy()
    masq = out["is_masquerade"].fillna(0).astype("int8").to_numpy() == 1
    return pd.DataFrame(
        {
            "y_primary": y_primary,
            "scenario_primary": out["scenario_primary"].fillna(0).astype("int8").to_numpy(),
            # A primary positive is never excluded; only the supervisor's
            # own (benign-by-owner) account-day is taken out of the negatives.
            "exclude_primary": masq & (y_primary == 0),
            "y_account": out["y_account"].fillna(0).astype("int8").to_numpy(),
            "scenario_account": out["scenario_account"].fillna(0).astype("int8").to_numpy(),
        },
        index=keys.index,
    )


def label_coverage(keys: pd.DataFrame, views: LabelViews) -> dict:
    """How many positive label rows for users in ``keys`` have a feature row.

    Only label days inside each user's feature date range must match. The
    dense Chapter 5 spine runs from a user's first to last active day, and a
    malicious day always has events, so under mid/full every label day is
    inside that range and ``outside_feature_window`` must be 0. The dev
    profile cuts the calendar to Jun-Aug 2010, so its insiders legitimately
    have label days outside the window; those are counted, not treated as
    missing. A label day inside the range with no feature row is
    ``unmatched`` and is an error.
    """
    k = pd.DataFrame({"user_id": _norm_user(keys["user_id"]).to_numpy(), "date": keys["date"].astype("string").to_numpy()})
    bounds = k.groupby("user_id")["date"].agg(["min", "max"])
    present = set(zip(k["user_id"], k["date"]))
    report = {}
    for name, frame in (("primary", views.primary), ("account", views.account)):
        mine = frame[frame["user_id"].isin(bounds.index)]
        lo = mine["user_id"].map(bounds["min"])
        hi = mine["user_id"].map(bounds["max"])
        inside = ((mine["date"] >= lo) & (mine["date"] <= hi)).to_numpy()
        pairs = list(zip(mine["user_id"], mine["date"]))
        missing = [p for p, ok in zip(pairs, inside) if ok and p not in present]
        report[name] = {
            "label_rows_for_profile_users": len(mine),
            "outside_feature_window": int((~inside).sum()),
            "matched_to_feature_rows": int(inside.sum()) - len(missing),
            "unmatched": len(missing),
            "unmatched_examples": [f"{u}@{d}" for u, d in missing[:10]],
        }
    report["primary"]["insiders_in_profile"] = int(views.primary.loc[views.primary["user_id"].isin(bounds.index), "user_id"].nunique())
    report["primary"]["insiders_total"] = int(views.primary["user_id"].nunique())
    return report


def insider_scenarios(views: LabelViews, users: set[str] | None = None) -> dict[str, int]:
    """user_id -> scenario for every insider (primary view)."""
    frame = views.primary
    if users is not None:
        frame = frame[frame["user_id"].isin(users)]
    return {str(u): int(s) for u, s in frame.groupby("user_id")["scenario"].min().items()}
