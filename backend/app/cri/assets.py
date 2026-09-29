"""Asset-criticality lookup over the ``assets`` table (Bible Ch9 step 3).

The Bible asks for an ``Asset`` entity in this chapter, created because the
CRI needs an asset-criticality lookup. The entity and this lookup exist.

What CERT r4.2 provides: PC identifiers in logon, device, file, email and
http events, and nothing about how critical any PC is. There is no asset
inventory, owner register or classification (N9). ``.env.example`` has said
since Chapter 1 that Chapter 9 must not assign a synthetic criticality, and
it does not:

* the ``assets.criticality`` column is nullable and nothing in this
  repository fills it from CERT;
* a user-day's component is the highest known criticality among the assets
  it touched, and null when none of them has a known criticality;
* when no user-day-to-asset mapping is supplied at all (the CERT batch
  path: the Chapter 5 matrix is per user-day and carries no PC ids), the
  component is unavailable for the whole run and its weight is taken out of
  the formula, with the reason recorded. It is never imputed.

An organisation that has an inventory fills ``assets.criticality`` (one of
low / medium / high / critical) and supplies the user-day-to-asset map;
Chapter 12 persists events, which is where that map will come from.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable, Mapping

import numpy as np
import pandas as pd

CRITICALITY_LEVELS = {"low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.00}
UNAVAILABLE_REASON = ("CERT r4.2 has no asset inventory or criticality source (N9); no user-day-to-asset "
                      "criticality was supplied, so the component is excluded, never invented")


@dataclass(frozen=True)
class AssetCriticalityLookup:
    levels: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_rows(cls, rows: Iterable[tuple[str, str | None]]) -> "AssetCriticalityLookup":
        levels = {}
        for key, level in rows:
            if key is None or level is None:
                continue
            lv = str(level).strip().casefold()
            if lv not in CRITICALITY_LEVELS:
                raise ValueError(f"asset {key!r}: criticality {level!r} is not one of {sorted(CRITICALITY_LEVELS)}")
            levels[str(key).strip().upper()] = lv
        return cls(levels)

    def __len__(self) -> int:
        return len(self.levels)

    def value(self, asset_key: str) -> float:
        lv = self.levels.get(str(asset_key).strip().upper())
        return CRITICALITY_LEVELS[lv] if lv else math.nan

    def user_day_component(self, touched: pd.DataFrame) -> pd.DataFrame:
        """``touched``: user_id, date, asset_key rows -> user_id, date, asset_criticality.

        Highest known criticality per user-day; null when none is known.
        """
        if touched.empty:
            return pd.DataFrame(columns=["user_id", "date", "asset_criticality"])
        v = touched["asset_key"].map(self.value).astype("float64")
        frame = touched[["user_id", "date"]].assign(asset_criticality=v.to_numpy())
        return frame.groupby(["user_id", "date"], as_index=False, sort=True)["asset_criticality"].max()


def asset_lookup_query():
    """SELECT asset_key, criticality FROM assets WHERE criticality IS NOT NULL."""
    from sqlalchemy import select

    from app.database.models.asset import Asset

    return select(Asset.asset_key, Asset.criticality).where(Asset.criticality.is_not(None))


async def load_asset_lookup(session) -> AssetCriticalityLookup:
    """Read the lookup through an ``AsyncSession`` (the app's session type)."""
    result = await session.execute(asset_lookup_query())
    return AssetCriticalityLookup.from_rows(result.all())


def align(component: pd.DataFrame, keys: pd.DataFrame) -> np.ndarray:
    """A user-day component frame aligned to ``keys`` (NaN where absent)."""
    k = keys[["user_id", "date"]].astype("string").reset_index(drop=True)
    j = k.merge(component.astype({"user_id": "string", "date": "string"}), on=["user_id", "date"],
                how="left", validate="one_to_one")
    return j["asset_criticality"].to_numpy(dtype="float64", na_value=np.nan)
