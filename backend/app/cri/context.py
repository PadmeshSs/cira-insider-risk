"""Context statistics for the CRI, from data Chapter 5 already produced.

Nothing here derives a new behavioural signal and nothing reads a label
(N5, N9). The statistics are computed per user-day, vectorised.

historical_statistic
    max over the ``hist_z_<feature>`` columns of max(z, 0): the largest rise
    above the user's own trailing 30-day baseline (Chapter 5 step 8; the
    current day is excluded from its own baseline, so nothing looks ahead,
    N3/N12). A drop below baseline is not treated as risk. Null when every
    z is null (fewer than 7 prior days, or zero prior variance).

peer positives
    max(peer_dev_<feature>, 0) per feature: how far above the leave-one-out
    same-day median of the user's functional unit + department (Chapter 5
    step 9). The engine puts each on the rarity scale and takes the largest
    (see ``calibration.RarityMaps.peer_statistic``). Null without LDAP
    department or peers that day.

role / user_context
    The LDAP role in the snapshot of the user-day's month (point in time, no
    look-ahead). user_context = 1.0 for a role in CRI_PRIVILEGED_ROLES,
    0.0 for any other role, null when the user has no LDAP row that month.
    The role is a policy prior, not a statistic, so it is not put on the
    rarity scale.

Why these reuse model inputs
    The served model already sees hist_z_* and peer_dev_* (its inputs are all
    behaviour columns). The CRI uses them again on purpose, as the
    Architecture's "historical deviation" and "peer deviation" terms, so an
    analyst gets a separately stated reason. The overlap is a form of double
    counting and is disclosed; Chapter 16's ablations measure what it adds.

Asset criticality and MITRE context are not computed here. CERT r4.2 has no
asset criticality (see ``assets.py``) and MITRE arrives in Chapter 10. They
enter the engine only as optional, externally supplied columns.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

HIST_PREFIX = "hist_z_"
PEER_PREFIX = "peer_dev_"
CONTEXT_COLUMNS = ("historical_statistic", "historical_top_feature", "role", "user_context_value")


def historical_columns(columns) -> list[str]:
    return sorted(c for c in columns if str(c).startswith(HIST_PREFIX))


def peer_columns(columns) -> list[str]:
    # peer_abs_dev_* and peer_median_* do not match this prefix, on purpose.
    return sorted(c for c in columns if str(c).startswith(PEER_PREFIX))


def historical_statistic(frame: pd.DataFrame, cols: list[str]) -> tuple[np.ndarray, np.ndarray]:
    n = len(frame)
    if not cols:
        return np.full(n, np.nan), np.full(n, None, dtype=object)
    z = frame[cols].to_numpy(dtype="float64", na_value=np.nan)
    pos = np.where(np.isnan(z), np.nan, np.maximum(z, 0.0))
    all_nan = np.isnan(pos).all(axis=1)
    filled = np.where(np.isnan(pos), -1.0, pos)
    idx = filled.argmax(axis=1)
    stat = np.where(all_nan, np.nan, filled[np.arange(n), idx])
    names = np.asarray([c[len(HIST_PREFIX):] for c in cols], dtype=object)
    top = np.where(all_nan | (stat <= 0), None, names[idx])
    return stat, top


def peer_positives(frame: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    """Positive part of each peer deviation, columns named by feature."""
    out = {}
    for c in cols:
        v = frame[c].to_numpy(dtype="float64", na_value=np.nan)
        out[c[len(PEER_PREFIX):]] = np.where(np.isnan(v), np.nan, np.maximum(v, 0.0))
    return pd.DataFrame(out, index=frame.index)


def load_roles(processed_dir: str | Path) -> pd.DataFrame:
    """user_id, month (YYYY-MM), role from the Chapter 5 LDAP context table."""
    path = Path(processed_dir) / "context" / "ldap_user_month.parquet"
    if not path.exists():
        raise FileNotFoundError(f"{path} not found; the Chapter 5 pipeline builds it")
    ldap = pd.read_parquet(path, columns=["user_id", "snapshot_month", "role"])
    out = pd.DataFrame({
        "user_id": ldap["user_id"].astype("string").str.strip().str.casefold(),
        "month": pd.to_datetime(ldap["snapshot_month"]).dt.strftime("%Y-%m").astype("string"),
        "role": ldap["role"].astype("string").fillna("").str.strip(),
    })
    return out.drop_duplicates(["user_id", "month"], keep="last").reset_index(drop=True)


def user_context(keys: pd.DataFrame, roles: pd.DataFrame, privileged: tuple[str, ...]) -> tuple[np.ndarray, np.ndarray]:
    """(user_context value, role) per key row; value NaN without an LDAP row."""
    k = pd.DataFrame({
        "user_id": keys["user_id"].astype("string").str.strip().str.casefold().to_numpy(),
        "month": keys["date"].astype("string").str.slice(0, 7).to_numpy(),
        "_pos": np.arange(len(keys)),
    })
    j = k.merge(roles, on=["user_id", "month"], how="left", validate="many_to_one").sort_values("_pos")
    role = j["role"].to_numpy(dtype=object)
    wanted = {r.casefold() for r in privileged}
    has = pd.notna(j["role"]).to_numpy() & (j["role"].fillna("").astype(str).str.len() > 0).to_numpy()
    is_priv = np.array([isinstance(r, str) and r.casefold() in wanted for r in role], dtype=bool)
    value = np.where(has, is_priv.astype("float64"), np.nan)
    return value, np.where(has, role, None)


def build_context(keys: pd.DataFrame, features: pd.DataFrame, roles: pd.DataFrame | None,
                  privileged: tuple[str, ...]) -> pd.DataFrame:
    """Context frame aligned 1:1 with ``keys``.

    ``features`` must already be aligned with ``keys`` (same rows, same
    order) and hold the hist_z_* and peer_dev_* columns. Returns the
    historical statistic, the peer positives (``peer_pos__<feature>``), the
    role and the user_context value.
    """
    if len(features) != len(keys):
        raise ValueError(f"features has {len(features)} rows, keys {len(keys)}")
    hcols, pcols = historical_columns(features.columns), peer_columns(features.columns)
    h_stat, h_top = historical_statistic(features, hcols)
    out = pd.DataFrame({
        "user_id": keys["user_id"].astype("string").to_numpy(),
        "date": keys["date"].astype("string").to_numpy(),
        "historical_statistic": h_stat,
        "historical_top_feature": h_top,
    })
    pos = peer_positives(features, pcols)
    for c in pos.columns:
        out[f"peer_pos__{c}"] = pos[c].to_numpy()
    if roles is None:
        out["role"] = None
        out["user_context_value"] = np.nan
    else:
        value, role = user_context(keys, roles, privileged)
        out["role"] = role
        out["user_context_value"] = value
    return out


def read_feature_columns(features_path: str | Path, keys: pd.DataFrame) -> pd.DataFrame:
    """Only the columns the CRI needs, aligned to ``keys``; refuses missing rows.

    Reads user_id, date, hist_z_* and peer_dev_* from the Chapter 5 matrix
    (HCEA R3/R4: never the whole matrix when a few columns will do).
    """
    import pyarrow.parquet as pq

    names = pq.read_schema(features_path).names
    wanted = ["user_id", "date", *historical_columns(names), *peer_columns(names)]
    frame = pd.read_parquet(features_path, columns=wanted)
    frame["user_id"] = frame["user_id"].astype("string").str.strip().str.casefold()
    frame["date"] = frame["date"].astype("string")
    k = pd.DataFrame({
        "user_id": keys["user_id"].astype("string").str.strip().str.casefold().to_numpy(),
        "date": keys["date"].astype("string").to_numpy(),
        "_pos": np.arange(len(keys)),
    })
    j = k.merge(frame, on=["user_id", "date"], how="left", validate="one_to_one", indicator=True)
    missing = int((j["_merge"] != "both").sum())
    if missing:
        raise ValueError(f"{missing} scored user-days have no row in {features_path}; the score and the "
                         "context must come from the same matrix")
    return j.sort_values("_pos").drop(columns=["_pos", "_merge"]).reset_index(drop=True)
