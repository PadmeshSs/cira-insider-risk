"""CERT r4.2 organizational context for Chapter 5."""
from __future__ import annotations

from pathlib import Path
import pandas as pd

from .common import atomic_to_parquet, ensure_pyarrow, normalize_user


def build_context(raw_dir: str | Path, processed_dir: str | Path, *, force: bool = False) -> None:
    ensure_pyarrow()
    raw = Path(raw_dir)
    out = Path(processed_dir) / "context"
    out.mkdir(parents=True, exist_ok=True)
    ldap_out = out / "ldap_user_month.parquet"
    psych_out = out / "psychometric.parquet"
    if not force and ldap_out.exists() and psych_out.exists():
        return

    frames = []
    ldap_dir = raw / "LDAP"
    for path in sorted(ldap_dir.glob("*.csv")):
        month = path.stem
        df = pd.read_csv(path, dtype="string", low_memory=False)
        df.columns = [str(c).strip().lower() for c in df.columns]
        df["user_id"] = normalize_user(df["user_id"])
        df["snapshot_month"] = pd.Timestamp(month + "-01")
        for col in ["role", "business_unit", "functional_unit", "department", "team", "supervisor", "email", "employee_name"]:
            df[col] = df[col].fillna("").astype("string").str.strip()
        frames.append(df[["user_id", "email", "role", "business_unit", "functional_unit", "department", "team", "supervisor", "snapshot_month"]])
    ldap = pd.concat(frames, ignore_index=True)
    atomic_to_parquet(ldap, ldap_out)

    psych = pd.read_csv(raw / "psychometric.csv", low_memory=False)
    psych.columns = [str(c).strip().lower() for c in psych.columns]
    psych["user_id"] = normalize_user(psych["user_id"])
    for col in ("o", "c", "e", "a", "n"):
        psych[col] = pd.to_numeric(psych[col], errors="raise").astype("float32")
    atomic_to_parquet(psych[["user_id", "o", "c", "e", "a", "n"]], psych_out)


def load_ldap(processed_dir: str | Path) -> pd.DataFrame:
    return pd.read_parquet(Path(processed_dir) / "context" / "ldap_user_month.parquet")


def load_psychometric(processed_dir: str | Path) -> pd.DataFrame:
    return pd.read_parquet(Path(processed_dir) / "context" / "psychometric.parquet")


def email_directory(processed_dir: str | Path) -> dict[str, str]:
    ldap = load_ldap(processed_dir)
    latest = ldap.sort_values("snapshot_month").drop_duplicates("user_id", keep="last")
    return dict(zip(latest["email"].str.casefold(), latest["user_id"]))
