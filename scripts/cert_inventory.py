"""
CERT r4.2 dataset inventory.

Counts logical CSV records for every CERT r4.2 domain without loading
the entire dataset into memory.

This script is an acceptance/verification utility for Chapter 3.

Usage:
    python scripts/cert_inventory.py --root D:\\CIRA_dataset\\datasets\\raw\\cert_r4.2
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


CERT_FILES = {
    "logon": "logon.csv",
    "device": "device.csv",
    "email": "email.csv",
    "file": "file.csv",
    "http": "http.csv",
    "psychometric": "psychometric.csv",
}


def count_csv_rows(
    path: Path,
    chunksize: int = 100_000,
) -> int:
    """Count logical CSV records without loading the entire file."""

    total = 0

    for chunk in pd.read_csv(
        path,
        chunksize=chunksize,
        low_memory=False,
    ):
        total += len(chunk)

    return total


def inventory_domain(
    root: Path,
    domain: str,
    filename: str,
) -> int:

    path = root / filename

    if not path.exists():
        raise FileNotFoundError(
            f"Missing CERT file: {path}"
        )

    print(
        f"Counting {domain:<15} {filename} ..."
    )

    count = count_csv_rows(path)

    print(
        f"  {domain:<15} {count:,} rows"
    )

    return count


def inventory_ldap(
    root: Path,
) -> tuple[int, int]:

    ldap_root = root / "LDAP"

    if not ldap_root.exists():
        raise FileNotFoundError(
            f"LDAP directory not found: {ldap_root}"
        )

    files = sorted(
        ldap_root.glob("*.csv")
    )

    if not files:
        raise FileNotFoundError(
            f"No LDAP CSV files found under: {ldap_root}"
        )

    total_rows = 0

    print()
    print("LDAP snapshots")
    print("-" * 50)

    for path in files:

        count = count_csv_rows(path)

        total_rows += count

        print(
            f"  {path.name:<20} {count:,} rows"
        )

    print("-" * 50)

    print(
        f"  {'LDAP total':<20} "
        f"{total_rows:,} rows"
    )

    return len(files), total_rows


def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Inventory CERT r4.2 raw dataset."
        )
    )

    parser.add_argument(
        "--root",
        required=True,
        type=Path,
        help="Path to CERT r4.2 root directory.",
    )

    args = parser.parse_args()

    root = args.root

    if not root.exists():
        raise SystemExit(
            f"ERROR: CERT root does not exist: {root}"
        )

    print("=" * 60)
    print("CERT r4.2 DATASET INVENTORY")
    print("=" * 60)
    print(f"Root: {root}")
    print()

    counts: dict[str, int] = {}

    for domain, filename in CERT_FILES.items():

        counts[domain] = inventory_domain(
            root,
            domain,
            filename,
        )

    ldap_snapshots, ldap_rows = inventory_ldap(
        root
    )

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)

    behavioural_total = sum(
        counts.values()
    )

    for domain, count in counts.items():

        print(
            f"{domain:<20} {count:>15,}"
        )

    print(
        f"{'LDAP snapshots':<20} "
        f"{ldap_snapshots:>15}"
    )

    print(
        f"{'LDAP rows':<20} "
        f"{ldap_rows:>15,}"
    )

    print("-" * 60)

    print(
        f"{'Behavioural total':<20} "
        f"{behavioural_total:>15,}"
    )

    print(
        f"{'All raw records*':<20} "
        f"{behavioural_total + ldap_rows:>15,}"
    )

    print()
    print(
        "* LDAP rows are organizational snapshots and are not "
        "behavioural events."
    )


if __name__ == "__main__":
    main()