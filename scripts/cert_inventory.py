"""
CERT r4.2 raw-data inventory.

Reports row counts for the six CERT source CSVs and
the LDAP snapshot CSVs.

LDAP rows are organizational/context snapshots and
are reported separately from the six primary event files.
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
    *,
    chunksize: int = 100_000,
) -> int:
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

    count = count_csv_rows(path)

    print(
        f"{domain:<15} "
        f"{count:>12,} rows  "
        f"{filename}"
    )

    return count


def inventory_ldap(
    root: Path,
) -> int:
    ldap_root = root / "LDAP"

    if not ldap_root.exists():
        raise FileNotFoundError(
            f"LDAP directory not found: "
            f"{ldap_root}"
        )

    files = sorted(
        ldap_root.glob("*.csv")
    )

    if not files:
        raise FileNotFoundError(
            f"No LDAP CSV files found under: "
            f"{ldap_root}"
        )

    total = 0

    print()
    print("LDAP snapshots")

    for path in files:
        count = count_csv_rows(path)
        total += count

        print(
            f"{path.name:<15} "
            f"{count:>12,} rows"
        )

    print(
        f"{'LDAP total':<15} "
        f"{total:>12,} rows"
    )

    return total


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Inventory CERT r4.2 raw files."
        )
    )

    parser.add_argument(
        "--root",
        required=True,
        type=Path,
        help="CERT r4.2 root directory.",
    )

    args = parser.parse_args()

    root = args.root.resolve()

    if not root.exists():
        parser.error(
            f"CERT root does not exist: {root}"
        )

    print(
        f"CERT root: {root}"
    )
    print()

    print("Primary source files")

    primary_total = 0

    for domain, filename in CERT_FILES.items():
        primary_total += inventory_domain(
            root,
            domain,
            filename,
        )

    print()
    print(
        f"{'Six-source total':<15} "
        f"{primary_total:>12,} rows"
    )

    ldap_total = inventory_ldap(root)

    print()
    print(
        f"{'All counted rows':<15} "
        f"{primary_total + ldap_total:>12,}"
    )

    print()
    print(
        "Inventory complete."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())