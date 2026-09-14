"""
CERT r4.2 ingestion smoke test.

This is a CLI validation script, not a pytest test module.

Usage:

    python scripts/cert_smoke_test.py \
        --root D:\\CIRA_dataset\\datasets\\raw\\cert_r4.2 \
        --rows 10
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


# Allow execution from the repository root:
#
#     python scripts/cert_smoke_test.py
#
# while importing the application from:
#
#     backend/app/
REPO_ROOT = Path(__file__).resolve().parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(REPO_ROOT),
    )

from backend.app.ingestion.cert_loader import (  # noqa: E402
    CERT_DOMAINS,
    FORBIDDEN_LABEL_COLUMNS,
    iter_cert_domain_events,
    iter_ldap_events,
)


def run_domain_smoke(
    root: Path,
    domain: str,
    rows: int,
) -> int:
    count = 0

    for event in iter_cert_domain_events(
        root,
        domain,
        chunksize=max(rows, 1),
    ):
        assert event.event_id
        assert event.source_type
        assert event.event_type

        assert (
            event.metadata["dataset"]
            == "CERT"
        )

        assert (
            event.metadata["release"]
            == "r4.2"
        )

        assert (
            event.metadata["domain"]
            == domain
        )

        assert event.metadata[
            "source_file"
        ]

        assert event.metadata[
            "source_row_number"
        ] == count + 1

        event_fields = set(
            event.model_dump().keys()
        )

        forbidden = (
            event_fields
            & FORBIDDEN_LABEL_COLUMNS
        )

        assert not forbidden

        count += 1

        if count >= rows:
            break

    assert count == rows, (
        f"{domain}: expected {rows} "
        f"events but received {count}"
    )

    print(
        f"PASS {domain}: "
        f"{count} canonical events"
    )

    return count


def run_ldap_smoke(
    root: Path,
    rows: int,
) -> int:
    count = 0

    for event in iter_ldap_events(
        root,
        chunksize=max(rows, 1),
    ):
        assert event.source_type == "ldap"
        assert event.event_type == (
            "ldap_snapshot"
        )

        assert event.user_id

        assert event.metadata[
            "dataset"
        ] == "CERT"

        assert event.metadata[
            "release"
        ] == "r4.2"

        assert event.metadata[
            "domain"
        ] == "ldap"

        assert event.metadata[
            "source_file"
        ].startswith("LDAP/")

        assert "\\" not in event.metadata[
            "source_file"
        ]

        assert event.metadata[
            "source_row_number"
        ] == count + 1

        assert event.timestamp is None

        count += 1

        if count >= rows:
            break

    assert count == rows, (
        "LDAP: expected "
        f"{rows} events but received "
        f"{count}"
    )

    print(
        f"PASS ldap: "
        f"{count} canonical events"
    )

    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Smoke-test CERT r4.2 "
            "canonical ingestion."
        )
    )

    parser.add_argument(
        "--root",
        required=True,
        type=Path,
        help="Path to CERT r4.2 root directory.",
    )

    parser.add_argument(
        "--rows",
        type=int,
        default=10,
        help=(
            "Number of events to validate "
            "per domain."
        ),
    )

    args = parser.parse_args()

    if args.rows < 1:
        parser.error(
            "--rows must be at least 1"
        )

    root = args.root.resolve()

    if not root.exists():
        parser.error(
            f"CERT root does not exist: {root}"
        )

    total = 0

    for domain in CERT_DOMAINS:
        total += run_domain_smoke(
            root,
            domain,
            args.rows,
        )

    total += run_ldap_smoke(
        root,
        args.rows,
    )

    print()
    print(
        "CERT ingestion smoke test: PASS"
    )
    print(
        f"Validated {total} canonical events."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())