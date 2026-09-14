"""
CERT r4.2 ingestion smoke test.

Loads a small sample from every CERT domain and verifies that each
record conforms to the CanonicalEvent contract.

Usage:
    python scripts/cert_smoke_test.py ^
        --root D:\\CIRA_dataset\\datasets\\raw\\cert_r4.2 ^
        --rows 10
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


# Allow the script to work when executed from repository root.
REPO_ROOT = Path(__file__).resolve().parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(REPO_ROOT),
    )


from backend.app.ingestion.cert_loader import (  # noqa: E402
    CERT_DOMAINS,
    iter_cert_domain_events,
    iter_ldap_events,
)


def test_domain(
    root: Path,
    domain: str,
    rows: int,
) -> int:

    print(
        f"\nTesting {domain}..."
    )

    count = 0

    iterator = iter_cert_domain_events(
        root,
        domain,
    )

    for event in iterator:

        count += 1

        # Pydantic validation has already occurred when the
        # CanonicalEvent object was constructed.

        assert event.event_id, (
            f"{domain}: missing event_id"
        )

        assert event.source_type, (
            f"{domain}: missing source_type"
        )

        assert event.event_type, (
            f"{domain}: missing event_type"
        )

        assert event.metadata["dataset"] == "CERT"

        assert event.metadata["release"] == "r4.2"

        assert event.metadata["domain"] == domain

        assert "source_file" in event.metadata

        assert "source_row_number" in event.metadata

        # Ground truth must never appear in the canonical event.

        forbidden = {
            "label",
            "labels",
            "malicious",
            "is_malicious",
            "ground_truth",
            "scenario",
        }

        event_data = event.model_dump()

        leaked = forbidden.intersection(
            event_data.keys()
        )

        assert not leaked, (
            f"{domain}: ground-truth leakage detected: "
            f"{sorted(leaked)}"
        )

        if count >= rows:
            break

    assert count == rows, (
        f"{domain}: expected {rows} rows, "
        f"received {count}"
    )

    print(
        f"  PASS: {count} canonical events"
    )

    return count


def test_ldap(
    root: Path,
    rows: int,
) -> int:

    print(
        "\nTesting LDAP..."
    )

    count = 0

    iterator = iter_ldap_events(
        root,
    )

    for event in iterator:

        count += 1

        assert event.event_id

        assert event.source_type == "ldap"

        assert event.event_type == "ldap_snapshot"

        assert event.metadata["dataset"] == "CERT"

        assert event.metadata["release"] == "r4.2"

        assert event.metadata["domain"] == "ldap"

        assert "source_file" in event.metadata

        assert "source_row_number" in event.metadata

        # LDAP snapshots legitimately have no timestamp in the
        # current canonical representation.
        assert event.timestamp is None

        # The actual CERT LDAP schema contains user_id.
        assert event.user_id is not None

        # Organizational attributes must remain available.
        assert isinstance(
            event.details,
            dict,
        )

        if count >= rows:
            break

    assert count == rows, (
        f"LDAP: expected {rows} rows, "
        f"received {count}"
    )

    print(
        f"  PASS: {count} canonical LDAP events"
    )

    return count


def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Smoke-test CERT r4.2 canonical ingestion."
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
            "Number of records to test per domain "
            "(default: 10)."
        ),
    )

    args = parser.parse_args()

    if args.rows <= 0:
        raise SystemExit(
            "--rows must be greater than zero."
        )

    root = args.root

    if not root.exists():
        raise SystemExit(
            f"ERROR: CERT root does not exist: {root}"
        )

    print("=" * 60)
    print("CERT r4.2 INGESTION SMOKE TEST")
    print("=" * 60)

    total = 0

    for domain in CERT_DOMAINS:

        total += test_domain(
            root,
            domain,
            args.rows,
        )

    total += test_ldap(
        root,
        args.rows,
    )

    print()
    print("=" * 60)
    print("RESULT")
    print("=" * 60)

    print(
        f"PASS: {total} canonical events validated."
    )

    print(
        "All CERT behavioural domains and LDAP passed "
        "the smoke test."
    )


if __name__ == "__main__":
    main()