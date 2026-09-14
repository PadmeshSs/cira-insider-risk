"""
Unit tests for the CERT r4.2 ingestion loader.

These tests use small synthetic CSV fixtures so that the loader's
behaviour can be tested without requiring the 4+ GB CERT dataset.

Real-data validation is performed separately by cert_smoke_test.py.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from backend.app.ingestion.cert_loader import (
    CERT_DOMAINS,
    iter_cert_domain_events,
    iter_ldap_events,
    load_cert_sample,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_csv(
    path: Path,
    rows: list[dict],
) -> None:
    dataframe = pd.DataFrame(rows)
    dataframe.to_csv(
        path,
        index=False,
    )


def create_cert_fixture(
    root: Path,
) -> None:

    # -----------------------------------------------------------------------
    # logon.csv
    # -----------------------------------------------------------------------

    write_csv(
        root / "logon.csv",
        [
            {
                "id": 1,
                "date": "2010-01-01 08:00:00",
                "user": "USER001",
                "pc": "PC001",
                "activity": "Logon",
            },
            {
                "id": 2,
                "date": "2010-01-01 18:00:00",
                "user": "USER001",
                "pc": "PC001",
                "activity": "Logoff",
            },
        ],
    )

    # -----------------------------------------------------------------------
    # device.csv
    # -----------------------------------------------------------------------

    write_csv(
        root / "device.csv",
        [
            {
                "id": 10,
                "date": "2010-01-01 09:00:00",
                "user": "USER001",
                "pc": "PC001",
                "activity": "Connect",
            },
        ],
    )

    # -----------------------------------------------------------------------
    # email.csv
    # -----------------------------------------------------------------------

    write_csv(
        root / "email.csv",
        [
            {
                "id": 20,
                "date": "2010-01-01 10:00:00",
                "user": "USER001",
                "pc": "PC001",
                "to": "USER002",
                "cc": "",
                "bcc": "",
                "from": "USER001",
                "size": 1024,
                "attachments": 1,
                "content": "test message",
            },
        ],
    )

    # -----------------------------------------------------------------------
    # file.csv
    # -----------------------------------------------------------------------

    write_csv(
        root / "file.csv",
        [
            {
                "id": 30,
                "date": "2010-01-01 11:00:00",
                "user": "USER001",
                "pc": "PC001",
                "filename": "report.doc",
                "content": "FileSystem",
            },
        ],
    )

    # -----------------------------------------------------------------------
    # http.csv
    # -----------------------------------------------------------------------

    write_csv(
        root / "http.csv",
        [
            {
                "id": 40,
                "date": "2010-01-01 12:00:00",
                "user": "USER001",
                "pc": "PC001",
                "url": "http://example.com",
                "content": "GET",
            },
        ],
    )

    # -----------------------------------------------------------------------
    # psychometric.csv
    # -----------------------------------------------------------------------

    write_csv(
        root / "psychometric.csv",
        [
            {
                "employee_name": "Test User",
                "user_id": "USER001",
                "O": 3.2,
                "C": 4.1,
                "E": 2.8,
                "A": 3.7,
                "N": 2.1,
            },
        ],
    )

    # -----------------------------------------------------------------------
    # LDAP snapshots
    # -----------------------------------------------------------------------

    ldap_root = root / "LDAP"
    ldap_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    write_csv(
        ldap_root / "2009-12.csv",
        [
            {
                "employee_name": "Test User",
                "user_id": "USER001",
                "email": "user001@example.com",
                "role": "ComputerProgrammer",
                "business_unit": 1,
                "functional_unit": "ResearchAndEngineering",
                "department": "SoftwareManagement",
                "team": "Software",
                "supervisor": "Supervisor001",
            },
        ],
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def cert_root(tmp_path: Path) -> Path:
    create_cert_fixture(tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_cert_domains_are_defined() -> None:
    """
    All six CERT behavioural domains required by Chapter 3 must be
    represented by the loader.
    """

    expected = {
        "logon",
        "device",
        "email",
        "file",
        "http",
        "psychometric",
    }

    assert set(CERT_DOMAINS) == expected


def test_logon_records_convert_to_canonical_events(
    cert_root: Path,
) -> None:

    events = list(
        iter_cert_domain_events(
            cert_root,
            "logon",
        )
    )

    assert len(events) == 2

    event = events[0]

    assert event.user_id == "USER001"
    assert event.device_id == "PC001"
    assert event.source_type == "authentication"
    assert event.event_type == "logon_logon"

    assert event.timestamp is not None

    assert event.metadata["dataset"] == "CERT"
    assert event.metadata["release"] == "r4.2"
    assert event.metadata["domain"] == "logon"
    assert event.metadata["source_file"] == "logon.csv"


def test_event_id_is_stable(
    cert_root: Path,
) -> None:

    first = list(
        iter_cert_domain_events(
            cert_root,
            "logon",
        )
    )

    second = list(
        iter_cert_domain_events(
            cert_root,
            "logon",
        )
    )

    assert first[0].event_id == second[0].event_id
    assert first[1].event_id == second[1].event_id


def test_all_behavioural_domains_can_be_loaded(
    cert_root: Path,
) -> None:

    for domain in CERT_DOMAINS:

        events = list(
            iter_cert_domain_events(
                cert_root,
                domain,
            )
        )

        assert len(events) > 0

        for event in events:
            assert event.source_type
            assert event.event_type
            assert event.event_id
            assert event.metadata["dataset"] == "CERT"
            assert event.metadata["release"] == "r4.2"


def test_ldap_snapshot_is_loaded(
    cert_root: Path,
) -> None:

    events = list(
        iter_ldap_events(cert_root)
    )

    assert len(events) == 1

    event = events[0]

    assert event.user_id == "USER001"
    assert event.timestamp is None
    assert event.source_type == "ldap"
    assert event.event_type == "ldap_snapshot"

    assert event.details["role"] == "ComputerProgrammer"
    assert event.details["department"] == "SoftwareManagement"

    assert event.metadata["dataset"] == "CERT"
    assert event.metadata["release"] == "r4.2"
    assert event.metadata["domain"] == "ldap"

    assert event.metadata["source_file"] == (
        "LDAP\\2009-12.csv"
    )


def test_load_cert_sample_returns_each_domain(
    cert_root: Path,
) -> None:

    result = load_cert_sample(
        cert_root,
        rows_per_domain=1,
    )

    expected_domains = {
        "logon",
        "device",
        "email",
        "file",
        "http",
        "psychometric",
        "ldap",
    }

    assert set(result) == expected_domains

    for domain, events in result.items():
        assert len(events) == 1
        assert events[0].metadata["domain"] == domain


def test_ground_truth_columns_are_rejected(
    tmp_path: Path,
) -> None:

    write_csv(
        tmp_path / "logon.csv",
        [
            {
                "id": 1,
                "date": "2010-01-01 08:00:00",
                "user": "USER001",
                "pc": "PC001",
                "activity": "Logon",
                "label": 1,
            },
        ],
    )

    with pytest.raises(
        ValueError,
        match="Ground-truth leakage detected",
    ):
        list(
            iter_cert_domain_events(
                tmp_path,
                "logon",
            )
        )


def test_missing_cert_file_fails_explicitly(
    tmp_path: Path,
) -> None:

    with pytest.raises(
        FileNotFoundError,
        match="CERT file not found",
    ):
        list(
            iter_cert_domain_events(
                tmp_path,
                "logon",
            )
        )