from pathlib import Path

import pandas as pd
import pytest

from app.ingestion.cert_loader import (
    CERT_DOMAINS,
    FORBIDDEN_LABEL_COLUMNS,
    iter_cert_domain_events,
    iter_ldap_events,
    load_cert_sample,
)


def _write_csv(
    path: Path,
    rows: list[dict],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    pd.DataFrame(rows).to_csv(
        path,
        index=False,
    )


@pytest.fixture
def cert_root(tmp_path: Path) -> Path:
    root = tmp_path / "cert_r4.2"
    root.mkdir()

    _write_csv(
        root / "logon.csv",
        [
            {
                "id": "1",
                "date": "2010-01-01 10:00:00",
                "user": "USR001",
                "pc": "PC-001",
                "activity": "Logon",
            }
        ],
    )

    _write_csv(
        root / "device.csv",
        [
            {
                "id": "2",
                "date": "2010-01-01 10:01:00",
                "user": "USR001",
                "pc": "PC-001",
                "activity": "Connect",
            }
        ],
    )

    _write_csv(
        root / "email.csv",
        [
            {
                "id": "3",
                "date": "2010-01-01 10:02:00",
                "user": "USR001",
                "pc": "PC-001",
                "to": "target@example.com",
                "cc": "",
                "bcc": "",
                "from": "USR001@example.com",
                "size": 100,
                "attachments": 1,
                "content": "test",
            }
        ],
    )

    _write_csv(
        root / "file.csv",
        [
            {
                "id": "4",
                "date": "2010-01-01 10:03:00",
                "user": "USR001",
                "pc": "PC-001",
                "filename": "test.txt",
                "content": "read",
            }
        ],
    )

    _write_csv(
        root / "http.csv",
        [
            {
                "id": "5",
                "date": "2010-01-01 10:04:00",
                "user": "USR001",
                "pc": "PC-001",
                "url": "https://example.com",
                "content": "GET",
            }
        ],
    )

    _write_csv(
        root / "psychometric.csv",
        [
            {
                "employee_name": "Example User",
                "user_id": "USR001",
                "O": 1,
                "C": 2,
                "E": 3,
                "A": 4,
                "N": 5,
            }
        ],
    )

    _write_csv(
        root / "LDAP" / "2009-12.csv",
        [
            {
                "employee_name": "Example User",
                "user_id": "USR001",
                "email": "example@example.com",
                "role": "Developer",
                "business_unit": 1,
                "functional_unit": "Engineering",
                "department": "Software",
                "team": "Platform",
                "supervisor": "Manager",
            }
        ],
    )

    return root


def test_cert_domains_are_defined():
    assert set(CERT_DOMAINS) == {
        "logon",
        "device",
        "email",
        "file",
        "http",
        "psychometric",
    }


def test_logon_records_convert_to_canonical_events(
    cert_root: Path,
):
    events = list(
        iter_cert_domain_events(
            cert_root,
            "logon",
            chunksize=1,
        )
    )

    assert len(events) == 1

    event = events[0]

    assert event.event_id == (
        "cert-r4.2:logon:1"
    )
    assert event.user_id == "USR001"
    assert event.device_id == "PC-001"
    assert event.source_type == "authentication"
    assert event.event_type == "logon_logon"

    assert event.metadata["dataset"] == "CERT"
    assert event.metadata["release"] == "r4.2"
    assert event.metadata["domain"] == "logon"
    assert event.metadata["source_file"] == "logon.csv"
    assert event.metadata["source_row_number"] == 1
    assert event.metadata["source_record_id"] == "1"


def test_event_id_is_stable(
    cert_root: Path,
):
    first = next(
        iter_cert_domain_events(
            cert_root,
            "logon",
        )
    )

    second = next(
        iter_cert_domain_events(
            cert_root,
            "logon",
        )
    )

    assert first.event_id == second.event_id


def test_all_behavioural_domains_can_be_loaded(
    cert_root: Path,
):
    for domain in CERT_DOMAINS:
        events = list(
            iter_cert_domain_events(
                cert_root,
                domain,
                chunksize=1,
            )
        )

        assert len(events) == 1
        assert events[0].metadata["domain"] == domain


def test_ldap_snapshot_is_loaded(
    cert_root: Path,
):
    event = next(
        iter_ldap_events(
            cert_root,
            chunksize=1,
        )
    )

    assert event.source_type == "ldap"
    assert event.event_type == "ldap_snapshot"
    assert event.user_id == "USR001"

    # Provenance is intentionally normalized to POSIX
    # separators for cross-platform consistency.
    assert event.metadata["source_file"] == (
        Path("LDAP", "2009-12.csv").as_posix()
    )

    assert event.metadata["source_row_number"] == 1
    assert event.timestamp is None


def test_load_cert_sample_returns_each_domain(
    cert_root: Path,
):
    result = load_cert_sample(
        cert_root,
        rows_per_domain=1,
    )

    assert set(result) == {
        *CERT_DOMAINS.keys(),
        "ldap",
    }

    for events in result.values():
        assert len(events) == 1


def test_ground_truth_columns_are_rejected(
    tmp_path: Path,
):
    root = tmp_path / "cert_r4.2"
    root.mkdir()

    _write_csv(
        root / "logon.csv",
        [
            {
                "id": "1",
                "date": "2010-01-01",
                "user": "USR001",
                "pc": "PC-001",
                "activity": "Logon",
                "scenario": "1",
            }
        ],
    )

    with pytest.raises(
        ValueError,
        match="Ground-truth leakage detected",
    ):
        list(
            iter_cert_domain_events(
                root,
                "logon",
            )
        )


def test_missing_cert_file_fails_explicitly(
    tmp_path: Path,
):
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


def test_forbidden_label_columns_are_nonempty():
    assert FORBIDDEN_LABEL_COLUMNS