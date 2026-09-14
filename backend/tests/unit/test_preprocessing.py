from datetime import datetime, timezone
import json

import pytest

from app.ingestion.contracts import CanonicalEvent
from app.preprocessing.normalize import (
    normalize_event,
    normalize_events,
    normalize_timestamp,
    write_rejected_records,
)
from app.preprocessing.validate import validate_canonical_event


def make_event(**overrides):
    payload = {
        "event_id": "CERT-R4.2:logon:1",
        "timestamp": "2010-01-02 08:15:00",
        "user_id": "  U001 ",
        "device_id": "  PC-001 ",
        "source_type": "authentication",
        "event_type": "logon_logon",
        "details": {
            "activity": "Logon",
            "bytes": 0,
            "missing_optional_number": None,
        },
        "metadata": {
            "dataset": "CERT",
            "release": "r4.2",
            "source_file": "logon.csv",
            "source_row_number": 1,
            "source_record_id": "1",
        },
    }
    payload.update(overrides)
    return payload


def test_timestamp_becomes_timezone_aware_and_targeted():
    value = normalize_timestamp(
        "2010-01-02 08:15:00",
        source_timezone="UTC",
        target_timezone="UTC",
    )
    assert value is not None
    assert value.tzinfo is not None
    assert value.utcoffset() == timezone.utc.utcoffset(value)
    assert value.isoformat() == "2010-01-02T08:15:00+00:00"


def test_timestamp_converts_between_timezones():
    value = normalize_timestamp(
        "2010-01-02T08:15:00+00:00",
        target_timezone="Asia/Kolkata",
    )
    assert value.isoformat() == "2010-01-02T13:45:00+05:30"


def test_identifiers_are_trimmed_casefolded_and_traceable():
    event = normalize_event(make_event())
    assert event.user_id == "u001"
    assert event.device_id == "pc-001"
    assert event.metadata["normalization"]["original_user_id"] == "U001"
    assert event.metadata["normalization"]["original_device_id"] == "PC-001"
    assert event.metadata["source_file"] == "logon.csv"


def test_missing_values_are_null_but_numeric_zero_is_preserved():
    event = normalize_event(make_event())
    assert event.details["bytes"] == 0
    assert event.details["missing_optional_number"] is None


@pytest.mark.parametrize(
    ("source_type", "event_type"),
    [
        ("auth", "login"),
        ("authentication", "logoff"),
        ("device", "connect"),
        ("email", "send"),
        ("file", "copy"),
        ("http", "request"),
        ("psychometric", "snapshot"),
        ("ldap", "snapshot"),
    ],
)
def test_categorical_values_are_canonicalized(source_type, event_type):
    timestamp = None if source_type in {"psychometric", "ldap"} else "2010-01-02 08:15:00"
    event = normalize_event(
        make_event(
            event_id=f"{source_type}-1",
            timestamp=timestamp,
            source_type=source_type,
            event_type=event_type,
        )
    )
    assert event.source_type in {
        "authentication",
        "device",
        "email",
        "file",
        "http",
        "psychometric",
        "ldap",
    }
    assert "_" in event.event_type


def test_malformed_timestamp_is_rejected_not_dropped():
    report = normalize_events(
        [make_event(timestamp="not-a-timestamp")]
    )
    assert report.accepted_count == 0
    assert report.rejected_count == 1
    assert report.rejected[0].reason_code == "normalization_or_validation_error"


def test_missing_required_user_is_rejected():
    report = normalize_events([make_event(user_id="")])
    assert report.accepted_count == 0
    assert report.rejected_count == 1
    assert "user_id is required" in report.rejected[0].reason


def test_target_label_key_is_rejected_even_if_nested():
    event = make_event(
        details={"activity": "Logon", "ground_truth": "benign"}
    )
    report = normalize_events([event])
    assert report.accepted_count == 0
    assert report.rejected_count == 1
    assert report.rejected[0].reason_code == "target_label_leakage"


def test_duplicate_event_is_rejected_and_recorded():
    event = make_event()
    report = normalize_events([event, event])
    assert report.accepted_count == 1
    assert report.rejected_count == 1
    assert report.duplicate_count == 1
    assert report.rejected[0].reason_code == "duplicate_event"


def test_duplicate_content_hash_catches_synthetic_id_difference():
    first = make_event(
        event_id="cert-r4.2:logon:100:aaaaaaaaaaaaaaaa",
    )
    second = make_event(
        event_id="cert-r4.2:logon:101:bbbbbbbbbbbbbbbb",
    )
    report = normalize_events([first, second])
    assert report.accepted_count == 1
    assert report.rejected_count == 1
    assert report.duplicate_count == 1


def test_valid_event_passes_canonical_validation():
    event = normalize_event(make_event())
    validated = validate_canonical_event(event)
    assert isinstance(validated, CanonicalEvent)
    assert validated.timestamp is not None
    assert validated.timestamp.tzinfo is not None


def test_rejected_records_are_jsonl(tmp_path):
    report = normalize_events(
        [
            make_event(timestamp="bad"),
            make_event(event_id="valid-2"),
        ]
    )
    path = write_rejected_records(
        report.rejected,
        tmp_path / "rejected_records.jsonl",
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["reason_code"] == "normalization_or_validation_error"
    assert "record" in payload
    assert "reason" in payload


def test_snapshot_sources_can_have_no_timestamp():
    for source in ("ldap", "psychometric"):
        event = normalize_event(
            make_event(
                event_id=f"{source}-1",
                timestamp=None,
                source_type=source,
                event_type="snapshot",
            )
        )
        assert event.timestamp is None


def test_snapshot_source_without_timestamp_still_requires_user():
    report = normalize_events(
        [
            make_event(
                event_id="ldap-1",
                timestamp=None,
                source_type="ldap",
                event_type="snapshot",
                user_id=None,
            )
        ]
    )
    assert report.accepted_count == 0
    assert report.rejected_count == 1
