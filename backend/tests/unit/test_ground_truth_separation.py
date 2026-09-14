from datetime import datetime

from app.ingestion.contracts import CanonicalEvent
from app.ingestion.ground_truth import (
    GroundTruthRecord,
    build_user_label_index,
    is_ground_truth_event,
)


def test_canonical_event_contains_no_ground_truth_fields():
    event = CanonicalEvent(
        event_id="test-event-1",
        timestamp=datetime(
            2010,
            3,
            10,
            12,
            0,
            0,
        ),
        user_id="USR001",
        device_id="PC-001",
        source_type="authentication",
        event_type="logon_logon",
        details={
            "activity": "logon",
        },
        metadata={
            "dataset": "CERT",
            "release": "r4.2",
        },
    )

    fields = set(
        event.model_dump().keys()
    )

    assert "label" not in fields
    assert "scenario" not in fields
    assert "malicious" not in fields
    assert "ground_truth" not in fields


def test_ground_truth_is_not_added_to_event_metadata():
    event = CanonicalEvent(
        event_id="test-event-2",
        timestamp=datetime(
            2010,
            3,
            10,
            12,
            0,
            0,
        ),
        user_id="USR001",
        source_type="authentication",
        event_type="logon_logon",
    )

    metadata = event.metadata

    assert "label" not in metadata
    assert "scenario" not in metadata
    assert "malicious" not in metadata
    assert "ground_truth" not in metadata


def test_ground_truth_is_evaluation_side_data():
    record = GroundTruthRecord(
        user_id="USR001",
        start=datetime(
            2010,
            3,
            1,
        ),
        end=datetime(
            2010,
            3,
            10,
        ),
        scenario="1",
        details="r2.csv",
        dataset="2.0",
        source_file="insiders.csv",
    )

    assert record.user_id == "USR001"
    assert record.scenario == "1"
    assert record.source_file == "insiders.csv"


def test_user_label_index_groups_records_by_user():
    records = [
        GroundTruthRecord(
            user_id="USR001",
            start=datetime(2010, 1, 1),
            end=datetime(2010, 1, 2),
        ),
        GroundTruthRecord(
            user_id="USR001",
            start=datetime(2010, 2, 1),
            end=datetime(2010, 2, 2),
        ),
        GroundTruthRecord(
            user_id="USR002",
            start=datetime(2010, 3, 1),
            end=datetime(2010, 3, 2),
        ),
    ]

    index = build_user_label_index(
        records
    )

    assert set(index) == {
        "USR001",
        "USR002",
    }

    assert len(index["USR001"]) == 2
    assert len(index["USR002"]) == 1


def test_ground_truth_temporal_match():
    records = [
        GroundTruthRecord(
            user_id="USR001",
            start=datetime(
                2010,
                3,
                1,
            ),
            end=datetime(
                2010,
                3,
                10,
            ),
        )
    ]

    assert is_ground_truth_event(
        user_id="USR001",
        timestamp=datetime(
            2010,
            3,
            5,
        ),
        records=records,
    )


def test_ground_truth_temporal_match_outside_interval():
    records = [
        GroundTruthRecord(
            user_id="USR001",
            start=datetime(
                2010,
                3,
                1,
            ),
            end=datetime(
                2010,
                3,
                10,
            ),
        )
    ]

    assert not is_ground_truth_event(
        user_id="USR001",
        timestamp=datetime(
            2010,
            3,
            11,
        ),
        records=records,
    )


def test_ground_truth_temporal_match_wrong_user():
    records = [
        GroundTruthRecord(
            user_id="USR001",
            start=datetime(
                2010,
                3,
                1,
            ),
            end=datetime(
                2010,
                3,
                10,
            ),
        )
    ]

    assert not is_ground_truth_event(
        user_id="USR002",
        timestamp=datetime(
            2010,
            3,
            5,
        ),
        records=records,
    )


def test_ground_truth_without_interval_does_not_create_match():
    records = [
        GroundTruthRecord(
            user_id="USR001",
            start=None,
            end=None,
        )
    ]

    assert not is_ground_truth_event(
        user_id="USR001",
        timestamp=datetime(
            2010,
            3,
            5,
        ),
        records=records,
    )