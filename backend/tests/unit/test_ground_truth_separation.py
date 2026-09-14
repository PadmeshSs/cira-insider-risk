"""
Tests ensuring CERT ground truth remains separate from the behavioural
event-ingestion pipeline.

Ground truth is evaluation metadata. It must never become part of
CanonicalEvent details or metadata.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from backend.app.ingestion.cert_loader import (
    iter_cert_domain_events,
)
from backend.app.ingestion.ground_truth import (
    GroundTruthRecord,
    build_user_label_index,
    is_ground_truth_event,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_csv(
    path: Path,
    rows: list[dict],
) -> None:
    pd.DataFrame(rows).to_csv(
        path,
        index=False,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_canonical_event_contains_no_ground_truth_fields(
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
            },
        ],
    )

    event = next(
        iter_cert_domain_events(
            tmp_path,
            "logon",
        )
    )

    event_data = event.model_dump()

    # Top-level canonical event must not contain labels.
    forbidden = {
        "label",
        "labels",
        "malicious",
        "is_malicious",
        "ground_truth",
        "scenario",
    }

    assert forbidden.isdisjoint(
        event_data.keys()
    )


def test_ground_truth_is_not_added_to_event_metadata(
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
            },
        ],
    )

    event = next(
        iter_cert_domain_events(
            tmp_path,
            "logon",
        )
    )

    metadata = event.metadata

    forbidden = {
        "label",
        "labels",
        "malicious",
        "is_malicious",
        "ground_truth",
        "scenario",
    }

    assert forbidden.isdisjoint(
        metadata.keys()
    )


def test_ground_truth_is_evaluation_side_data() -> None:

    record = GroundTruthRecord(
        user_id="USER001",
        start=pd.Timestamp(
            "2010-01-01 08:00:00"
        ).to_pydatetime(),
        end=pd.Timestamp(
            "2010-01-01 18:00:00"
        ).to_pydatetime(),
        scenario="r4.2-1",
        details="Example insider scenario",
        dataset="r4.2",
        source_file="insiders",
    )

    assert record.user_id == "USER001"
    assert record.scenario == "r4.2-1"

    # The record exists independently from CanonicalEvent.
    assert not hasattr(
        record,
        "event_id",
    )


def test_user_label_index_groups_records_by_user() -> None:

    records = [
        GroundTruthRecord(
            user_id="USER001",
            start=None,
            end=None,
            scenario="r4.2-1",
        ),
        GroundTruthRecord(
            user_id="USER001",
            start=None,
            end=None,
            scenario="r4.2-2",
        ),
        GroundTruthRecord(
            user_id="USER002",
            start=None,
            end=None,
            scenario="r4.2-3",
        ),
    ]

    index = build_user_label_index(
        records
    )

    assert set(index) == {
        "USER001",
        "USER002",
    }

    assert len(
        index["USER001"]
    ) == 2

    assert len(
        index["USER002"]
    ) == 1


def test_ground_truth_temporal_match() -> None:

    records = [
        GroundTruthRecord(
            user_id="USER001",
            start=pd.Timestamp(
                "2010-01-01 08:00:00"
            ).to_pydatetime(),
            end=pd.Timestamp(
                "2010-01-01 18:00:00"
            ).to_pydatetime(),
            scenario="r4.2-1",
        ),
    ]

    assert is_ground_truth_event(
        user_id="USER001",
        timestamp="2010-01-01 12:00:00",
        records=records,
    ) is True


def test_ground_truth_temporal_match_outside_interval() -> None:

    records = [
        GroundTruthRecord(
            user_id="USER001",
            start=pd.Timestamp(
                "2010-01-01 08:00:00"
            ).to_pydatetime(),
            end=pd.Timestamp(
                "2010-01-01 18:00:00"
            ).to_pydatetime(),
            scenario="r4.2-1",
        ),
    ]

    assert is_ground_truth_event(
        user_id="USER001",
        timestamp="2010-01-02 12:00:00",
        records=records,
    ) is False


def test_ground_truth_temporal_match_wrong_user() -> None:

    records = [
        GroundTruthRecord(
            user_id="USER001",
            start=pd.Timestamp(
                "2010-01-01 08:00:00"
            ).to_pydatetime(),
            end=pd.Timestamp(
                "2010-01-01 18:00:00"
            ).to_pydatetime(),
            scenario="r4.2-1",
        ),
    ]

    assert is_ground_truth_event(
        user_id="USER002",
        timestamp="2010-01-01 12:00:00",
        records=records,
    ) is False


def test_ground_truth_without_interval_does_not_create_match() -> None:

    records = [
        GroundTruthRecord(
            user_id="USER001",
            start=None,
            end=None,
            scenario="r4.2-1",
        ),
    ]

    assert is_ground_truth_event(
        user_id="USER001",
        timestamp="2010-01-01 12:00:00",
        records=records,
    ) is False