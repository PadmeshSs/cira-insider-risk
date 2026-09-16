from datetime import timezone

import pandas as pd

from app.ingestion.ground_truth import (
    _parse_dataframe,
    build_user_label_index,
    is_ground_truth_event,
)


def _frame():
    return pd.DataFrame(
        [
            {
                "user": "UserA",
                "start": "01/02/2010 06:49:00",
                "end": "01/02/2010 08:49:00",
                "scenario": "1",
                "dataset": "4.2",
            },
            {
                "user": "UserB",
                "start": "01/02/2010 06:49:00",
                "end": "01/02/2010 08:49:00",
                "scenario": "1",
                "dataset": "4.1",
            },
        ]
    )


def test_ground_truth_is_scoped_to_r42_and_user_ids_normalized():
    records = _parse_dataframe(
        _frame(),
        source_file="insiders.csv",
    )

    assert len(records) == 1
    assert records[0].dataset == "4.2"
    assert records[0].user_id == "usera"


def test_ground_truth_timestamps_are_utc_aware():
    records = _parse_dataframe(
        _frame(),
        source_file="insiders.csv",
    )

    assert records[0].start.tzinfo == timezone.utc
    assert records[0].end.tzinfo == timezone.utc


def test_ground_truth_join_normalizes_user_and_timestamp():
    records = _parse_dataframe(
        _frame(),
        source_file="insiders.csv",
    )

    assert is_ground_truth_event(
        user_id="USERA",
        timestamp="01/02/2010 07:00:00",
        records=records,
    )


def test_ground_truth_index_uses_normalized_ids():
    records = _parse_dataframe(
        _frame(),
        source_file="insiders.csv",
    )

    index = build_user_label_index(records)

    assert "usera" in index
    assert "USERA" not in index
