from datetime import datetime, timezone

from app.preprocessing.normalize import normalize_timestamp


def test_chapter4_normalizer_accepts_real_cert_timestamp():
    result = normalize_timestamp(
        "01/02/2010 06:49:00",
        source_timezone="UTC",
        target_timezone="UTC",
    )

    assert result == datetime(
        2010, 1, 2, 6, 49, 0, tzinfo=timezone.utc
    )
    assert result.tzinfo is not None
