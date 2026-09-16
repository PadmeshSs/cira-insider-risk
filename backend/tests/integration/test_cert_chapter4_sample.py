import os
from pathlib import Path

import pytest

from app.ingestion.cert_loader import load_cert_sample
from app.preprocessing.normalize import normalize_events

CERT_ROOT = Path(os.getenv("CERT_RAW_DIR", "datasets/raw/cert_r4.2"))


def test_cert_sample_normalizes_without_accepted_schema_failures():
    if not CERT_ROOT.exists():
        pytest.skip(
            "CERT r4.2 is not present locally; run this test on a machine "
            "with datasets/raw/cert_r4.2 extracted."
        )

    samples = load_cert_sample(
        CERT_ROOT,
        rows_per_domain=10,
    )
    events = [
        event
        for domain_events in samples.values()
        for event in domain_events
    ]

    report = normalize_events(events)

    assert report.accepted_count > 0
    assert all(event.timestamp is None or event.timestamp.tzinfo is not None
               for event in report.accepted)

    # Rejected records are allowed for malformed input, but every rejection
    # must carry an explicit reason. Nothing may disappear silently.
    assert all(
        rejection.reason and rejection.reason_code
        for rejection in report.rejected
    )
