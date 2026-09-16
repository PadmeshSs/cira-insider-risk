import pandas as pd

from app.ingestion.cert_loader import _build_event


def test_cert_loader_parses_real_cert_timestamp():
    event = _build_event(
        domain="logon",
        source_file="logon.csv",
        row_number=1,
        row={
            "id": "L1",
            "date": "01/02/2010 06:49:00",
            "user": "UserA",
            "pc": "PC-1",
            "activity": "Logon",
        },
    )

    assert event.timestamp == pd.Timestamp(
        "2010-01-02 06:49:00"
    ).to_pydatetime()
    assert event.event_id == "cert-r4.2:logon:L1"
    assert event.user_id == "UserA"
