from app.ingestion.cert_loader import _build_event


def test_ldap_snapshot_month_is_propagated():
    event = _build_event(
        domain="ldap",
        source_file="LDAP/2010-03.csv",
        row_number=1,
        row={
            "user_id": "UserA",
            "date": "03/01/2010 00:00:00",
            "role": "Employee",
        },
        snapshot_month="2010-03",
    )

    assert event.metadata["snapshot_month"] == "2010-03"
    assert event.metadata["source_file"] == "LDAP/2010-03.csv"
