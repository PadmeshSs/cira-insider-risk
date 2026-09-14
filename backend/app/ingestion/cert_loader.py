"""
CERT r4.2 ingestion loader.

Responsibilities:
1. Read CERT r4.2 raw CSV files.
2. Process large files in chunks.
3. Convert records to CanonicalEvent.
4. Preserve source traceability.
5. Reject obvious ground-truth leakage.
6. Support sampling for smoke tests.
7. Support CERT LDAP snapshots located under:

       cert_r4.2/
           LDAP/
               2009-12.csv
               2010-01.csv
               ...

Cross-platform provenance:
    metadata["source_file"] always uses POSIX-style "/" separators.
    This keeps lineage values identical on Windows, Linux, and macOS.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterator

import pandas as pd

from .contracts import CanonicalEvent


CERT_DOMAINS: dict[str, str] = {
    "logon": "logon.csv",
    "device": "device.csv",
    "email": "email.csv",
    "file": "file.csv",
    "http": "http.csv",
    "psychometric": "psychometric.csv",
}

FORBIDDEN_LABEL_COLUMNS = {
    "label",
    "labels",
    "insider",
    "malicious",
    "is_malicious",
    "ground_truth",
    "scenario",
}

ID_COLUMNS = ("id", "event_id")
TIMESTAMP_COLUMNS = ("date", "timestamp", "datetime", "time")
USER_COLUMNS = ("user", "user_id")
DEVICE_COLUMNS = ("pc", "device", "device_id")
ACTIVITY_COLUMNS = ("activity", "action")


def _normalise_column_name(value: Any) -> str:
    return str(value).strip().lower()


def _is_missing(value: Any) -> bool:
    if value is None:
        return True

    try:
        result = pd.isna(value)

        if isinstance(result, bool):
            return result

    except (TypeError, ValueError):
        pass

    return False


def _clean_value(value: Any) -> Any:
    if _is_missing(value):
        return None

    if hasattr(value, "item"):
        try:
            return value.item()
        except (ValueError, TypeError):
            pass

    return value


def _row_to_dict(row: pd.Series) -> dict[str, Any]:
    return {
        str(key): _clean_value(value)
        for key, value in row.to_dict().items()
    }


def _find_column(
    columns: list[str],
    candidates: tuple[str, ...],
) -> str | None:
    normalized = {
        _normalise_column_name(column): column
        for column in columns
    }

    for candidate in candidates:
        result = normalized.get(
            _normalise_column_name(candidate)
        )

        if result is not None:
            return result

    return None


def _parse_timestamp(value: Any):
    if _is_missing(value):
        return None

    parsed = pd.to_datetime(
        value,
        errors="coerce",
    )

    if pd.isna(parsed):
        return None

    return parsed.to_pydatetime()


def _assert_no_label_columns(
    columns: list[str],
) -> None:
    normalized = {
        _normalise_column_name(column)
        for column in columns
    }

    leaked = normalized.intersection(
        FORBIDDEN_LABEL_COLUMNS
    )

    if leaked:
        raise ValueError(
            "Ground-truth leakage detected. "
            f"Forbidden columns found: {sorted(leaked)}"
        )


def _stable_event_id(
    domain: str,
    row_number: int,
    row: dict[str, Any],
) -> str:
    id_column = _find_column(
        list(row.keys()),
        ID_COLUMNS,
    )

    source_id = (
        row.get(id_column)
        if id_column is not None
        else None
    )

    if not _is_missing(source_id):
        source_id = str(source_id).strip()

        if source_id:
            return (
                f"cert-r4.2:{domain}:{source_id}"
            )

    canonical = repr(
        sorted(
            (str(k), str(v))
            for k, v in row.items()
        )
    )

    digest = hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()[:16]

    return (
        f"cert-r4.2:{domain}:"
        f"{row_number}:{digest}"
    )


def _read_csv_chunks(
    path: Path,
    chunksize: int,
) -> Iterator[pd.DataFrame]:
    if not path.exists():
        raise FileNotFoundError(
            f"CERT file not found: {path}"
        )

    yield from pd.read_csv(
        path,
        chunksize=chunksize,
        low_memory=False,
    )


def _build_event(
    *,
    domain: str,
    source_file: str,
    row_number: int,
    row: dict[str, Any],
) -> CanonicalEvent:
    columns = list(row.keys())

    id_column = _find_column(
        columns,
        ID_COLUMNS,
    )

    timestamp_column = _find_column(
        columns,
        TIMESTAMP_COLUMNS,
    )

    user_column = _find_column(
        columns,
        USER_COLUMNS,
    )

    device_column = _find_column(
        columns,
        DEVICE_COLUMNS,
    )

    activity_column = _find_column(
        columns,
        ACTIVITY_COLUMNS,
    )

    timestamp = (
        _parse_timestamp(
            row.get(timestamp_column)
        )
        if timestamp_column
        else None
    )

    user_id = (
        str(row[user_column]).strip()
        if (
            user_column
            and not _is_missing(
                row.get(user_column)
            )
        )
        else None
    )

    device_id = (
        str(row[device_column]).strip()
        if (
            device_column
            and not _is_missing(
                row.get(device_column)
            )
        )
        else None
    )

    activity = (
        str(
            row[activity_column]
        ).strip().lower()
        if (
            activity_column
            and not _is_missing(
                row.get(activity_column)
            )
        )
        else None
    )

    source_type_map = {
        "logon": "authentication",
        "device": "device",
        "email": "email",
        "file": "file",
        "http": "http",
        "psychometric": "psychometric",
        "ldap": "ldap",
    }

    source_type = source_type_map[domain]

    if domain == "logon":
        event_type = (
            f"logon_{activity}"
            if activity
            else "logon_event"
        )

    elif domain == "device":
        event_type = (
            f"device_{activity}"
            if activity
            else "device_event"
        )

    elif domain == "file":
        event_type = (
            f"file_{activity}"
            if activity
            else "file_event"
        )

    elif domain == "email":
        event_type = (
            f"email_{activity}"
            if activity
            else "email_event"
        )

    elif domain == "http":
        event_type = "http_request"

    elif domain == "psychometric":
        event_type = "psychometric_snapshot"

    elif domain == "ldap":
        event_type = "ldap_snapshot"

    else:
        event_type = f"{domain}_event"

    metadata: dict[str, Any] = {
        "dataset": "CERT",
        "release": "r4.2",
        "domain": domain,
        "source_file": source_file,
        "source_row_number": row_number,
    }

    if (
        id_column
        and not _is_missing(
            row.get(id_column)
        )
    ):
        metadata["source_record_id"] = str(
            row[id_column]
        )

    return CanonicalEvent(
        event_id=_stable_event_id(
            domain=domain,
            row_number=row_number,
            row=row,
        ),
        timestamp=timestamp,
        user_id=user_id,
        device_id=device_id,
        source_type=source_type,
        event_type=event_type,
        details=row,
        metadata=metadata,
    )


def iter_cert_domain_events(
    root: str | Path,
    domain: str,
    *,
    chunksize: int = 10_000,
) -> Iterator[CanonicalEvent]:
    root = Path(root)

    if domain not in CERT_DOMAINS:
        raise ValueError(
            f"Unsupported CERT domain: {domain}. "
            f"Expected: {sorted(CERT_DOMAINS)}"
        )

    path = root / CERT_DOMAINS[domain]

    row_number = 0

    for chunk in _read_csv_chunks(
        path,
        chunksize,
    ):
        _assert_no_label_columns(
            list(chunk.columns)
        )

        for _, pandas_row in chunk.iterrows():
            row_number += 1

            row = _row_to_dict(
                pandas_row
            )

            yield _build_event(
                domain=domain,
                source_file=CERT_DOMAINS[domain],
                row_number=row_number,
                row=row,
            )


def iter_ldap_events(
    root: str | Path,
    *,
    chunksize: int = 10_000,
) -> Iterator[CanonicalEvent]:
    root = Path(root)

    ldap_root = root / "LDAP"

    if not ldap_root.exists():
        raise FileNotFoundError(
            f"LDAP directory not found: {ldap_root}"
        )

    if not ldap_root.is_dir():
        raise NotADirectoryError(
            f"Expected LDAP directory but found: "
            f"{ldap_root}"
        )

    ldap_files = sorted(
        ldap_root.glob("*.csv")
    )

    if not ldap_files:
        raise FileNotFoundError(
            f"No LDAP CSV snapshots found under: "
            f"{ldap_root}"
        )

    row_number = 0

    for path in ldap_files:
        # IMPORTANT:
        # Always use POSIX separators so provenance
        # is identical across operating systems.
        source_file = path.relative_to(
            root
        ).as_posix()

        for chunk in _read_csv_chunks(
            path,
            chunksize,
        ):
            _assert_no_label_columns(
                list(chunk.columns)
            )

            for _, pandas_row in chunk.iterrows():
                row_number += 1

                row = _row_to_dict(
                    pandas_row
                )

                yield _build_event(
                    domain="ldap",
                    source_file=source_file,
                    row_number=row_number,
                    row=row,
                )


def iter_cert_events(
    root: str | Path,
    *,
    domains: list[str] | None = None,
    chunksize: int = 10_000,
    sample_rows: int | None = None,
) -> Iterator[CanonicalEvent]:
    selected_domains = (
        domains
        if domains is not None
        else [
            *CERT_DOMAINS.keys(),
            "ldap",
        ]
    )

    emitted = 0

    for domain in selected_domains:
        if domain == "ldap":
            iterator = iter_ldap_events(
                root,
                chunksize=chunksize,
            )
        else:
            iterator = iter_cert_domain_events(
                root,
                domain,
                chunksize=chunksize,
            )

        for event in iterator:
            yield event

            emitted += 1

            if (
                sample_rows is not None
                and emitted >= sample_rows
            ):
                return


def load_cert_sample(
    root: str | Path,
    *,
    rows_per_domain: int = 10,
    chunksize: int = 10_000,
) -> dict[str, list[CanonicalEvent]]:
    result: dict[
        str,
        list[CanonicalEvent]
    ] = {}

    for domain in CERT_DOMAINS:
        events: list[
            CanonicalEvent
        ] = []

        for event in iter_cert_domain_events(
            root,
            domain,
            chunksize=chunksize,
        ):
            events.append(event)

            if len(events) >= rows_per_domain:
                break

        result[domain] = events

    ldap_events: list[
        CanonicalEvent
    ] = []

    for event in iter_ldap_events(
        root,
        chunksize=chunksize,
    ):
        ldap_events.append(event)

        if len(ldap_events) >= rows_per_domain:
            break

    result["ldap"] = ldap_events

    return result


def inspect_csv_headers(
    root: str | Path,
) -> dict[str, list[str]]:
    root = Path(root)

    headers: dict[
        str,
        list[str]
    ] = {}

    for domain, filename in CERT_DOMAINS.items():
        path = root / filename

        if not path.exists():
            raise FileNotFoundError(
                f"Missing CERT file: {path}"
            )

        header = pd.read_csv(
            path,
            nrows=0,
        )

        _assert_no_label_columns(
            list(header.columns)
        )

        headers[domain] = [
            str(column)
            for column in header.columns
        ]

    ldap_root = root / "LDAP"

    if not ldap_root.exists():
        raise FileNotFoundError(
            f"LDAP directory not found: {ldap_root}"
        )

    ldap_files = sorted(
        ldap_root.glob("*.csv")
    )

    if not ldap_files:
        raise FileNotFoundError(
            f"No LDAP CSV snapshots found under: "
            f"{ldap_root}"
        )

    for path in ldap_files:
        source_name = path.relative_to(
            root
        ).as_posix()

        header = pd.read_csv(
            path,
            nrows=0,
        )

        _assert_no_label_columns(
            list(header.columns)
        )

        headers[source_name] = [
            str(column)
            for column in header.columns
        ]

    return headers