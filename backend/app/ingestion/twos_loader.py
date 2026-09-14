"""
TWOS secondary-dataset ingestion loader.

Chapter 3 responsibilities:
    - Define the TWOS ingestion interface.
    - Detect whether TWOS data is actually available.
    - Inspect the supplied TWOS files.
    - Convert available TWOS records into the CIRA CanonicalEvent contract.
    - Preserve source traceability.
    - Prevent ground-truth labels from entering the event stream.

IMPORTANT:
    TWOS access is dependent on the dataset release agreement.
    This module must never fabricate TWOS data or claim that TWOS has
    been acquired when the raw dataset is unavailable.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterator

import pandas as pd

from .contracts import CanonicalEvent


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TWOS_DATASET_NAME = "TWOS"

TWOS_RELEASE_STATUS = "PLANNED"
"""
Allowed operational states:

    PLANNED
        Dataset has not yet been received.

    IN_PROGRESS
        Access/release process is underway.

    AVAILABLE
        Raw TWOS data has actually been supplied and can be parsed.

The default is deliberately PLANNED.
"""

FORBIDDEN_LABEL_COLUMNS = {
    "label",
    "labels",
    "insider",
    "malicious",
    "is_malicious",
    "ground_truth",
    "groundtruth",
    "target",
}


# Generic aliases because the exact TWOS schema must be verified against
# the actual released files rather than assumed in advance.

ID_COLUMNS = (
    "id",
    "event_id",
    "eventid",
)

TIMESTAMP_COLUMNS = (
    "timestamp",
    "date",
    "datetime",
    "time",
)

USER_COLUMNS = (
    "user",
    "user_id",
    "userid",
    "employee",
    "employee_id",
)

DEVICE_COLUMNS = (
    "device",
    "device_id",
    "deviceid",
    "pc",
    "computer",
)

ACTIVITY_COLUMNS = (
    "activity",
    "action",
    "event",
    "event_type",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
            "Ground-truth leakage detected in TWOS event data. "
            f"Forbidden columns found: {sorted(leaked)}"
        )


def _stable_event_id(
    source_file: str,
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
                f"twos:{source_id}"
            )

    canonical = repr(
        sorted(
            (str(key), str(value))
            for key, value in row.items()
        )
    )

    digest = hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()[:16]

    return (
        f"twos:{source_file}:"
        f"{row_number}:{digest}"
    )


# ---------------------------------------------------------------------------
# Dataset availability
# ---------------------------------------------------------------------------

def twos_available(
    root: str | Path,
) -> bool:
    """
    Return True only when a TWOS dataset directory exists and contains
    at least one supported data file.
    """

    root = Path(root)

    if not root.exists():
        return False

    if not root.is_dir():
        return False

    supported_files = (
        list(root.rglob("*.csv"))
        + list(root.rglob("*.parquet"))
    )

    return bool(supported_files)


def get_twos_status(
    root: str | Path,
) -> str:
    """
    Determine the operational TWOS status from the filesystem.

    This does NOT claim that a dataset is officially licensed or released.
    It only reports whether usable raw files are physically present.
    """

    if twos_available(root):
        return "AVAILABLE"

    return TWOS_RELEASE_STATUS


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def discover_twos_files(
    root: str | Path,
) -> list[Path]:

    root = Path(root)

    if not root.exists():
        return []

    if not root.is_dir():
        return []

    files = (
        list(root.rglob("*.csv"))
        + list(root.rglob("*.parquet"))
    )

    return sorted(
        files,
        key=lambda path: str(path).lower(),
    )


# ---------------------------------------------------------------------------
# Header inspection
# ---------------------------------------------------------------------------

def inspect_twos_headers(
    root: str | Path,
) -> dict[str, list[str]]:
    """
    Inspect headers of all discovered TWOS files.

    This function is intentionally schema-agnostic.
    The exact TWOS schema should be confirmed when the actual release
    is received.
    """

    root = Path(root)

    files = discover_twos_files(root)

    if not files:
        raise FileNotFoundError(
            f"No TWOS data files found under: {root}"
        )

    result: dict[str, list[str]] = {}

    for path in files:

        relative_path = str(
            path.relative_to(root)
        )

        if path.suffix.lower() == ".csv":

            dataframe = pd.read_csv(
                path,
                nrows=0,
            )

        elif path.suffix.lower() == ".parquet":

            dataframe = pd.read_parquet(
                path,
            ).head(0)

        else:
            continue

        columns = [
            str(column)
            for column in dataframe.columns
        ]

        _assert_no_label_columns(
            columns
        )

        result[relative_path] = columns

    return result


# ---------------------------------------------------------------------------
# Event construction
# ---------------------------------------------------------------------------

def _build_event(
    *,
    source_file: str,
    row_number: int,
    row: dict[str, Any],
) -> CanonicalEvent:

    columns = list(row.keys())

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

    user_id = None

    if user_column:
        value = row.get(user_column)

        if not _is_missing(value):
            user_id = str(value).strip()

    device_id = None

    if device_column:
        value = row.get(device_column)

        if not _is_missing(value):
            device_id = str(value).strip()

    activity = None

    if activity_column:
        value = row.get(activity_column)

        if not _is_missing(value):
            activity = str(value).strip().lower()

    event_type = (
        activity
        if activity
        else "twos_event"
    )

    metadata: dict[str, Any] = {
        "dataset": TWOS_DATASET_NAME,
        "source_file": source_file,
        "source_row_number": row_number,
    }

    id_column = _find_column(
        columns,
        ID_COLUMNS,
    )

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
            source_file=source_file,
            row_number=row_number,
            row=row,
        ),
        timestamp=timestamp,
        user_id=user_id,
        device_id=device_id,
        source_type="twos",
        event_type=event_type,
        details=row,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# File readers
# ---------------------------------------------------------------------------

def _iter_csv_events(
    path: Path,
    *,
    root: Path,
    chunksize: int,
) -> Iterator[CanonicalEvent]:

    source_file = str(
        path.relative_to(root)
    )

    row_number = 0

    for chunk in pd.read_csv(
        path,
        chunksize=chunksize,
        low_memory=False,
    ):

        columns = [
            str(column)
            for column in chunk.columns
        ]

        _assert_no_label_columns(
            columns
        )

        for _, pandas_row in chunk.iterrows():

            row_number += 1

            row = _row_to_dict(
                pandas_row
            )

            yield _build_event(
                source_file=source_file,
                row_number=row_number,
                row=row,
            )


def _iter_parquet_events(
    path: Path,
    *,
    root: Path,
) -> Iterator[CanonicalEvent]:

    source_file = str(
        path.relative_to(root)
    )

    dataframe = pd.read_parquet(
        path
    )

    columns = [
        str(column)
        for column in dataframe.columns
    ]

    _assert_no_label_columns(
        columns
    )

    for row_number, (_, pandas_row) in enumerate(
        dataframe.iterrows(),
        start=1,
    ):

        row = _row_to_dict(
            pandas_row
        )

        yield _build_event(
            source_file=source_file,
            row_number=row_number,
            row=row,
        )


# ---------------------------------------------------------------------------
# Public event iterator
# ---------------------------------------------------------------------------

def iter_twos_events(
    root: str | Path,
    *,
    chunksize: int = 10_000,
    sample_rows: int | None = None,
) -> Iterator[CanonicalEvent]:
    """
    Convert available TWOS records into CanonicalEvent objects.

    If TWOS has not been received, fail explicitly rather than producing
    synthetic or fabricated data.
    """

    root = Path(root)

    files = discover_twos_files(root)

    if not files:
        raise FileNotFoundError(
            "TWOS dataset is not available. "
            f"No supported files were found under: {root}. "
            "Do not fabricate TWOS records; obtain the authorised "
            "dataset release first."
        )

    emitted = 0

    for path in files:

        if path.suffix.lower() == ".csv":

            iterator = _iter_csv_events(
                path,
                root=root,
                chunksize=chunksize,
            )

        elif path.suffix.lower() == ".parquet":

            iterator = _iter_parquet_events(
                path,
                root=root,
            )

        else:
            continue

        for event in iterator:

            yield event

            emitted += 1

            if (
                sample_rows is not None
                and emitted >= sample_rows
            ):
                return


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------

def load_twos_sample(
    root: str | Path,
    *,
    rows: int = 10,
    chunksize: int = 10_000,
) -> list[CanonicalEvent]:
    """
    Load a small TWOS sample for smoke testing.
    """

    return list(
        iter_twos_events(
            root,
            chunksize=chunksize,
            sample_rows=rows,
        )
    )