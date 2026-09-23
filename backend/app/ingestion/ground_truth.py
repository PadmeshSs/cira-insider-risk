"""
CERT r4.2 ground-truth loader.

Ground truth is kept completely separate from the behavioural-event
ingestion pipeline.

This module is used ONLY for:
    - evaluation
    - supervised baseline experiments
    - validation of anomaly detection results

Ground-truth labels must never enter the feature-input/event stream.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import pandas as pd


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GroundTruthRecord:
    """
    One CERT insider-threat ground-truth record.

    The loader preserves the raw values rather than imposing assumptions
    about the exact answer-file schema.
    """

    user_id: str
    start: Any
    end: Any
    scenario: str | None = None
    details: str | None = None
    dataset: str | None = None
    source_file: str | None = None


# ---------------------------------------------------------------------------
# Column aliases
# ---------------------------------------------------------------------------

USER_COLUMNS = (
    "user",
    "user_id",
    "userid",
)

START_COLUMNS = (
    "start",
    "start_date",
    "start_time",
)

END_COLUMNS = (
    "end",
    "end_date",
    "end_time",
)

SCENARIO_COLUMNS = (
    "scenario",
    "scenario_id",
)

DETAILS_COLUMNS = (
    "details",
    "detail",
    "description",
)

DATASET_COLUMNS = (
    "dataset",
    "release",
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


CERT_TIMESTAMP_FORMAT = "%m/%d/%Y %H:%M:%S"


def _parse_datetime(value: Any) -> Any:
    """
    Parse CERT r4.2 ground-truth timestamps into timezone-aware UTC values.

    CERT supplies timestamps without a timezone. UTC is the canonical source
    timezone used by Chapter 4 unless a caller explicitly performs another
    conversion.
    """

    if _is_missing(value):
        return None

    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = pd.to_datetime(
            value,
            format=CERT_TIMESTAMP_FORMAT,
            errors="coerce",
        )

    if pd.isna(parsed):
        return None

    # pandas Timestamp has .to_pydatetime(); native datetime does not.
    if isinstance(parsed, pd.Timestamp):
        parsed = parsed.to_pydatetime()

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed


# ---------------------------------------------------------------------------
# Schema detection
# ---------------------------------------------------------------------------

def inspect_ground_truth_headers(
    root: str | Path,
) -> dict[str, list[str]]:
    """
    Inspect CSV files inside the CERT ground-truth directory.

    This function intentionally does not assume a particular filename.
    """

    root = Path(root)

    if not root.exists():
        raise FileNotFoundError(
            f"Ground-truth directory not found: {root}"
        )

    if not root.is_dir():
        raise NotADirectoryError(
            f"Expected ground-truth directory but found: {root}"
        )

    csv_files = sorted(root.rglob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV ground-truth files found under: {root}"
        )

    result: dict[str, list[str]] = {}

    for path in csv_files:
        header = pd.read_csv(
            path,
            nrows=0,
        )

        result[str(path.relative_to(root))] = [
            str(column)
            for column in header.columns
        ]

    return result


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _find_ground_truth_files(root: Path) -> list[Path]:
    """
    Locate the CERT ground-truth index.

    CERT r4.2 stores the insider ground truth in:

        <root>/insiders.csv

    Other CSV files under the same directory are scenario/event
    files and must NOT be interpreted as ground-truth records.
    """
    candidates = [
        root / "insiders.csv",
        root / "insiders",
    ]

    for path in candidates:
        if path.exists() and path.is_file():
            return [path]

    raise FileNotFoundError(
        "CERT ground-truth index not found. Expected one of: "
        f"{root / 'insiders.csv'} or {root / 'insiders'}"
    )


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse_dataframe(
    dataframe: pd.DataFrame,
    *,
    source_file: str,
) -> list[GroundTruthRecord]:

    columns = [
        str(column)
        for column in dataframe.columns
    ]

    user_column = _find_column(
        columns,
        USER_COLUMNS,
    )

    if user_column is None:
        raise ValueError(
            "Unable to identify the user column in "
            f"ground-truth file '{source_file}'. "
            f"Available columns: {columns}"
        )

    start_column = _find_column(
        columns,
        START_COLUMNS,
    )

    end_column = _find_column(
        columns,
        END_COLUMNS,
    )

    scenario_column = _find_column(
        columns,
        SCENARIO_COLUMNS,
    )

    details_column = _find_column(
        columns,
        DETAILS_COLUMNS,
    )

    dataset_column = _find_column(
        columns,
        DATASET_COLUMNS,
    )

    if dataset_column is None:
        raise ValueError(
            "CERT ground-truth file must contain a dataset/release column "
            "so r4.2 can be scoped explicitly."
        )

    records: list[GroundTruthRecord] = []

    for _, pandas_row in dataframe.iterrows():

        row = {
            str(key): _clean_value(value)
            for key, value in pandas_row.to_dict().items()
        }

        user_value = row.get(user_column)

        if _is_missing(user_value):
            continue

        user_id = str(user_value).strip().casefold()

        if not user_id:
            continue

        dataset_raw = row.get(dataset_column)
        if _is_missing(dataset_raw):
            continue

        dataset_value = str(dataset_raw).strip()
        if dataset_value != "4.2":
            continue

        start_value = (
            _parse_datetime(row.get(start_column))
            if start_column
            else None
        )

        end_value = (
            _parse_datetime(row.get(end_column))
            if end_column
            else None
        )

        scenario_value = (
            str(row.get(scenario_column)).strip()
            if (
                scenario_column
                and not _is_missing(row.get(scenario_column))
            )
            else None
        )

        details_value = (
            str(row.get(details_column)).strip()
            if (
                details_column
                and not _is_missing(row.get(details_column))
            )
            else None
        )

        # dataset_value was validated and scoped above.
        dataset_value = "4.2"

        records.append(
            GroundTruthRecord(
                user_id=user_id,
                start=start_value,
                end=end_value,
                scenario=scenario_value,
                details=details_value,
                dataset=dataset_value,
                source_file=source_file,
            )
        )

    return records


# ---------------------------------------------------------------------------
# Public loader
# ---------------------------------------------------------------------------

def iter_cert_ground_truth(
    root: str | Path,
    *,
    chunksize: int = 10_000,
) -> Iterator[GroundTruthRecord]:
    """
    Iterate over CERT r4.2 ground-truth records.

    Only insiders.csv is treated as the ground-truth source.
    Scenario/event CSV files are intentionally excluded.
    """
    root = Path(root)

    if not root.exists():
        raise FileNotFoundError(
            f"Ground-truth directory not found: {root}"
        )

    if not root.is_dir():
        raise NotADirectoryError(
            f"Expected ground-truth directory but found: {root}"
        )

    files = _find_ground_truth_files(root)

    for path in files:
        source_file = str(path.relative_to(root))

        for chunk in pd.read_csv(
            path,
            chunksize=chunksize,
            low_memory=False,
        ):
            records = _parse_dataframe(
                chunk,
                source_file=source_file,
            )

            yield from records


def load_cert_ground_truth(
    root: str | Path,
) -> list[GroundTruthRecord]:
    """
    Load all CERT ground-truth records into memory.

    Intended for evaluation datasets, not behavioural-event ingestion.
    """

    return list(
        iter_cert_ground_truth(root)
    )


# ---------------------------------------------------------------------------
# Evaluation helper
# ---------------------------------------------------------------------------

def build_user_label_index(
    records: list[GroundTruthRecord],
) -> dict[str, list[GroundTruthRecord]]:
    """
    Group ground-truth records by user.

    This is useful during evaluation when determining whether an
    anomaly falls inside a known malicious-user/time interval.
    """

    index: dict[str, list[GroundTruthRecord]] = {}

    for record in records:
        index.setdefault(
            record.user_id.strip().casefold(),
            [],
        ).append(record)

    return index


def is_ground_truth_event(
    *,
    user_id: str,
    timestamp: Any,
    records: list[GroundTruthRecord],
) -> bool:
    """
    Determine whether a user/timestamp falls inside any known
    ground-truth interval.

    Used ONLY during evaluation.

    Returns False when a record has no usable temporal interval.
    """

    if _is_missing(timestamp):
        return False

    timestamp = _parse_datetime(timestamp)

    if timestamp is None:
        return False

    canonical_user_id = str(user_id).strip().casefold()

    for record in records:

        if record.user_id.strip().casefold() != canonical_user_id:
            continue

        if record.start is None or record.end is None:
            continue

        record_start = _parse_datetime(record.start)
        record_end = _parse_datetime(record.end)

        if record_start is None or record_end is None:
            continue

        # All comparison values are canonical UTC-aware datetimes.
        if record_start <= timestamp <= record_end:
            return True

    return False

# ---------------------------------------------------------------------------
# Event-level answer files -> evaluation label tables (HCEA §3.4)
# ---------------------------------------------------------------------------
# The r4.2 answer folders (r4.2-1/, r4.2-2/, r4.2-3/) hold one headerless CSV
# per insider.  Every line is one malicious source event:
#     <domain>, <event id>, <MM/DD/YYYY HH:MM:SS>, <user>, <pc>, ...
# Trailing fields vary by domain (email/http carry content), so only the
# first five fields are read.  These files are the precise event-level
# ground truth; insiders.csv start/end windows are coarser and are NOT used
# to label user-days.
#
# Output lives under <processed>/labels/, a tree the feature pipeline never
# reads.  Labels are joined to features only inside the evaluation harness.

R42_SCENARIO_DIRS = ("r4.2-1", "r4.2-2", "r4.2-3")


def iter_r42_malicious_events(ground_truth_dir: str | Path) -> Iterator[dict[str, Any]]:
    import csv

    root = Path(ground_truth_dir)
    found_any = False
    for folder in R42_SCENARIO_DIRS:
        scenario_dir = root / folder
        if not scenario_dir.is_dir():
            continue
        scenario = int(folder.rsplit("-", 1)[1])
        for path in sorted(scenario_dir.glob("*.csv")):
            found_any = True
            with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                for line_no, fields in enumerate(csv.reader(handle, skipinitialspace=True), start=1):
                    if len(fields) < 4 or not fields[0].strip():
                        continue
                    ts = pd.to_datetime(fields[2].strip(), format=CERT_TIMESTAMP_FORMAT, errors="coerce")
                    if pd.isna(ts):
                        raise ValueError(f"Unparseable timestamp in {path.name}:{line_no}: {fields[2]!r}")
                    yield {
                        "domain": fields[0].strip().casefold(),
                        "event_id": fields[1].strip(),
                        "timestamp": ts,
                        "user_id": fields[3].strip().casefold(),
                        "device_id": fields[4].strip().casefold() if len(fields) > 4 else None,
                        "scenario": scenario,
                        "source_file": f"{folder}/{path.name}",
                    }
    if not found_any:
        raise FileNotFoundError(
            f"No r4.2 answer files under {root} (expected {', '.join(R42_SCENARIO_DIRS)})"
        )


def build_insider_label_tables(
    ground_truth_dir: str | Path,
    processed_dir: str | Path,
) -> dict[str, Any]:
    """Write labels/insider_events.parquet and labels/insider_user_days.parquet."""
    events = pd.DataFrame(list(iter_r42_malicious_events(ground_truth_dir)))
    events["date"] = events["timestamp"].dt.normalize()
    events = events.drop_duplicates(["domain", "event_id"])

    user_days = (
        events.groupby(["user_id", "date"], as_index=False)
        .agg(scenario=("scenario", "min"), n_malicious_events=("event_id", "size"))
    )
    user_days["is_malicious"] = 1
    user_days["n_malicious_events"] = user_days["n_malicious_events"].astype("int32")
    user_days["scenario"] = user_days["scenario"].astype("int8")
    user_days["is_malicious"] = user_days["is_malicious"].astype("int8")

    out = Path(processed_dir) / "labels"
    out.mkdir(parents=True, exist_ok=True)
    for frame, name in ((events, "insider_events.parquet"), (user_days, "insider_user_days.parquet")):
        tmp = out / (name + ".tmp")
        frame.to_parquet(tmp, index=False)
        tmp.replace(out / name)

    return {
        "malicious_events": int(len(events)),
        "insider_users": int(events["user_id"].nunique()),
        "malicious_user_days": int(len(user_days)),
        "users_per_scenario": {int(k): int(v) for k, v in events.groupby("scenario")["user_id"].nunique().items()},
        "first_event": str(events["timestamp"].min()),
        "last_event": str(events["timestamp"].max()),
        "output_dir": str(out),
    }
