"""Chapter 4 normalization pipeline.

Input: CanonicalEvent objects produced by Chapter 3 loaders.
Output: normalized, validated CanonicalEvent objects plus explicit rejections.

No target labels are introduced or inferred here.  Ground truth remains an
evaluation-only concern.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import ValidationError

from app.ingestion.contracts import CanonicalEvent
from app.preprocessing.validate import (
    SourceType,
    validation_errors,
    validate_canonical_event,
)

DEFAULT_SOURCE_TIMEZONE = "UTC"
DEFAULT_TARGET_TIMEZONE = "UTC"

SOURCE_ALIASES = {
    "auth": "authentication",
    "authentication": "authentication",
    "login": "authentication",
    "logon": "authentication",
    "device": "device",
    "usb": "device",
    "email": "email",
    "file": "file",
    "http": "http",
    "web": "http",
    "psychometric": "psychometric",
    "ldap": "ldap",
}

EVENT_ALIASES = {
    "logon": "logon_logon",
    "login": "logon_logon",
    "logoff": "logon_logoff",
    "logout": "logon_logoff",
    "connect": "device_connect",
    "disconnect": "device_disconnect",
    "send": "email_send",
    "receive": "email_receive",
}

_MISSING = object()


@dataclass(frozen=True)
class RejectedRecord:
    """Audit record for an event that could not safely enter the pipeline."""

    reason_code: str
    reason: str
    stage: str
    record: dict[str, Any]
    errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "reason_code": self.reason_code,
            "reason": self.reason,
            "stage": self.stage,
            "errors": list(self.errors),
            "record": _json_safe(self.record),
        }


@dataclass
class NormalizationReport:
    accepted: list[CanonicalEvent] = field(default_factory=list)
    rejected: list[RejectedRecord] = field(default_factory=list)
    duplicate_count: int = 0

    @property
    def accepted_count(self) -> int:
        return len(self.accepted)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    @property
    def total_count(self) -> int:
        return self.accepted_count + self.rejected_count

    def summary(self) -> dict[str, int]:
        return {
            "input": self.total_count,
            "accepted": self.accepted_count,
            "rejected": self.rejected_count,
            "duplicates": self.duplicate_count,
        }


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    try:
        # Handle pandas/numpy scalar missing values without importing either.
        result = value != value
        return isinstance(result, bool) and result
    except Exception:
        return False


def _clean_detail_value(value: Any) -> Any:
    """Convert missing representations to None; never convert 0 to None/zero."""
    if _is_missing(value):
        return None
    if isinstance(value, dict):
        return {str(k): _clean_detail_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean_detail_value(v) for v in value]
    if isinstance(value, tuple):
        return [_clean_detail_value(v) for v in value]

    # numpy scalar compatibility without taking a hard dependency on numpy here
    item = getattr(value, "item", None)
    if callable(item):
        try:
            return item()
        except (TypeError, ValueError):
            pass
    return value


def _canonical_identifier(
    value: str | None,
    *,
    field_name: str,
) -> tuple[str | None, str | None]:
    if value is None:
        return None, None

    normalized = unicodedata.normalize("NFKC", str(value)).strip().casefold()
    if not normalized:
        return None, None
    return normalized, str(value).strip()


def normalize_identifier(
    value: str | None,
    *,
    field_name: str,
) -> str | None:
    """Normalize user/device identifiers to NFKC + trim + casefold."""
    normalized, _ = _canonical_identifier(value, field_name=field_name)
    return normalized


def normalize_timestamp(
    value: datetime | str | None,
    *,
    source_timezone: str = DEFAULT_SOURCE_TIMEZONE,
    target_timezone: str = DEFAULT_TARGET_TIMEZONE,
) -> datetime | None:
    """Return a timezone-aware timestamp in the target timezone.

    Naive timestamps are interpreted in the explicitly configured
    source_timezone. This assumption is recorded by the caller in metadata.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        parsed = _parse_datetime_string(text)
    else:
        # Pydantic-compatible fallback for date-like objects.
        try:
            parsed = datetime.fromisoformat(str(value))
        except ValueError as exc:
            raise ValueError(f"Unparseable timestamp: {value!r}") from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        try:
            parsed = parsed.replace(tzinfo=ZoneInfo(source_timezone))
        except ZoneInfoNotFoundError as exc:
            raise ValueError(
                f"Unknown source timezone: {source_timezone!r}"
            ) from exc

    try:
        target = ZoneInfo(target_timezone)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(
            f"Unknown target timezone: {target_timezone!r}"
        ) from exc

    return parsed.astimezone(target)


def _parse_datetime_string(value: str) -> datetime:
    # CERT uses ISO-like "YYYY-MM-DD HH:MM:SS" values; support common ISO
    # variants without accepting ambiguous locale-specific date formats.
    candidate = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        # Accept a trailing UTC marker with whitespace trimmed only.
        if candidate.endswith("+0000"):
            return datetime.fromisoformat(candidate[:-5] + "+00:00")
        raise ValueError(
            f"Unparseable timestamp {value!r}; expected ISO-8601-like format"
        )


def normalize_source_type(value: str) -> str:
    normalized = re.sub(r"[\s-]+", "_", str(value).strip().casefold())
    normalized = SOURCE_ALIASES.get(normalized, normalized)
    return normalized


def normalize_event_type(
    value: str | None,
    *,
    source_type: str,
) -> str:
    if value is None or not str(value).strip():
        raise ValueError("event_type is required")

    normalized = re.sub(
        r"[^a-zA-Z0-9]+",
        "_",
        str(value).strip().casefold(),
    ).strip("_")

    if normalized in EVENT_ALIASES:
        return EVENT_ALIASES[normalized]

    # Chapter 3 already emits domain-prefixed types such as file_copy.
    prefix = {
        SourceType.AUTHENTICATION.value: "logon",
        SourceType.DEVICE.value: "device",
        SourceType.EMAIL.value: "email",
        SourceType.FILE.value: "file",
        SourceType.HTTP.value: "http",
        SourceType.PSYCHOMETRIC.value: "psychometric",
        SourceType.LDAP.value: "ldap",
    }.get(source_type)

    if prefix and not normalized.startswith(prefix + "_"):
        normalized = f"{prefix}_{normalized}"

    return normalized


def _is_synthetic_event_id(event: CanonicalEvent) -> bool:
    # Chapter 3 fallback IDs are cert-r4.2:<domain>:<row>:<16-char-sha256>.
    return bool(re.fullmatch(r"cert-r4\.2:[^:]+:\d+:[0-9a-f]{16}", event.event_id))


def _content_hash(event: CanonicalEvent) -> str:
    payload = event.model_dump(mode="json")
    # Source row number and event_id are excluded for synthetic IDs so the
    # same underlying record moved to another row cannot bypass deduplication.
    metadata = payload.get("metadata", {})
    metadata = {
        key: value
        for key, value in metadata.items()
        if key not in {"source_row_number"}
    }
    payload["metadata"] = metadata
    if _is_synthetic_event_id(event):
        payload.pop("event_id", None)
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_event(
    event: CanonicalEvent | dict[str, Any],
    *,
    source_timezone: str = DEFAULT_SOURCE_TIMEZONE,
    target_timezone: str = DEFAULT_TARGET_TIMEZONE,
) -> CanonicalEvent:
    """Normalize one Chapter 3 event without silently dropping information."""
    try:
        raw = (
            event.model_dump(mode="python")
            if isinstance(event, CanonicalEvent)
            else dict(event)
        )

        # Explicit missing-value policy:
        # - blank identifiers -> None (validation later decides if required)
        # - blank detail values -> None
        # - numeric zero is preserved as zero
        # - no synthetic numeric zero-filling
        source_type = normalize_source_type(raw.get("source_type"))
        event_type = normalize_event_type(
            raw.get("event_type"),
            source_type=source_type,
        )

        user_id, original_user_id = _canonical_identifier(
            raw.get("user_id"),
            field_name="user_id",
        )
        device_id, original_device_id = _canonical_identifier(
            raw.get("device_id"),
            field_name="device_id",
        )

        details = _clean_detail_value(raw.get("details") or {})
        metadata = _clean_detail_value(raw.get("metadata") or {})

        if not isinstance(details, dict):
            raise ValueError("details must be an object")
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be an object")

        if original_user_id is not None and original_user_id != user_id:
            metadata.setdefault("normalization", {})["original_user_id"] = original_user_id
        if original_device_id is not None and original_device_id != device_id:
            metadata.setdefault("normalization", {})["original_device_id"] = original_device_id

        metadata.setdefault("normalization", {}).update(
            {
                "version": "chapter4-v1",
                "source_timezone": source_timezone,
                "target_timezone": target_timezone,
                "missing_value_policy": "blank_or_missing_to_null; numeric_zero_preserved",
            }
        )

        timestamp = normalize_timestamp(
            raw.get("timestamp"),
            source_timezone=source_timezone,
            target_timezone=target_timezone,
        )

        normalized = CanonicalEvent(
            event_id=str(raw.get("event_id", "")).strip(),
            timestamp=timestamp,
            user_id=user_id,
            device_id=device_id,
            source_type=source_type,
            event_type=event_type,
            details=details,
            metadata=metadata,
        )

        return validate_canonical_event(normalized)

    except ValidationError:
        raise
    except Exception:
        raise


def _as_raw_dict(event: CanonicalEvent | dict[str, Any]) -> dict[str, Any]:
    if isinstance(event, CanonicalEvent):
        return event.model_dump(mode="python")
    return dict(event)


def normalize_events(
    events: Iterable[CanonicalEvent | dict[str, Any]],
    *,
    source_timezone: str = DEFAULT_SOURCE_TIMEZONE,
    target_timezone: str = DEFAULT_TARGET_TIMEZONE,
) -> NormalizationReport:
    """Normalize, validate and deduplicate a stream.

    Invalid records and duplicates are both written to the rejection collection
    so the pipeline never silently loses an input record.
    """
    report = NormalizationReport()
    seen_event_ids: set[str] = set()
    seen_hashes: set[str] = set()

    for input_record in events:
        raw = _as_raw_dict(input_record)

        try:
            normalized = normalize_event(
                input_record,
                source_timezone=source_timezone,
                target_timezone=target_timezone,
            )

            event_key = normalized.event_id
            content_key = _content_hash(normalized)
            synthetic = _is_synthetic_event_id(normalized)

            if event_key in seen_event_ids or (synthetic and content_key in seen_hashes):
                report.duplicate_count += 1
                report.rejected.append(
                    RejectedRecord(
                        reason_code="duplicate_event",
                        reason="Duplicate event_id or content hash",
                        stage="deduplication",
                        record=raw,
                    )
                )
                continue

            seen_event_ids.add(event_key)
            if synthetic:
                seen_hashes.add(content_key)
            report.accepted.append(normalized)

        except ValidationError as exc:
            report.rejected.append(
                RejectedRecord(
                    reason_code="schema_validation_error",
                    reason="Canonical Pydantic schema validation failed",
                    stage="validation",
                    record=raw,
                    errors=tuple(validation_errors(exc)),
                )
            )
        except ValueError as exc:
            message = str(exc)
            reason_code = (
                "target_label_leakage"
                if "Target-label leakage" in message
                else "normalization_or_validation_error"
            )
            report.rejected.append(
                RejectedRecord(
                    reason_code=reason_code,
                    reason=message,
                    stage="normalization",
                    record=raw,
                    errors=(message,),
                )
            )
        except Exception as exc:  # defensive: no raw event should disappear
            report.rejected.append(
                RejectedRecord(
                    reason_code="unexpected_processing_error",
                    reason="Unexpected preprocessing failure",
                    stage="normalization",
                    record=raw,
                    errors=(f"{type(exc).__name__}: {exc}",),
                )
            )

    return report


def write_rejected_records(
    rejected: Iterable[RejectedRecord],
    path: str | Path,
) -> Path:
    """Write rejected records as append-friendly JSON Lines."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open("w", encoding="utf-8") as handle:
        for item in rejected:
            handle.write(
                json.dumps(
                    item.as_dict(),
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )

    return destination


def write_normalized_events(
    events: Iterable[CanonicalEvent],
    path: str | Path,
) -> Path:
    """Write accepted normalized events as JSON Lines."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(
                json.dumps(
                    event.model_dump(mode="json"),
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )

    return destination


def normalize_and_persist(
    events: Iterable[CanonicalEvent | dict[str, Any]],
    *,
    normalized_path: str | Path,
    rejected_path: str | Path,
    source_timezone: str = DEFAULT_SOURCE_TIMEZONE,
    target_timezone: str = DEFAULT_TARGET_TIMEZONE,
) -> NormalizationReport:
    report = normalize_events(
        events,
        source_timezone=source_timezone,
        target_timezone=target_timezone,
    )
    write_normalized_events(report.accepted, normalized_path)
    write_rejected_records(report.rejected, rejected_path)
    return report
