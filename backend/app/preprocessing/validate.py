"""Validation and policy enforcement for normalized CIRA events.

Chapter 4 keeps validation separate from transformation so every rule is
independently testable.  Target labels are forbidden by key, never by value:
an email body containing the word "malicious" is not itself a label leak.
"""
from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import ValidationError

from app.ingestion.contracts import CanonicalEvent


class SourceType(StrEnum):
    AUTHENTICATION = "authentication"
    DEVICE = "device"
    EMAIL = "email"
    FILE = "file"
    HTTP = "http"
    PSYCHOMETRIC = "psychometric"
    LDAP = "ldap"


SOURCE_EVENT_PREFIX: dict[SourceType, str] = {
    SourceType.AUTHENTICATION: "logon",
    SourceType.DEVICE: "device",
    SourceType.EMAIL: "email",
    SourceType.FILE: "file",
    SourceType.HTTP: "http",
    SourceType.PSYCHOMETRIC: "psychometric",
    SourceType.LDAP: "ldap",
}

ALLOWED_SNAPSHOT_SOURCES = {
    SourceType.PSYCHOMETRIC,
    SourceType.LDAP,
}

FORBIDDEN_LABEL_KEYS = {
    "label",
    "labels",
    "malicious",
    "is_malicious",
    "benign",
    "is_benign",
    "ground_truth",
    "groundtruth",
    "target",
    "y",
    "scenario",
}

EVENT_TYPE_RE = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")


def _contains_forbidden_key(value: Any, path: str = "") -> tuple[str, ...]:
    """Return paths of keys that would leak evaluation targets."""
    found: list[str] = []

    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            child_path = f"{path}.{key}" if path else str(key)
            if normalized in FORBIDDEN_LABEL_KEYS:
                found.append(child_path)
            found.extend(_contains_forbidden_key(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_contains_forbidden_key(child, f"{path}[{index}]"))

    return tuple(found)


def assert_no_target_labels(event: CanonicalEvent | dict[str, Any]) -> None:
    """Raise ValueError if label/target keys occur anywhere in the event."""
    payload = (
        event.model_dump(mode="python")
        if isinstance(event, CanonicalEvent)
        else event
    )
    leaked = _contains_forbidden_key(payload)
    if leaked:
        raise ValueError(
            "Target-label leakage detected in normalized event: "
            + ", ".join(leaked)
        )


def validate_canonical_event(event: CanonicalEvent) -> CanonicalEvent:
    """Apply the canonical contract plus Chapter 4 semantic constraints."""
    # Re-run Pydantic validation even when a CanonicalEvent instance was passed.
    validated = CanonicalEvent.model_validate(event.model_dump(mode="python"))

    assert_no_target_labels(validated)

    try:
        source = SourceType(validated.source_type)
    except ValueError as exc:
        raise ValueError(
            f"Unsupported source_type={validated.source_type!r}; "
            f"expected one of {[item.value for item in SourceType]}"
        ) from exc

    if not EVENT_TYPE_RE.fullmatch(validated.event_type):
        raise ValueError(
            f"event_type={validated.event_type!r} is not canonical snake_case"
        )

    expected_prefix = SOURCE_EVENT_PREFIX[source]
    if not validated.event_type.startswith(expected_prefix):
        raise ValueError(
            f"event_type={validated.event_type!r} is incompatible with "
            f"source_type={source.value!r}; expected prefix "
            f"{expected_prefix!r}"
        )

    if not validated.event_id.strip():
        raise ValueError("event_id must not be blank")

    if validated.user_id is None or not validated.user_id.strip():
        raise ValueError("user_id is required for the normalized feature-input path")

    if validated.timestamp is None and source not in ALLOWED_SNAPSHOT_SOURCES:
        raise ValueError(
            f"timestamp is required for source_type={source.value!r}"
        )

    if validated.timestamp is not None and validated.timestamp.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware after normalization")

    if not isinstance(validated.details, dict):
        raise ValueError("details must be an object")

    if not isinstance(validated.metadata, dict):
        raise ValueError("metadata must be an object")

    return validated


def validation_errors(exc: Exception) -> list[str]:
    """Convert Pydantic/semantic validation failures into stable strings."""
    if isinstance(exc, ValidationError):
        return [
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        ]
    return [str(exc)]
