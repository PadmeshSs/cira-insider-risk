"""
Canonical event contract for CIRA ingestion.

Chapter 3:
- Defines the normalized event shape emitted by dataset loaders.
- Ground-truth / malicious labels are intentionally NOT part of this model.
- Source traceability is preserved in metadata.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CanonicalEvent(BaseModel):
    """
    Canonical representation of a single CIRA event.

    All dataset-specific loaders (CERT, TWOS) should convert their
    raw records into this structure before passing data downstream.

    IMPORTANT:
    Ground-truth labels are deliberately excluded from this contract
    to prevent data leakage into the feature/model pipeline.
    """

    model_config = ConfigDict(extra="forbid")

    # ---------------------------------------------------------
    # Event identity
    # ---------------------------------------------------------

    event_id: str = Field(
        ...,
        min_length=1,
        description="Stable unique identifier for the event.",
    )

    # ---------------------------------------------------------
    # Temporal information
    # ---------------------------------------------------------

    timestamp: datetime | None = Field(
        default=None,
        description="Event timestamp. May be None for snapshot-style data such as LDAP.",
    )

    # ---------------------------------------------------------
    # Principal / device information
    # ---------------------------------------------------------

    user_id: str | None = Field(
        default=None,
        description="Canonical user identifier associated with the event.",
    )

    device_id: str | None = Field(
        default=None,
        description="Canonical device identifier associated with the event.",
    )

    # ---------------------------------------------------------
    # Event classification
    # ---------------------------------------------------------

    source_type: str = Field(
        ...,
        min_length=1,
        description="High-level source category, e.g. authentication, file, email.",
    )

    event_type: str = Field(
        ...,
        min_length=1,
        description="Specific event type, e.g. logon_logon, file_copy.",
    )

    # ---------------------------------------------------------
    # Source-specific information
    # ---------------------------------------------------------

    details: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Event-specific attributes preserved from the source record. "
            "These are not yet feature-engineered."
        ),
    )

    # ---------------------------------------------------------
    # Traceability / provenance
    # ---------------------------------------------------------

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Dataset and source-record provenance, such as dataset name, "
            "release, source file, domain, row number, and source record ID."
        ),
    )