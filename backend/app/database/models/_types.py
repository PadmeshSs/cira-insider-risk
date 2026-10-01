"""Column types shared by the Chapter 12 entities."""
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB

# JSONB on PostgreSQL, plain JSON elsewhere (the unit tests use SQLite).
JSONType = JSON().with_variant(JSONB(), "postgresql")
