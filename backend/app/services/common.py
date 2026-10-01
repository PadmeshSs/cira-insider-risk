"""Small helpers shared by the services."""
from __future__ import annotations

from datetime import date, timedelta

from .errors import BadRequest

DEFAULT_LIMIT = 50
MAX_LIMIT = 200          # HCEA §13: every list endpoint has a hard server-side cap
SEVERITY_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def clamp_page(limit: int | None, offset: int | None) -> tuple[int, int]:
    """Server-side cap. A larger limit is not an error; it is cut to the cap and the response says so."""
    lim = DEFAULT_LIMIT if limit is None else int(limit)
    off = 0 if offset is None else int(offset)
    if lim < 1 or off < 0:
        raise BadRequest("limit must be >= 1 and offset >= 0")
    return min(lim, MAX_LIMIT), off


def page_info(total: int, limit: int, offset: int) -> dict:
    return {"total": int(total), "limit": limit, "offset": offset, "max_limit": MAX_LIMIT}


def user_variants(user_id: str) -> list[str]:
    """CERT ids are upper case in r4.2 and some runs casefold them; accept either spelling of one id."""
    u = (user_id or "").strip()
    if not u or len(u) > 64:
        raise BadRequest("user_id must be 1-64 characters")
    return sorted({u, u.upper(), u.lower()})


def in_sample(split: str | None) -> bool:
    return str(split) == "train"


def max_severity(values) -> str | None:
    vals = [v for v in values if v in SEVERITY_ORDER]
    return max(vals, key=SEVERITY_ORDER.index) if vals else None


def parse_day(text: str) -> date:
    try:
        return date.fromisoformat(str(text))
    except ValueError as exc:
        raise BadRequest(f"date must be YYYY-MM-DD, got {text!r}") from exc


def week_start(d: date) -> date:
    return d - timedelta(days=d.weekday())
