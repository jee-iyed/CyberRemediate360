"""UTC time helpers. All timestamps are stored and returned in UTC."""

from __future__ import annotations

from datetime import UTC, date, datetime


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def ensure_utc(value: datetime | date | None) -> datetime | None:
    """Normalise a datetime (or date) to an aware UTC datetime.

    Naive datetimes are interpreted as UTC (documented convention).
    """
    if value is None:
        return None
    if not isinstance(value, datetime):
        value = datetime(value.year, value.month, value.day, tzinfo=UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
