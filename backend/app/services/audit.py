"""Audit trail helpers. Events are appended in the caller's transaction (atomic)."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditEvent


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_jsonable(v) for v in value]
    return value


def record_event(
    db: Session,
    *,
    entity_type: str,
    entity_id: str | int,
    action: str,
    actor: str,
    previous: dict | None = None,
    new: dict | None = None,
) -> AuditEvent:
    event = AuditEvent(
        entity_type=entity_type,
        entity_id=str(entity_id),
        action=action,
        previous_value=_jsonable(previous) if previous is not None else None,
        new_value=_jsonable(new) if new is not None else None,
        actor=actor,
    )
    db.add(event)
    return event


def diff(obj: Any, fields: list[str], new_values: dict) -> tuple[dict, dict]:
    """Return (previous, new) dicts restricted to fields whose value actually changes."""
    previous, changed = {}, {}
    for name in fields:
        if name in new_values and getattr(obj, name) != new_values[name]:
            previous[name] = getattr(obj, name)
            changed[name] = new_values[name]
    return previous, changed
