from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog, Event
from app.services.normalizers import normalize_file, normalize_text


def persist_events(db: Session, normalized: list[dict[str, Any]], actor: str = "system") -> list[Event]:
    events: list[Event] = []
    for item in normalized:
        event = Event(
            timestamp=item["timestamp"],
            source=item.get("source", "generic"),
            event_type=item.get("event_type", "generic_event"),
            severity=item.get("severity", "info"),
            source_ip=item.get("source_ip"),
            destination_ip=item.get("destination_ip"),
            source_port=item.get("source_port"),
            destination_port=item.get("destination_port"),
            username=item.get("username"),
            hostname=item.get("hostname"),
            process_name=item.get("process_name"),
            command_line=item.get("command_line"),
            message=item.get("message", ""),
            raw_data=json.dumps(item.get("raw_data", {}), default=str),
        )
        db.add(event)
        events.append(event)
    db.flush()
    db.add(
        AuditLog(
            action="events_ingested",
            entity_type="event_batch",
            entity_id=str(events[0].id) if events else None,
            details=json.dumps({"count": len(events)}),
            actor=actor,
        )
    )
    db.commit()
    for event in events:
        db.refresh(event)
    return events


def ingest_text(db: Session, content: str, source_type: str = "auto", actor: str = "system") -> list[Event]:
    return persist_events(db, normalize_text(content, source_type), actor)


def ingest_file(db: Session, path: str | Path, source_type: str = "auto", actor: str = "system") -> list[Event]:
    return persist_events(db, normalize_file(path, source_type), actor)
