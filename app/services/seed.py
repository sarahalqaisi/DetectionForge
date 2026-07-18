from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import BASE_DIR
from app.models import DetectionRule, DetectionTest, Event, IncidentNote
from app.services.correlation import correlate_alerts
from app.services.detection import parse_rule, run_detection, test_rule
from app.services.ingestion import ingest_file
from app.services.rules import import_rules


def seed_demo(db: Session, force: bool = False) -> dict:
    import_rules(db)
    count = db.scalar(select(func.count(Event.id))) or 0
    if count and not force:
        return {"seeded": False, "reason": "events already exist"}

    sample_dir = BASE_DIR / "sample-data"
    ingested = []
    for filename, source_type in [
        ("linux_auth.log", "linux_auth"),
        ("nginx_access.log", "nginx"),
        ("windows_sysmon.jsonl", "windows"),
        ("suricata_eve.json", "suricata"),
    ]:
        path = sample_dir / filename
        if path.exists():
            ingested.extend(ingest_file(db, path, source_type, actor="demo-seed"))

    alerts = run_detection(db, ingested)
    incidents = correlate_alerts(db)
    if incidents:
        incidents[0].notes.append(
            IncidentNote(
                author="Demo Analyst",
                body="Initial triage confirms repeated authentication failures followed by successful access. Review account activity and isolate the source if unauthorized.",
            )
        )
        db.commit()

    # Add one automated quality test per rule using the first declared test fixture.
    rules = list(db.scalars(select(DetectionRule)).all())
    tests = 0
    for rule_model in rules:
        data = parse_rule(rule_model.yaml_content)
        fixture = data.get("test") or {}
        sample = fixture.get("event") if isinstance(fixture, dict) else None
        if isinstance(sample, dict):
            test_rule(
                db,
                rule_model,
                sample,
                bool(fixture.get("expected", True)),
                test_name=str(fixture.get("name", "Seed validation")),
            )
            tests += 1
    return {"seeded": True, "events": len(ingested), "alerts": len(alerts), "incidents": len(incidents), "tests": tests}
