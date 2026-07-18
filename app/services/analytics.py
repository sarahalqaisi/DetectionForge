from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Alert, DetectionRule, DetectionTest, Event, Incident
from app.services.mitre import TACTIC_ORDER


def dashboard_stats(db: Session) -> dict:
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    total_events = db.scalar(select(func.count(Event.id))) or 0
    active_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.status.in_(["new", "investigating"]))) or 0
    open_incidents = db.scalar(select(func.count(Incident.id)).where(Incident.status != "closed")) or 0
    total_tests = db.scalar(select(func.count(DetectionTest.id))) or 0
    passed_tests = db.scalar(select(func.count(DetectionTest.id)).where(DetectionTest.passed.is_(True))) or 0
    events_24h = db.scalar(select(func.count(Event.id)).where(Event.timestamp >= day_ago)) or 0
    return {
        "total_events": total_events,
        "active_alerts": active_alerts,
        "open_incidents": open_incidents,
        "detection_success_rate": round((passed_tests / total_tests * 100), 1) if total_tests else 0.0,
        "events_24h": events_24h,
    }


def chart_data(db: Session) -> dict:
    events = list(db.scalars(select(Event).order_by(Event.timestamp.asc())).all())
    alerts = list(db.scalars(select(Alert)).all())
    incidents = list(db.scalars(select(Incident)).all())
    rules = list(db.scalars(select(DetectionRule)).all())

    hourly = Counter()
    for event in events:
        label = event.timestamp.strftime("%m-%d %H:00")
        hourly[label] += 1
    severity = Counter(alert.severity for alert in alerts)
    sources = Counter(event.source for event in events)
    tactics = Counter(rule.mitre_tactic or "Unmapped" for rule in rules if rule.enabled)
    incident_status = Counter(incident.status for incident in incidents)
    return {
        "events_timeline": {"labels": list(hourly.keys())[-24:], "values": list(hourly.values())[-24:]},
        "alert_severity": {"labels": list(severity.keys()), "values": list(severity.values())},
        "event_sources": {"labels": list(sources.keys()), "values": list(sources.values())},
        "mitre_tactics": {"labels": list(tactics.keys()), "values": list(tactics.values())},
        "incident_status": {"labels": list(incident_status.keys()), "values": list(incident_status.values())},
    }


def coverage_matrix(db: Session) -> list[dict]:
    rules = list(db.scalars(select(DetectionRule)).all())
    tests = list(db.scalars(select(DetectionTest)).all())
    by_rule = {}
    for test in tests:
        by_rule.setdefault(test.rule_id, []).append(test)
    rows: list[dict] = []
    for rule in rules:
        rule_tests = by_rule.get(rule.id, [])
        if not rule.enabled:
            status = "disabled"
        elif any(not test.passed for test in rule_tests):
            status = "failed"
        elif rule_tests:
            status = "passed"
        else:
            status = "untested"
        rows.append(
            {
                "rule": rule,
                "status": status,
                "tests": len(rule_tests),
                "pass_rate": round(sum(1 for t in rule_tests if t.passed) / len(rule_tests) * 100, 1) if rule_tests else 0.0,
            }
        )
    order = {tactic: index for index, tactic in enumerate(TACTIC_ORDER)}
    return sorted(rows, key=lambda row: (order.get(row["rule"].mitre_tactic or "", 999), row["rule"].mitre_technique or ""))
