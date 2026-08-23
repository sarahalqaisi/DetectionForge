from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import DetectionRule, Event
from app.services.detection import evaluate_rule
from app.services.detection import alert_fingerprint


def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def event(db, when, event_type, source_ip="192.0.2.1", username="user"):
    item = Event(timestamp=when, source="test", event_type=event_type, severity="info", source_ip=source_ip, username=username)
    db.add(item); db.flush()
    return item


def rule(db, correlation, selections=None):
    selections = selections or {"selection": {"source": "test", "event_type": "hit"}}
    lines = ["id: DF-TST-CORR", "title: Correlation test", "logsource: {category: test}", "level: high", "detection:"]
    for name, fields in selections.items():
        lines.append(f"  {name}:")
        lines.extend(f"    {key}: {value}" for key, value in fields.items())
    lines.extend(["  condition: " + " or ".join(selections), "  correlation:"])
    lines.extend(f"    {line}" for line in correlation.splitlines())
    model = DetectionRule(rule_key="DF-TST-CORR", title="Correlation test", yaml_content="\n".join(lines), level="high")
    db.add(model); db.flush()
    return model


def test_count_threshold_boundary_grouping_and_deduplication():
    db = session(); start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    model = rule(db, "type: count\ngroup_by: [source_ip]\nthreshold: 3\ntimeframe: 5m")
    first = [event(db, start + timedelta(minutes=i), "hit") for i in range(2)]
    assert evaluate_rule(db, model, first) == []
    assert evaluate_rule(db, model, [first[0], first[0], first[1]]) == []
    at_boundary = event(db, start + timedelta(minutes=5), "hit")
    alerts = evaluate_rule(db, model, first + [at_boundary])
    assert len(alerts) == 1
    db.add_all(alerts); db.commit()
    assert evaluate_rule(db, model, first + [at_boundary]) == []
    other = [event(db, start + timedelta(minutes=i), "hit", "192.0.2.2") for i in range(2)]
    assert evaluate_rule(db, model, other) == []
    missing_key = [event(db, start + timedelta(minutes=i), "hit", None) for i in range(3)]
    assert evaluate_rule(db, model, missing_key) == []


def test_ordered_sequence_rejects_incomplete_but_handles_input_order():
    db = session(); start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    selections = {"failed": {"event_type": "failed"}, "success": {"event_type": "success"}}
    model = rule(db, "type: sequence\ngroup_by: [source_ip, username]\nsequence: [failed, success]\ntimeframe: 10m", selections)
    failed = event(db, start, "failed")
    success = event(db, start + timedelta(minutes=2), "success")
    assert len(evaluate_rule(db, model, [success, failed])) == 1
    assert evaluate_rule(db, model, [success]) == []
    early_success = event(db, start - timedelta(minutes=1), "success", "192.0.2.4")
    later_failed = event(db, start, "failed", "192.0.2.4")
    assert evaluate_rule(db, model, [later_failed, early_success]) == []
    too_late = event(db, start + timedelta(minutes=11), "success", "192.0.2.3")
    other_failed = event(db, start, "failed", "192.0.2.3")
    assert evaluate_rule(db, model, [too_late, other_failed]) == []


def test_alert_fingerprint_is_stable_without_collapsing_distinct_terminal_events():
    assert alert_fingerprint("DF-1", "host-a", 10) == alert_fingerprint("DF-1", "host-a", 10)
    assert alert_fingerprint("DF-1", "host-a", 10) != alert_fingerprint("DF-1", "host-a", 11)
