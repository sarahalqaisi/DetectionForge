from __future__ import annotations

import json
import hashlib
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Alert, DetectionRule, DetectionTest, Event
from app.services.conditions import evaluate_condition
from app.services.rule_validation import parse_and_validate_rule


SEVERITY_SCORE = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}


def parse_rule(content: str) -> dict[str, Any]:
    return parse_and_validate_rule(content)


def _event_value(event: dict[str, Any], field: str) -> Any:
    parts = field.split(".")
    if parts[0] == "raw_data":
        current: Any = event.get("raw_data", {})
        parts = parts[1:]
    elif parts[0] in event:
        current = event
    else:
        current = event.get("raw_data", {})
    for part in parts:
        if isinstance(current, dict):
            if part in current:
                current = current[part]
            else:
                return None
        else:
            return None
    return current


def _compare(actual: Any, expected: Any, operator: str) -> bool:
    if isinstance(expected, list):
        return any(_compare(actual, item, operator) for item in expected)
    if operator == "exists":
        return (actual is not None) is bool(expected)
    if actual is None:
        return False
    actual_text = str(actual)
    expected_text = str(expected)
    if operator == "contains":
        return expected_text.lower() in actual_text.lower()
    if operator == "startswith":
        return actual_text.lower().startswith(expected_text.lower())
    if operator == "endswith":
        return actual_text.lower().endswith(expected_text.lower())
    if operator in {"re", "regex"}:
        if len(expected_text) > 256 or len(actual_text) > 16_384:
            return False
        if re.search(r"(\([^)]*[+*][^)]*\))[+*{]", expected_text):
            return False
        try:
            return bool(re.search(expected_text, actual_text, re.I))
        except re.error:
            return False
    if operator == "gt":
        try:
            return float(actual) > float(expected)
        except (TypeError, ValueError):
            return False
    if operator == "gte":
        try:
            return float(actual) >= float(expected)
        except (TypeError, ValueError):
            return False
    if operator == "lt":
        try:
            return float(actual) < float(expected)
        except (TypeError, ValueError):
            return False
    if operator == "lte":
        try:
            return float(actual) <= float(expected)
        except (TypeError, ValueError):
            return False
    return actual_text.lower() == expected_text.lower()


def _selection_match(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    for raw_field, expected in selection.items():
        if "|" in raw_field:
            field, operator = raw_field.split("|", 1)
        else:
            field, operator = raw_field, "equals"
        if not _compare(_event_value(event, field), expected, operator):
            return False
    return True


def match_event(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    detection = rule.get("detection") or {}
    condition = str(detection.get("condition", "selection")).strip()
    selections = {
        key: value
        for key, value in detection.items()
        if key not in {"condition", "timeframe", "threshold", "group_by", "correlation", "sequence"}
        and isinstance(value, dict)
    }
    if not selections:
        return False
    results = {name: _selection_match(event, selection) for name, selection in selections.items()}
    return evaluate_condition(condition, results)


def event_to_dict(event: Event) -> dict[str, Any]:
    try:
        raw_data = json.loads(event.raw_data or "{}")
    except json.JSONDecodeError:
        raw_data = {}
    return {
        "id": event.id,
        "timestamp": event.timestamp,
        "source": event.source,
        "event_type": event.event_type,
        "severity": event.severity,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "username": event.username,
        "hostname": event.hostname,
        "process_name": event.process_name,
        "command_line": event.command_line,
        "message": event.message,
        "raw_data": raw_data,
    }


def entity_key(event: dict[str, Any], group_by: list[str] | None = None) -> str:
    fields = group_by or ["source_ip", "hostname", "username"]
    if group_by and any(event.get(field) in (None, "") for field in fields):
        return ""
    parts = [str(event.get(field)) for field in fields if event.get(field)]
    return "|".join(parts) if parts else "unknown"


def _parse_timeframe(value: str | int | None) -> timedelta:
    if value is None:
        return timedelta(minutes=5)
    if isinstance(value, int):
        return timedelta(seconds=value)
    text = str(value).strip().lower()
    match = re.fullmatch(r"(\d+)\s*([smhd])", text)
    if not match:
        return timedelta(minutes=5)
    amount = int(match.group(1))
    unit = match.group(2)
    return {"s": timedelta(seconds=amount), "m": timedelta(minutes=amount), "h": timedelta(hours=amount), "d": timedelta(days=amount)}[unit]


def _alert_exists(db: Session, rule_id: int, event_id: int | None, key: str) -> bool:
    query = select(Alert.id).where(Alert.rule_id == rule_id, Alert.entity_key == key)
    if event_id is not None:
        query = query.where(Alert.event_id == event_id)
    return db.scalar(query.limit(1)) is not None


def _build_alert(rule_model: DetectionRule, event: Event | None, key: str, evidence: dict[str, Any]) -> Alert:
    level = (rule_model.level or "medium").lower()
    score = SEVERITY_SCORE.get(level, 50)
    fingerprint = alert_fingerprint(rule_model.rule_key, key, event.id if event else None)
    evidence = {**evidence, "alert_fingerprint": fingerprint}
    return Alert(
        event_id=event.id if event else None,
        rule_id=rule_model.id,
        title=rule_model.title,
        severity=level,
        risk_score=float(score),
        entity_key=key,
        evidence=json.dumps(evidence, default=str),
    )


def alert_fingerprint(rule_key: str, entity: str, terminal_event_id: int | None) -> str:
    raw = json.dumps([rule_key, entity, terminal_event_id], separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def evaluate_rule(db: Session, rule_model: DetectionRule, events: list[Event]) -> list[Alert]:
    rule = parse_rule(rule_model.yaml_content)
    detection = rule.get("detection") or {}
    correlation = detection.get("correlation") or {}
    unique_events = []
    seen_events = set()
    for event in events:
        identity = ("database", event.id) if event.id is not None else ("object", id(event))
        if identity not in seen_events:
            seen_events.add(identity)
            unique_events.append(event)
    matched = [(event, event_to_dict(event)) for event in unique_events if match_event(rule, event_to_dict(event))]
    alerts: list[Alert] = []

    if correlation:
        correlation_type = str(correlation.get("type", "count"))
        threshold = int(correlation.get("threshold", 5))
        group_by = correlation.get("group_by") or ["source_ip"]
        timeframe = _parse_timeframe(correlation.get("timeframe", "5m"))
        grouped: dict[str, list[tuple[Event, dict[str, Any]]]] = defaultdict(list)
        for pair in matched:
            key = entity_key(pair[1], group_by)
            if key:
                grouped[key].append(pair)
        for key, pairs in grouped.items():
            pairs.sort(key=lambda item: item[0].timestamp)
            if correlation_type == "sequence":
                stages = correlation.get("sequence") or []
                if len(stages) >= 2:
                    for start_index, (start_event, start_dict) in enumerate(pairs):
                        if not _selection_match(start_dict, detection.get(stages[0], {})):
                            continue
                        matched_events = [start_event]
                        cursor = start_index + 1
                        complete = True
                        for stage_name in stages[1:]:
                            stage_selection = detection.get(stage_name, {})
                            found = None
                            while cursor < len(pairs):
                                candidate_event, candidate_dict = pairs[cursor]
                                cursor += 1
                                if candidate_event.timestamp - start_event.timestamp > timeframe:
                                    break
                                if _selection_match(candidate_dict, stage_selection):
                                    found = candidate_event
                                    break
                            if found is None:
                                complete = False
                                break
                            matched_events.append(found)
                        if complete and not _alert_exists(db, rule_model.id, matched_events[-1].id, key):
                            evidence = {
                                "type": "sequence",
                                "stages": stages,
                                "timeframe": str(correlation.get("timeframe", "5m")),
                                "event_ids": [item.id for item in matched_events],
                                "group_by": group_by,
                            }
                            alerts.append(_build_alert(rule_model, matched_events[-1], key, evidence))
                            break
                continue
            for index, (event, event_dict) in enumerate(pairs):
                window_start = event.timestamp - timeframe
                window = [pair for pair in pairs[: index + 1] if pair[0].timestamp >= window_start]
                if correlation_type == "count" and len(window) >= threshold:
                    if not _alert_exists(db, rule_model.id, event.id, key):
                        evidence = {
                            "type": "correlation",
                            "count": len(window),
                            "threshold": threshold,
                            "timeframe": str(correlation.get("timeframe", "5m")),
                            "event_ids": [item[0].id for item in window],
                            "group_by": group_by,
                        }
                        alerts.append(_build_alert(rule_model, event, key, evidence))
                    break
        return alerts

    for event, event_dict in matched:
        key = entity_key(event_dict)
        if _alert_exists(db, rule_model.id, event.id, key):
            continue
        alerts.append(_build_alert(rule_model, event, key, {"type": "single_event", "event": event_dict}))
    return alerts


def run_detection(db: Session, events: list[Event] | None = None) -> list[Alert]:
    selected_events = events or list(db.scalars(select(Event).order_by(Event.timestamp.asc())).all())
    rules = list(db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))).all())
    alerts: list[Alert] = []
    for rule in rules:
        alerts.extend(evaluate_rule(db, rule, selected_events))
    db.add_all(alerts)
    db.commit()
    for alert in alerts:
        db.refresh(alert)
    return alerts


def test_rule(db: Session, rule_model: DetectionRule, sample_event: dict[str, Any], expected_match: bool = True, test_name: str = "Manual test") -> DetectionTest:
    started = time.perf_counter()
    actual = match_event(parse_rule(rule_model.yaml_content), sample_event)
    elapsed = (time.perf_counter() - started) * 1000
    test = DetectionTest(
        rule_id=rule_model.id,
        test_name=test_name,
        expected_match=expected_match,
        actual_match=actual,
        passed=actual is expected_match,
        execution_ms=elapsed,
        sample_event=json.dumps(sample_event, default=str),
    )
    db.add(test)
    db.commit()
    db.refresh(test)
    return test
