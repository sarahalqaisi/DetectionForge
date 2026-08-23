from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import DetectionRule
from app.services.detection import match_event, parse_rule
from app.services.mitre import technique_ids
from app.services.rules import import_rules


VALID = """id: DF-TST-001
title: Test rule
logsource: {category: test}
level: high
tags: [attack.t1059.001]
detection:
  selection: {event_type: process_create}
  condition: selection
"""


def test_rule_schema_and_attack_tag_mapping():
    rule = parse_rule(VALID)
    assert technique_ids(rule) == ["T1059.001"]


@pytest.mark.parametrize("replacement, message", [
    ("level: extreme", "level"),
    ("selection: {command_line|base64: value}", "modifier"),
    ("condition: missing", "Unknown selection"),
])
def test_invalid_rules_are_rejected(replacement, message):
    if replacement.startswith("level"):
        content = VALID.replace("level: high", replacement)
    elif replacement.startswith("selection"):
        content = VALID.replace("selection: {event_type: process_create}", replacement)
    else:
        content = VALID.replace("condition: selection", replacement)
    with pytest.raises(ValueError, match=message):
        parse_rule(content)


def test_malformed_correlation_is_rejected():
    content = VALID + "  correlation:\n    type: count\n    threshold: 0\n    timeframe: never\n"
    with pytest.raises(ValueError, match="timeframe|threshold"):
        parse_rule(content)


def test_duplicate_rule_ids_are_rejected_before_database_changes(tmp_path: Path):
    (tmp_path / "one.yml").write_text(VALID)
    (tmp_path / "two.yml").write_text(VALID.replace("Test rule", "Other title"))
    engine = create_engine("sqlite:///:memory:"); Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    with pytest.raises(ValueError, match="Duplicate rule ids"):
        import_rules(db, tmp_path)
    assert db.scalar(select(func.count(DetectionRule.id))) == 0


def test_regex_limits_reject_nested_quantifier_and_oversized_input():
    rule = parse_rule(VALID.replace("event_type: process_create", "command_line|re: '(a+)+'"))
    assert not match_event(rule, {"command_line": "a" * 100})
    safe_rule = parse_rule(VALID.replace("event_type: process_create", "command_line|contains: needle"))
    assert match_event(safe_rule, {"command_line": "needle"})
