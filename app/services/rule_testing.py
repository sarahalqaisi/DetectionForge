from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.services.detection import match_event, parse_rule


@dataclass(frozen=True)
class FixtureResult:
    rule_id: str
    name: str
    expected: bool
    actual: bool
    passed: bool
    event_id: str | None


def rule_fixtures(rule: dict[str, Any]) -> list[tuple[str, bool, dict[str, Any]]]:
    fixtures = []
    legacy = rule.get("test")
    if isinstance(legacy, dict) and isinstance(legacy.get("event"), dict):
        fixtures.append((str(legacy.get("name", "Legacy fixture")), bool(legacy.get("expected", True)), legacy["event"]))
    configured = rule.get("tests") or {}
    if isinstance(configured, dict):
        for group, expected in (("positive", True), ("negative", False)):
            for index, fixture in enumerate(configured.get(group) or [], start=1):
                if not isinstance(fixture, dict):
                    raise ValueError(f"{group} fixture {index} must be an object")
                event = fixture.get("event", fixture)
                if not isinstance(event, dict):
                    raise ValueError(f"{group} fixture {index} requires an event object")
                fixtures.append((str(fixture.get("name", f"{group} {index}")), expected, event))
    return fixtures


def test_rule_file(path: Path) -> list[FixtureResult]:
    rule = parse_rule(path.read_text(encoding="utf-8"))
    results = []
    for name, expected, event in rule_fixtures(rule):
        actual = match_event(rule, event)
        results.append(FixtureResult(rule["id"], name, expected, actual, actual is expected, str(event.get("id")) if event.get("id") is not None else None))
    return results


def test_rule_directory(root: Path) -> dict[str, Any]:
    paths = sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml"))
    all_results: list[FixtureResult] = []
    errors = []
    ids = []
    for path in paths:
        try:
            rule = parse_rule(path.read_text(encoding="utf-8"))
            ids.append(rule["id"])
            all_results.extend(test_rule_file(path))
        except ValueError as exc:
            errors.append({"file": str(path), "error": str(exc)})
    duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    errors.extend({"file": "rules", "error": f"Duplicate rule id: {rule_id}"} for rule_id in duplicates)
    passed = sum(result.passed for result in all_results)
    serialized = [asdict(result) for result in all_results]
    return {
        "valid_rules": len(paths) - len(errors),
        "total_rules": len(paths),
        "fixtures": len(all_results),
        "passed": passed,
        "failed": len(all_results) - passed,
        "errors": errors,
        "matched_event_ids": [result.event_id for result in all_results if result.actual and result.event_id is not None],
        "missed_positives": [result.name for result in all_results if result.expected and not result.actual],
        "unexpected_matches": [result.name for result in all_results if not result.expected and result.actual],
        "results": serialized,
    }
