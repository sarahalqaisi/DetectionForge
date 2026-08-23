from __future__ import annotations

import re
from typing import Any

import yaml

from app.services.conditions import evaluate_condition

MAX_RULE_BYTES = 256 * 1024
LEVELS = {"informational", "info", "low", "medium", "high", "critical"}
MODIFIERS = {"contains", "startswith", "endswith", "re", "regex", "exists", "gt", "gte", "lt", "lte"}
RESERVED = {"condition", "timeframe", "threshold", "group_by", "correlation", "sequence"}
RULE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")


def parse_and_validate_rule(content: str) -> dict[str, Any]:
    if len(content.encode("utf-8")) > MAX_RULE_BYTES:
        raise ValueError("Rule YAML exceeds 256 KiB")
    try:
        rule = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError("Rule contains invalid YAML") from exc
    if not isinstance(rule, dict):
        raise ValueError("Rule must be a YAML object")
    for field in ("title", "id"):
        if not isinstance(rule.get(field), str) or not rule[field].strip():
            raise ValueError(f"Rule requires a non-empty {field}")
    if not RULE_ID_RE.fullmatch(rule["id"]):
        raise ValueError("Rule id must be a stable 3-128 character identifier")
    if rule.get("level", "medium") not in LEVELS:
        raise ValueError("Rule level is unsupported")
    if not isinstance(rule.get("logsource"), dict) or not rule["logsource"]:
        raise ValueError("Rule requires a logsource object")
    for field in ("references", "tags"):
        if field in rule and (not isinstance(rule[field], list) or not all(isinstance(item, str) for item in rule[field])):
            raise ValueError(f"Rule {field} must be a list of strings")
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        raise ValueError("Rule requires a detection object")
    condition = detection.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        raise ValueError("Detection requires a condition")
    selections = {key: value for key, value in detection.items() if key not in RESERVED}
    if not selections or not all(isinstance(value, dict) and value for value in selections.values()):
        raise ValueError("Detection selections must be non-empty objects")
    for selection in selections.values():
        for raw_field in selection:
            if not isinstance(raw_field, str) or not raw_field:
                raise ValueError("Selection fields must be non-empty strings")
            parts = raw_field.split("|")
            if len(parts) > 2 or (len(parts) == 2 and parts[1].lower() not in MODIFIERS):
                raise ValueError(f"Unsupported field modifier: {raw_field}")
    evaluate_condition(condition, {name: False for name in selections})
    _validate_correlation(detection, selections)
    return rule


def _validate_correlation(detection: dict[str, Any], selections: dict[str, Any]) -> None:
    correlation = detection.get("correlation")
    if correlation is None:
        return
    if not isinstance(correlation, dict):
        raise ValueError("Correlation must be an object")
    kind = correlation.get("type", "count")
    if kind not in {"count", "sequence"}:
        raise ValueError("Correlation type must be count or sequence")
    group_by = correlation.get("group_by", ["source_ip"])
    if not isinstance(group_by, list) or not group_by or not all(isinstance(item, str) and item for item in group_by):
        raise ValueError("Correlation group_by must be a non-empty list")
    timeframe = correlation.get("timeframe", "5m")
    if not isinstance(timeframe, int) and not re.fullmatch(r"[1-9]\d*[smhd]", str(timeframe).lower()):
        raise ValueError("Correlation timeframe is invalid")
    if isinstance(timeframe, int) and timeframe <= 0:
        raise ValueError("Correlation timeframe must be positive")
    if kind == "count":
        threshold = correlation.get("threshold")
        if not isinstance(threshold, int) or threshold < 1:
            raise ValueError("Count correlation requires a positive integer threshold")
    else:
        stages = correlation.get("sequence")
        if not isinstance(stages, list) or len(stages) < 2 or not all(stage in selections for stage in stages):
            raise ValueError("Sequence correlation requires at least two known stages")

