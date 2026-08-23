from __future__ import annotations

from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import DetectionRule
from app.services.detection import parse_rule
from app.services.mitre import technique_ids, technique_info


def import_rules(db: Session, rules_dir: Path | None = None) -> tuple[int, int]:
    root = rules_dir or settings.rules_dir
    created = 0
    updated = 0
    loaded = []
    for path in sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml")):
        content = path.read_text(encoding="utf-8")
        data = parse_rule(content)
        loaded.append((path, content, data))
    ids = [data["id"] for _, _, data in loaded]
    duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    if duplicates:
        raise ValueError(f"Duplicate rule ids: {', '.join(duplicates)}")
    for path, content, data in loaded:
        rule_key = str(data.get("id") or path.stem)
        techniques = technique_ids(data)
        technique = techniques[0] if techniques else None
        mitre = technique_info(technique)
        existing = db.scalar(select(DetectionRule).where(DetectionRule.rule_key == rule_key))
        payload = {
            "title": str(data.get("title")),
            "description": str(data.get("description", "")),
            "source_category": str((data.get("logsource") or {}).get("category", "generic")),
            "level": str(data.get("level", "medium")).lower(),
            "yaml_content": content,
            "mitre_tactic": str((data.get("mitre") or {}).get("tactic") or mitre["tactic"]),
            "mitre_technique": technique,
            "mitre_name": str((data.get("mitre") or {}).get("name") or mitre["name"]),
            "author": str(data.get("author", "DetectionForge")),
            "false_positive_notes": str(data.get("falsepositives", "")),
        }
        if existing:
            changed = any(getattr(existing, key) != value for key, value in payload.items())
            if changed:
                for key, value in payload.items():
                    setattr(existing, key, value)
                existing.version += 1
                updated += 1
        else:
            db.add(DetectionRule(rule_key=rule_key, enabled=True, **payload))
            created += 1
    db.commit()
    return created, updated


def save_rule(db: Session, rule: DetectionRule, content: str) -> DetectionRule:
    data = parse_rule(content)
    if data["id"] != rule.rule_key:
        raise ValueError("Rule id cannot be changed in the editor")
    techniques = technique_ids(data)
    technique = techniques[0] if techniques else None
    mitre = technique_info(technique)
    rule.title = str(data.get("title"))
    rule.description = str(data.get("description", ""))
    rule.source_category = str((data.get("logsource") or {}).get("category", "generic"))
    rule.level = str(data.get("level", "medium")).lower()
    rule.yaml_content = content
    rule.mitre_technique = technique
    rule.mitre_tactic = str((data.get("mitre") or {}).get("tactic") or mitre["tactic"])
    rule.mitre_name = str((data.get("mitre") or {}).get("name") or mitre["name"])
    rule.false_positive_notes = str(data.get("falsepositives", ""))
    rule.version += 1
    db.commit()
    db.refresh(rule)
    return rule
