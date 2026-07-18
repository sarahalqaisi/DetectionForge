from __future__ import annotations

import json
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models import Alert, Incident


SEVERITY_WEIGHT = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}


def _incident_score(alerts: list[Alert]) -> float:
    if not alerts:
        return 0.0
    base = max(SEVERITY_WEIGHT.get(alert.severity, 50) for alert in alerts)
    diversity = len({alert.rule_id for alert in alerts})
    volume_bonus = min(15, max(0, len(alerts) - 1) * 3)
    diversity_bonus = min(10, max(0, diversity - 1) * 3)
    return float(min(100, base + volume_bonus + diversity_bonus))


def _severity(score: float) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def correlate_alerts(db: Session) -> list[Incident]:
    unassigned = list(
        db.scalars(
            select(Alert)
            .where(Alert.incident_id.is_(None))
            .order_by(Alert.created_at.asc())
            .options(selectinload(Alert.rule))
        ).all()
    )
    groups: dict[str, list[Alert]] = defaultdict(list)
    for alert in unassigned:
        groups[alert.entity_key or "unknown"].append(alert)

    created: list[Incident] = []
    for key, alerts in groups.items():
        alerts.sort(key=lambda a: a.created_at)
        clusters: list[list[Alert]] = []
        current: list[Alert] = []
        for alert in alerts:
            if current and alert.created_at - current[-1].created_at > timedelta(minutes=30):
                clusters.append(current)
                current = []
            current.append(alert)
        if current:
            clusters.append(current)

        for cluster in clusters:
            score = _incident_score(cluster)
            techniques = sorted({a.rule.mitre_technique for a in cluster if a.rule and a.rule.mitre_technique})
            incident = Incident(
                title=f"Correlated activity involving {key}",
                severity=_severity(score),
                risk_score=score,
                entity_key=key,
                summary=f"{len(cluster)} alert(s), {len(techniques)} MITRE technique(s): {', '.join(techniques) or 'unmapped'}",
            )
            db.add(incident)
            db.flush()
            for alert in cluster:
                alert.incident_id = incident.id
                alert.status = "investigating"
            created.append(incident)
    db.commit()
    for incident in created:
        db.refresh(incident)
    return created


def similar_incidents(db: Session, incident: Incident, limit: int = 5) -> list[dict]:
    candidates = list(
        db.scalars(
            select(Incident)
            .where(Incident.id != incident.id)
            .options(selectinload(Incident.alerts).selectinload(Alert.rule))
        ).all()
    )
    current_techniques = {a.rule.mitre_technique for a in incident.alerts if a.rule and a.rule.mitre_technique}
    results: list[dict] = []
    for candidate in candidates:
        score = 0
        reasons: list[str] = []
        if incident.entity_key and candidate.entity_key == incident.entity_key:
            score += 60
            reasons.append("same entity")
        candidate_techniques = {a.rule.mitre_technique for a in candidate.alerts if a.rule and a.rule.mitre_technique}
        overlap = current_techniques & candidate_techniques
        if overlap:
            score += min(30, len(overlap) * 10)
            reasons.append(f"shared MITRE: {', '.join(sorted(overlap))}")
        if candidate.severity == incident.severity:
            score += 10
            reasons.append("same severity")
        if score:
            results.append({"incident": candidate, "score": score, "reasons": reasons})
    return sorted(results, key=lambda item: item["score"], reverse=True)[:limit]
