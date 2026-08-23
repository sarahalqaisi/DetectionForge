from __future__ import annotations

import json
import logging
import secrets
import shutil
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.config import BASE_DIR, settings
from app.database import get_db
from app.models import Alert, AuditLog, DetectionRule, DetectionTest, Event, Incident, IncidentNote
from app.services.analytics import attack_coverage, chart_data, coverage_matrix, dashboard_stats
from app.services.correlation import correlate_alerts, similar_incidents
from app.services.detection import parse_rule, run_detection, test_rule
from app.services.ingestion import ingest_file
from app.services.reporting import incident_csv, incident_json, incident_pdf
from app.services.rules import import_rules, save_rule


router = APIRouter()
logger = logging.getLogger(__name__)
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))


def context(request: Request, **kwargs: Any) -> dict[str, Any]:
    return {"request": request, "app_name": settings.app_name, **kwargs}


def parse_evidence(alert: Alert) -> dict:
    try:
        return json.loads(alert.evidence or "{}")
    except json.JSONDecodeError:
        return {}


def paginate(query, db: Session, page: int, per_page: int = 20):
    page = max(1, page)
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    items = list(db.scalars(query.offset((page - 1) * per_page).limit(per_page)).all())
    pages = max(1, (total + per_page - 1) // per_page)
    return items, total, pages


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    stats = dashboard_stats(db)
    recent_alerts = list(
        db.scalars(
            select(Alert)
            .options(selectinload(Alert.rule))
            .order_by(desc(Alert.created_at))
            .limit(8)
        ).all()
    )
    recent_incidents = list(db.scalars(select(Incident).order_by(desc(Incident.updated_at)).limit(6)).all())
    return templates.TemplateResponse(request=request, name="dashboard.html", context=context(request, title="SOC Overview", stats=stats, recent_alerts=recent_alerts, recent_incidents=recent_incidents))


@router.get("/events", response_class=HTMLResponse)
def events_page(
    request: Request,
    db: Session = Depends(get_db),
    page: int = 1,
    q: str = "",
    source: str = "",
    severity: str = "",
):
    query = select(Event).order_by(desc(Event.timestamp))
    if q:
        like = f"%{q}%"
        query = query.where(or_(Event.message.ilike(like), Event.source_ip.ilike(like), Event.username.ilike(like), Event.hostname.ilike(like)))
    if source:
        query = query.where(Event.source == source)
    if severity:
        query = query.where(Event.severity == severity)
    items, total, pages = paginate(query, db, page)
    sources = list(db.scalars(select(Event.source).distinct().order_by(Event.source)).all())
    return templates.TemplateResponse(request=request, name="events.html", context=context(request, title="Live Events", events=items, total=total, page=page, pages=pages, q=q, source=source, severity=severity, sources=sources))


@router.get("/alerts", response_class=HTMLResponse)
def alerts_page(
    request: Request,
    db: Session = Depends(get_db),
    page: int = 1,
    q: str = "",
    severity: str = "",
    status: str = "",
):
    query = select(Alert).options(selectinload(Alert.rule), selectinload(Alert.event)).order_by(desc(Alert.created_at))
    if q:
        query = query.where(or_(Alert.title.ilike(f"%{q}%"), Alert.entity_key.ilike(f"%{q}%")))
    if severity:
        query = query.where(Alert.severity == severity)
    if status:
        query = query.where(Alert.status == status)
    items, total, pages = paginate(query, db, page)
    return templates.TemplateResponse(request=request, name="alerts.html", context=context(request, title="Alerts", alerts=items, total=total, page=page, pages=pages, q=q, severity=severity, status=status))


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail(alert_id: int, request: Request, db: Session = Depends(get_db)):
    alert = db.scalar(
        select(Alert)
        .where(Alert.id == alert_id)
        .options(selectinload(Alert.rule), selectinload(Alert.event), selectinload(Alert.incident))
    )
    if not alert:
        raise HTTPException(404, "Alert not found")
    return templates.TemplateResponse(request=request, name="alert_detail.html", context=context(request, title=f"Alert #{alert.id}", alert=alert, evidence=parse_evidence(alert)))


@router.get("/incidents", response_class=HTMLResponse)
def incidents_page(
    request: Request,
    db: Session = Depends(get_db),
    page: int = 1,
    q: str = "",
    severity: str = "",
    status: str = "",
):
    query = select(Incident).order_by(desc(Incident.updated_at))
    if q:
        query = query.where(or_(Incident.title.ilike(f"%{q}%"), Incident.entity_key.ilike(f"%{q}%"), Incident.summary.ilike(f"%{q}%")))
    if severity:
        query = query.where(Incident.severity == severity)
    if status:
        query = query.where(Incident.status == status)
    items, total, pages = paginate(query, db, page)
    return templates.TemplateResponse(request=request, name="incidents.html", context=context(request, title="Incidents", incidents=items, total=total, page=page, pages=pages, q=q, severity=severity, status=status))


@router.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail(incident_id: int, request: Request, db: Session = Depends(get_db)):
    incident = db.scalar(
        select(Incident)
        .where(Incident.id == incident_id)
        .options(
            selectinload(Incident.alerts).selectinload(Alert.rule),
            selectinload(Incident.alerts).selectinload(Alert.event),
            selectinload(Incident.notes),
        )
    )
    if not incident:
        raise HTTPException(404, "Incident not found")
    if status not in {"open", "investigating", "contained", "closed"} or severity not in {"info", "low", "medium", "high", "critical"}:
        raise HTTPException(400, "Invalid incident status or severity")
    similar = similar_incidents(db, incident)
    evidence = {alert.id: parse_evidence(alert) for alert in incident.alerts}
    return templates.TemplateResponse(request=request, name="incident_detail.html", context=context(request, title=f"Incident #{incident.id}", incident=incident, similar=similar, evidence=evidence))


@router.post("/incidents/{incident_id}/update")
def incident_update(
    incident_id: int,
    status: str = Form(...),
    severity: str = Form(...),
    assignee: str = Form(""),
    db: Session = Depends(get_db),
):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    incident.status = status
    incident.severity = severity
    incident.assignee = assignee.strip() or None
    db.add(AuditLog(action="incident_updated", entity_type="incident", entity_id=str(incident.id), details=json.dumps({"status": status, "severity": severity, "assignee": assignee}), actor="analyst"))
    db.commit()
    return RedirectResponse(f"/incidents/{incident_id}?toast=Incident+updated", status_code=303)


@router.post("/incidents/{incident_id}/notes")
def incident_note(incident_id: int, body: str = Form(...), author: str = Form("Analyst"), db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    if not body.strip():
        return RedirectResponse(f"/incidents/{incident_id}?toast=Note+cannot+be+empty", status_code=303)
    db.add(IncidentNote(incident_id=incident.id, author=author.strip() or "Analyst", body=body.strip()))
    db.add(AuditLog(action="note_added", entity_type="incident", entity_id=str(incident.id), details=json.dumps({"author": author}), actor=author or "Analyst"))
    db.commit()
    return RedirectResponse(f"/incidents/{incident_id}?toast=Note+added", status_code=303)


@router.get("/rules", response_class=HTMLResponse)
def rules_page(request: Request, db: Session = Depends(get_db), q: str = "", level: str = ""):
    query = select(DetectionRule).order_by(DetectionRule.rule_key)
    if q:
        query = query.where(or_(DetectionRule.title.ilike(f"%{q}%"), DetectionRule.rule_key.ilike(f"%{q}%"), DetectionRule.mitre_technique.ilike(f"%{q}%")))
    if level:
        query = query.where(DetectionRule.level == level)
    rules = list(db.scalars(query).all())
    return templates.TemplateResponse(request=request, name="rules.html", context=context(request, title="Rule Studio", rules=rules, q=q, level=level))


@router.get("/rules/{rule_id}", response_class=HTMLResponse)
def rule_detail(rule_id: int, request: Request, db: Session = Depends(get_db)):
    rule = db.scalar(select(DetectionRule).where(DetectionRule.id == rule_id).options(selectinload(DetectionRule.tests)))
    if not rule:
        raise HTTPException(404, "Rule not found")
    return templates.TemplateResponse(request=request, name="rule_detail.html", context=context(request, title=rule.title, rule=rule, tests=sorted(rule.tests, key=lambda t: t.created_at, reverse=True)))


@router.post("/rules/{rule_id}")
def rule_update(rule_id: int, yaml_content: str = Form(...), db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    try:
        save_rule(db, rule, yaml_content)
    except ValueError:
        logger.exception("Rule validation failed for rule id %s", rule_id)
        return RedirectResponse(f"/rules/{rule_id}?toast=Rule+validation+failed", status_code=303)
    db.add(AuditLog(action="rule_updated", entity_type="detection_rule", entity_id=str(rule.id), details=json.dumps({"version": rule.version}), actor="analyst"))
    db.commit()
    return RedirectResponse(f"/rules/{rule_id}?toast=Rule+saved", status_code=303)


@router.post("/rules/{rule_id}/toggle")
def rule_toggle(rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    rule.enabled = not rule.enabled
    db.add(AuditLog(action="rule_toggled", entity_type="detection_rule", entity_id=str(rule.id), details=json.dumps({"enabled": rule.enabled}), actor="analyst"))
    db.commit()
    return RedirectResponse("/rules?toast=Rule+status+updated", status_code=303)


@router.post("/rules/{rule_id}/test")
def rule_test(
    rule_id: int,
    sample_event: str = Form(...),
    expected_match: bool = Form(False),
    test_name: str = Form("Manual rule test"),
    db: Session = Depends(get_db),
):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    try:
        payload = json.loads(sample_event)
        if not isinstance(payload, dict):
            raise ValueError("JSON object required")
        result = test_rule(db, rule, payload, expected_match, test_name)
        message = "Test+passed" if result.passed else "Test+failed"
    except (ValueError, TypeError):
        logger.exception("Manual rule test input failed for rule id %s", rule_id)
        message = "Invalid+test+input"
    return RedirectResponse(f"/rules/{rule_id}?toast={message}", status_code=303)


@router.get("/coverage", response_class=HTMLResponse)
def coverage_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(request=request, name="coverage.html", context=context(request, title="MITRE Coverage", coverage=coverage_matrix(db)))


@router.get("/quality", response_class=HTMLResponse)
def quality_page(request: Request, db: Session = Depends(get_db)):
    rows = coverage_matrix(db)
    latest_tests = list(db.scalars(select(DetectionTest).options(selectinload(DetectionTest.rule)).order_by(desc(DetectionTest.created_at)).limit(30)).all())
    return templates.TemplateResponse(request=request, name="quality.html", context=context(request, title="Detection Quality", coverage=rows, latest_tests=latest_tests))


@router.get("/ingest", response_class=HTMLResponse)
def ingest_page(request: Request):
    return templates.TemplateResponse(request=request, name="ingest.html", context=context(request, title="Log Ingestion"))


@router.post("/ingest")
def ingest_upload(
    file: UploadFile = File(...),
    source_type: str = Form("auto"),
    run_engine: bool = Form(False),
    db: Session = Depends(get_db),
):
    filename = Path(file.filename or "upload.log").name
    target = settings.uploads_dir / f"{secrets.token_hex(8)}-{filename}"
    max_bytes = settings.max_upload_mb * 1024 * 1024
    total = 0
    with target.open("wb") as output:
        while chunk := file.file.read(1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                output.close()
                target.unlink(missing_ok=True)
                raise HTTPException(413, f"File exceeds {settings.max_upload_mb} MB")
            output.write(chunk)
    try:
        events = ingest_file(db, target, source_type, actor="web-upload")
        alerts = run_detection(db, events) if run_engine else []
        incidents = correlate_alerts(db) if run_engine else []
    except (ValueError, OSError, json.JSONDecodeError):
        logger.exception("Ingestion failed for sanitized filename %s", filename)
        target.unlink(missing_ok=True)
        raise HTTPException(400, "The uploaded telemetry could not be parsed") from None
    target.unlink(missing_ok=True)
    return RedirectResponse(f"/ingest?toast=Ingested+{len(events)}+events%2C+{len(alerts)}+alerts%2C+{len(incidents)}+incidents", status_code=303)


@router.post("/engine/run")
def engine_run(db: Session = Depends(get_db)):
    alerts = run_detection(db)
    incidents = correlate_alerts(db)
    return RedirectResponse(f"/?toast=Engine+created+{len(alerts)}+alerts+and+{len(incidents)}+incidents", status_code=303)


@router.post("/rules/import")
def rules_import(db: Session = Depends(get_db)):
    created, updated = import_rules(db)
    return RedirectResponse(f"/rules?toast=Imported+{created}+and+updated+{updated}+rules", status_code=303)


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, db: Session = Depends(get_db), page: int = 1):
    query = select(AuditLog).order_by(desc(AuditLog.created_at))
    items, total, pages = paginate(query, db, page, per_page=30)
    return templates.TemplateResponse(request=request, name="audit.html", context=context(request, title="Audit Log", logs=items, total=total, page=page, pages=pages))


@router.get("/reports/incidents/{incident_id}.{format}")
def incident_report(incident_id: int, format: str, db: Session = Depends(get_db)):
    incident = db.scalar(
        select(Incident)
        .where(Incident.id == incident_id)
        .options(selectinload(Incident.alerts).selectinload(Alert.rule), selectinload(Incident.notes))
    )
    if not incident:
        raise HTTPException(404, "Incident not found")
    if format == "pdf":
        data, media = incident_pdf(incident), "application/pdf"
    elif format == "csv":
        data, media = incident_csv(incident), "text/csv"
    elif format == "json":
        data, media = incident_json(incident), "application/json"
    else:
        raise HTTPException(400, "Unsupported format")
    return Response(data, media_type=media, headers={"Content-Disposition": f'attachment; filename="incident-{incident.id}.{format}"'})


@router.get("/api/health")
def health():
    return {"status": "ok", "service": settings.app_name}


@router.get("/api/stats")
def stats_api(db: Session = Depends(get_db)):
    return {"summary": dashboard_stats(db), "charts": chart_data(db)}


@router.get("/api/attack-coverage")
def attack_coverage_api(db: Session = Depends(get_db)):
    return attack_coverage(db)


@router.get("/api/events/live")
def live_events(db: Session = Depends(get_db), limit: int = Query(20, ge=1, le=100)):
    events = list(db.scalars(select(Event).order_by(desc(Event.timestamp)).limit(limit)).all())
    return [
        {
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "source": event.source,
            "event_type": event.event_type,
            "severity": event.severity,
            "source_ip": event.source_ip,
            "username": event.username,
            "hostname": event.hostname,
            "message": event.message,
        }
        for event in events
    ]


@router.post("/api/rules/{rule_id}/test")
def rule_test_api(rule_id: int, payload: dict[str, Any], db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    event = payload.get("event")
    if not isinstance(event, dict):
        raise HTTPException(422, "event must be an object")
    result = test_rule(db, rule, event, bool(payload.get("expected", True)), str(payload.get("name", "API test")))
    return {"passed": result.passed, "expected": result.expected_match, "actual": result.actual_match, "execution_ms": result.execution_ms}
