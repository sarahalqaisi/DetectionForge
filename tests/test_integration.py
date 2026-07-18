from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.database import SessionLocal, init_db
from app.main import app
from app.models import Alert, AuditLog, DetectionRule, DetectionTest, Event, Incident, IncidentNote
from app.services.seed import seed_demo


client = TestClient(app)


def reset_data():
    init_db()
    with SessionLocal() as db:
        for model in (IncidentNote, DetectionTest, Alert, Incident, Event, AuditLog, DetectionRule):
            db.execute(delete(model))
        db.commit()
        result = seed_demo(db, force=True)
        return result


def test_seed_and_dashboard():
    result = reset_data()
    assert result["events"] >= 40
    assert result["alerts"] >= 8
    response = client.get("/")
    assert response.status_code == 200
    assert "DetectionForge" in response.text
    assert "SOC Overview" in response.text


def test_api_and_pages():
    reset_data()
    for path in ("/events", "/alerts", "/incidents", "/rules", "/coverage", "/quality", "/ingest", "/audit", "/api/health", "/api/stats"):
        response = client.get(path)
        assert response.status_code == 200, path


def test_reports():
    reset_data()
    with SessionLocal() as db:
        incident = db.query(Incident).first()
        assert incident is not None
        incident_id = incident.id
    for ext, media in (("pdf", "application/pdf"), ("csv", "text/csv"), ("json", "application/json")):
        response = client.get(f"/reports/incidents/{incident_id}.{ext}")
        assert response.status_code == 200
        assert media in response.headers["content-type"]
        assert len(response.content) > 50


def test_rule_api_test():
    reset_data()
    with SessionLocal() as db:
        rule = db.query(DetectionRule).filter(DetectionRule.rule_key == "DF-WIN-001").one()
        rule_id = rule.id
    response = client.post(f"/api/rules/{rule_id}/test", json={"event": {"source": "windows", "event_type": "process_create", "process_name": "powershell.exe", "command_line": "powershell -EncodedCommand AAA"}, "expected": True})
    assert response.status_code == 200
    assert response.json()["passed"] is True


def test_log_upload_pipeline():
    reset_data()
    content = b"Jul 19 12:00:01 host sshd[1]: Failed password for root from 203.0.113.200 port 50000 ssh2\n"
    response = client.post(
        "/ingest",
        files={"file": ("auth.log", content, "text/plain")},
        data={"source_type": "linux_auth", "run_engine": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "Ingested+1+events" in response.headers["location"]
