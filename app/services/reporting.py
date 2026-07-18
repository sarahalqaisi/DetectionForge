from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models import Incident


def incident_payload(incident: Incident) -> dict:
    return {
        "id": incident.id,
        "title": incident.title,
        "status": incident.status,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "entity_key": incident.entity_key,
        "summary": incident.summary,
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
        "alerts": [
            {
                "id": alert.id,
                "title": alert.title,
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "status": alert.status,
                "created_at": alert.created_at.isoformat(),
                "rule": alert.rule.title if alert.rule else None,
                "mitre_technique": alert.rule.mitre_technique if alert.rule else None,
                "mitre_tactic": alert.rule.mitre_tactic if alert.rule else None,
            }
            for alert in incident.alerts
        ],
        "notes": [
            {"author": note.author, "body": note.body, "created_at": note.created_at.isoformat()}
            for note in incident.notes
        ],
    }


def incident_json(incident: Incident) -> bytes:
    return json.dumps(incident_payload(incident), indent=2).encode("utf-8")


def incident_csv(incident: Incident) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["incident_id", "title", "severity", "risk_score", "status", "entity_key"])
    writer.writerow([incident.id, incident.title, incident.severity, incident.risk_score, incident.status, incident.entity_key])
    writer.writerow([])
    writer.writerow(["alert_id", "alert_title", "severity", "risk_score", "rule", "mitre_technique", "mitre_tactic", "created_at"])
    for alert in incident.alerts:
        writer.writerow([
            alert.id,
            alert.title,
            alert.severity,
            alert.risk_score,
            alert.rule.title if alert.rule else "",
            alert.rule.mitre_technique if alert.rule else "",
            alert.rule.mitre_tactic if alert.rule else "",
            alert.created_at.isoformat(),
        ])
    return output.getvalue().encode("utf-8")


def incident_pdf(incident: Incident) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=15 * mm, leftMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("DetectionForge Incident Report", styles["Title"]),
        Paragraph(f"Generated {datetime.now(timezone.utc).isoformat()}", styles["Normal"]),
        Spacer(1, 8),
        Paragraph(incident.title, styles["Heading2"]),
        Table(
            [
                ["Incident ID", incident.id, "Status", incident.status],
                ["Severity", incident.severity, "Risk Score", f"{incident.risk_score:.0f}/100"],
                ["Entity", incident.entity_key or "Unknown", "Created", incident.created_at.isoformat()],
            ],
            colWidths=[30 * mm, 55 * mm, 30 * mm, 55 * mm],
        ),
        Spacer(1, 10),
        Paragraph("Summary", styles["Heading3"]),
        Paragraph(incident.summary or "No summary", styles["BodyText"]),
        Spacer(1, 10),
        Paragraph("Alerts", styles["Heading3"]),
    ]
    rows = [["ID", "Alert", "Severity", "MITRE", "Score"]]
    for alert in incident.alerts:
        rows.append([
            str(alert.id),
            Paragraph(alert.title, styles["BodyText"]),
            alert.severity,
            alert.rule.mitre_technique if alert.rule and alert.rule.mitre_technique else "Unmapped",
            f"{alert.risk_score:.0f}",
        ])
    table = Table(rows, colWidths=[12 * mm, 85 * mm, 22 * mm, 28 * mm, 18 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
            ]
        )
    )
    story.append(table)
    if incident.notes:
        story.extend([Spacer(1, 10), Paragraph("Analyst Notes", styles["Heading3"])])
        for note in incident.notes:
            story.append(Paragraph(f"<b>{note.author}</b> — {note.created_at.isoformat()}<br/>{note.body}", styles["BodyText"]))
            story.append(Spacer(1, 5))
    doc.build(story)
    return buffer.getvalue()
