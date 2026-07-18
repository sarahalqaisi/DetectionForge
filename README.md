<p align="center">
  <img src="docs/banner.svg" alt="DetectionForge banner" width="100%">
</p>

# DetectionForge

> **Open-source Detection Engineering and Mini SOC Platform**

DetectionForge is a defensive security platform for ingesting and normalizing security telemetry, executing YAML-based detection rules, correlating related alerts, managing incidents, validating detection quality, and visualizing MITRE ATT&CK coverage.

It is designed as a portfolio-ready cybersecurity project that demonstrates practical skills in SOC workflows, log analysis, detection engineering, incident response, API development, data modeling, automated testing, and secure deployment.


## Dashboard Preview

<p align="center">
  <img src="docs/screenshots/dashboard-preview.svg" alt="DetectionForge SOC dashboard preview" width="100%">
</p>

## Highlights

- Multi-source log ingestion for Linux authentication logs, Windows/Sysmon JSON, Nginx access logs, Suricata EVE JSON, and normalized JSON.
- Common security event schema across all collectors.
- YAML detection engine with equality, list, contains, prefix, suffix, numeric, and regular-expression operators.
- Count-based correlation and ordered sequence detection.
- Alert generation, risk scoring, incident correlation, timelines, notes, assignments, and case status management.
- MITRE ATT&CK technique and tactic mapping.
- Detection Quality scorecard with rule tests, pass rates, execution time, and version history.
- Rule Studio for editing, validating, enabling, disabling, and testing rules.
- Responsive dark SOC dashboard with charts, search, filters, and pagination.
- PDF, CSV, and JSON incident reports.
- Audit logging for ingestion, rule changes, notes, and case updates.
- REST API with automatically generated OpenAPI and Swagger documentation.
- Safe demo telemetry and 15 starter rules.
- SQLite for fast local use and PostgreSQL through Docker Compose.

## Detection Content

The included rule pack covers:

| Category | Examples |
|---|---|
| Linux | SSH brute force, successful login after failures, root login, local account creation |
| Windows | Suspicious PowerShell, cleared Security log, service installation, privileged group changes, account discovery, security control disable attempts |
| Network | High-confidence Suricata alerts, connection bursts, unusual DNS volume |
| Web | Directory traversal and injection-style web requests |

Every starter rule includes a safe test fixture and a MITRE ATT&CK mapping.

## Architecture

```mermaid
flowchart LR
    A[Linux / Windows / Nginx / Suricata Logs] --> B[Collectors & Parsers]
    B --> C[Normalized Event Schema]
    C --> D[YAML Detection Engine]
    D --> E[Alerts]
    E --> F[Correlation Engine]
    F --> G[Incidents]
    D --> H[Detection Tests]
    H --> I[Quality Scorecard]
    G --> J[PDF / CSV / JSON Reports]
    D --> K[MITRE ATT&CK Coverage]
    C --> L[(SQLite / PostgreSQL)]
    E --> L
    G --> L
```

More detail is available in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quick Start on Kali Linux

```bash
unzip DetectionForge.zip
cd DetectionForge
chmod +x setup_kali.sh
./setup_kali.sh
source .venv/bin/activate
python run.py
```

Open:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

The installer:

1. Creates `.venv` inside the project.
2. Installs the minimal Python dependencies.
3. Creates `.env` with a random secret key.
4. Initializes the database.
5. Imports the YAML rules.
6. Loads safe demo telemetry and executes the detection pipeline.

## Manual Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
cp .env.example .env
python scripts/init_db.py
python scripts/seed_demo.py
python run.py
```

## Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

The Docker deployment uses PostgreSQL and exposes the platform on port `8000`.

> Replace the example database password and `SECRET_KEY` before any non-local deployment.

## Using the Platform

### Ingest Logs

Open **Log Ingestion**, choose a source type or Auto Detect, and upload a supported file. DetectionForge can immediately:

1. Normalize records.
2. Evaluate enabled rules.
3. Generate alerts.
4. Correlate alerts into incidents.

Sample files are available in [`sample-data/`](sample-data/).

### Add a Detection Rule

Rules use a readable YAML format inspired by common detection-as-code practices:

```yaml
id: DF-LNX-001
title: Multiple Failed SSH Logins
logsource:
  category: linux_auth
level: high
mitre:
  technique: T1110
  name: Brute Force
  tactic: Credential Access
detection:
  selection:
    source: linux_auth
    event_type: failed_login
  condition: selection
  correlation:
    type: count
    group_by: [source_ip]
    threshold: 5
    timeframe: 5m
```

Put new rules in one of the directories under `rules/`, then click **Sync YAML Rules** or run:

```bash
python scripts/init_db.py
```

### Test a Rule

Rules can be tested from Rule Studio or the API:

```bash
curl -X POST http://127.0.0.1:8000/api/rules/1/test \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "PowerShell validation",
    "expected": true,
    "event": {
      "source": "windows",
      "event_type": "process_create",
      "process_name": "powershell.exe",
      "command_line": "powershell -EncodedCommand AAA"
    }
  }'
```

## Project Structure

```text
DetectionForge/
├── app/
│   ├── routers/          # Web pages and REST endpoints
│   ├── services/         # Normalization, detection, correlation, reports
│   ├── static/           # Responsive dashboard CSS and JavaScript
│   ├── templates/        # SOC interface templates
│   ├── config.py
│   ├── database.py
│   ├── main.py
│   └── models.py
├── rules/                # Detection-as-code YAML rule pack
├── sample-data/          # Safe demonstration telemetry
├── scripts/              # Database and demo utilities
├── tests/                # Unit and integration tests
├── docs/                 # Architecture, security, and validation notes
├── Dockerfile
├── docker-compose.yml
├── setup_kali.sh
└── run.py
```

## Testing

```bash
source .venv/bin/activate
pytest -q
```

The automated suite covers:

- Linux, Nginx, and Suricata normalization.
- Detection matching and regex operators.
- Demo ingestion and detection execution.
- Dashboard, Events, Alerts, Incidents, Rules, Coverage, Quality, and Audit pages.
- API health and statistics endpoints.
- Rule testing through the API.
- PDF, CSV, and JSON report generation.

See [`docs/VALIDATION.md`](docs/VALIDATION.md) for the verified release results.

## Security Notes

- Demo data uses documentation-only IP ranges and contains no malware.
- Uploaded files are size-limited and deleted after ingestion.
- `.env`, databases, reports, uploads, and virtual environments are excluded from Git.
- The project is a defensive educational platform, not a replacement for a production SIEM.
- Add authentication, TLS, centralized secrets, rate limiting, background jobs, and hardened storage before exposing it to untrusted networks.

See [`docs/SECURITY.md`](docs/SECURITY.md).

## Roadmap

- Native Sigma conversion layer.
- Streaming collectors and WebSocket event updates.
- Authentication and role-based access control.
- Redis-backed task queue for large ingestion jobs.
- Elasticsearch/OpenSearch storage adapter.
- Detection rule Git synchronization and approval workflow.
- STIX/TAXII threat-intelligence enrichment.
- Case comments, attachments, and analyst collaboration.

## License

Released under the [MIT License](LICENSE).
