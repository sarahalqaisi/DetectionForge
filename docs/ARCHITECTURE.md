# DetectionForge Architecture

## Processing Pipeline

1. **Ingestion** accepts uploaded telemetry and selects a parser explicitly or through auto-detection.
2. **Normalization** maps source-specific fields into a common `Event` schema.
3. **Detection** evaluates enabled YAML rules against normalized events.
4. **Correlation** supports event-count windows and ordered event sequences.
5. **Alerting** records the matched rule, evidence, severity, entity, and risk score.
6. **Incident Correlation** groups related alerts by entity and time proximity.
7. **Investigation** provides timelines, notes, assignments, status changes, similarity, and exports.
8. **Validation** executes safe fixtures and records expected result, actual result, pass/fail state, and runtime.

## Main Components

- `normalizers.py`: Linux auth, Nginx, Windows/Sysmon, Suricata, and generic JSON parsers.
- `detection.py`: YAML parsing, field operators, event matching, count correlation, sequence correlation, and test execution.
- `correlation.py`: alert-to-incident grouping, incident scoring, and similar-incident scoring.
- `rules.py`: filesystem rule import and versioned rule updates.
- `reporting.py`: incident serialization to PDF, CSV, and JSON.
- `analytics.py`: SOC metrics, charts, MITRE coverage, and quality calculations.

## Data Model

- `events`: normalized source telemetry.
- `detection_rules`: versioned YAML detection content and MITRE metadata.
- `alerts`: rule matches and correlation findings.
- `incidents`: correlated alert groups and analyst workflow state.
- `detection_tests`: rule validation history.
- `incident_notes`: analyst investigation notes.
- `audit_logs`: operational accountability records.

## Deployment Modes

- **Local portfolio/demo:** SQLite and `python run.py`.
- **Container deployment:** FastAPI application and PostgreSQL through Docker Compose.
