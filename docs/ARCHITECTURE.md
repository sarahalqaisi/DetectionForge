# DetectionForge Architecture

## Processing Pipeline

1. **Ingestion** accepts uploaded telemetry and selects a parser explicitly or through auto-detection.
2. **Normalization** maps source-specific fields into a common `Event` schema.
3. **Rule Validation** safely parses YAML, validates the supported Sigma subset and DetectionForge correlation extensions, and parses boolean conditions without dynamic code execution.
4. **Detection** evaluates enabled rule selections against normalized events.
5. **Event Correlation** supports count windows and ordered sequences with entity grouping and inclusive timeframe boundaries.
6. **Alerting** records the matched rule, evidence, severity, entity, risk score, and stable replay fingerprint.
6. **Incident Correlation** groups related alerts by entity and time proximity.
7. **Investigation** provides timelines, notes, assignments, status changes, similarity, and exports.
8. **Validation** executes safe fixtures and records expected result, actual result, pass/fail state, and runtime.

## Main Components

- `normalizers.py`: Linux auth, Nginx, Windows/Sysmon, Suricata, and generic JSON parsers.
- `conditions.py`: bounded boolean tokenizer and recursive-descent parser for selection conditions.
- `rule_validation.py`: rule metadata, selections, modifiers, and correlation schema validation.
- `detection.py`: field operators, normalized event matching, count/sequence evaluation, alerting, and test execution.
- `rule_testing.py`: positive/negative fixture execution and structured quality results.
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

Evaluation is synchronous and scales approximately with enabled rules × events. This is appropriate for controlled demonstrations, not unbounded production telemetry.
