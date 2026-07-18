# Security Notes

DetectionForge is built for defensive education, portfolio demonstration, and controlled lab use.

## Implemented Safeguards

- Upload size limit controlled by `MAX_UPLOAD_MB`.
- Uploaded files are reduced to a safe basename and deleted after processing.
- SQLAlchemy parameterization is used for database queries.
- Rule YAML is parsed with `yaml.safe_load`.
- HTML templates use Jinja automatic escaping.
- Production cookies can be marked HTTPS-only through `APP_ENV=production`.
- Secrets and runtime data are excluded by `.gitignore`.
- Demo IP addresses use reserved documentation networks.

## Before Internet Exposure

Add authentication and role-based authorization, CSRF protection for state-changing forms, TLS termination, secure secrets management, request throttling, malware-safe file storage, database backups, centralized logging, and a background task queue for large ingestion jobs.

Never place real credentials, API keys, production logs, private incident data, or malware samples in a public Git repository.
