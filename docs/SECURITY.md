# Security Notes

DetectionForge is built for defensive education, portfolio demonstration, and controlled lab use.

## Implemented Safeguards

- Upload size limit controlled by `MAX_UPLOAD_MB`.
- Uploaded files are reduced to a safe basename and deleted after processing.
- SQLAlchemy parameterization is used for database queries.
- Rule YAML is parsed with `yaml.safe_load`.
- Rule YAML is size-limited and structurally validated before persistence.
- Conditions use a bounded parser with no `eval`, `exec`, or dynamic execution.
- Regex patterns and compared values are length-limited; obvious nested quantifiers are rejected.
- HTML templates use Jinja automatic escaping.
- Production cookies can be marked HTTPS-only through `APP_ENV=production`.
- Known placeholder session secrets are rejected in production mode.
- Responses disable caching and set CSP, frame, MIME-sniffing, referrer, and permissions headers.
- Client errors do not include parser exceptions, local paths, SQL errors, or stack traces.
- Secrets and runtime data are excluded by `.gitignore`.
- Demo IP addresses use reserved documentation networks.

## Before Internet Exposure

Authentication and authorization are not implemented. Before internet exposure, add both, plus CSRF protection for state-changing forms, TLS termination, secure secrets management, request throttling, malware-safe file storage, database backups, centralized logging, and a background task queue for large ingestion jobs. Python regex matching has no portable timeout in this implementation; conservative limits reduce but do not eliminate ReDoS risk from untrusted rules.

Never place real credentials, API keys, production logs, private incident data, or malware samples in a public Git repository.
