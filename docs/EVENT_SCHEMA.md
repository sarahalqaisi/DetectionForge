# Normalized event schema

DetectionForge normalizes supported telemetry into these fields:

- `timestamp`: timezone-aware event time
- `source`: normalizer or telemetry source
- `event_type`: normalized activity name
- `severity`: info, low, medium, high, or critical
- `source_ip`, `destination_ip`, `source_port`, `destination_port`
- `username`, `hostname`
- `process_name`, `command_line`
- `message`
- `raw_data`: original source-specific object

Rule lookups use dot-separated paths. A normalized top-level field always wins over a same-named field in `raw_data`. Use `raw_data.field` to request the original field explicitly. For backward compatibility, a field whose first component is absent from the normalized schema falls back to `raw_data`; lookup never merges nested objects or silently changes from top-level to raw data partway through a path.

Timestamp parsing accepts ISO 8601 and supported source formats. Missing or invalid timestamps currently receive ingestion time, which is convenient for a lab but can affect correlation ordering; production pipelines should reject or quarantine invalid source timestamps.

Raw data can contain sensitive telemetry. It is stored locally in the configured database and should not be committed or shared. Client upload errors do not echo source content.
