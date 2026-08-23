# Detection quality and fixture coverage

DetectionForge measures deterministic fixture coverage, not production accuracy. No field dataset, prevalence study, false-positive rate, precision, or recall claim is made.

Each rule can contain the existing singular `test` fixture and optional `tests.positive` and `tests.negative` lists. Positive fixtures must match; negative fixtures must not match.

```yaml
tests:
  positive:
    - name: Encoded command
      event: {event_type: process_create, command_line: powershell -enc AAA}
  negative:
    - name: Benign shell
      event: {event_type: process_create, command_line: cmd.exe /c whoami}
```

Run all validation and fixtures with:

```bash
python scripts/test_rules.py
python scripts/test_rules.py --json reports/rule-tests.json
```

The structured result contains valid and total rules, fixture pass/fail counts, rule IDs, fixture names, expected and actual outcomes, optional event IDs, missed positives, and unexpected matches represented as failed fixture rows. CI exits non-zero on a validation or fixture failure.

The web quality view reports stored test executions by rule. The ATT&CK coverage view and `/api/attack-coverage` summarize mapped techniques; this is content mapping coverage, not ATT&CK completeness.

## Scaling limit

Event evaluation is currently synchronous and approximately proportional to enabled rules × selected events. Correlation additionally sorts matched events per entity. Use controlled lab-sized batches; a production deployment would need streaming state, background workers, and bounded retention.

## Alert replay deduplication

An alert fingerprint is derived from rule ID, normalized entity key, and terminal event ID. This is stable for deterministic replay, separates later terminal events, and distinguishes entities. The database deduplication query uses the same components. Identical duplicate event records with different database IDs remain distinct by design because DetectionForge has no source-level event identity guarantee.

