# Sigma compatibility

DetectionForge implements a deliberately scoped Sigma-compatible YAML subset. It does not implement the complete Sigma specification or pySigma processing pipeline.

## Supported rule metadata

`title`, stable `id`, `status`, `description`, `author`, `date`, `modified`, `references`, `tags`, `logsource`, `detection`, `condition`, `falsepositives`, and `level` are accepted. Levels are informational/info, low, medium, high, and critical. References and tags must be string lists.

ATT&CK tags such as `attack.t1059` and `attack.t1059.001` are parsed into technique IDs. The legacy `mitre.technique`, `mitre.name`, and `mitre.tactic` object remains a DetectionForge extension for backward compatibility.

## Conditions

Conditions support named selections, case-insensitive `AND`, `OR`, `NOT`, and nested parentheses. Precedence is `NOT`, then `AND`, then `OR`. Conditions are evaluated by a bounded parser; rule text is never passed to Python `eval`, `exec`, or another dynamic execution mechanism.

Sigma quantifiers and aggregations such as `1 of selection_*`, `all of them`, and `count(field)` are not supported.

## Field matching

Supported modifiers are:

- `contains`, `startswith`, `endswith`
- `re` and the backward-compatible `regex` alias
- `exists`
- DetectionForge numeric extensions: `gt`, `gte`, `lt`, `lte`

Plain scalar equality and expected-value lists are supported. Regular-expression patterns are limited to 256 characters, compared values to 16 KiB, and obvious nested-quantifier patterns are rejected. Python regular expressions do not provide a portable timeout here, so residual ReDoS risk remains; only trusted, reviewed rules should be enabled.

## Event fields

Dot-separated nested paths are supported. Normalized top-level fields take precedence. Use an explicit `raw_data.` prefix to access a colliding raw field. If a first path component does not exist at the top level, lookup falls back to `raw_data` for compatibility.

## DetectionForge correlation extensions

`detection.correlation` supports `count` and ordered `sequence`, positive thresholds, explicit `group_by`, and bounded `s`, `m`, `h`, or `d` timeframes. These extensions are not native Sigma correlation syntax.

## Unsupported features

- Full Sigma collection and correlation specifications
- Wildcard selection quantifiers and aggregation expressions
- Value placeholder and pipeline transformations
- Backend-specific field mappings
- Base64, windash, CIDR, and other unlisted modifiers
- Full regular-expression denial-of-service isolation

