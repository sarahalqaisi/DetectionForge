# Contributing

Use a focused branch and include tests for behavior changes. Detection rules must pass schema validation and include positive or negative fixtures where practical.

```bash
python -m pytest -q
python scripts/test_rules.py
python -m compileall -q app scripts tests
```

Rules should use the supported syntax documented in [Sigma compatibility](docs/SIGMA_COMPATIBILITY.md), map ATT&CK techniques only when justified, avoid sensitive event data, and explain likely false positives. Security issues should follow [SECURITY.md](SECURITY.md).
