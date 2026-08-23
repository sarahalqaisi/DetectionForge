#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.rule_testing import test_rule_directory


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate DetectionForge rules and run fixtures")
    parser.add_argument("--rules", type=Path, default=Path("rules"))
    parser.add_argument("--json", type=Path, dest="json_output")
    args = parser.parse_args()
    result = test_rule_directory(args.rules)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Rules: {result['valid_rules']}/{result['total_rules']} valid; fixtures: {result['passed']}/{result['fixtures']} passed")
    for error in result["errors"]:
        print(f"ERROR {error['file']}: {error['error']}")
    for fixture in result["results"]:
        if not fixture["passed"]:
            print(f"FAIL {fixture['rule_id']}: {fixture['name']} expected={fixture['expected']} actual={fixture['actual']}")
    return 0 if not result["errors"] and result["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
