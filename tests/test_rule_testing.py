from app.config import settings
from app.services.rule_testing import test_rule_directory as run_rule_directory


def test_repository_rule_fixtures_are_structured_and_pass():
    result = run_rule_directory(settings.rules_dir)
    assert result["valid_rules"] == result["total_rules"] == 15
    assert result["fixtures"] == result["passed"] == 16
    assert result["failed"] == 0
    assert result["missed_positives"] == []
    assert result["unexpected_matches"] == []
