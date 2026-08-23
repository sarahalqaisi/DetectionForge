import pytest

from app.services.conditions import ConditionSyntaxError, evaluate_condition


def test_boolean_condition_operators_and_parentheses():
    values = {"selection": True, "filter": False, "other": True}
    assert evaluate_condition("selection", values)
    assert evaluate_condition("selection AND other", values)
    assert evaluate_condition("selection or filter", values)
    assert evaluate_condition("selection AND NOT filter", values)
    assert evaluate_condition("(selection OR filter) AND (other OR filter)", values)


@pytest.mark.parametrize("expression", ["selection and", "(selection", "selection xor other", "selection && other"])
def test_malformed_conditions_are_rejected(expression):
    with pytest.raises(ConditionSyntaxError):
        evaluate_condition(expression, {"selection": True, "other": False})


def test_unknown_selection_is_rejected():
    with pytest.raises(ConditionSyntaxError, match="Unknown selection"):
        evaluate_condition("missing", {"selection": True})


def test_code_like_input_is_never_executed(tmp_path):
    marker = tmp_path / "executed"
    expression = f'__import__("pathlib").Path("{marker}").touch()'
    with pytest.raises(ConditionSyntaxError):
        evaluate_condition(expression, {"selection": True})
    assert not marker.exists()


def test_condition_complexity_limits_are_enforced():
    with pytest.raises(ConditionSyntaxError, match="too long"):
        evaluate_condition("s" * 2049, {"selection": True})
    with pytest.raises(ConditionSyntaxError, match="too many tokens"):
        evaluate_condition(" ".join(["not"] * 128 + ["selection"]), {"selection": True})
    with pytest.raises(ConditionSyntaxError, match="nesting is too deep"):
        evaluate_condition("(" * 18 + "selection" + ")" * 18, {"selection": True})
