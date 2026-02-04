"""
Rule Condition Evaluator
Extracted from StrategyRuleEngine for better separation of concerns.
"""

import logging
from typing import Any, Dict, Optional, Tuple, List
from enum import Enum

LOG = logging.getLogger("strategy_rule_engine.evaluator")


class RuleCondition(Enum):
    """Types of rule conditions"""

    EQUALS = "equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    IN_LIST = "in_list"
    NOT_IN_LIST = "not_in_list"


def _coerce_condition_type(condition_type: Any) -> Optional[RuleCondition]:
    """
    Allow condition_type to be either RuleCondition or its string value.
    Returns None if it can't be coerced.
    """
    if isinstance(condition_type, RuleCondition):
        return condition_type
    if isinstance(condition_type, str):
        try:
            return RuleCondition(condition_type)
        except ValueError:
            return None
    return None


def _truncate_value(value: Any, max_len: int = 140) -> Any:
    """Truncate value representation for diagnostics"""
    try:
        s = repr(value)
    except Exception:
        return "<unrepr-able>"
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return value


def evaluate_condition(actual_value: Any, condition_type: Any, expected_value: Any) -> bool:
    """
    Evaluate a single condition.

    Args:
        actual_value: Actual value from fingerprint
        condition_type: Type of condition to evaluate
        expected_value: Expected value for comparison

    Returns:
        True if condition is met, False otherwise
    """
    if actual_value is None:
        return False

    coerced = _coerce_condition_type(condition_type)
    if coerced is None:
        LOG.warning(f"Unknown condition type: {condition_type!r}")
        return False

    try:
        if coerced == RuleCondition.EQUALS:
            return actual_value == expected_value
        elif coerced == RuleCondition.GREATER_THAN:
            return float(actual_value) > float(expected_value)
        elif coerced == RuleCondition.LESS_THAN:
            return float(actual_value) < float(expected_value)
        elif coerced == RuleCondition.CONTAINS:
            if isinstance(actual_value, (list, tuple, set, frozenset)):
                return expected_value in actual_value
            if isinstance(actual_value, dict):
                return expected_value in actual_value
            return str(expected_value) in str(actual_value)
        elif coerced == RuleCondition.NOT_CONTAINS:
            if isinstance(actual_value, (list, tuple, set, frozenset)):
                return expected_value not in actual_value
            if isinstance(actual_value, dict):
                return expected_value not in actual_value
            return str(expected_value) not in str(actual_value)
        elif coerced == RuleCondition.IN_LIST:
            if not isinstance(expected_value, (list, tuple, set, frozenset)):
                LOG.warning(
                    f"IN_LIST expected list-like value, got: {type(expected_value).__name__}"
                )
                return False
            return actual_value in expected_value
        elif coerced == RuleCondition.NOT_IN_LIST:
            if not isinstance(expected_value, (list, tuple, set, frozenset)):
                LOG.warning(
                    f"NOT_IN_LIST expected list-like value, got: {type(expected_value).__name__}"
                )
                return False
            return actual_value not in expected_value
        else:
            return False
    except (ValueError, TypeError) as e:
        LOG.warning(f"Error evaluating condition: {e}")
        return False


def evaluate_rule_conditions_detailed(
    rule, fingerprint_data: Dict[str, Any], max_failed_conditions: int = 3
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Evaluate rule conditions with detailed failure information.

    Args:
        rule: Rule to evaluate
        fingerprint_data: Fingerprint data to check against
        max_failed_conditions: Maximum number of failed conditions to report

    Returns:
        Tuple of (matched: bool, failures: List[Dict])
    """
    from .field_utils import get_nested_field_value

    failures: List[Dict[str, Any]] = []
    for condition in getattr(rule, "conditions", []) or []:
        if not isinstance(condition, dict):
            failures.append(
                {"error": "condition_not_a_dict", "condition": _truncate_value(condition)}
            )
            if len(failures) >= max_failed_conditions:
                break
            continue

        field = condition.get("field")
        condition_type = condition.get("condition")
        expected_value = condition.get("value")

        if not field or condition_type is None:
            failures.append(
                {"error": "invalid_condition_structure", "condition": _truncate_value(condition)}
            )
            if len(failures) >= max_failed_conditions:
                break
            continue

        actual_value = get_nested_field_value(fingerprint_data, field)
        if not evaluate_condition(actual_value, condition_type, expected_value):
            coerced = _coerce_condition_type(condition_type)
            failures.append(
                {
                    "field": field,
                    "condition": coerced.value if coerced else condition_type,
                    "expected": _truncate_value(expected_value),
                    "actual": _truncate_value(actual_value),
                }
            )
            if len(failures) >= max_failed_conditions:
                break

    return (len(failures) == 0), failures


def evaluate_rule_conditions(rule, fingerprint_data: Dict[str, Any]) -> bool:
    """
    Evaluate if all conditions of a rule are met.

    Args:
        rule: Rule to evaluate
        fingerprint_data: Fingerprint data to check against

    Returns:
        True if all conditions are met, False otherwise
    """
    matched, _failures = evaluate_rule_conditions_detailed(rule, fingerprint_data)
    return matched
