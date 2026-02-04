"""
Tests for Strategy Rule Engine refactoring
Ensures backward compatibility and functionality after refactoring.
"""

import pytest
from core.strategy import (
    StrategyRuleEngine,
    Rule,
    RuleCondition,
    RuleEvaluationResult,
    create_default_rule_engine,
)


def test_engine_initialization():
    """Test that engine initializes with default rules"""
    engine = StrategyRuleEngine()
    assert len(engine.rules) > 0
    assert engine.rule_stats["evaluations"] == 0


def test_factory_function():
    """Test factory function creates engine correctly"""
    engine = create_default_rule_engine()
    assert isinstance(engine, StrategyRuleEngine)
    assert len(engine.rules) > 0


def test_evaluate_fingerprint():
    """Test fingerprint evaluation returns correct structure"""
    engine = StrategyRuleEngine()

    fingerprint = {
        "confidence": 0.85,
        "fragmentation_handling": "vulnerable",
        "checksum_validation": False,
    }

    result = engine.evaluate_fingerprint(fingerprint)

    assert isinstance(result, RuleEvaluationResult)
    assert isinstance(result.matched_rules, list)
    assert isinstance(result.recommended_techniques, list)
    assert isinstance(result.technique_priorities, dict)
    assert isinstance(result.technique_confidences, dict)
    assert len(result.matched_rules) > 0
    assert len(result.recommended_techniques) > 0


def test_rule_management():
    """Test adding, removing, enabling, disabling rules"""
    engine = StrategyRuleEngine()
    initial_count = len(engine.rules)

    # Add rule
    new_rule = Rule(
        rule_id="test_001",
        name="Test Rule",
        description="Test rule for testing",
        conditions=[{"field": "test_field", "condition": RuleCondition.EQUALS, "value": "test"}],
        recommendations=["test_technique"],
        priority=50,
    )
    engine.add_rule(new_rule)
    assert len(engine.rules) == initial_count + 1

    # Disable rule
    assert engine.disable_rule("test_001") is True
    assert not engine.rules[-1].enabled

    # Enable rule
    assert engine.enable_rule("test_001") is True
    assert engine.rules[-1].enabled

    # Remove rule
    assert engine.remove_rule("test_001") is True
    assert len(engine.rules) == initial_count


def test_statistics():
    """Test statistics tracking"""
    engine = StrategyRuleEngine()

    fingerprint = {"confidence": 0.85, "fragmentation_handling": "vulnerable"}

    engine.evaluate_fingerprint(fingerprint)

    stats = engine.get_rule_statistics()
    assert stats["total_rules"] > 0
    assert stats["enabled_rules"] > 0
    assert stats["rule_stats"]["evaluations"] == 1


def test_condition_evaluation():
    """Test different condition types"""
    from core.strategy.rule_evaluator import evaluate_condition

    # EQUALS
    assert evaluate_condition(5, RuleCondition.EQUALS, 5) is True
    assert evaluate_condition(5, RuleCondition.EQUALS, 6) is False

    # GREATER_THAN
    assert evaluate_condition(10, RuleCondition.GREATER_THAN, 5) is True
    assert evaluate_condition(5, RuleCondition.GREATER_THAN, 10) is False

    # LESS_THAN
    assert evaluate_condition(5, RuleCondition.LESS_THAN, 10) is True
    assert evaluate_condition(10, RuleCondition.LESS_THAN, 5) is False

    # CONTAINS
    assert evaluate_condition("hello world", RuleCondition.CONTAINS, "world") is True
    assert evaluate_condition("hello world", RuleCondition.CONTAINS, "xyz") is False

    # IN_LIST
    assert evaluate_condition("a", RuleCondition.IN_LIST, ["a", "b", "c"]) is True
    assert evaluate_condition("d", RuleCondition.IN_LIST, ["a", "b", "c"]) is False


def test_nested_field_access():
    """Test nested field value extraction"""
    from core.strategy.field_utils import get_nested_field_value

    data = {"level1": {"level2": {"level3": "value"}}}

    assert get_nested_field_value(data, "level1.level2.level3") == "value"
    assert get_nested_field_value(data, "level1.level2") == {"level3": "value"}
    assert get_nested_field_value(data, "nonexistent") is None
    assert get_nested_field_value(data, "level1.nonexistent") is None


def test_backward_compatibility():
    """Test that old import paths still work"""
    from core.strategy.strategy_rule_engine import (
        StrategyRuleEngine as DirectEngine,
        create_default_rule_engine as direct_factory,
    )

    engine1 = DirectEngine()
    engine2 = direct_factory()

    assert isinstance(engine1, StrategyRuleEngine)
    assert isinstance(engine2, StrategyRuleEngine)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
