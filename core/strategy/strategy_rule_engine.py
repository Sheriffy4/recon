"""
Strategy Rule Engine - Task 24.1 Implementation
Converts detailed fingerprint data into basic attack recommendations using rule-based logic.
"""

import logging
from typing import Dict, Optional, Any

from .models import Rule, RuleEvaluationResult
from .rule_evaluator import (
    RuleCondition,
    evaluate_condition,
    evaluate_rule_conditions,
    evaluate_rule_conditions_detailed,
)
from .field_utils import get_nested_field_value
from .rule_manager import RuleManager
from .rule_persistence import RulePersistence
from .rule_loader import load_default_rules
from .technique_aggregator import aggregate_techniques, sort_techniques_by_priority

LOG = logging.getLogger("strategy_rule_engine")


class StrategyRuleEngine:
    """
    Rule-based engine that converts fingerprint data into attack recommendations.

    The engine evaluates fingerprint characteristics against a set of rules
    and produces prioritized recommendations for attack techniques.
    """

    def __init__(self, rules_file: Optional[str] = None):
        self._manager = RuleManager()
        self._persistence = RulePersistence()

        if rules_file:
            self.load_rules_from_file(rules_file)
        else:
            self._load_default_rules()

    @property
    def rules(self):
        """Access rules from manager"""
        return self._manager.rules

    @property
    def rule_stats(self):
        """Access rule stats from manager"""
        return self._manager.rule_stats

    def _load_default_rules(self):
        """Load default strategy generation rules from JSON file"""
        try:
            self._manager.rules = load_default_rules()
        except Exception as e:
            LOG.error(f"Failed to load default rules: {e}")
            # Fallback to empty rules list
            self._manager.rules = []
            raise

    def evaluate_fingerprint(self, fingerprint_data: Dict[str, Any]) -> RuleEvaluationResult:
        """
        Evaluate fingerprint data against all rules and generate recommendations.

        Args:
            fingerprint_data: Dictionary containing fingerprint characteristics

        Returns:
            RuleEvaluationResult with matched rules and recommendations
        """
        self._manager.increment_evaluations()

        matched_rules = []
        evaluation_details = {
            "total_rules_evaluated": len(self.rules),
            "rules_matched": 0,
            "fingerprint_fields": list(fingerprint_data.keys()),
        }

        MAX_FAILED_RULES = 5
        MAX_FAILED_CONDITIONS_PER_RULE = 3
        failed_conditions: list = []
        total_rules_failed = 0

        # Evaluate each rule
        for rule in self.rules:
            if not rule.enabled:
                continue

            matched, failures = evaluate_rule_conditions_detailed(
                rule, fingerprint_data, max_failed_conditions=MAX_FAILED_CONDITIONS_PER_RULE
            )
            if matched:
                matched_rules.append(rule)
                self._manager.increment_matches()
            else:
                total_rules_failed += 1
                if failures and len(failed_conditions) < MAX_FAILED_RULES:
                    failed_conditions.append(
                        {"rule_id": rule.rule_id, "rule_name": rule.name, "failed": failures}
                    )

        # Aggregate techniques from matched rules
        (
            recommended_techniques,
            technique_priorities,
            technique_confidences,
        ) = aggregate_techniques(matched_rules, fingerprint_data)

        evaluation_details["rules_matched"] = len(matched_rules)
        self._manager.increment_recommendations(len(recommended_techniques))
        evaluation_details["rules_failed"] = total_rules_failed
        evaluation_details["failed_conditions"] = failed_conditions
        evaluation_details["failed_conditions_truncated"] = (
            len(failed_conditions) >= MAX_FAILED_RULES
        )

        # Sort recommendations by priority
        sorted_techniques = sort_techniques_by_priority(
            recommended_techniques, technique_priorities
        )

        result = RuleEvaluationResult(
            matched_rules=matched_rules,
            recommended_techniques=sorted_techniques,
            technique_priorities=technique_priorities,
            technique_confidences=technique_confidences,
            evaluation_details=evaluation_details,
        )

        LOG.info(
            f"Rule evaluation complete: {len(matched_rules)} rules matched, "
            f"{len(sorted_techniques)} techniques recommended"
        )

        return result

    def _evaluate_rule_conditions(self, rule: Rule, fingerprint_data: Dict[str, Any]) -> bool:
        """Wrapper for backward compatibility. Delegates to rule_evaluator module."""
        return evaluate_rule_conditions(rule, fingerprint_data)

    def _get_nested_field_value(self, data: Dict[str, Any], field_path: str) -> Any:
        """Wrapper for backward compatibility. Delegates to field_utils module."""
        return get_nested_field_value(data, field_path)

    def _evaluate_condition(
        self, actual_value: Any, condition_type: RuleCondition, expected_value: Any
    ) -> bool:
        """Wrapper for backward compatibility. Delegates to rule_evaluator module."""
        return evaluate_condition(actual_value, condition_type, expected_value)

    def add_rule(self, rule: Rule):
        """Add a new rule to the engine"""
        self._manager.add_rule(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID"""
        return self._manager.remove_rule(rule_id)

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID"""
        return self._manager.enable_rule(rule_id)

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID"""
        return self._manager.disable_rule(rule_id)

    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return self._manager.get_rule_statistics()

    def load_rules_from_file(self, file_path: str):
        """Load rules from JSON file"""
        try:
            loaded = self._persistence.load_rules_from_file(file_path, Rule)
            self._normalize_rule_conditions(loaded)
            self._manager.rules = loaded
        except Exception as e:
            LOG.warning(f"Failed to load rules from {file_path}, using defaults: {e}")
            self._load_default_rules()

    def save_rules_to_file(self, file_path: str):
        """Save current rules to JSON file"""
        try:
            self._persistence.save_rules_to_file(self._manager.rules, file_path)
        except Exception as e:
            LOG.error(f"Failed to save rules to {file_path}: {e}")
            raise


def create_default_rule_engine() -> StrategyRuleEngine:
    """Factory function to create a rule engine with default rules"""
    return StrategyRuleEngine()


# Example usage and testing
if __name__ == "__main__":
    # Create rule engine
    engine = create_default_rule_engine()

    # Test fingerprint data
    test_fingerprint = {
        "domain": "example.com",
        "confidence": 0.85,
        "fragmentation_handling": "vulnerable",
        "checksum_validation": False,
        "stateful_inspection": True,
        "dpi_type": "roskomnadzor_tspu",
        "tls_parser_quality": "weak",
    }

    # Evaluate rules
    result = engine.evaluate_fingerprint(test_fingerprint)

    print(f"Matched {len(result.matched_rules)} rules:")
    for rule in result.matched_rules:
        print(f"  - {rule.name} (priority: {rule.priority})")

    print(f"\nRecommended techniques ({len(result.recommended_techniques)}):")
    for technique in result.recommended_techniques[:5]:  # Show top 5
        priority = result.technique_priorities.get(technique, 0)
        confidence = result.technique_confidences.get(technique, 0.0)
        print(f"  - {technique} (priority: {priority}, confidence: {confidence:.2f})")

    # Show statistics
    stats = engine.get_rule_statistics()
    print(f"\nEngine statistics: {stats}")
