"""
Strategy Rule Engine - Task 24.1 Implementation (Fixed Version)
Converts detailed fingerprint data into basic attack recommendations using rule-based logic.
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import json

LOG = logging.getLogger("strategy_rule_engine")


class RuleCondition(Enum):
    """Types of rule conditions"""

    EQUALS = "equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    IN_LIST = "in_list"
    NOT_IN_LIST = "not_in_list"


@dataclass
class Rule:
    """A single strategy generation rule"""

    rule_id: str
    name: str
    description: str
    conditions: List[Dict[str, Any]]  # List of conditions that must all be true
    recommendations: List[str]  # Attack techniques to recommend
    priority: int = 50  # Higher number = higher priority
    confidence_modifier: float = 1.0  # Multiplier for confidence score
    enabled: bool = True


@dataclass
class RuleEvaluationResult:
    """Result of evaluating rules against a fingerprint"""

    matched_rules: List[Rule]
    recommended_techniques: List[str]
    technique_priorities: Dict[str, int]
    technique_confidences: Dict[str, float]
    evaluation_details: Dict[str, Any]


class StrategyRuleEngine:
    """
    Rule-based engine that converts fingerprint data into attack recommendations.

    The engine evaluates fingerprint characteristics against a set of rules
    and produces prioritized recommendations for attack techniques.
    """

    def __init__(self, rules_file: Optional[str] = None):
        self.rules: List[Rule] = []
        self.rule_stats = {
            "evaluations": 0,
            "rule_matches": 0,
            "recommendations_generated": 0,
        }

        if rules_file:
            self.load_rules_from_file(rules_file)
        else:
            self._load_default_rules()

    def _load_default_rules(self):
        """Load default strategy generation rules"""

        default_rules = [
            # Fragmentation vulnerability rules
            Rule(
                rule_id="frag_vulnerable_001",
                name="Fragmentation Vulnerable - Multisplit Priority",
                description="If DPI is vulnerable to fragmentation, prioritize multisplit attacks",
                conditions=[
                    {
                        "field": "fragmentation_handling",
                        "condition": RuleCondition.EQUALS,
                        "value": "vulnerable",
                    }
                ],
                recommendations=[
                    "tcp_multisplit",
                    "tcp_multidisorder",
                    "ip_basic_fragmentation",
                ],
                priority=90,
                confidence_modifier=1.2,
            ),
            Rule(
                rule_id="frag_filtered_001",
                name="Fragmentation Filtered - Avoid Fragmentation",
                description="If DPI filters fragmentation, avoid fragmentation-based attacks",
                conditions=[
                    {
                        "field": "fragmentation_handling",
                        "condition": RuleCondition.EQUALS,
                        "value": "filtered",
                    }
                ],
                recommendations=[
                    "tcp_fakeddisorder",
                    "payload_obfuscation",
                    "timing_manipulation",
                ],
                priority=85,
                confidence_modifier=1.1,
            ),
            # Checksum validation rules
            Rule(
                rule_id="checksum_bypass_001",
                name="Bad Checksum Bypass",
                description="If DPI doesn't validate checksums, use badsum fooling",
                conditions=[
                    {
                        "field": "checksum_validation",
                        "condition": RuleCondition.EQUALS,
                        "value": False,
                    }
                ],
                recommendations=["badsum_fooling", "tcp_fakeddisorder_badsum"],
                priority=80,
                confidence_modifier=1.15,
            ),
            Rule(
                rule_id="checksum_strict_001",
                name="Strict Checksum Validation",
                description="If DPI validates checksums strictly, avoid badsum attacks",
                conditions=[
                    {
                        "field": "checksum_validation",
                        "condition": RuleCondition.EQUALS,
                        "value": True,
                    }
                ],
                recommendations=[
                    "tcp_multisplit",
                    "sequence_manipulation",
                    "timing_attacks",
                ],
                priority=75,
                confidence_modifier=1.0,
            ),
            # Stateful inspection rules
            Rule(
                rule_id="stateful_dpi_001",
                name="Stateful DPI Detection",
                description="If DPI performs stateful inspection, use state confusion attacks",
                conditions=[
                    {
                        "field": "stateful_inspection",
                        "condition": RuleCondition.EQUALS,
                        "value": True,
                    }
                ],
                recommendations=[
                    "tcp_seqovl",
                    "tcp_multidisorder",
                    "state_confusion_attacks",
                ],
                priority=85,
                confidence_modifier=1.2,
            ),
            # TTL sensitivity rules
            Rule(
                rule_id="ttl_sensitive_001",
                name="TTL Sensitive DPI",
                description="If DPI is sensitive to TTL, use low TTL attacks",
                conditions=[
                    {
                        "field": "ttl_sensitivity",
                        "condition": RuleCondition.EQUALS,
                        "value": "high",
                    }
                ],
                recommendations=["low_ttl_attacks", "tcp_fakeddisorder_low_ttl"],
                priority=70,
                confidence_modifier=1.1,
            ),
            # Protocol-specific rules
            Rule(
                rule_id="tls_parser_weak_001",
                name="Weak TLS Parser",
                description="If DPI has weak TLS parsing, use TLS-specific attacks",
                conditions=[
                    {
                        "field": "tls_parser_quality",
                        "condition": RuleCondition.EQUALS,
                        "value": "weak",
                    }
                ],
                recommendations=[
                    "tls_record_split",
                    "client_hello_fragmentation",
                    "tls_extension_attacks",
                ],
                priority=80,
                confidence_modifier=1.15,
            ),
            Rule(
                rule_id="http_filtering_001",
                name="HTTP Content Filtering",
                description="If DPI performs HTTP content filtering, use HTTP evasion",
                conditions=[
                    {
                        "field": "http_content_filtering",
                        "condition": RuleCondition.EQUALS,
                        "value": True,
                    }
                ],
                recommendations=[
                    "http_header_manipulation",
                    "payload_encoding",
                    "http_tunneling",
                ],
                priority=75,
                confidence_modifier=1.1,
            ),
            # DPI type specific rules
            Rule(
                rule_id="roskomnadzor_001",
                name="Roskomnadzor TSPU Specific",
                description="Specific attacks for Roskomnadzor TSPU systems",
                conditions=[
                    {
                        "field": "dpi_type",
                        "condition": RuleCondition.EQUALS,
                        "value": "roskomnadzor_tspu",
                    }
                ],
                recommendations=[
                    "tcp_fakeddisorder",
                    "badsum_fooling",
                    "md5sig_fooling",
                    "low_ttl_attacks",
                ],
                priority=95,
                confidence_modifier=1.3,
            ),
            Rule(
                rule_id="commercial_dpi_001",
                name="Commercial DPI Systems",
                description="Attacks effective against commercial DPI systems",
                conditions=[
                    {
                        "field": "dpi_type",
                        "condition": RuleCondition.EQUALS,
                        "value": "commercial_dpi",
                    }
                ],
                recommendations=[
                    "tcp_multisplit",
                    "advanced_fragmentation",
                    "timing_manipulation",
                ],
                priority=90,
                confidence_modifier=1.2,
            ),
            # Behavioral analysis rules
            Rule(
                rule_id="behavioral_analysis_001",
                name="Behavioral Analysis Detection",
                description="If DPI performs behavioral analysis, use pattern breaking",
                conditions=[
                    {
                        "field": "behavioral_analysis",
                        "condition": RuleCondition.EQUALS,
                        "value": True,
                    }
                ],
                recommendations=[
                    "traffic_mimicry",
                    "pattern_randomization",
                    "multi_flow_correlation",
                ],
                priority=85,
                confidence_modifier=1.1,
            ),
            # Rate limiting rules
            Rule(
                rule_id="rate_limiting_001",
                name="Rate Limiting Detection",
                description="If rate limiting is detected, use distributed attacks",
                conditions=[
                    {
                        "field": "rate_limiting_detected",
                        "condition": RuleCondition.EQUALS,
                        "value": True,
                    }
                ],
                recommendations=[
                    "distributed_attacks",
                    "timing_variation",
                    "connection_pooling",
                ],
                priority=70,
                confidence_modifier=1.0,
            ),
            # Fallback rules
            Rule(
                rule_id="fallback_001",
                name="Generic Fallback",
                description="Default recommendations when no specific patterns detected",
                conditions=[
                    {
                        "field": "confidence",
                        "condition": RuleCondition.LESS_THAN,
                        "value": 0.5,
                    }
                ],
                recommendations=[
                    "tcp_fakeddisorder",
                    "tcp_multisplit",
                    "basic_fragmentation",
                ],
                priority=30,
                confidence_modifier=0.8,
            ),
            # High confidence boost
            Rule(
                rule_id="high_confidence_001",
                name="High Confidence Boost",
                description="Boost recommendations when fingerprint confidence is high",
                conditions=[
                    {
                        "field": "confidence",
                        "condition": RuleCondition.GREATER_THAN,
                        "value": 0.8,
                    }
                ],
                recommendations=["advanced_attacks", "multi_stage_attacks"],
                priority=60,
                confidence_modifier=1.3,
            ),
        ]

        self.rules = default_rules
        LOG.info(f"Loaded {len(self.rules)} default strategy rules")

    def evaluate_fingerprint(
        self, fingerprint_data: Dict[str, Any]
    ) -> RuleEvaluationResult:
        """
        Evaluate fingerprint data against all rules and generate recommendations.

        Args:
            fingerprint_data: Dictionary containing fingerprint characteristics

        Returns:
            RuleEvaluationResult with matched rules and recommendations
        """

        self.rule_stats["evaluations"] += 1

        matched_rules = []
        recommended_techniques = set()
        technique_priorities = {}
        technique_confidences = {}
        evaluation_details = {
            "total_rules_evaluated": len(self.rules),
            "rules_matched": 0,
            "fingerprint_fields": list(fingerprint_data.keys()),
        }

        # Evaluate each rule
        for rule in self.rules:
            if not rule.enabled:
                continue

            if self._evaluate_rule_conditions(rule, fingerprint_data):
                matched_rules.append(rule)
                self.rule_stats["rule_matches"] += 1

                # Add recommendations from this rule
                for technique in rule.recommendations:
                    recommended_techniques.add(technique)

                    # Track highest priority and confidence for each technique
                    current_priority = technique_priorities.get(technique, 0)
                    if rule.priority > current_priority:
                        technique_priorities[technique] = rule.priority

                    current_confidence = technique_confidences.get(technique, 0.0)
                    rule_confidence = rule.confidence_modifier * fingerprint_data.get(
                        "confidence", 0.5
                    )
                    if rule_confidence > current_confidence:
                        technique_confidences[technique] = rule_confidence

        evaluation_details["rules_matched"] = len(matched_rules)
        self.rule_stats["recommendations_generated"] += len(recommended_techniques)

        # Sort recommendations by priority
        sorted_techniques = sorted(
            recommended_techniques,
            key=lambda t: technique_priorities.get(t, 0),
            reverse=True,
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

    def _evaluate_rule_conditions(
        self, rule: Rule, fingerprint_data: Dict[str, Any]
    ) -> bool:
        """
        Evaluate if all conditions of a rule are met.

        Args:
            rule: Rule to evaluate
            fingerprint_data: Fingerprint data to check against

        Returns:
            True if all conditions are met, False otherwise
        """

        for condition in rule.conditions:
            field = condition["field"]
            condition_type = condition["condition"]
            expected_value = condition["value"]

            # Get actual value from fingerprint data
            actual_value = self._get_nested_field_value(fingerprint_data, field)

            # Evaluate condition
            if not self._evaluate_condition(
                actual_value, condition_type, expected_value
            ):
                return False

        return True

    def _get_nested_field_value(self, data: Dict[str, Any], field_path: str) -> Any:
        """
        Get value from nested dictionary using dot notation.

        Args:
            data: Dictionary to search in
            field_path: Field path like 'tcp_analysis.fragmentation_handling'

        Returns:
            Field value or None if not found
        """

        keys = field_path.split(".")
        current = data

        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None

        return current

    def _evaluate_condition(
        self, actual_value: Any, condition_type: RuleCondition, expected_value: Any
    ) -> bool:
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

        try:
            if condition_type == RuleCondition.EQUALS:
                return actual_value == expected_value
            elif condition_type == RuleCondition.GREATER_THAN:
                return float(actual_value) > float(expected_value)
            elif condition_type == RuleCondition.LESS_THAN:
                return float(actual_value) < float(expected_value)
            elif condition_type == RuleCondition.CONTAINS:
                return str(expected_value) in str(actual_value)
            elif condition_type == RuleCondition.NOT_CONTAINS:
                return str(expected_value) not in str(actual_value)
            elif condition_type == RuleCondition.IN_LIST:
                return actual_value in expected_value
            elif condition_type == RuleCondition.NOT_IN_LIST:
                return actual_value not in expected_value
            else:
                LOG.warning(f"Unknown condition type: {condition_type}")
                return False
        except (ValueError, TypeError) as e:
            LOG.warning(f"Error evaluating condition: {e}")
            return False

    def add_rule(self, rule: Rule):
        """Add a new rule to the engine"""
        self.rules.append(rule)
        LOG.info(f"Added rule: {rule.name}")

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID"""
        for i, rule in enumerate(self.rules):
            if rule.rule_id == rule_id:
                removed_rule = self.rules.pop(i)
                LOG.info(f"Removed rule: {removed_rule.name}")
                return True
        return False

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = True
                LOG.info(f"Enabled rule: {rule.name}")
                return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = False
                LOG.info(f"Disabled rule: {rule.name}")
                return True
        return False

    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            "total_rules": len(self.rules),
            "enabled_rules": len([r for r in self.rules if r.enabled]),
            "disabled_rules": len([r for r in self.rules if not r.enabled]),
            "rule_stats": self.rule_stats.copy(),
        }

    def load_rules_from_file(self, file_path: str):
        """Load rules from JSON file"""
        try:
            with open(file_path, "r") as f:
                rules_data = json.load(f)

            self.rules = []
            for rule_dict in rules_data:
                rule = Rule(**rule_dict)
                self.rules.append(rule)

            LOG.info(f"Loaded {len(self.rules)} rules from {file_path}")
        except Exception as e:
            LOG.error(f"Failed to load rules from {file_path}: {e}")
            self._load_default_rules()

    def save_rules_to_file(self, file_path: str):
        """Save current rules to JSON file"""
        try:
            rules_data = []
            for rule in self.rules:
                rule_dict = {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "description": rule.description,
                    "conditions": rule.conditions,
                    "recommendations": rule.recommendations,
                    "priority": rule.priority,
                    "confidence_modifier": rule.confidence_modifier,
                    "enabled": rule.enabled,
                }
                rules_data.append(rule_dict)

            with open(file_path, "w") as f:
                json.dump(rules_data, f, indent=2)

            LOG.info(f"Saved {len(self.rules)} rules to {file_path}")
        except Exception as e:
            LOG.error(f"Failed to save rules to {file_path}: {e}")


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
