"""
Strategy Rule Engine Models
Data classes for rules and evaluation results.
"""

from dataclasses import dataclass
from typing import Dict, List, Any


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
