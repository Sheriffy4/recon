"""
Technique Aggregator
Aggregates and prioritizes attack techniques from matched rules.
"""

from typing import Dict, List, Set, Any, Tuple


def aggregate_techniques(
    matched_rules: List, fingerprint_data: Dict[str, Any]
) -> Tuple[Set[str], Dict[str, int], Dict[str, float]]:
    """
    Aggregate techniques from matched rules and calculate priorities/confidences.

    Args:
        matched_rules: List of matched Rule objects
        fingerprint_data: Original fingerprint data (for confidence calculation)

    Returns:
        Tuple of (recommended_techniques, technique_priorities, technique_confidences)
    """
    recommended_techniques = set()
    technique_priorities = {}
    technique_confidences = {}

    try:
        base_confidence = float(fingerprint_data.get("confidence", 0.5))
    except (TypeError, ValueError):
        base_confidence = 0.5

    for rule in matched_rules:
        for technique in rule.recommendations:
            recommended_techniques.add(technique)

            # Track highest priority for each technique
            current_priority = technique_priorities.get(technique, 0)
            if rule.priority > current_priority:
                technique_priorities[technique] = rule.priority

            # Track highest confidence for each technique
            current_confidence = technique_confidences.get(technique, 0.0)
            rule_confidence = rule.confidence_modifier * base_confidence
            if rule_confidence > current_confidence:
                technique_confidences[technique] = rule_confidence

    return recommended_techniques, technique_priorities, technique_confidences


def sort_techniques_by_priority(
    techniques: Set[str], technique_priorities: Dict[str, int]
) -> List[str]:
    """
    Sort techniques by priority (highest first).

    Args:
        techniques: Set of technique names
        technique_priorities: Dictionary mapping technique to priority

    Returns:
        Sorted list of technique names
    """
    return sorted(techniques, key=lambda t: technique_priorities.get(t, 0), reverse=True)
