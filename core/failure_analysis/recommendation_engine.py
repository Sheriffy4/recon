"""
Recommendation Engine Module

Generates strategic recommendations and determines next iteration focus
based on detected failure patterns and technique effectiveness.
"""

from typing import List, Dict
from .models import FailurePattern, FAILURE_PATTERNS, TECHNIQUE_EFFECTIVENESS


def generate_strategic_recommendations(
    patterns: List[FailurePattern],
    failed_techniques: Dict[str, List[str]],
    success_rates: List[float],
) -> List[str]:
    """
    Generate high-level strategic recommendations based on detected patterns.

    Args:
        patterns: List of detected failure patterns
        failed_techniques: Map of failure types to failed techniques
        success_rates: List of effectiveness scores

    Returns:
        List of strategic recommendation strings
    """
    recommendations = []

    # Based on detected patterns
    for pattern in patterns:
        if pattern.pattern_type.startswith("dominant_"):
            failure_type = pattern.pattern_type.replace("dominant_", "").upper()
            pattern_info = FAILURE_PATTERNS.get(failure_type, {})
            strategic_focus = pattern_info.get("strategic_focus", [])

            if strategic_focus:
                recommendations.append(
                    f"Focus next iteration on {', '.join(strategic_focus)} techniques"
                )

    # Based on overall performance
    if success_rates:
        avg_success = sum(success_rates) / len(success_rates)
        if avg_success < 0.1:
            recommendations.append(
                "Consider fundamental approach change - current techniques are ineffective"
            )
        elif avg_success < 0.3:
            recommendations.append(
                "Moderate success detected - refine parameters and try variations"
            )
        elif avg_success > 0.7:
            recommendations.append("Good success rate - focus on optimization and consistency")

    # Based on technique diversity
    all_failed_techniques = set().union(*failed_techniques.values()) if failed_techniques else set()
    if len(all_failed_techniques) > 5:
        recommendations.append("High technique failure rate - consider protocol-level changes")

    return recommendations


def determine_next_focus(
    patterns: List[FailurePattern], failed_techniques: Dict[str, List[str]]
) -> List[str]:
    """
    Determine what the next iteration should focus on.

    Args:
        patterns: List of detected failure patterns
        failed_techniques: Map of failure types to failed techniques

    Returns:
        List of focus areas for next iteration
    """
    focus_areas = []

    # Extract strategic focus from patterns
    for pattern in patterns:
        failure_type = pattern.pattern_type.replace("dominant_", "").upper()
        pattern_info = FAILURE_PATTERNS.get(failure_type, {})
        strategic_focus = pattern_info.get("strategic_focus", [])
        focus_areas.extend(strategic_focus)

    # Add technique-specific recommendations
    all_failed = set().union(*failed_techniques.values()) if failed_techniques else set()

    # Recommend techniques that are effective against observed failure types
    for failure_type, techniques in failed_techniques.items():
        effective_techniques = []
        for technique, effective_against in TECHNIQUE_EFFECTIVENESS.items():
            if failure_type in effective_against and technique not in all_failed:
                effective_techniques.append(technique)

        if effective_techniques:
            focus_areas.extend(effective_techniques[:2])  # Top 2 recommendations

    # Remove duplicates and return
    return list(set(focus_areas))


def get_technique_recommendations(failure_type: str) -> List[str]:
    """
    Get recommended techniques for a specific failure type.

    Args:
        failure_type: Type of failure observed

    Returns:
        List of recommended technique names
    """
    recommendations = []

    for technique, effective_against in TECHNIQUE_EFFECTIVENESS.items():
        if failure_type in effective_against:
            recommendations.append(technique)

    return recommendations
