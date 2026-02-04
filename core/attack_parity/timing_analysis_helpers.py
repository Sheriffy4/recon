"""
Timing analysis helper functions for attack correlation.

This module provides specialized timing analysis utilities extracted
from TimingAnalyzer to reduce feature envy and improve modularity.
"""

from typing import Any, Dict, List


def detect_attack_bursts(
    sorted_attacks: List, burst_threshold: float = 0.1
) -> List[Dict[str, Any]]:
    """
    Detect bursts of attacks occurring in rapid succession.

    Args:
        sorted_attacks: Attacks sorted by timestamp
        burst_threshold: Maximum interval to consider part of a burst (seconds)

    Returns:
        List of detected burst information
    """
    from .timing_utils import calculate_burst_info

    bursts = []
    if not sorted_attacks:
        return bursts

    # Track burst by indices to avoid O(n^2) list.index() calls.
    burst_start_idx = 0

    for i in range(1, len(sorted_attacks)):
        prev_attack = sorted_attacks[i - 1]
        attack = sorted_attacks[i]

        time_diff = (attack.timestamp - prev_attack.timestamp).total_seconds()
        if time_diff > burst_threshold:
            # Burst ends at i-1
            if (i - 1) > burst_start_idx:
                bursts.append(calculate_burst_info(sorted_attacks, burst_start_idx, i - 1))
            burst_start_idx = i

    # Final burst
    if (len(sorted_attacks) - 1) > burst_start_idx:
        bursts.append(
            calculate_burst_info(sorted_attacks, burst_start_idx, len(sorted_attacks) - 1)
        )

    return bursts


def generate_timing_recommendations(
    discovery_patterns: Dict[str, Any], service_patterns: Dict[str, Any], similarity_score: float
) -> List[str]:
    """
    Generate recommendations based on timing analysis.

    Args:
        discovery_patterns: Timing patterns from discovery mode
        service_patterns: Timing patterns from service mode
        similarity_score: Timing similarity score between modes

    Returns:
        List of recommendation strings
    """
    recommendations = []

    if similarity_score < 0.5:
        recommendations.append("Significant timing differences detected between modes")

    if discovery_patterns["timing_regularity"] > service_patterns["timing_regularity"] + 0.2:
        recommendations.append(
            "Discovery mode shows more regular timing - service mode may have performance issues"
        )
    elif service_patterns["timing_regularity"] > discovery_patterns["timing_regularity"] + 0.2:
        recommendations.append(
            "Service mode shows more regular timing - discovery mode may have variable delays"
        )

    if len(discovery_patterns["burst_detection"]) != len(service_patterns["burst_detection"]):
        recommendations.append("Different burst patterns detected between modes")

    return recommendations
