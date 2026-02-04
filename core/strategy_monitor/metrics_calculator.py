"""
Metrics calculation utilities for strategy monitoring.

Provides functions for calculating trends, confidence scores, and latency estimates
from effectiveness data.
"""

from collections import deque
from typing import Dict


def calculate_effectiveness_trend(effectiveness_data: deque) -> str:
    """
    Calculate trend from effectiveness data.

    Args:
        effectiveness_data: Deque of effectiveness measurements with 'success_rate' key

    Returns:
        Trend string: 'improving', 'degrading', or 'stable'
    """
    if len(effectiveness_data) < 3:
        return "stable"

    recent_rates = [item["success_rate"] for item in list(effectiveness_data)[-3:]]
    older_rates = (
        [item["success_rate"] for item in list(effectiveness_data)[-6:-3]]
        if len(effectiveness_data) >= 6
        else recent_rates
    )

    recent_avg = sum(recent_rates) / len(recent_rates)
    older_avg = sum(older_rates) / len(older_rates)

    change = recent_avg - older_avg

    if change > 0.1:
        return "improving"
    elif change < -0.1:
        return "degrading"
    else:
        return "stable"


def calculate_confidence(effectiveness_data: deque) -> float:
    """
    Calculate confidence score based on data quality.

    Args:
        effectiveness_data: Deque of effectiveness measurements with 'success_rate' key

    Returns:
        Confidence score between 0.0 and 1.0
    """
    if not effectiveness_data:
        return 0.0

    # Confidence based on data points and consistency
    data_points = len(effectiveness_data)
    data_confidence = min(data_points / 10.0, 1.0)  # Max confidence at 10+ data points

    # Consistency confidence (lower variance = higher confidence)
    if data_points > 1:
        rates = [item["success_rate"] for item in effectiveness_data]
        variance = sum((rate - sum(rates) / len(rates)) ** 2 for rate in rates) / len(rates)
        consistency_confidence = max(0.0, 1.0 - variance * 2)  # Penalize high variance
    else:
        consistency_confidence = 0.5

    return (data_confidence + consistency_confidence) / 2.0


def calculate_attack_effectiveness_trend(effectiveness_data: deque) -> str:
    """
    Calculate trend for attack effectiveness.

    Args:
        effectiveness_data: Deque of attack effectiveness measurements

    Returns:
        Trend string: 'improving', 'degrading', or 'stable'
    """
    if len(effectiveness_data) < 3:
        return "stable"

    try:
        # Get recent measurements
        recent_data = list(effectiveness_data)[-5:]  # Last 5 measurements
        success_rates = [data["success_rate"] for data in recent_data]

        # Calculate trend
        if len(success_rates) >= 2:
            recent_avg = sum(success_rates[-2:]) / 2
            older_avg = sum(success_rates[:-2]) / max(1, len(success_rates) - 2)

            if recent_avg > older_avg + 0.1:  # 10% improvement
                return "improving"
            elif recent_avg < older_avg - 0.1:  # 10% degradation
                return "degrading"

        return "stable"

    except Exception:
        return "stable"


def calculate_attack_confidence(effectiveness_data: deque) -> float:
    """
    Calculate confidence score for attack effectiveness.

    Args:
        effectiveness_data: Deque of attack effectiveness measurements

    Returns:
        Confidence score between 0.0 and 1.0
    """
    if not effectiveness_data:
        return 0.0

    try:
        # Confidence based on data points and consistency
        data_points = len(effectiveness_data)
        if data_points < 3:
            return 0.3  # Low confidence with few data points

        # Calculate variance in success rates
        success_rates = [data["success_rate"] for data in effectiveness_data]
        if len(success_rates) > 1:
            mean_rate = sum(success_rates) / len(success_rates)
            variance = sum((rate - mean_rate) ** 2 for rate in success_rates) / len(success_rates)

            # Lower variance = higher confidence
            consistency_score = max(0.0, 1.0 - variance * 2)  # Scale variance

            # More data points = higher confidence (up to a limit)
            data_score = min(1.0, data_points / 10.0)

            return (consistency_score + data_score) / 2

        return 0.5  # Neutral confidence

    except Exception:
        return 0.5


def estimate_latency_from_stats(combined_stats: Dict[str, int]) -> float:
    """
    Estimate latency from packet processing statistics.

    Args:
        combined_stats: Dictionary with packet processing statistics

    Returns:
        Estimated latency in milliseconds
    """
    # Simple estimation based on packet processing complexity
    total_packets = combined_stats.get("packets_captured", 1)
    fragments = combined_stats.get("fragments_sent", 0)
    fake_packets = combined_stats.get("fake_packets_sent", 0)

    # Base latency + complexity factors
    base_latency = 5.0
    fragment_penalty = (fragments / total_packets) * 10.0 if total_packets > 0 else 0.0
    fake_packet_penalty = (fake_packets / total_packets) * 5.0 if total_packets > 0 else 0.0

    return base_latency + fragment_penalty + fake_packet_penalty


def estimate_technique_latency(technique: str) -> float:
    """
    Estimate latency for a technique based on complexity.

    Args:
        technique: Technique name

    Returns:
        Estimated latency in milliseconds
    """
    latency_estimates = {
        "fakeddisorder": 5.0,
        "multisplit": 8.0,
        "multidisorder": 10.0,
        "seqovl": 12.0,
        "badsum_fooling": 3.0,
        "md5sig_fooling": 3.0,
        "ip_fragmentation_advanced": 15.0,
        "timing_based_evasion": 20.0,
    }

    return latency_estimates.get(technique, 10.0)
