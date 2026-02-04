"""
Timing utility functions for attack correlation analysis.

This module provides reusable timing calculation utilities extracted
from correlation engine to reduce code duplication.
"""

from typing import Any, Dict, List


def calculate_burst_info(attacks: List[Any], start_idx: int, end_idx: int) -> Dict[str, Any]:
    """
    Calculate burst information for a sequence of attacks.

    Args:
        attacks: List of attacks (must have timestamp and attack_type attributes)
        start_idx: Start index of burst in attacks list
        end_idx: End index of burst in attacks list (inclusive)

    Returns:
        Dictionary containing burst information
    """
    burst_attacks = attacks[start_idx : end_idx + 1]

    return {
        "start_time": burst_attacks[0].timestamp,
        "end_time": burst_attacks[-1].timestamp,
        "duration": (burst_attacks[-1].timestamp - burst_attacks[0].timestamp).total_seconds(),
        "attack_count": len(burst_attacks),
        "attack_types": [a.attack_type for a in burst_attacks],
    }


def calculate_intervals(attacks: List[Any]) -> List[float]:
    """
    Calculate time intervals between consecutive attacks.

    Args:
        attacks: List of attacks sorted by timestamp

    Returns:
        List of intervals in seconds
    """
    intervals = []
    for i in range(len(attacks) - 1):
        interval = (attacks[i + 1].timestamp - attacks[i].timestamp).total_seconds()
        intervals.append(interval)
    return intervals
