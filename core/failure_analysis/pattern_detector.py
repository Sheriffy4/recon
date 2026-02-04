"""
Pattern Detection Module

Detects patterns in failure data to provide actionable insights.
Identifies dominant failures, performance issues, latency problems, and technique ineffectiveness.
"""

from typing import List, Dict, Counter
from .models import FailurePattern, FAILURE_PATTERNS


def detect_failure_patterns(
    failure_types: Counter,
    failed_techniques: Dict[str, List[str]],
    success_rates: List[float],
    latency_patterns: Dict[str, List[float]],
    fingerprint_failure_map: Dict = None,
) -> List[FailurePattern]:
    """
    Detect patterns in failures to provide insights.

    Args:
        failure_types: Counter of failure types
        failed_techniques: Map of failure types to failed techniques
        success_rates: List of effectiveness scores
        latency_patterns: Map of techniques to latency measurements
        fingerprint_failure_map: Optional map of (dpi_type, attack) to failure stats

    Returns:
        List of detected FailurePattern objects
    """
    patterns = []
    total_failures = sum(failure_types.values())

    if total_failures == 0:
        return patterns

    # Detect various pattern types
    patterns.extend(_detect_dominant_failure(failure_types, failed_techniques, total_failures))
    patterns.extend(_detect_low_performance(success_rates, failed_techniques))
    patterns.extend(_detect_high_latency(latency_patterns))

    if fingerprint_failure_map:
        patterns.extend(_detect_technique_ineffectiveness(fingerprint_failure_map))

    return patterns


def _detect_dominant_failure(
    failure_types: Counter, failed_techniques: Dict[str, List[str]], total_failures: int
) -> List[FailurePattern]:
    """
    Detect if a single failure type dominates (>60% of failures).

    Returns:
        List with 0 or 1 FailurePattern
    """
    patterns = []

    most_common_failure = failure_types.most_common(1)[0]
    failure_type, count = most_common_failure

    if count / total_failures > 0.6:  # More than 60% of failures are of this type
        pattern_info = FAILURE_PATTERNS.get(failure_type, {})

        pattern = FailurePattern(
            pattern_type=f"dominant_{failure_type.lower()}",
            frequency=count,
            confidence=min(0.9, count / total_failures),
            likely_causes=pattern_info.get("причины", []),
            recommended_actions=pattern_info.get("решения", []),
            affected_techniques=failed_techniques.get(failure_type, []),
        )
        patterns.append(pattern)

    return patterns


def _detect_low_performance(
    success_rates: List[float], failed_techniques: Dict[str, List[str]]
) -> List[FailurePattern]:
    """
    Detect consistent low performance across all techniques.

    Returns:
        List with 0 or 1 FailurePattern
    """
    patterns = []

    if success_rates and max(success_rates) < 0.3:
        pattern = FailurePattern(
            pattern_type="consistent_low_performance",
            frequency=len([r for r in success_rates if r < 0.3]),
            confidence=0.8,
            likely_causes=[
                "DPI система эффективно противодействует всем испробованным техникам",
                "Неправильная классификация типа DPI",
                "Требуются более продвинутые техники обхода",
            ],
            recommended_actions=[
                "Переключиться на альтернативные протоколы (QUIC, HTTP/3)",
                "Использовать техники имитации трафика",
                "Применить многоуровневые атаки",
            ],
            affected_techniques=(
                list(set().union(*failed_techniques.values())) if failed_techniques else []
            ),
        )
        patterns.append(pattern)

    return patterns


def _detect_high_latency(latency_patterns: Dict[str, List[float]]) -> List[FailurePattern]:
    """
    Detect techniques with abnormally high latency (>5 seconds average).

    Returns:
        List with 0 or 1 FailurePattern
    """
    patterns = []
    high_latency_techniques = []

    for technique, latencies in latency_patterns.items():
        if latencies and sum(latencies) / len(latencies) > 5000:  # > 5 seconds average
            high_latency_techniques.append(technique)

    if high_latency_techniques:
        pattern = FailurePattern(
            pattern_type="high_latency_detection",
            frequency=len(high_latency_techniques),
            confidence=0.7,
            likely_causes=[
                "DPI система детектирует атаку и замедляет соединение",
                "Техники вызывают дополнительную обработку в DPI",
            ],
            recommended_actions=[
                "Использовать более быстрые техники обхода",
                "Применить техники минимизации задержек",
                "Переключиться на UDP-based протоколы",
            ],
            affected_techniques=high_latency_techniques,
        )
        patterns.append(pattern)

    return patterns


def _detect_technique_ineffectiveness(fingerprint_failure_map: Dict) -> List[FailurePattern]:
    """
    Detect techniques that consistently fail against specific DPI types.

    Args:
        fingerprint_failure_map: Map of (dpi_type, attack_name) to failure stats

    Returns:
        List of FailurePattern objects (one per ineffective technique)
    """
    patterns = []

    for (dpi_type, attack_name), stats in fingerprint_failure_map.items():
        total_runs = stats.get("total_runs", 0)
        failures = stats.get("failures", 0)

        if total_runs > 3 and failures / total_runs > 0.8:  # High failure rate after enough runs
            pattern = FailurePattern(
                pattern_type="technique_ineffective_vs_dpi",
                frequency=failures,
                confidence=0.9,
                likely_causes=[
                    f"Technique '{attack_name}' is consistently blocked by '{dpi_type}'."
                ],
                recommended_actions=[
                    f"Avoid using '{attack_name}' against '{dpi_type}'.",
                    "Prioritize other attacks for this DPI signature.",
                ],
                affected_techniques=[attack_name],
            )
            patterns.append(pattern)

    return patterns
