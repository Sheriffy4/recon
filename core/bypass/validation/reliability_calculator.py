#!/usr/bin/env python3
"""
Reliability calculation and scoring functions.

This module contains pure calculation functions for scoring strategy effectiveness,
reliability, consistency, and performance.
"""

import statistics
from typing import Dict, Any, List

from .types import (
    ValidationMethod,
    ValidationResult,
    AccessibilityResult,
    AccessibilityStatus,
    ReliabilityLevel,
)
from core.utils.level_classifier import classify_by_thresholds


def calculate_reliability_score(
    validation_results: List[ValidationResult],
    max_response_time: float = 10.0,
) -> float:
    """Calculate overall reliability score from validation results."""
    if not validation_results:
        return 0.0

    # Weight different validation methods
    method_weights = {
        ValidationMethod.HTTP_RESPONSE: 0.25,
        ValidationMethod.CONTENT_CHECK: 0.20,
        ValidationMethod.TIMING_ANALYSIS: 0.15,
        ValidationMethod.MULTI_REQUEST: 0.15,
        ValidationMethod.DNS_RESOLUTION: 0.10,
        ValidationMethod.SSL_HANDSHAKE: 0.05,
        ValidationMethod.HEADER_ANALYSIS: 0.05,
        ValidationMethod.PAYLOAD_VERIFICATION: 0.05,
    }

    weighted_score = 0.0
    total_weight = 0.0

    for result in validation_results:
        weight = method_weights.get(result.method, 0.1)
        score = 1.0 if result.success else 0.0

        # Adjust score based on response time
        if result.success and result.response_time > 0:
            time_penalty = min(result.response_time / max_response_time, 1.0)
            score *= 1.0 - time_penalty * 0.2  # Up to 20% penalty for slow responses

        weighted_score += score * weight
        total_weight += weight

    return weighted_score / total_weight if total_weight > 0 else 0.0


def detect_false_positive_in_results(
    validation_results: List[ValidationResult],
    status_code_consistency_threshold: float = 0.9,
) -> bool:
    """Detect false positives in validation results."""
    if len(validation_results) < 2:
        return False

    # Check for inconsistent results
    success_rates = [1.0 if r.success else 0.0 for r in validation_results]
    success_rate = statistics.mean(success_rates)

    # Check response time consistency
    response_times = [
        r.response_time for r in validation_results if r.success and r.response_time > 0
    ]
    if len(response_times) > 1:
        time_variance = statistics.stdev(response_times)
        avg_time = statistics.mean(response_times)

        # High variance in response times might indicate false positives
        if time_variance > avg_time * 0.5:
            return True

    # Check status code consistency
    status_codes = [r.status_code for r in validation_results if r.status_code is not None]
    if len(status_codes) > 1:
        unique_codes = set(status_codes)
        consistency_rate = 1.0 - (len(unique_codes) - 1) / len(status_codes)

        if consistency_rate < status_code_consistency_threshold:
            return True

    # Check for mixed success/failure patterns that might indicate instability
    if 0.3 < success_rate < 0.7:  # Mixed results
        return True

    return False


def determine_accessibility_status(
    validation_results: List[ValidationResult], reliability_score: float
) -> AccessibilityStatus:
    """Determine overall accessibility status from validation results."""
    if not validation_results:
        return AccessibilityStatus.UNKNOWN

    successful_tests = sum(1 for r in validation_results if r.success)
    total_tests = len(validation_results)
    success_rate = successful_tests / total_tests

    # Check for specific error patterns
    dns_errors = sum(
        1
        for r in validation_results
        if r.method == ValidationMethod.DNS_RESOLUTION and not r.success
    )
    ssl_errors = sum(
        1
        for r in validation_results
        if r.method == ValidationMethod.SSL_HANDSHAKE and not r.success
    )
    timeout_errors = sum(
        1 for r in validation_results if "timeout" in (r.error_message or "").lower()
    )

    # Determine status based on patterns
    if dns_errors > 0 and success_rate < 0.3:
        return AccessibilityStatus.DNS_ERROR
    elif ssl_errors > 0 and success_rate < 0.3:
        return AccessibilityStatus.SSL_ERROR
    elif timeout_errors > total_tests * 0.5:
        return AccessibilityStatus.TIMEOUT
    elif success_rate >= 0.8 and reliability_score >= 0.7:
        return AccessibilityStatus.ACCESSIBLE
    elif success_rate >= 0.3:
        return AccessibilityStatus.PARTIALLY_BLOCKED
    elif success_rate < 0.3:
        return AccessibilityStatus.BLOCKED
    else:
        return AccessibilityStatus.UNKNOWN


def calculate_effectiveness_score(
    accessibility_results: List[AccessibilityResult],
    baseline_result: Dict[str, Any],
) -> float:
    """Calculate strategy effectiveness score."""
    if not accessibility_results:
        return 0.0

    # Calculate average bypass effectiveness
    bypass_scores = [r.bypass_effectiveness for r in accessibility_results]
    avg_bypass_effectiveness = statistics.mean(bypass_scores)

    # Compare with baseline
    baseline_success_rate = baseline_result.get("successful_tests", 0) / max(
        baseline_result.get("total_tests", 1), 1
    )

    # Calculate improvement over baseline
    improvement_factor = avg_bypass_effectiveness / max(baseline_success_rate, 0.1)

    # Normalize improvement factor to 0-1 scale
    normalized_improvement = min(improvement_factor / 2.0, 1.0)  # Cap at 2x improvement

    # Weight by consistency
    reliability_scores = [r.reliability_score for r in accessibility_results]
    avg_reliability = statistics.mean(reliability_scores)

    # Final effectiveness score
    effectiveness_score = (
        avg_bypass_effectiveness * 0.6 + normalized_improvement * 0.2 + avg_reliability * 0.2
    )

    return min(effectiveness_score, 1.0)


def detect_false_positives(
    accessibility_results: List[AccessibilityResult],
    baseline_result: Dict[str, Any],
    response_time_variance_threshold: float = 2.0,
) -> float:
    """Detect and calculate false positive rate."""
    if not accessibility_results:
        return 1.0

    false_positive_indicators = 0
    total_indicators = 0

    for result in accessibility_results:
        # Check for false positive indicators
        total_indicators += 1

        # High variance in response times
        if len(result.validation_results) > 1:
            response_times = [
                r.response_time
                for r in result.validation_results
                if r.success and r.response_time > 0
            ]
            if len(response_times) > 1:
                time_variance = statistics.stdev(response_times)
                avg_time = statistics.mean(response_times)

                if time_variance > avg_time * response_time_variance_threshold:
                    false_positive_indicators += 1

        # Inconsistent results across validation methods
        if result.false_positive_detected:
            false_positive_indicators += 1

        # Suspiciously high success rate compared to baseline
        baseline_success_rate = baseline_result.get("successful_tests", 0) / max(
            baseline_result.get("total_tests", 1), 1
        )

        if (
            result.bypass_effectiveness > baseline_success_rate + 0.5
            and baseline_success_rate < 0.3
        ):  # Dramatic improvement from very low baseline
            false_positive_indicators += 0.5  # Partial indicator

    return false_positive_indicators / max(total_indicators, 1)


def calculate_consistency_score(accessibility_results: List[AccessibilityResult]) -> float:
    """Calculate consistency score across multiple test iterations."""
    if len(accessibility_results) < 2:
        return 1.0  # Single result is perfectly consistent

    # Check consistency of bypass effectiveness
    bypass_scores = [r.bypass_effectiveness for r in accessibility_results]
    bypass_variance = statistics.stdev(bypass_scores) if len(bypass_scores) > 1 else 0.0
    bypass_consistency = 1.0 - min(bypass_variance, 1.0)

    # Check consistency of reliability scores
    reliability_scores = [r.reliability_score for r in accessibility_results]
    reliability_variance = (
        statistics.stdev(reliability_scores) if len(reliability_scores) > 1 else 0.0
    )
    reliability_consistency = 1.0 - min(reliability_variance, 1.0)

    # Check consistency of accessibility status
    status_values = [r.status.value for r in accessibility_results]
    unique_statuses = set(status_values)
    status_consistency = 1.0 - (len(unique_statuses) - 1) / len(status_values)

    # Weighted average
    consistency_score = (
        bypass_consistency * 0.4 + reliability_consistency * 0.3 + status_consistency * 0.3
    )

    return consistency_score


def calculate_performance_score(
    accessibility_results: List[AccessibilityResult], max_acceptable_time: float = 10.0
) -> float:
    """Calculate performance score based on response times and efficiency."""
    if not accessibility_results:
        return 0.0

    # Collect all response times
    all_response_times = []
    for result in accessibility_results:
        if result.average_response_time > 0:
            all_response_times.append(result.average_response_time)

    if not all_response_times:
        return 0.0

    avg_response_time = statistics.mean(all_response_times)

    # Calculate performance score (inverse of response time, normalized)
    if avg_response_time <= 1.0:  # Excellent performance
        performance_score = 1.0
    elif avg_response_time <= max_acceptable_time:  # Acceptable performance
        performance_score = 1.0 - (avg_response_time - 1.0) / (max_acceptable_time - 1.0) * 0.5
    else:  # Poor performance
        performance_score = 0.5 * (max_acceptable_time / avg_response_time)

    return min(performance_score, 1.0)


def determine_reliability_level(
    effectiveness_score: float,
    consistency_score: float,
    false_positive_rate: float,
) -> ReliabilityLevel:
    """Determine overall reliability level using threshold classification."""
    # Calculate composite reliability score
    composite_score = (
        effectiveness_score * 0.5 + consistency_score * 0.3 + (1.0 - false_positive_rate) * 0.2
    )

    # Define thresholds for reliability levels
    thresholds = [
        (0.95, ReliabilityLevel.EXCELLENT),
        (0.85, ReliabilityLevel.VERY_GOOD),
        (0.70, ReliabilityLevel.GOOD),
        (0.50, ReliabilityLevel.MODERATE),
        (0.30, ReliabilityLevel.POOR),
    ]

    return classify_by_thresholds(
        composite_score, thresholds, ReliabilityLevel.UNRELIABLE, descending=True
    )


def generate_strategy_recommendation(
    reliability_level: ReliabilityLevel,
    false_positive_rate: float,
    consistency_score: float,
    performance_score: float,
) -> str:
    """Generate recommendation for strategy usage."""
    if reliability_level in [
        ReliabilityLevel.EXCELLENT,
        ReliabilityLevel.VERY_GOOD,
    ]:
        if performance_score >= 0.8:
            return "Highly recommended - excellent reliability and performance"
        else:
            return "Recommended - excellent reliability but consider performance optimization"

    elif reliability_level == ReliabilityLevel.GOOD:
        if false_positive_rate < 0.1:
            return "Recommended with monitoring - good reliability, low false positive rate"
        else:
            return "Use with caution - good reliability but elevated false positive rate"

    elif reliability_level == ReliabilityLevel.MODERATE:
        if consistency_score >= 0.7:
            return "Limited use recommended - moderate reliability but consistent results"
        else:
            return "Use with extensive testing - moderate and inconsistent reliability"

    elif reliability_level == ReliabilityLevel.POOR:
        return "Not recommended - poor reliability, consider alternative strategies"

    else:  # UNRELIABLE
        return "Avoid - unreliable results, strategy may be ineffective or harmful"
