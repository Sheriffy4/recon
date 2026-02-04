"""
DPI Insights Extractor Module

Extracts behavioral insights about DPI systems from test results.
Analyzes response timing, failure distribution, and recommends DPI classification.
"""

from typing import List, Dict, Any, Counter


def extract_dpi_insights(
    effectiveness_results: List[Any], failure_types: Counter
) -> Dict[str, Any]:
    """
    Extract insights about DPI behavior from test results.

    Args:
        effectiveness_results: List of EffectivenessResult objects
        failure_types: Counter of failure types

    Returns:
        Dictionary with DPI behavior insights
    """
    insights = {
        "detection_patterns": [],
        "response_characteristics": {},
        "vulnerability_indicators": [],
        "recommended_classification": None,
    }

    # Analyze response timing patterns
    insights["response_characteristics"].update(_analyze_response_timing(effectiveness_results))

    # Analyze failure distribution
    _analyze_failure_distribution(failure_types, insights)

    # Recommend DPI classification
    insights["recommended_classification"] = _recommend_dpi_classification(failure_types)

    return insights


def _analyze_response_timing(effectiveness_results: List[Any]) -> Dict[str, Any]:
    """
    Analyze response timing patterns to detect DPI characteristics.

    Args:
        effectiveness_results: List of test results

    Returns:
        Dictionary with timing analysis
    """
    timing_data = {}
    response_times = []

    for result in effectiveness_results:
        if hasattr(result, "baseline_latency"):
            response_times.append(result.baseline_latency)

    if response_times:
        avg_response_time = sum(response_times) / len(response_times)
        timing_data["average_latency_ms"] = avg_response_time

    return timing_data


def _analyze_failure_distribution(failure_types: Counter, insights: Dict[str, Any]) -> None:
    """
    Analyze failure distribution to identify DPI behavior patterns.

    Args:
        failure_types: Counter of failure types
        insights: Insights dictionary to update (modified in-place)
    """
    if not failure_types:
        return

    # Get dominant failure type
    if hasattr(failure_types, "most_common"):
        dominant_failure = failure_types.most_common(1)[0][0]
    else:
        # Handle case where failure_types is a regular dict
        dominant_failure = max(failure_types, key=failure_types.get)

    insights["response_characteristics"]["primary_failure_mode"] = dominant_failure

    # Analyze timing characteristics
    avg_latency = insights["response_characteristics"].get("average_latency_ms", 0)
    if avg_latency > 1000:
        insights["detection_patterns"].append("High latency suggests active DPI processing")
    elif avg_latency > 0 and avg_latency < 100:
        insights["detection_patterns"].append("Low latency suggests hardware-based DPI")

    # Analyze failure mode characteristics
    if dominant_failure == "RST_RECEIVED" or dominant_failure == "MIDDLEBOX_RST_RECEIVED":
        insights["vulnerability_indicators"].append("DPI sends RST - vulnerable to race conditions")
    elif dominant_failure == "TIMEOUT":
        insights["vulnerability_indicators"].append("DPI drops packets - try alternative protocols")
    elif dominant_failure == "TLS_HANDSHAKE_FAILURE":
        insights["vulnerability_indicators"].append(
            "TLS-aware DPI - focus on handshake obfuscation"
        )


def _recommend_dpi_classification(failure_types: Counter) -> str:
    """
    Recommend DPI classification based on failure patterns.

    Args:
        failure_types: Counter of failure types

    Returns:
        Recommended DPI classification string
    """
    if not failure_types:
        return "unknown_dpi_type"

    # Check for specific patterns
    if "RST_RECEIVED" in failure_types and failure_types["RST_RECEIVED"] > 2:
        return "active_rst_injection"
    elif "MIDDLEBOX_RST_RECEIVED" in failure_types and failure_types["MIDDLEBOX_RST_RECEIVED"] > 2:
        return "active_middlebox_rst_injection"
    elif "TIMEOUT" in failure_types and failure_types["TIMEOUT"] > 2:
        return "passive_packet_drop"
    elif "TLS_HANDSHAKE_FAILURE" in failure_types:
        return "tls_aware_dpi"
    else:
        return "unknown_dpi_type"
