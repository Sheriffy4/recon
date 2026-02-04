"""
Failure Classification Module

Classifies failure types based on test results and fingerprint data.
Provides detailed categorization of DPI bypass failures.
"""

from typing import Any


def classify_failure_type(result: Any, fingerprint_aware: bool = True) -> str:
    """
    Classify the type of failure based on EffectivenessResult.

    Args:
        result: EffectivenessResult object with test results
        fingerprint_aware: Whether to use fingerprint data for enhanced classification

    Returns:
        String classification of failure type
    """
    # Check baseline vs bypass results
    if not result.baseline_success and not result.bypass_success:
        return "CONNECTION_REFUSED"

    if result.baseline_success and not result.bypass_success:
        # Bypass made things worse
        if hasattr(result, "bypass_error") and result.bypass_error:
            error_lower = result.bypass_error.lower()

            if "timeout" in error_lower:
                return "TIMEOUT"
            elif "reset" in error_lower or "rst" in error_lower:
                # Enhanced: Check for more specific RST cause from fingerprint
                if fingerprint_aware and _is_middlebox_rst(result):
                    return "MIDDLEBOX_RST_RECEIVED"
                return "RST_RECEIVED"
            elif "handshake" in error_lower:
                return "TLS_HANDSHAKE_FAILURE"

        return "BYPASS_DEGRADATION"

    if not result.baseline_success:
        if hasattr(result, "baseline_error") and result.baseline_error:
            error_lower = result.baseline_error.lower()

            if "timeout" in error_lower:
                return "TIMEOUT_ON_SYN"
            elif "refused" in error_lower:
                return "CONNECTION_REFUSED"

        return "BASELINE_FAILURE"

    # Low effectiveness despite successful connections
    if result.effectiveness_score < 0.2:
        return "INEFFECTIVE_BYPASS"

    return "UNKNOWN_FAILURE"


def _is_middlebox_rst(result: Any) -> bool:
    """
    Check if RST packet came from a middlebox based on fingerprint analysis.

    Args:
        result: EffectivenessResult with potential fingerprint data

    Returns:
        True if RST is identified as coming from middlebox
    """
    if not hasattr(result, "fingerprint"):
        return False

    fingerprint = result.fingerprint
    if not fingerprint or not isinstance(fingerprint, dict):
        return False

    return fingerprint.get("rst_source_analysis") == "middlebox"
