# File: core/testing/connection_tester.py
"""
Connection testing utilities for strategy validation.

This module provides focused functions for testing strategies in testing mode,
extracted from UnifiedBypassEngine to reduce method complexity.
"""

import time
import logging
from typing import Dict, Any, Optional, Union, Tuple

LOG = logging.getLogger("connection_tester")


def prepare_strategy_for_testing(
    strategy_loader,
    strategy_input: Union[str, Dict[str, Any]],
    ensure_compatibility_func,
    logger,
) -> Tuple[Any, Dict[str, Any]]:
    """
    Load, normalize, and prepare strategy for testing.

    Args:
        strategy_loader: UnifiedStrategyLoader instance
        strategy_input: Strategy configuration (string or dict)
        ensure_compatibility_func: Function to ensure testing mode compatibility
        logger: Logger instance

    Returns:
        Tuple of (normalized_strategy, forced_config)

    Raises:
        Exception: If strategy loading or validation fails
    """
    # Step 1: Load and normalize strategy (as in testing mode)
    normalized_strategy = strategy_loader.load_strategy(strategy_input)

    # Step 2: Validate strategy (as in testing mode)
    strategy_loader.validate_strategy(normalized_strategy)

    # Step 3: Create forced override configuration (CRITICAL)
    forced_config = strategy_loader.create_forced_override(normalized_strategy)
    forced_config = ensure_compatibility_func(forced_config)

    logger.info(f"🧪 Prepared strategy for testing: {normalized_strategy.type}")

    return normalized_strategy, forced_config


def apply_strategy_to_engine(
    engine,
    forced_config: Dict[str, Any],
    logger,
) -> Dict[str, Any]:
    """
    Apply strategy to engine with forced override and capture baseline telemetry.

    Args:
        engine: Bypass engine instance
        forced_config: Forced override configuration
        logger: Logger instance

    Returns:
        Baseline telemetry snapshot
    """
    # Step 4: Apply strategy to engine with forced override
    engine.set_strategy_override(forced_config)

    # Set testing mode for packet sender (Requirement 9.1)
    if hasattr(engine, "_packet_sender") and engine._packet_sender:
        engine._packet_sender.set_mode("testing")
        logger.debug("📊 Set PacketSender to TESTING mode")

    # Get baseline telemetry for comparison
    baseline_telemetry = engine.get_telemetry_snapshot()

    return baseline_telemetry


def reset_engine_to_production_mode(engine, logger):
    """
    Reset engine to production mode after testing.

    Args:
        engine: Bypass engine instance
        logger: Logger instance
    """
    if hasattr(engine, "_packet_sender") and engine._packet_sender:
        engine._packet_sender.set_mode("production")
        logger.debug("📊 Reset PacketSender to PRODUCTION mode")


def build_test_result(
    test_success: bool,
    reason: Optional[str],
    normalized_strategy,
    forced_config: Dict[str, Any],
    target_ip: str,
    domain: Optional[str],
    test_duration: float,
    timeout: float,
    baseline_telemetry: Dict[str, Any],
    final_telemetry: Dict[str, Any],
    telemetry_delta_func,
    test_start_wall: float,
) -> Dict[str, Any]:
    """
    Build comprehensive test result dictionary.

    Args:
        test_success: Whether test succeeded
        reason: Failure reason (if any)
        normalized_strategy: Normalized strategy object
        forced_config: Forced override configuration
        target_ip: Target IP address
        domain: Domain name (optional)
        test_duration: Test duration in seconds
        timeout: Timeout value in seconds
        baseline_telemetry: Baseline telemetry snapshot
        final_telemetry: Final telemetry snapshot
        telemetry_delta_func: Function to calculate telemetry delta
        test_start_wall: Wall clock test start time

    Returns:
        Dictionary with test results
    """
    timeout_ms = float(timeout) * 1000.0
    execution_time_ms = test_duration * 1000.0
    is_timeout = (not test_success) and ("timeout" in (reason or "").lower())

    result = {
        "success": test_success,
        "strategy_type": normalized_strategy.type,
        "strategy_params": forced_config.get("params", {}),
        "target_ip": target_ip,
        "domain": domain,
        "test_duration_ms": test_duration * 1000,
        # Standardized timing fields (do not remove legacy fields)
        "execution_time_ms": execution_time_ms,
        "timeout_ms": timeout_ms,
        "is_timeout": bool(is_timeout),
        "forced_override": True,
        "no_fallbacks": forced_config.get("no_fallbacks", False),
        "telemetry_delta": telemetry_delta_func(baseline_telemetry, final_telemetry),
        "timestamp": test_start_wall,
    }

    # Add error reason if test failed
    if not test_success:
        result["error"] = reason

    return result


def build_error_result(
    error: Exception,
    target_ip: str,
    domain: Optional[str],
    test_start: float,
    timeout: float,
    test_start_wall: float,
) -> Dict[str, Any]:
    """
    Build error result dictionary when test fails with exception.

    Args:
        error: Exception that occurred
        target_ip: Target IP address
        domain: Domain name (optional)
        test_start: Monotonic test start time
        timeout: Timeout value in seconds
        test_start_wall: Wall clock test start time

    Returns:
        Dictionary with error details
    """
    timeout_ms = float(timeout) * 1000.0
    is_timeout = "timeout" in str(error).lower()
    execution_time_ms = (time.monotonic() - test_start) * 1000

    return {
        "success": False,
        "error": str(error),
        "target_ip": target_ip,
        "domain": domain,
        "test_duration_ms": execution_time_ms,
        # Standardized timing fields (do not remove legacy fields)
        "execution_time_ms": execution_time_ms,
        "timeout_ms": timeout_ms,
        "is_timeout": bool(is_timeout),
        "timestamp": test_start_wall,
    }


def track_strategy_application(
    strategy_applications: Dict[str, list],
    lock,
    domain: Optional[str],
    target_ip: str,
    normalized_strategy,
    test_start: float,
    test_success: bool,
):
    """
    Track strategy application for monitoring and diagnostics.

    Args:
        strategy_applications: Dictionary tracking strategy applications
        lock: Threading lock for thread safety
        domain: Domain name (optional)
        target_ip: Target IP address
        normalized_strategy: Normalized strategy object
        test_start: Monotonic test start time
        test_success: Whether test succeeded
    """
    with lock:
        key = domain or target_ip
        if key not in strategy_applications:
            strategy_applications[key] = []
        strategy_applications[key].append(
            {
                "strategy_type": normalized_strategy.type,
                "timestamp": test_start,
                "forced_override": True,
                "test_mode": True,
                "success": test_success,
            }
        )
