# Файл: core/unified/telemetry.py
"""
Unified telemetry and mode management utilities.

This module provides reusable functions for enabling/disabling various modes
(debug, testing, discovery) with consistent logging and state management.
"""

import logging
from typing import Any, Optional, Dict, Callable


def logging_enable_mode(
    obj: Any,
    mode_name: str,
    flag_attr: str,
    logger: Optional[logging.Logger] = None,
    emoji: str = "🔍",
    additional_setup: Optional[Callable[[Any], None]] = None,
    config_updates: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Enable a mode with consistent logging and state management.

    Args:
        obj: Object to modify
        mode_name: Name of the mode (e.g., "debug", "testing", "discovery")
        flag_attr: Name of the flag attribute to set to True
        logger: Optional logger instance
        emoji: Emoji for log message (default: "🔍")
        additional_setup: Optional function to call for additional setup
        config_updates: Optional dict of config attributes to update

    Examples:
        >>> logging_enable_mode(
        ...     engine, "debug", "_debug_mode",
        ...     emoji="🔍",
        ...     config_updates={"debug": True, "verbose": True}
        ... )
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # Set the flag
    setattr(obj, flag_attr, True)

    # Update config if provided
    if config_updates and hasattr(obj, "config"):
        for key, value in config_updates.items():
            setattr(obj.config, key, value)

    # Call additional setup if provided
    if additional_setup:
        additional_setup(obj)

    # Log the change
    logger.info(f"{emoji} {mode_name.capitalize()} mode enabled")


def logging_disable_mode(
    obj: Any,
    mode_name: str,
    flag_attr: str,
    logger: Optional[logging.Logger] = None,
    emoji: str = "🔇",
    additional_cleanup: Optional[Callable[[Any], None]] = None,
    config_updates: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Disable a mode with consistent logging and state management.

    Args:
        obj: Object to modify
        mode_name: Name of the mode (e.g., "debug", "testing", "discovery")
        flag_attr: Name of the flag attribute to set to False
        logger: Optional logger instance
        emoji: Emoji for log message (default: "🔇")
        additional_cleanup: Optional function to call for cleanup
        config_updates: Optional dict of config attributes to update

    Examples:
        >>> logging_disable_mode(
        ...     engine, "debug", "_debug_mode",
        ...     emoji="🔇",
        ...     config_updates={"debug": False, "verbose": False}
        ... )
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # Set the flag
    setattr(obj, flag_attr, False)

    # Update config if provided
    if config_updates and hasattr(obj, "config"):
        for key, value in config_updates.items():
            setattr(obj.config, key, value)

    # Call additional cleanup if provided
    if additional_cleanup:
        additional_cleanup(obj)

    # Log the change
    logger.info(f"{emoji} {mode_name.capitalize()} mode disabled")


def logging_enable_debug_mode(
    obj: Any, logger: Optional[logging.Logger] = None, set_log_level: bool = True
) -> None:
    """
    Enable debug mode with comprehensive logging.

    Args:
        obj: Object with config attribute
        logger: Optional logger instance
        set_log_level: Whether to set logger level to DEBUG

    Examples:
        >>> logging_enable_debug_mode(engine, logger=engine.logger)
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # Additional setup for debug mode
    def setup_debug(obj):
        if set_log_level and hasattr(logger, "setLevel"):
            logger.setLevel(logging.DEBUG)

    logging_enable_mode(
        obj,
        "debug",
        "_debug_mode",  # Placeholder, actual flag may vary
        logger=logger,
        emoji="🔍",
        additional_setup=setup_debug,
        config_updates={
            "debug": True,
            "enable_diagnostics": True,
            "log_all_strategies": True,
            "track_forced_override": True,
        },
    )

    # Additional message
    logger.info("🔍 Debug mode enabled - comprehensive logging active")


def logging_disable_debug_mode(
    obj: Any, logger: Optional[logging.Logger] = None, set_log_level: bool = True
) -> None:
    """
    Disable debug mode and return to essential logging.

    Args:
        obj: Object with config attribute
        logger: Optional logger instance
        set_log_level: Whether to set logger level to INFO

    Examples:
        >>> logging_disable_debug_mode(engine, logger=engine.logger)
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # Additional cleanup for debug mode
    def cleanup_debug(obj):
        if set_log_level and hasattr(logger, "setLevel"):
            logger.setLevel(logging.INFO)

    logging_disable_mode(
        obj,
        "debug",
        "_debug_mode",  # Placeholder
        logger=logger,
        emoji="🔇",
        additional_cleanup=cleanup_debug,
        config_updates={"debug": False, "enable_diagnostics": False, "log_all_strategies": False},
    )

    # Additional message
    logger.info("🔇 Debug mode disabled - essential logging only")


def logging_enable_testing_mode(
    obj: Any, logger: Optional[logging.Logger] = None, message: Optional[str] = None
) -> None:
    """
    Enable testing mode to prevent domain rule substitution.

    Args:
        obj: Object to modify
        logger: Optional logger instance
        message: Optional custom message

    Examples:
        >>> logging_enable_testing_mode(engine, logger=engine.logger)
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    setattr(obj, "_testing_mode", True)

    msg = message or "Testing mode enabled - domain rules will not override test strategies"
    logger.info(f"🧪 {msg}")


def logging_disable_testing_mode(
    obj: Any, logger: Optional[logging.Logger] = None, message: Optional[str] = None
) -> None:
    """
    Disable testing mode.

    Args:
        obj: Object to modify
        logger: Optional logger instance
        message: Optional custom message

    Examples:
        >>> logging_disable_testing_mode(engine, logger=engine.logger)
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    setattr(obj, "_testing_mode", False)

    msg = message or "Testing mode disabled"
    logger.info(f"🧪 {msg}")


def logging_enable_discovery_mode(
    engine: Any,
    logger: Optional[logging.Logger] = None,
    delegate_to_attr: str = "engine",
    message: Optional[str] = None,
) -> None:
    """
    Enable discovery mode - delegates to underlying engine.

    Args:
        engine: Engine object (wrapper)
        logger: Optional logger instance
        delegate_to_attr: Attribute name of underlying engine
        message: Optional custom message

    Examples:
        >>> logging_enable_discovery_mode(
        ...     unified_engine,
        ...     logger=unified_engine.logger,
        ...     delegate_to_attr='engine'
        ... )
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # Get underlying engine
    underlying_engine = getattr(engine, delegate_to_attr, None)

    if underlying_engine and hasattr(underlying_engine, "enable_discovery_mode"):
        underlying_engine.enable_discovery_mode()
        msg = message or "Discovery mode enabled"
        logger.info(f"🔍 {msg}")
    else:
        logger.warning("⚠️ Underlying engine does not support discovery mode")


def logging_disable_discovery_mode(
    engine: Any,
    logger: Optional[logging.Logger] = None,
    delegate_to_attr: str = "engine",
    message: Optional[str] = None,
) -> None:
    """
    Disable discovery mode - delegates to underlying engine.

    Args:
        engine: Engine object (wrapper)
        logger: Optional logger instance
        delegate_to_attr: Attribute name of underlying engine
        message: Optional custom message

    Examples:
        >>> logging_disable_discovery_mode(
        ...     unified_engine,
        ...     logger=unified_engine.logger,
        ...     delegate_to_attr='engine'
        ... )
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # Get underlying engine
    underlying_engine = getattr(engine, delegate_to_attr, None)

    if underlying_engine and hasattr(underlying_engine, "disable_discovery_mode"):
        underlying_engine.disable_discovery_mode()
        msg = message or "Discovery mode disabled"
        logger.info(f"🔍 {msg}")
    else:
        logger.warning("⚠️ Underlying engine does not support discovery mode")


def get_telemetry_snapshot(
    engine: Any,
    lock: Any,
    forced_override_count: int,
    strategy_applications: Dict[str, Any],
    running: bool,
    start_time_mono: Optional[float],
    start_time: Optional[float],
    config: Any,
) -> Dict[str, Any]:
    """
    Get comprehensive telemetry data including unified engine metrics.

    Args:
        engine: Underlying engine instance
        lock: Threading lock for safe access
        forced_override_count: Number of forced overrides applied
        strategy_applications: Dict of strategy applications by target
        running: Whether engine is running
        start_time_mono: Monotonic start time
        start_time: Wall clock start time
        config: Engine configuration

    Returns:
        Dictionary containing telemetry data with unified engine metrics

    Examples:
        >>> telemetry = get_telemetry_snapshot(
        ...     engine=self.engine,
        ...     lock=self._lock,
        ...     forced_override_count=self._forced_override_count,
        ...     strategy_applications=self._strategy_applications,
        ...     running=self._running,
        ...     start_time_mono=self._start_time_mono,
        ...     start_time=self._start_time,
        ...     config=self.config
        ... )
        >>> print(telemetry['unified_engine']['uptime_seconds'])
    """
    import time

    # Get base telemetry from underlying engine
    base_telemetry = engine.get_telemetry_snapshot()

    # Add unified engine specific metrics
    with lock:
        unified_metrics = {
            "unified_engine": {
                "forced_override_count": forced_override_count,
                "strategy_applications": dict(strategy_applications),
                "running": running,
                "uptime_seconds": (
                    (time.monotonic() - start_time_mono)
                    if start_time_mono is not None
                    else (time.time() - start_time if start_time else 0)
                ),
                "config": {
                    "force_override": config.force_override,
                    "enable_diagnostics": config.enable_diagnostics,
                    "debug": config.debug,
                },
            }
        }

    # Merge telemetry data
    base_telemetry.update(unified_metrics)
    return base_telemetry


def report_high_level_outcome(
    engine: Any, target_ip: str, success: bool, config: Any, logger: Optional[logging.Logger] = None
) -> None:
    """
    Report high-level outcome for a target with optional diagnostics logging.

    Args:
        engine: Underlying engine instance
        target_ip: Target IP address
        success: Whether the connection was successful
        config: Engine configuration
        logger: Optional logger instance

    Examples:
        >>> report_high_level_outcome(
        ...     engine=self.engine,
        ...     target_ip="1.2.3.4",
        ...     success=True,
        ...     config=self.config,
        ...     logger=self.logger
        ... )
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # Report to underlying engine
    engine.report_high_level_outcome(target_ip, success)

    # Log diagnostics if enabled
    if config.enable_diagnostics:
        outcome = "SUCCESS" if success else "FAILURE"
        logger.debug(f"📊 High-level outcome for {target_ip}: {outcome}")


def log_strategy_application(
    strategy_type: str,
    target: str,
    params: Dict[str, Any],
    success: bool,
    details: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
) -> None:
    """
    Log strategy application with structured information.

    Args:
        strategy_type: Type of strategy applied
        target: Target IP or domain
        params: Strategy parameters
        success: Whether application was successful
        details: Optional additional details
        logger: Optional logger instance

    Examples:
        >>> log_strategy_application(
        ...     strategy_type="fake",
        ...     target="example.com",
        ...     params={"ttl": 1, "fooling": "badsum"},
        ...     success=True,
        ...     details="Applied successfully"
        ... )
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    status_emoji = "✅" if success else "❌"
    status_text = "SUCCESS" if success else "FAILED"

    logger.info(
        f"{status_emoji} Strategy Application {status_text}: "
        f"type={strategy_type}, target={target}"
    )

    if logger.level <= logging.DEBUG:
        logger.debug(f"   Parameters: {params}")
        if details:
            logger.debug(f"   Details: {details}")


def track_forced_override_usage(
    strategy_type: str,
    target: str,
    forced_override_count: int,
    logger: Optional[logging.Logger] = None,
) -> None:
    """
    Track and log forced override usage.

    Args:
        strategy_type: Type of strategy being forced
        target: Target IP or domain
        forced_override_count: Current count of forced overrides
        logger: Optional logger instance

    Examples:
        >>> track_forced_override_usage(
        ...     strategy_type="fake",
        ...     target="example.com",
        ...     forced_override_count=5
        ... )
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    logger.info(
        f"🔥 Forced override #{forced_override_count}: " f"type={strategy_type}, target={target}"
    )
    logger.debug(f"   Total forced overrides applied: {forced_override_count}")


def calculate_telemetry_delta(
    baseline: Dict[str, Any], final: Dict[str, Any], logger: Optional[logging.Logger] = None
) -> Dict[str, Any]:
    """
    Calculate the difference between baseline and final telemetry snapshots.

    Args:
        baseline: Baseline telemetry snapshot
        final: Final telemetry snapshot
        logger: Optional logger instance

    Returns:
        Dict with telemetry differences (segments_sent, fake_packets_sent, modified_packets_sent)

    Examples:
        >>> baseline = {"aggregate": {"segments_sent": 10, "fake_packets_sent": 5}}
        >>> final = {"aggregate": {"segments_sent": 25, "fake_packets_sent": 15}}
        >>> delta = calculate_telemetry_delta(baseline, final)
        >>> delta['segments_sent']
        15
        >>> delta['fake_packets_sent']
        10
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    try:
        delta = {}

        # Calculate aggregate differences
        baseline_agg = baseline.get("aggregate", {})
        final_agg = final.get("aggregate", {})

        delta["segments_sent"] = final_agg.get("segments_sent", 0) - baseline_agg.get(
            "segments_sent", 0
        )
        delta["fake_packets_sent"] = final_agg.get("fake_packets_sent", 0) - baseline_agg.get(
            "fake_packets_sent", 0
        )
        delta["modified_packets_sent"] = final_agg.get(
            "modified_packets_sent", 0
        ) - baseline_agg.get("modified_packets_sent", 0)

        return delta

    except Exception as e:
        logger.warning(f"Failed to calculate telemetry delta: {e}")
        return {}


def get_diagnostics_report(
    lock: Any,
    start_time: Optional[float],
    running: bool,
    forced_override_count: int,
    strategy_applications: Dict[str, list],
    config: Any,
    get_telemetry_snapshot_func: callable,
    logger: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
    """
    Generate comprehensive diagnostics report with engine statistics.

    Args:
        lock: Threading lock for safe access
        start_time: Engine start time (wall clock)
        running: Whether engine is running
        forced_override_count: Number of forced overrides applied
        strategy_applications: Dict of strategy applications by target
        config: Engine configuration
        get_telemetry_snapshot_func: Function to get telemetry snapshot
        logger: Optional logger instance

    Returns:
        Dict with detailed diagnostics information including:
        - unified_engine_diagnostics: Engine-specific metrics
        - engine_telemetry: Underlying engine telemetry
        - timestamp: Report generation time

    Examples:
        >>> report = get_diagnostics_report(
        ...     lock=threading.Lock(),
        ...     start_time=time.time(),
        ...     running=True,
        ...     forced_override_count=5,
        ...     strategy_applications={},
        ...     config=config,
        ...     get_telemetry_snapshot_func=lambda: {},
        ...     logger=logger
        ... )
        >>> 'unified_engine_diagnostics' in report
        True
        >>> 'engine_telemetry' in report
        True
    """
    import time

    if logger is None:
        logger = logging.getLogger(__name__)

    with lock:
        uptime = time.time() - start_time if start_time else 0

        # Calculate strategy type distribution
        strategy_types = {}
        for applications in strategy_applications.values():
            for app in applications:
                strategy_type = app.get("strategy_type", "unknown")
                strategy_types[strategy_type] = strategy_types.get(strategy_type, 0) + 1

        # Calculate success rates
        total_tests = 0
        successful_tests = 0
        for applications in strategy_applications.values():
            for app in applications:
                if "success" in app:
                    total_tests += 1
                    if app["success"]:
                        successful_tests += 1

        success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0

    # Get engine telemetry
    engine_telemetry = get_telemetry_snapshot_func()

    report = {
        "unified_engine_diagnostics": {
            "uptime_seconds": uptime,
            "running": running,
            "forced_override_count": forced_override_count,
            "strategy_applications_count": sum(
                len(apps) for apps in strategy_applications.values()
            ),
            "unique_targets": len(strategy_applications),
            "strategy_type_distribution": strategy_types,
            "test_success_rate": success_rate,
            "total_tests": total_tests,
            "successful_tests": successful_tests,
            "configuration": {
                "force_override": config.force_override,
                "enable_diagnostics": config.enable_diagnostics,
                "log_all_strategies": config.log_all_strategies,
                "track_forced_override": config.track_forced_override,
                "debug": config.debug,
            },
        },
        "engine_telemetry": engine_telemetry,
        "timestamp": time.time(),
    }

    return report


def log_diagnostics_summary(
    get_diagnostics_report_func: callable, logger: Optional[logging.Logger] = None
) -> None:
    """
    Log a summary of diagnostics information.

    Args:
        get_diagnostics_report_func: Function to get diagnostics report
        logger: Optional logger instance

    Examples:
        >>> log_diagnostics_summary(
        ...     get_diagnostics_report_func=lambda: {
        ...         "unified_engine_diagnostics": {
        ...             "uptime_seconds": 120.5,
        ...             "forced_override_count": 5,
        ...             "unique_targets": 3
        ...         }
        ...     },
        ...     logger=logger
        ... )
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    report = get_diagnostics_report_func()
    diag = report["unified_engine_diagnostics"]

    logger.info("📊 UnifiedBypassEngine Diagnostics Summary:")
    logger.info(f"   Uptime: {diag['uptime_seconds']:.2f} seconds")
    logger.info(f"   Forced overrides applied: {diag['forced_override_count']}")
    logger.info(f"   Unique targets: {diag['unique_targets']}")
    logger.info(f"   Total strategy applications: {diag['strategy_applications_count']}")

    if diag["total_tests"] > 0:
        logger.info(f"   Test success rate: {diag['test_success_rate']:.1f}%")
        logger.info(f"   Tests: {diag['successful_tests']}/{diag['total_tests']} successful")
