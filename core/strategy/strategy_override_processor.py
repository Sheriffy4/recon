from __future__ import annotations

# Файл: core/strategy/strategy_override_processor.py
"""
Strategy override processing utilities.

This module provides reusable functions for processing strategy overrides
to ensure consistency across different engine modes (testing, service).
"""

import logging
from typing import Optional, Dict, Any, Tuple


def process_strategy_override(
    strategy_loader: Any,
    strategy_override: Optional[Dict[str, Any]],
    logger: Optional[logging.Logger] = None,
    mode: str = "default",
) -> Tuple[Optional[Any], bool]:
    """
    Process strategy override using the unified strategy loader.

    This function handles the common pattern of:
    1. Loading and normalizing the strategy
    2. Creating a forced override
    3. Logging the result
    4. Handling errors gracefully

    Args:
        strategy_loader: UnifiedStrategyLoader instance
        strategy_override: Optional strategy override dict or string
        logger: Optional logger instance for logging
        mode: Mode name for logging (e.g., "testing", "service", "default")

    Returns:
        Tuple[Optional[Any], bool]: (processed_override, success)
        - processed_override: The processed override object or None
        - success: True if processing succeeded, False otherwise

    Examples:
        >>> from core.unified_strategy_loader import UnifiedStrategyLoader
        >>> loader = UnifiedStrategyLoader()
        >>> override, success = process_strategy_override(
        ...     loader,
        ...     {"type": "fake", "params": {"ttl": 5}},
        ...     mode="testing"
        ... )
        >>> if success:
        ...     print(f"Override processed: {override}")
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # No override provided
    if not strategy_override:
        return None, True

    try:
        # Check if it's a dict/string that needs processing or a raw strategy
        if isinstance(strategy_override, (str, dict)):
            # Load and normalize the strategy
            normalized_override = strategy_loader.load_strategy(strategy_override)

            # Best-effort validation if loader supports it
            if hasattr(strategy_loader, "validate_strategy"):
                strategy_loader.validate_strategy(normalized_override)

            # Create forced override
            processed_override = strategy_loader.create_forced_override(normalized_override)

            # Log success
            mode_label = f"{mode} mode " if mode != "default" else ""
            logger.info(
                f"🔥 {mode_label.capitalize()}strategy override: " f"{normalized_override.type}"
            )
        else:
            # Raw strategy object - use as-is
            processed_override = strategy_override
            mode_label = f"{mode} mode " if mode != "default" else ""
            logger.info(f"🔥 {mode_label.capitalize()}raw strategy override applied")

        return processed_override, True

    except Exception as e:
        # Log error
        mode_label = f"{mode} mode " if mode != "default" else ""
        logger.error(f"❌ Failed to process {mode_label}override: {e}")

        return None, False


def apply_runtime_filtering_if_enabled(
    engine: Any,
    runtime_filtering_enabled: bool,
    runtime_filter_config: Optional[Dict[str, Any]],
    logger: Optional[logging.Logger] = None,
    mode: str = "default",
) -> bool:
    """
    Apply runtime filtering configuration if enabled.

    This is a common pattern used before starting the engine in different modes.

    Args:
        engine: The bypass engine instance
        runtime_filtering_enabled: Whether runtime filtering is enabled
        runtime_filter_config: Runtime filter configuration dict
        logger: Optional logger instance
        mode: Mode name for logging (e.g., "testing", "service")

    Returns:
        bool: True if filtering was applied or not needed, False on error

    Examples:
        >>> apply_runtime_filtering_if_enabled(
        ...     engine,
        ...     True,
        ...     {"mode": "blacklist", "domains": ["example.com"]},
        ...     mode="testing"
        ... )
        True
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # Runtime filtering not enabled - nothing to do
    if not runtime_filtering_enabled or not runtime_filter_config:
        return True

    try:
        # Apply runtime filtering configuration
        engine.enable_runtime_filtering(runtime_filter_config)

        # Log success
        mode_label = f"for {mode} mode" if mode != "default" else ""
        logger.info(f"Applied runtime filtering configuration {mode_label}")

        return True

    except Exception as e:
        logger.error(f"Failed to apply runtime filtering: {e}")
        return False


def validate_and_process_strategy_override(
    strategy_loader: Any,
    strategy_override: Optional[Dict[str, Any]],
    engine: Any,
    runtime_filtering_enabled: bool,
    runtime_filter_config: Optional[Dict[str, Any]],
    logger: Optional[logging.Logger] = None,
    mode: str = "default",
) -> Tuple[Optional[Any], bool]:
    """
    Combined function that processes strategy override and applies runtime filtering.

    This is the most common pattern used when starting the engine.

    Args:
        strategy_loader: UnifiedStrategyLoader instance
        strategy_override: Optional strategy override
        engine: The bypass engine instance
        runtime_filtering_enabled: Whether runtime filtering is enabled
        runtime_filter_config: Runtime filter configuration
        logger: Optional logger instance
        mode: Mode name for logging

    Returns:
        Tuple[Optional[Any], bool]: (processed_override, success)

    Examples:
        >>> override, success = validate_and_process_strategy_override(
        ...     loader, strategy_override, engine,
        ...     True, filter_config, mode="testing"
        ... )
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # Process strategy override
    processed_override, override_success = process_strategy_override(
        strategy_loader, strategy_override, logger, mode
    )

    # Apply runtime filtering
    filtering_success = apply_runtime_filtering_if_enabled(
        engine, runtime_filtering_enabled, runtime_filter_config, logger, mode
    )

    # Overall success if both operations succeeded (or were not needed)
    overall_success = override_success and filtering_success

    return processed_override, overall_success
