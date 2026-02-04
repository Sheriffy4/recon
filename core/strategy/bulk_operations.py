# Файл: core/strategy/bulk_operations.py
"""
Bulk strategy operations for applying multiple strategies efficiently.

This module provides functions for bulk application of strategies with
forced override, tracking, and comprehensive logging.
"""

import logging
import time
from typing import Dict, Any, Set, Optional, Union

LOG = logging.getLogger(__name__)


def apply_strategies_bulk(
    strategy_map: Dict[str, Union[str, Dict[str, Any]]],
    target_ips: Optional[Set[str]],
    strategy_loader: Any,
    ensure_testing_mode_compatibility_func: callable,
    lock: Any,
    forced_override_count_ref: Dict[str, int],  # Mutable reference
    strategy_applications_ref: Dict[str, list],  # Mutable reference
    config: Any,
    logger: Optional[logging.Logger] = None,
) -> Dict[str, bool]:
    """
    Apply multiple strategies in bulk with forced override.

    This function processes a strategy map (like service mode) but ensures
    all strategies are applied with forced override (like testing mode).

    Args:
        strategy_map: Map of domain/IP to strategy configuration
        target_ips: Optional set of target IPs to filter by
        strategy_loader: UnifiedStrategyLoader instance
        ensure_testing_mode_compatibility_func: Function to ensure compatibility
        lock: Threading lock for safe access
        forced_override_count_ref: Mutable dict with 'count' key
        strategy_applications_ref: Dict of strategy applications by target
        config: Engine configuration
        logger: Optional logger instance

    Returns:
        Dict mapping keys to success status

    Examples:
        >>> strategy_map = {
        ...     "example.com": "--dpi-desync=split",
        ...     "test.com": {"type": "fake", "ttl": 1}
        ... }
        >>> results = apply_strategies_bulk(
        ...     strategy_map=strategy_map,
        ...     target_ips=None,
        ...     strategy_loader=loader,
        ...     ensure_testing_mode_compatibility_func=compat_func,
        ...     lock=threading.Lock(),
        ...     forced_override_count_ref={'count': 0},
        ...     strategy_applications_ref={},
        ...     config=config,
        ...     logger=logger
        ... )
        >>> all(results.values())  # Check if all succeeded
        True
    """
    if logger is None:
        logger = LOG

    results = {}

    logger.info(f"🚀 Applying {len(strategy_map)} strategies in bulk with forced override")

    for key, strategy_input in strategy_map.items():
        try:
            # Skip if target_ips filter is provided and key is not in it
            if target_ips and key not in target_ips and key != "default":
                continue

            # Load and normalize strategy
            normalized_strategy = strategy_loader.load_strategy(strategy_input)

            # Validate strategy
            strategy_loader.validate_strategy(normalized_strategy)

            # Create forced override (CRITICAL)
            forced_config = strategy_loader.create_forced_override(normalized_strategy)

            # Ensure testing mode compatibility
            forced_config = ensure_testing_mode_compatibility_func(forced_config)

            # Track application
            with lock:
                forced_override_count_ref["count"] += 1
                if key not in strategy_applications_ref:
                    strategy_applications_ref[key] = []
                strategy_applications_ref[key].append(
                    {
                        "strategy_type": normalized_strategy.type,
                        "timestamp": time.time(),
                        "forced_override": True,
                        "bulk_application": True,
                    }
                )

            results[key] = True

            if config.log_all_strategies:
                logger.info(
                    f"✅ Bulk applied forced strategy for {key}: {normalized_strategy.type}"
                )

        except Exception as e:
            logger.error(f"❌ Failed to apply bulk strategy for {key}: {e}")
            results[key] = False

    successful = sum(1 for success in results.values() if success)
    logger.info(
        f"📊 Bulk application complete: {successful}/{len(results)} strategies applied successfully"
    )

    return results


def set_strategy_override(
    strategy_input: Union[str, Dict[str, Any]],
    strategy_loader: Any,
    ensure_testing_mode_compatibility_func: callable,
    normalize_strategy_dict_func: callable,
    engine: Any,
    lock: Any,
    forced_override_count_ref: Dict[str, int],
    logger: Optional[logging.Logger] = None,
) -> None:
    """
    Set a global strategy override with forced application.

    Args:
        strategy_input: Strategy to override with
        strategy_loader: UnifiedStrategyLoader instance
        ensure_testing_mode_compatibility_func: Function to ensure compatibility
        normalize_strategy_dict_func: Function to normalize strategy dict
        engine: Underlying engine instance
        lock: Threading lock for safe access
        forced_override_count_ref: Mutable dict with 'count' key
        logger: Optional logger instance

    Raises:
        Exception: If strategy override fails

    Examples:
        >>> set_strategy_override(
        ...     strategy_input="--dpi-desync=split",
        ...     strategy_loader=loader,
        ...     ensure_testing_mode_compatibility_func=compat_func,
        ...     normalize_strategy_dict_func=normalize_func,
        ...     engine=engine,
        ...     lock=threading.Lock(),
        ...     forced_override_count_ref={'count': 0},
        ...     logger=logger
        ... )
    """
    if logger is None:
        logger = LOG

    try:
        # Load and normalize strategy
        normalized_strategy = strategy_loader.load_strategy(strategy_input)

        # Validate strategy
        strategy_loader.validate_strategy(normalized_strategy)

        # Create forced override (CRITICAL)
        forced_config = strategy_loader.create_forced_override(normalized_strategy)
        forced_config = normalize_strategy_dict_func(forced_config)
        forced_config = ensure_testing_mode_compatibility_func(forced_config)

        # Apply to engine
        engine.set_strategy_override(forced_config)

        # Track override
        with lock:
            forced_override_count_ref["count"] += 1

        logger.info(f"🔥 Global strategy override set: {normalized_strategy.type} (forced)")

    except Exception as e:
        logger.error(f"❌ Failed to set strategy override: {e}")
        raise Exception(f"Strategy override failed: {e}")


def clear_strategy_override(engine: Any, logger: Optional[logging.Logger] = None) -> None:
    """
    Clear the global strategy override in the underlying engine.

    Args:
        engine: Underlying engine instance
        logger: Optional logger instance

    Examples:
        >>> clear_strategy_override(engine=engine, logger=logger)
    """
    if logger is None:
        logger = LOG

    engine.clear_strategy_override()
    logger.debug("🔄 Global strategy override cleared")
