#!/usr/bin/env python3
"""
Domain Strategy Engine Initialization Utilities

This module provides utilities for initializing domain-based strategy engine
components, including feature flag checking, environment variable handling,
and domain rule registry setup.

Extracted from base_engine.py to reduce god class complexity and improve testability.
"""

import os
import logging
from typing import Optional, Tuple, Any

# Try to import domain strategy components (may not be available)
try:
    from core.bypass.engine.domain_strategy_engine import DomainStrategyEngine
    from core.bypass.engine.domain_rule_registry import DomainRuleRegistry
except ImportError:
    DomainStrategyEngine = None
    DomainRuleRegistry = None


def initialize_domain_strategy_engine(
    logger: logging.Logger,
    strategy_failure_threshold: int = 5,
    is_domain_based_filtering_enabled: Optional[callable] = None,
) -> Tuple[Optional[Any], bool]:
    """
    Initialize domain-based strategy engine components.

    This function checks feature flags and environment variables to determine
    if domain-based filtering should be enabled, then loads domain rules
    from configuration and initializes the domain strategy engine.

    Args:
        logger: Logger instance for status messages
        strategy_failure_threshold: Revalidation threshold for domain strategy engine
        is_domain_based_filtering_enabled: Optional feature flag check function

    Returns:
        Tuple of (domain_strategy_engine, use_domain_based_filtering):
        - domain_strategy_engine: Initialized DomainStrategyEngine or None
        - use_domain_based_filtering: Boolean indicating if enabled

    Examples:
        >>> logger = logging.getLogger("test")
        >>> engine, enabled = initialize_domain_strategy_engine(logger)
        >>> if enabled:
        ...     print("Domain-based filtering active")
    """
    # Check environment variable first (highest priority)
    env_enabled = os.getenv("USE_DOMAIN_BASED_FILTERING", "").lower() in (
        "true",
        "1",
        "yes",
        "on",
    )

    # Check feature flag
    feature_flag_enabled = False
    if is_domain_based_filtering_enabled:
        try:
            feature_flag_enabled = is_domain_based_filtering_enabled()
        except Exception as e:
            logger.warning("Failed to check domain-based filtering feature flag: %s", e)

    # Determine if domain-based filtering should be enabled
    should_enable = env_enabled or feature_flag_enabled

    if not should_enable:
        logger.info("🔄 Domain-based filtering disabled (using legacy IP-based filtering)")
        logger.info("   To enable: set USE_DOMAIN_BASED_FILTERING=true " "or enable feature flag")
        return None, False

    # Check if domain strategy components are available
    if not DomainStrategyEngine or not DomainRuleRegistry:
        logger.error(
            "❌ Domain strategy engine components not available, "
            "falling back to legacy IP-based filtering"
        )
        logger.error("   This may indicate missing domain engine modules")
        return None, False

    try:
        # Initialize domain rule registry
        domain_registry = DomainRuleRegistry("domain_rules.json")

        # Get domain rules and default strategy
        domain_rules = domain_registry.get_all_domain_rules()
        default_strategy = domain_registry.get_default_strategy()

        # Initialize domain strategy engine
        # Use revalidation_threshold for fast auto-recovery
        domain_strategy_engine = DomainStrategyEngine(
            domain_rules,
            default_strategy,
            revalidation_threshold=strategy_failure_threshold,
        )

        logger.info(
            f"✅ DomainStrategyEngine revalidation_threshold "
            f"set to {strategy_failure_threshold}"
        )

        # Log which method enabled domain-based filtering
        if env_enabled:
            logger.info("✅ Domain-based filtering enabled via environment variable")
        else:
            logger.info("✅ Domain-based filtering enabled via feature flag")

        logger.info(
            f"✅ Domain strategy engine initialized " f"with {len(domain_rules)} domain rules"
        )

        return domain_strategy_engine, True

    except Exception as e:
        logger.error("❌ Failed to initialize domain strategy engine: %s", e)
        logger.error("   Falling back to legacy IP-based filtering")
        return None, False
