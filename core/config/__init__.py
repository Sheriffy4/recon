"""
Configuration management module for DPI bypass strategies.

This module provides enhanced configuration management with support for:
- Wildcard patterns in domain rules
- Strategy priorities and metadata
- Backward compatibility with legacy formats
- Configuration validation and error handling
"""

from .strategy_config_manager import (
    StrategyConfigManager,
    StrategyConfiguration,
    StrategyRule,
    StrategyMetadata,
    ConfigurationError,
)

__all__ = [
    "StrategyConfigManager",
    "StrategyConfiguration",
    "StrategyRule",
    "StrategyMetadata",
    "ConfigurationError",
]
