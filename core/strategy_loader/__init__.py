# Файл: core/strategy_loader/__init__.py
"""
Strategy Loader Package

This package provides modular components for loading, parsing, normalizing,
and validating DPI bypass strategies across different formats.

Modules:
- registry_integration: AttackRegistry integration and hardcoded attacks
- param_normalizer: Parameter normalization and transformation
- format_detection: Strategy format detection utilities
- parsing_utils: Low-level parsing utilities (split, parse_value, etc.)
- strategy_parsers: Strategy parsers for different formats
- strategy_validator: Strategy validation logic
- file_operations: File I/O operations for strategies
- registry_helpers: Registry query helper methods
- strategy_helpers: Miscellaneous helper utilities

Public API:
Import from core.unified_strategy_loader:
    from core.unified_strategy_loader import (
        UnifiedStrategyLoader,
        NormalizedStrategy,
        StrategyLoadError,
        StrategyValidationError,
        load_strategy,
        create_forced_override,
        load_strategies_from_file,
    )
"""

__version__ = "2.0.0"
__author__ = "DPI Bypass Team"

# Note: Public API is exported from core.unified_strategy_loader
# to avoid circular import issues. Import from there instead of this package.
