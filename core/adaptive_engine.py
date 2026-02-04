"""
AdaptiveEngine - Compatibility Layer

This module provides backward compatibility by redirecting imports to the refactored version.
The original monolithic AdaptiveEngine has been refactored into a well-structured architecture.

For new code, please import directly from:
    from core.adaptive_refactored.facade import AdaptiveEngine, AdaptiveConfig, StrategyResult

The original implementation has been archived to: archive/adaptive_engine_original.py
"""

import warnings

# Issue deprecation warning when this module is imported
warnings.warn(
    "Importing from core.adaptive_engine is deprecated. "
    "Please use 'from core.adaptive_refactored.facade import AdaptiveEngine, AdaptiveConfig, StrategyResult' instead. "
    "The original implementation has been moved to archive/adaptive_engine_original.py",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export the refactored classes for backward compatibility
from core.adaptive_refactored.facade import AdaptiveEngine, AdaptiveConfig, StrategyResult

# Export the main classes
__all__ = ["AdaptiveEngine", "AdaptiveConfig", "StrategyResult"]
