#!/usr/bin/env python3
"""
Reliability validation package for bypass strategies.

This package provides comprehensive validation of bypass strategies with
multi-level accessibility checking, false positive detection, and effectiveness scoring.
"""

# Import types for backward compatibility
from .types import (
    ValidationMethod,
    ReliabilityLevel,
    AccessibilityStatus,
    ValidationResult,
    AccessibilityResult,
    StrategyEffectivenessResult,
)

# Import main validator class
from .reliability_validator import (
    ReliabilityValidator,
    get_global_reliability_validator,
    validate_domain_accessibility,
    validate_strategy_reliability,
)

# Export all public APIs
__all__ = [
    # Types
    "ValidationMethod",
    "ReliabilityLevel",
    "AccessibilityStatus",
    "ValidationResult",
    "AccessibilityResult",
    "StrategyEffectivenessResult",
    # Main validator
    "ReliabilityValidator",
    "get_global_reliability_validator",
    "validate_domain_accessibility",
    "validate_strategy_reliability",
]
