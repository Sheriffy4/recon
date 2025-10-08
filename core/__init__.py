#!/usr/bin/env python3
"""
Core module for DPI bypass functionality.

This module provides the unified interface for all DPI bypass operations,
including strategy loading, engine management, and packet processing.

Key Components:
- UnifiedStrategyLoader: Single source of truth for strategy parsing
- UnifiedBypassEngine: Unified engine wrapper for all modes
- BaseBypassEngine: Core bypass engine implementation
"""

# Core unified components (primary interfaces)
from .unified_strategy_loader import (
    UnifiedStrategyLoader,
    NormalizedStrategy,
    StrategyLoadError,
    StrategyValidationError,
    load_strategy,
    create_forced_override,
    load_strategies_from_file
)

# Utility components
from .packet_validator import PacketValidator
from .simple_packet_validator import SimplePacketValidator

# Strategy components
from .strategy_combinator import StrategyCombinator
from .strategy_comparator import StrategyComparator

# NOTE: Eagerly importing platform-dependent modules like UnifiedBypassEngine
# was causing ImportError on non-Windows systems. They are now imported
# directly where needed, rather than being exposed through the package's __init__.

__all__ = [
    # Unified components (primary interfaces)
    'UnifiedStrategyLoader',
    'NormalizedStrategy',
    'StrategyLoadError',
    'StrategyValidationError',
    'load_strategy',
    'create_forced_override',
    'load_strategies_from_file',
    
    # Utilities
    'PacketValidator',
    'SimplePacketValidator',
    'StrategyCombinator',
    'StrategyComparator',
]