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
    load_strategies_from_file,
)

from .unified_bypass_engine import (
    UnifiedBypassEngine,
    UnifiedEngineConfig,
    UnifiedBypassEngineError,
)

# Core bypass engine
from .bypass.engine.base_engine import WindowsBypassEngine, EngineConfig

# Utility components
from .packet_validator import PacketValidator
from .simple_packet_validator import SimplePacketValidator

# Strategy components
from .strategy_combinator import StrategyCombinator
from .strategy_comparator import StrategyComparator

__all__ = [
    # Unified components (primary interfaces)
    "UnifiedStrategyLoader",
    "NormalizedStrategy",
    "StrategyLoadError",
    "StrategyValidationError",
    "load_strategy",
    "create_forced_override",
    "load_strategies_from_file",
    "UnifiedBypassEngine",
    "UnifiedEngineConfig",
    "UnifiedBypassEngineError",
    # Core engine
    "WindowsBypassEngine",
    "EngineConfig",
    # Utilities
    "PacketValidator",
    "SimplePacketValidator",
    "StrategyCombinator",
    "StrategyComparator",
]
