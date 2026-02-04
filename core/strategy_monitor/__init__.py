"""
Enhanced StrategyMonitor - Automatic strategy effectiveness monitoring and DPI change detection.

This package provides comprehensive monitoring capabilities for DPI bypass strategies and attacks,
integrating with FastBypassEngine, AdvancedFingerprintEngine, and the unified attack system.
"""

from .models import (
    AttackEffectivenessReport,
    EffectivenessReport,
    DPIChange,
    Strategy,
)

from .metrics_calculator import (
    calculate_effectiveness_trend,
    calculate_confidence,
    calculate_attack_effectiveness_trend,
    calculate_attack_confidence,
    estimate_latency_from_stats,
    estimate_technique_latency,
)

from .strategy_monitor_core import StrategyMonitor

__all__ = [
    "StrategyMonitor",
    "AttackEffectivenessReport",
    "EffectivenessReport",
    "DPIChange",
    "Strategy",
    "calculate_effectiveness_trend",
    "calculate_confidence",
    "calculate_attack_effectiveness_trend",
    "calculate_attack_confidence",
    "estimate_latency_from_stats",
    "estimate_technique_latency",
]
