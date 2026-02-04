"""
Diagnostics Module

Модуль диагностики для мониторинга и метрик системы обхода.
"""

from core.diagnostics.metrics_integration import (
    DiagnosticsMetricsCollector,
    StrategyMetrics,
    DoHMetrics,
    PCAPMetrics,
    get_diagnostics_metrics_collector,
)

try:
    from .accessibility_diagnostics import AccessibilityDiagnostics
except ImportError:
    AccessibilityDiagnostics = None

__all__ = [
    "DiagnosticsMetricsCollector",
    "StrategyMetrics",
    "DoHMetrics",
    "PCAPMetrics",
    "get_diagnostics_metrics_collector",
]

if AccessibilityDiagnostics is not None:
    __all__.append("AccessibilityDiagnostics")
