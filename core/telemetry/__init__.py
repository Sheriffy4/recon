"""
Telemetry collection components for UnifiedBypassEngine refactoring.

This module provides structured telemetry collection and aggregation
for bypass engine operations.

Feature: unified-engine-refactoring
Requirements: 6.1, 6.2, 6.4
"""

from .interfaces import ITelemetryCollector
from .collector import TelemetryCollector

__all__ = ["ITelemetryCollector", "TelemetryCollector"]
