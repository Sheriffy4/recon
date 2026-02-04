"""
Monitoring system components for DPI bypass.

This package provides modular components for monitoring site accessibility
and automatic recovery:

Components:
    - models: Shared data models (ConnectionHealth, MonitoringConfig)
    - HealthChecker: Asynchronous connectivity testing (HTTP/TCP)
    - AutoRecoverySystem: Automatic recovery with strategy optimization
    - SiteManager: Site lifecycle and health tracking
    - Strategy helpers: Strategy generation and validation
    - Reporters: Status and metrics reporting
    - Effectiveness: Rule effectiveness analysis
    - Config helpers: Configuration persistence

The main MonitoringSystem class in the parent module acts as a facade,
orchestrating these components to provide a unified monitoring interface.
"""

from core.monitoring.models import ConnectionHealth, MonitoringConfig
from core.monitoring.health_checker import HealthChecker
from core.monitoring.auto_recovery import AutoRecoverySystem

__all__ = [
    "ConnectionHealth",
    "MonitoringConfig",
    "HealthChecker",
    "AutoRecoverySystem",
]
