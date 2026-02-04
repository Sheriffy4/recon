"""
Refactored Adaptive Engine Components

This package contains the refactored components of the monolithic AdaptiveEngine,
following SOLID principles and clean architecture patterns.
"""

from .interfaces import *
from .config import *
from .models import *
from .container import (
    DIContainer,
    create_default_container,
    get_container,
    set_container,
    reset_container,
)

__all__ = [
    # Interfaces
    "IStrategyService",
    "ITestingService",
    "IAnalyticsService",
    "IStrategyGenerator",
    "ITestCoordinator",
    "ICacheManager",
    "IConfigurationManager",
    "IFailureAnalyzer",
    "IMetricsCollector",
    "IPerformanceMonitor",
    "IBypassEngine",
    "IPCAPAnalyzer",
    "IStrategyValidator",
    # Configuration
    "AdaptiveEngineConfig",
    "StrategyConfig",
    "TestingConfig",
    "CacheConfig",
    "AnalyticsConfig",
    "NetworkingConfig",
    "ErrorHandlingConfig",
    # Models
    "Strategy",
    "TestResult",
    "TestArtifacts",
    "PerformanceMetrics",
    "DPIFingerprint",
    "FailureReport",
    "TestVerdict",
    "CacheType",
    "ValidationError",
    "TestMode",
    "StrategyType",
    "CacheEntry",
    "ComponentHealth",
    "SystemStatus",
    # Container
    "DIContainer",
    "create_default_container",
    "get_container",
    "set_container",
    "reset_container",
]
