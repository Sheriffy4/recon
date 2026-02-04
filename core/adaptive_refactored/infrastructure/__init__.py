"""
Infrastructure layer components for the refactored Adaptive Engine.

This package contains the infrastructure components that handle
cross-cutting concerns like caching, configuration, metrics, and resilience.
"""

# Import all infrastructure implementations
from .cache_manager import CacheManager
from .configuration_manager import ConfigurationManager
from .metrics_collector import MetricsCollector
from .performance_monitor import PerformanceMonitor

# Import resilience components
from .circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerManager,
    CircuitBreakerConfig,
    CircuitState,
    CircuitBreakerError,
    with_circuit_breaker,
)
from .failure_isolation import (
    FailureIsolator,
    IsolationPolicy,
    FailureEvent,
    FailureType,
    IsolationLevel,
    isolated_execution,
)
from .retry_mechanisms import (
    RetryMechanism,
    RetryManager,
    RetryConfig,
    RetryStrategy,
    RetryExhaustedException,
    with_retry,
    setup_default_retry_configs,
)
from .error_context import (
    ErrorContextBuilder,
    EnhancedErrorContext,
    ErrorSeverity,
    ErrorCategory,
    RecoverySuggestion,
)
from .resilience_manager import (
    ResilienceManager,
    ResilienceConfig,
    ResilienceStats,
    with_resilience,
    get_global_resilience_manager,
)

__all__ = [
    # Core infrastructure
    "CacheManager",
    "ConfigurationManager",
    "MetricsCollector",
    "PerformanceMonitor",
    # Circuit breaker components
    "CircuitBreaker",
    "CircuitBreakerManager",
    "CircuitBreakerConfig",
    "CircuitState",
    "CircuitBreakerError",
    "with_circuit_breaker",
    # Failure isolation components
    "FailureIsolator",
    "IsolationPolicy",
    "FailureEvent",
    "FailureType",
    "IsolationLevel",
    "isolated_execution",
    # Retry mechanism components
    "RetryMechanism",
    "RetryManager",
    "RetryConfig",
    "RetryStrategy",
    "RetryExhaustedException",
    "with_retry",
    "setup_default_retry_configs",
    # Error context components
    "ErrorContextBuilder",
    "EnhancedErrorContext",
    "ErrorSeverity",
    "ErrorCategory",
    "RecoverySuggestion",
    # Resilience manager
    "ResilienceManager",
    "ResilienceConfig",
    "ResilienceStats",
    "with_resilience",
    "get_global_resilience_manager",
]
