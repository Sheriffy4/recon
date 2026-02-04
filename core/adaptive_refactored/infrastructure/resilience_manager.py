"""
Resilience manager that integrates circuit breakers, failure isolation, and retry mechanisms.

Provides a unified interface for all error handling and resilience features
in the adaptive engine system.
"""

import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional, TypeVar
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .circuit_breaker import CircuitBreakerManager, CircuitBreakerConfig, CircuitState
from .failure_isolation import FailureIsolator, IsolationPolicy, FailureEvent, FailureType
from .retry_mechanisms import RetryManager, RetryConfig, RetryExhaustedException
from .error_context import ErrorContextBuilder, EnhancedErrorContext, ErrorSeverity
from ..models import ComponentHealth

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class ResilienceConfig:
    """Configuration for resilience manager."""

    enable_circuit_breaker: bool = True  # Fixed property name to match ErrorHandlingConfig
    enable_failure_isolation: bool = True
    enable_retry_mechanisms: bool = True
    enable_error_context: bool = True

    # Default configurations
    default_circuit_breaker_config: CircuitBreakerConfig = field(
        default_factory=CircuitBreakerConfig
    )
    default_isolation_policy: IsolationPolicy = field(default_factory=IsolationPolicy)
    default_retry_config: RetryConfig = field(default_factory=RetryConfig)

    @classmethod
    def from_error_handling_config(cls, error_config: "ErrorHandlingConfig") -> "ResilienceConfig":
        """Create ResilienceConfig from ErrorHandlingConfig."""
        from .circuit_breaker import CircuitBreakerConfig
        from .retry_mechanisms import RetryConfig, RetryStrategy

        circuit_breaker_config = CircuitBreakerConfig(
            failure_threshold=error_config.circuit_breaker_failure_threshold,
            recovery_timeout=error_config.circuit_breaker_recovery_timeout,
            success_threshold=error_config.circuit_breaker_half_open_max_calls,
        )

        retry_config = RetryConfig(
            max_attempts=error_config.max_retries,
            base_delay=error_config.retry_base_delay,
            max_delay=error_config.retry_max_delay,
            backoff_multiplier=error_config.retry_exponential_base,
            strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
        )

        isolation_policy = IsolationPolicy()

        return cls(
            enable_circuit_breaker=error_config.enable_circuit_breaker,
            enable_failure_isolation=error_config.enable_failure_isolation,
            enable_retry_mechanisms=error_config.enable_retry_mechanism,
            enable_error_context=error_config.enable_structured_logging,
            default_circuit_breaker_config=circuit_breaker_config,
            default_isolation_policy=isolation_policy,
            default_retry_config=retry_config,
        )

    @classmethod
    def from_error_config(cls, error_config: "ErrorHandlingConfig") -> "ResilienceConfig":
        """Create ResilienceConfig from ErrorHandlingConfig (alias for compatibility)."""
        return cls.from_error_handling_config(error_config)


@dataclass
class ResilienceStats:
    """Statistics for resilience manager."""

    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    circuit_breaker_trips: int = 0
    isolation_events: int = 0
    retry_attempts: int = 0
    recovery_successes: int = 0
    last_updated: datetime = field(default_factory=datetime.now)

    def get_success_rate(self) -> float:
        """Calculate overall success rate."""
        if self.total_operations == 0:
            return 0.0
        return self.successful_operations / self.total_operations

    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "total_operations": self.total_operations,
            "successful_operations": self.successful_operations,
            "failed_operations": self.failed_operations,
            "circuit_breaker_trips": self.circuit_breaker_trips,
            "isolation_events": self.isolation_events,
            "retry_attempts": self.retry_attempts,
            "recovery_successes": self.recovery_successes,
            "success_rate": self.get_success_rate(),
            "last_updated": self.last_updated.isoformat(),
        }


class ResilienceManager:
    """
    Unified resilience manager integrating all error handling mechanisms.

    Provides a single interface for circuit breakers, failure isolation,
    retry mechanisms, and error context generation.
    """

    def __init__(self, config: ResilienceConfig):
        self.config = config
        self.stats = ResilienceStats()

        # Initialize components
        self.circuit_breaker_manager = (
            CircuitBreakerManager() if config.enable_circuit_breaker else None
        )
        self.failure_isolator = (
            FailureIsolator(config.default_isolation_policy, self.circuit_breaker_manager)
            if config.enable_failure_isolation
            else None
        )
        self.retry_manager = RetryManager() if config.enable_retry_mechanisms else None
        self.error_context_builder = ErrorContextBuilder() if config.enable_error_context else None

        logger.info(f"Resilience manager initialized with config: {config}")

    async def execute_with_resilience(
        self,
        operation_name: str,
        component_name: str,
        func: Callable[..., T],
        *args,
        circuit_breaker_config: Optional[CircuitBreakerConfig] = None,
        retry_config: Optional[RetryConfig] = None,
        **kwargs,
    ) -> T:
        """
        Execute function with full resilience protection.

        Args:
            operation_name: Name of the operation
            component_name: Name of the component
            func: Function to execute
            *args: Function arguments
            circuit_breaker_config: Optional circuit breaker configuration
            retry_config: Optional retry configuration
            **kwargs: Function keyword arguments

        Returns:
            Function result

        Raises:
            Various exceptions based on failure modes
        """
        start_time = datetime.now(timezone.utc)
        self.stats.total_operations += 1

        try:
            # Check if component is isolated
            if self.failure_isolator and self.failure_isolator.is_component_isolated(
                component_name
            ):
                logger.warning(f"Component '{component_name}' is isolated, attempting fallback")
                result = await self.failure_isolator.execute_with_isolation(
                    component_name, func, *args, **kwargs
                )
                if result is not None:
                    self.stats.successful_operations += 1
                    return result
                else:
                    raise RuntimeError(
                        f"Component '{component_name}' is isolated and no fallback available"
                    )

            # Execute with circuit breaker protection
            if self.circuit_breaker_manager:
                breaker = self.circuit_breaker_manager.get_breaker(
                    component_name,
                    circuit_breaker_config or self.config.default_circuit_breaker_config,
                )

                try:
                    if self.retry_manager:
                        # Execute with both circuit breaker and retry
                        result = await self._execute_with_circuit_breaker_and_retry(
                            breaker, operation_name, func, retry_config, *args, **kwargs
                        )
                    else:
                        # Execute with circuit breaker only
                        result = await breaker.call(func, *args, **kwargs)

                    self.stats.successful_operations += 1
                    return result

                except Exception as e:
                    if breaker.get_state() == CircuitState.OPEN:
                        self.stats.circuit_breaker_trips += 1
                    raise

            elif self.retry_manager:
                # Execute with retry only
                retry_mechanism = self.retry_manager.get_retry_mechanism("default", operation_name)
                result = await retry_mechanism.execute_with_retry(func, *args, **kwargs)
                self.stats.successful_operations += 1
                return result

            else:
                # Execute without resilience mechanisms
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                self.stats.successful_operations += 1
                return result

        except Exception as e:
            self.stats.failed_operations += 1

            # Handle failure with isolation if enabled
            if self.failure_isolator:
                failure_event = FailureEvent(
                    component_name=component_name,
                    failure_type=self._classify_failure_type(e),
                    error_message=str(e),
                )
                await self.failure_isolator.isolate_component(component_name, failure_event)
                self.stats.isolation_events += 1

            # Generate error context if enabled
            if self.error_context_builder:
                execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
                error_context = self.error_context_builder.build_context(
                    e,
                    operation_name,
                    component_name,
                    parameters=kwargs,
                    execution_time=execution_time,
                )

                # Log detailed error context
                logger.error(
                    f"Operation '{operation_name}' failed with context: {error_context.to_dict()}"
                )

                # Attach error context to exception if possible
                if hasattr(e, "__dict__"):
                    e.error_context = error_context

            raise

        finally:
            self.stats.last_updated = datetime.now(timezone.utc)

    async def _execute_with_circuit_breaker_and_retry(
        self,
        breaker,
        operation_name: str,
        func: Callable[..., T],
        retry_config: Optional[RetryConfig],
        *args,
        **kwargs,
    ) -> T:
        """Execute function with both circuit breaker and retry protection."""
        retry_mechanism = self.retry_manager.get_retry_mechanism("default", operation_name)

        # Override retry config if provided
        if retry_config:
            retry_mechanism.config = retry_config

        try:

            async def circuit_breaker_wrapper():
                return await breaker.call(func, *args, **kwargs)

            result = await retry_mechanism.execute_with_retry(circuit_breaker_wrapper)
            return result

        except RetryExhaustedException as e:
            self.stats.retry_attempts += e.error_context.total_attempts
            raise

    def _classify_failure_type(self, exception: Exception) -> FailureType:
        """Classify exception into failure type."""
        if isinstance(exception, asyncio.TimeoutError):
            return FailureType.TIMEOUT
        elif isinstance(exception, ConnectionError):
            return FailureType.CONNECTION_ERROR
        elif isinstance(exception, PermissionError):
            return FailureType.AUTHENTICATION_ERROR
        elif isinstance(exception, MemoryError):
            return FailureType.RESOURCE_EXHAUSTION
        elif isinstance(exception, ValueError):
            return FailureType.INVALID_RESPONSE
        else:
            return FailureType.UNKNOWN

    async def recover_component(self, component_name: str) -> bool:
        """
        Attempt to recover a failed component.

        Args:
            component_name: Name of the component to recover

        Returns:
            True if recovery was successful
        """
        if not self.failure_isolator:
            return True

        success = await self.failure_isolator.recover_component(component_name)
        if success:
            self.stats.recovery_successes += 1

            # Reset circuit breaker if exists
            if self.circuit_breaker_manager:
                breaker = self.circuit_breaker_manager._breakers.get(component_name)
                if breaker:
                    breaker.reset()

        return success

    def get_component_health(self) -> Dict[str, ComponentHealth]:
        """Get health status of all components."""
        if not self.failure_isolator:
            return {}

        return self.failure_isolator.get_component_health()

    def get_resilience_stats(self) -> ResilienceStats:
        """Get resilience statistics."""
        return self.stats

    def get_detailed_stats(self) -> Dict[str, Any]:
        """Get detailed statistics from all resilience components."""
        stats = {"overall": self.stats.to_dict()}

        if self.circuit_breaker_manager:
            stats["circuit_breakers"] = self.circuit_breaker_manager.get_health_summary()

        if self.failure_isolator:
            stats["isolation"] = {
                "isolated_components": [
                    name
                    for name, status in self.failure_isolator.get_all_isolation_status().items()
                    if status.is_isolated
                ],
                "component_health": {
                    name: {
                        "is_healthy": health.is_healthy,
                        "error_count": health.error_count,
                        "status_message": health.status_message,
                    }
                    for name, health in self.failure_isolator.get_component_health().items()
                },
            }

        if self.retry_manager:
            stats["retry"] = self.retry_manager.get_retry_stats()

        return stats

    def register_fallback_handler(self, component_name: str, handler: Callable) -> None:
        """Register fallback handler for component."""
        if self.failure_isolator:
            self.failure_isolator.register_fallback_handler(component_name, handler)

    def reset_stats(self) -> None:
        """Reset all statistics."""
        self.stats = ResilienceStats()

        if self.circuit_breaker_manager:
            self.circuit_breaker_manager.reset_all()

        if self.retry_manager:
            self.retry_manager.reset_stats()


# Decorator for easy resilience integration
def with_resilience(
    operation_name: str,
    component_name: str,
    circuit_breaker_config: Optional[CircuitBreakerConfig] = None,
    retry_config: Optional[RetryConfig] = None,
):
    """
    Decorator to add resilience protection to functions.

    Args:
        operation_name: Name of the operation
        component_name: Name of the component
        circuit_breaker_config: Optional circuit breaker configuration
        retry_config: Optional retry configuration

    Usage:
        @with_resilience("generate_strategy", "strategy_generator")
        async def generate_strategy(domain: str):
            # Strategy generation implementation
            pass
    """

    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Get global resilience manager (would be injected in practice)
            resilience_manager = getattr(wrapper, "_resilience_manager", None)
            if not resilience_manager:
                # Create default resilience manager
                config = ResilienceConfig()
                resilience_manager = ResilienceManager(config)
                wrapper._resilience_manager = resilience_manager

            return await resilience_manager.execute_with_resilience(
                operation_name,
                component_name,
                func,
                *args,
                circuit_breaker_config=circuit_breaker_config,
                retry_config=retry_config,
                **kwargs,
            )

        return wrapper

    return decorator


# Global resilience manager instance (for simple usage)
_global_resilience_manager: Optional[ResilienceManager] = None


def get_global_resilience_manager() -> ResilienceManager:
    """Get or create global resilience manager."""
    global _global_resilience_manager
    if _global_resilience_manager is None:
        config = ResilienceConfig()
        _global_resilience_manager = ResilienceManager(config)
    return _global_resilience_manager


def set_global_resilience_manager(manager: ResilienceManager) -> None:
    """Set global resilience manager."""
    global _global_resilience_manager
    _global_resilience_manager = manager
