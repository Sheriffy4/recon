"""
Failure isolation mechanisms for the adaptive engine.

Provides component isolation, graceful degradation, and failure containment
to prevent cascading failures across the system.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, TypeVar
from contextlib import asynccontextmanager

from .circuit_breaker import CircuitBreakerManager, CircuitBreakerConfig
from ..models import ComponentHealth

logger = logging.getLogger(__name__)

T = TypeVar("T")


class IsolationLevel(Enum):
    """Levels of failure isolation."""

    NONE = "none"  # No isolation
    COMPONENT = "component"  # Isolate at component level
    SERVICE = "service"  # Isolate at service level
    SYSTEM = "system"  # System-wide isolation


class FailureType(Enum):
    """Types of failures that can be isolated."""

    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    AUTHENTICATION_ERROR = "authentication_error"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    INVALID_RESPONSE = "invalid_response"
    DEPENDENCY_FAILURE = "dependency_failure"
    CONFIGURATION_ERROR = "configuration_error"
    UNKNOWN = "unknown"


@dataclass
class IsolationPolicy:
    """Policy for failure isolation behavior."""

    isolation_level: IsolationLevel = IsolationLevel.COMPONENT
    max_failures_per_minute: int = 10
    isolation_duration_seconds: float = 300.0  # 5 minutes
    enable_graceful_degradation: bool = True
    enable_fallback_mechanisms: bool = True
    critical_components: Set[str] = field(default_factory=set)

    # Advanced policies
    failure_escalation_threshold: int = 5
    cascade_prevention_enabled: bool = True
    auto_recovery_enabled: bool = True


@dataclass
class FailureEvent:
    """Represents a failure event in the system."""

    component_name: str
    failure_type: FailureType
    error_message: str
    timestamp: datetime = field(default_factory=datetime.now)
    isolation_level: IsolationLevel = IsolationLevel.NONE
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert failure event to dictionary."""
        return {
            "component_name": self.component_name,
            "failure_type": self.failure_type.value,
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat(),
            "isolation_level": self.isolation_level.value,
            "metadata": self.metadata,
        }


@dataclass
class IsolationStatus:
    """Status of component isolation."""

    component_name: str
    is_isolated: bool
    isolation_level: IsolationLevel
    isolated_at: Optional[datetime] = None
    isolation_reason: Optional[str] = None
    recovery_attempts: int = 0
    last_recovery_attempt: Optional[datetime] = None

    def is_recovery_due(self, policy: IsolationPolicy) -> bool:
        """Check if component is due for recovery attempt."""
        if not self.is_isolated or not policy.auto_recovery_enabled:
            return False

        if self.isolated_at is None:
            return True

        elapsed = (datetime.now() - self.isolated_at).total_seconds()
        return elapsed >= policy.isolation_duration_seconds


class IFailureIsolator(ABC):
    """Interface for failure isolation implementations."""

    @abstractmethod
    async def isolate_component(self, component_name: str, failure_event: FailureEvent) -> None:
        """Isolate a component due to failure."""
        pass

    @abstractmethod
    async def recover_component(self, component_name: str) -> bool:
        """Attempt to recover an isolated component."""
        pass

    @abstractmethod
    def is_component_isolated(self, component_name: str) -> bool:
        """Check if component is currently isolated."""
        pass

    @abstractmethod
    def get_isolation_status(self, component_name: str) -> Optional[IsolationStatus]:
        """Get isolation status for component."""
        pass


class FailureIsolator(IFailureIsolator):
    """
    Failure isolation implementation with graceful degradation.

    Provides component-level isolation, cascade prevention, and
    automatic recovery mechanisms.
    """

    def __init__(self, policy: IsolationPolicy, circuit_breaker_manager: CircuitBreakerManager):
        self.policy = policy
        self.circuit_breaker_manager = circuit_breaker_manager
        self._isolation_status: Dict[str, IsolationStatus] = {}
        self._failure_history: List[FailureEvent] = []
        self._component_health: Dict[str, ComponentHealth] = {}
        self._fallback_handlers: Dict[str, Callable] = {}
        self._lock = asyncio.Lock()

        # Start background recovery task
        self._recovery_task = asyncio.create_task(self._recovery_loop())

        logger.info(f"Failure isolator initialized with policy: {policy}")

    async def isolate_component(self, component_name: str, failure_event: FailureEvent) -> None:
        """
        Isolate a component due to failure.

        Args:
            component_name: Name of the component to isolate
            failure_event: Details of the failure event
        """
        async with self._lock:
            # Record failure event
            self._failure_history.append(failure_event)
            self._cleanup_failure_history()

            # Check if isolation is needed
            if await self._should_isolate_component(component_name, failure_event):
                isolation_level = self._determine_isolation_level(component_name, failure_event)

                # Create or update isolation status
                self._isolation_status[component_name] = IsolationStatus(
                    component_name=component_name,
                    is_isolated=True,
                    isolation_level=isolation_level,
                    isolated_at=datetime.now(),
                    isolation_reason=failure_event.error_message,
                )

                # Update component health
                self._component_health[component_name] = ComponentHealth(
                    component_name=component_name,
                    is_healthy=False,
                    status_message=f"Isolated due to: {failure_event.error_message}",
                    error_count=self._get_recent_failure_count(component_name),
                )

                logger.warning(
                    f"Component '{component_name}' isolated at level {isolation_level.value} "
                    f"due to {failure_event.failure_type.value}: {failure_event.error_message}"
                )

                # Prevent cascade failures
                if self.policy.cascade_prevention_enabled:
                    await self._prevent_cascade_failures(component_name, failure_event)

    async def recover_component(self, component_name: str) -> bool:
        """
        Attempt to recover an isolated component.

        Args:
            component_name: Name of the component to recover

        Returns:
            True if recovery was successful, False otherwise
        """
        async with self._lock:
            status = self._isolation_status.get(component_name)
            if not status or not status.is_isolated:
                return True  # Already recovered or not isolated

            status.recovery_attempts += 1
            status.last_recovery_attempt = datetime.now()

            try:
                # Attempt recovery based on isolation level
                recovery_successful = await self._attempt_recovery(component_name, status)

                if recovery_successful:
                    # Mark as recovered
                    status.is_isolated = False

                    # Update component health
                    self._component_health[component_name] = ComponentHealth(
                        component_name=component_name,
                        is_healthy=True,
                        status_message="Recovered from isolation",
                        error_count=0,
                    )

                    logger.info(
                        f"Component '{component_name}' successfully recovered from isolation"
                    )
                    return True
                else:
                    logger.warning(
                        f"Recovery attempt {status.recovery_attempts} failed for '{component_name}'"
                    )
                    return False

            except Exception as e:
                logger.error(f"Error during recovery of '{component_name}': {e}")
                return False

    def is_component_isolated(self, component_name: str) -> bool:
        """Check if component is currently isolated."""
        status = self._isolation_status.get(component_name)
        return status is not None and status.is_isolated

    def get_isolation_status(self, component_name: str) -> Optional[IsolationStatus]:
        """Get isolation status for component."""
        return self._isolation_status.get(component_name)

    def get_all_isolation_status(self) -> Dict[str, IsolationStatus]:
        """Get isolation status for all components."""
        return self._isolation_status.copy()

    def get_component_health(self) -> Dict[str, ComponentHealth]:
        """Get health status for all components."""
        return self._component_health.copy()

    def register_fallback_handler(self, component_name: str, handler: Callable) -> None:
        """Register fallback handler for component."""
        self._fallback_handlers[component_name] = handler
        logger.info(f"Registered fallback handler for component '{component_name}'")

    async def execute_with_isolation(
        self, component_name: str, func: Callable[..., T], *args, **kwargs
    ) -> Optional[T]:
        """
        Execute function with isolation protection.

        Args:
            component_name: Name of the component
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result or None if isolated/failed
        """
        # Check if component is isolated
        if self.is_component_isolated(component_name):
            logger.warning(f"Component '{component_name}' is isolated, attempting fallback")

            # Try fallback handler
            if component_name in self._fallback_handlers:
                try:
                    return await self._execute_fallback(component_name, *args, **kwargs)
                except Exception as e:
                    logger.error(f"Fallback handler failed for '{component_name}': {e}")

            return None

        # Execute with failure tracking
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            # Record success
            await self._record_success(component_name)
            return result

        except Exception as e:
            # Record failure and potentially isolate
            failure_event = FailureEvent(
                component_name=component_name,
                failure_type=self._classify_failure(e),
                error_message=str(e),
            )

            await self.isolate_component(component_name, failure_event)
            raise

    async def _should_isolate_component(
        self, component_name: str, failure_event: FailureEvent
    ) -> bool:
        """Determine if component should be isolated."""
        # Check failure rate
        recent_failures = self._get_recent_failure_count(component_name)
        if recent_failures >= self.policy.max_failures_per_minute:
            return True

        # Check for critical failure types
        critical_failures = {
            FailureType.RESOURCE_EXHAUSTION,
            FailureType.DEPENDENCY_FAILURE,
            FailureType.CONFIGURATION_ERROR,
        }

        if failure_event.failure_type in critical_failures:
            return True

        # Check if component is critical and has multiple failures
        if component_name in self.policy.critical_components:
            if recent_failures >= self.policy.failure_escalation_threshold:
                return True

        return False

    def _determine_isolation_level(
        self, component_name: str, failure_event: FailureEvent
    ) -> IsolationLevel:
        """Determine appropriate isolation level."""
        # Critical components get service-level isolation
        if component_name in self.policy.critical_components:
            return IsolationLevel.SERVICE

        # High-impact failures get service-level isolation
        high_impact_failures = {FailureType.RESOURCE_EXHAUSTION, FailureType.DEPENDENCY_FAILURE}

        if failure_event.failure_type in high_impact_failures:
            return IsolationLevel.SERVICE

        # Default to component-level isolation
        return IsolationLevel.COMPONENT

    def _get_recent_failure_count(self, component_name: str) -> int:
        """Get count of recent failures for component."""
        cutoff_time = datetime.now() - timedelta(minutes=1)
        return sum(
            1
            for event in self._failure_history
            if event.component_name == component_name and event.timestamp > cutoff_time
        )

    def _cleanup_failure_history(self) -> None:
        """Remove old failure events from history."""
        cutoff_time = datetime.now() - timedelta(hours=1)
        self._failure_history = [
            event for event in self._failure_history if event.timestamp > cutoff_time
        ]

    async def _prevent_cascade_failures(
        self, component_name: str, failure_event: FailureEvent
    ) -> None:
        """Prevent cascade failures by isolating dependent components."""
        # This is a simplified implementation - in practice, you'd have
        # a dependency graph to determine which components to isolate

        dependent_components = self._get_dependent_components(component_name)

        for dependent in dependent_components:
            if not self.is_component_isolated(dependent):
                logger.info(
                    f"Preemptively isolating dependent component '{dependent}' "
                    f"due to failure in '{component_name}'"
                )

                cascade_event = FailureEvent(
                    component_name=dependent,
                    failure_type=FailureType.DEPENDENCY_FAILURE,
                    error_message=f"Dependency failure in {component_name}",
                    isolation_level=IsolationLevel.COMPONENT,
                )

                await self.isolate_component(dependent, cascade_event)

    def _get_dependent_components(self, component_name: str) -> List[str]:
        """Get list of components that depend on the given component."""
        # Simplified dependency mapping - in practice, this would be
        # configured or discovered dynamically
        dependencies = {
            "cache_manager": ["strategy_service", "testing_service"],
            "configuration_manager": ["strategy_service", "testing_service", "analytics_service"],
            "metrics_collector": ["analytics_service"],
            "strategy_generator": ["strategy_service"],
            "test_coordinator": ["testing_service"],
            "failure_analyzer": ["strategy_service"],
        }

        return dependencies.get(component_name, [])

    async def _attempt_recovery(self, component_name: str, status: IsolationStatus) -> bool:
        """Attempt to recover an isolated component."""
        try:
            # Reset circuit breaker if exists
            breaker = self.circuit_breaker_manager._breakers.get(component_name)
            if breaker:
                breaker.reset()

            # Perform component-specific recovery
            if component_name in self._fallback_handlers:
                # Test fallback handler
                await self._execute_fallback(component_name)

            # Simple health check - in practice, this would be more sophisticated
            await asyncio.sleep(0.1)  # Simulate health check

            return True

        except Exception as e:
            logger.error(f"Recovery failed for '{component_name}': {e}")
            return False

    async def _execute_fallback(self, component_name: str, *args, **kwargs) -> Any:
        """Execute fallback handler for component."""
        handler = self._fallback_handlers.get(component_name)
        if not handler:
            raise RuntimeError(f"No fallback handler for component '{component_name}'")

        if asyncio.iscoroutinefunction(handler):
            return await handler(*args, **kwargs)
        else:
            return handler(*args, **kwargs)

    async def _record_success(self, component_name: str) -> None:
        """Record successful operation for component."""
        # Update component health
        if component_name in self._component_health:
            health = self._component_health[component_name]
            health.is_healthy = True
            health.error_count = max(0, health.error_count - 1)
            health.last_check = datetime.now()

    def _classify_failure(self, exception: Exception) -> FailureType:
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

    async def validate_traffic_purity(self, expected_domain: str, captured_packets: list) -> bool:
        """
        Проверяет, не попали ли в дамп пакеты других доменов.
        Если обнаружен 'чужой' SNI, тест считается загрязненным.
        """
        for packet in captured_packets:
            actual_domain = self._extract_sni(packet)
            if actual_domain and actual_domain != expected_domain:
                logger.warning(
                    f"Isolation breach! Found traffic for {actual_domain} during {expected_domain} test"
                )
                return False
        return True

    def _extract_sni(self, packet):
        # Логика извлечения SNI из сырого пакета (перенос из оригинала)
        pass

    async def _recovery_loop(self) -> None:
        """Background task for automatic component recovery."""
        while True:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds

                async with self._lock:
                    for component_name, status in self._isolation_status.items():
                        if status.is_recovery_due(self.policy):
                            logger.info(f"Attempting automatic recovery for '{component_name}'")
                            await self.recover_component(component_name)

            except Exception as e:
                logger.error(f"Error in recovery loop: {e}")
                await asyncio.sleep(60)  # Wait longer on error


class FailureIsolationManager:
    """
    Manager for failure isolation across multiple components.

    Provides centralized management of component isolation policies,
    failure tracking, and recovery coordination.
    """

    def __init__(self, policy: IsolationPolicy, circuit_breaker_manager: CircuitBreakerManager):
        self.policy = policy
        self.circuit_breaker_manager = circuit_breaker_manager
        self._isolators: Dict[str, FailureIsolator] = {}
        self._global_isolation_status: Dict[str, IsolationStatus] = {}
        self._lock = asyncio.Lock()

        logger.info(f"Failure isolation manager initialized with policy: {policy}")

    def get_isolator(self, component_name: str) -> FailureIsolator:
        """Get or create failure isolator for component."""
        if component_name not in self._isolators:
            self._isolators[component_name] = FailureIsolator(
                self.policy, self.circuit_breaker_manager
            )
        return self._isolators[component_name]

    async def isolate_component(self, component_name: str, failure_event: FailureEvent) -> None:
        """Isolate a component across all isolators."""
        isolator = self.get_isolator(component_name)
        await isolator.isolate_component(component_name, failure_event)

        # Update global status
        async with self._lock:
            self._global_isolation_status[component_name] = isolator.get_isolation_status(
                component_name
            )

    async def recover_component(self, component_name: str) -> bool:
        """Attempt to recover a component across all isolators."""
        if component_name not in self._isolators:
            return True  # Not isolated

        isolator = self._isolators[component_name]
        success = await isolator.recover_component(component_name)

        # Update global status
        async with self._lock:
            if success:
                self._global_isolation_status.pop(component_name, None)
            else:
                self._global_isolation_status[component_name] = isolator.get_isolation_status(
                    component_name
                )

        return success

    def is_component_isolated(self, component_name: str) -> bool:
        """Check if component is isolated in any isolator."""
        if component_name in self._isolators:
            return self._isolators[component_name].is_component_isolated(component_name)
        return False

    def get_all_isolation_status(self) -> Dict[str, IsolationStatus]:
        """Get isolation status for all components."""
        return self._global_isolation_status.copy()

    def get_component_health(self) -> Dict[str, ComponentHealth]:
        """Get health status for all components."""
        health_status = {}
        for component_name, isolator in self._isolators.items():
            component_health = isolator.get_component_health()
            health_status.update(component_health)
        return health_status

    def register_fallback_handler(self, component_name: str, handler: Callable) -> None:
        """Register fallback handler for component."""
        isolator = self.get_isolator(component_name)
        isolator.register_fallback_handler(component_name, handler)

    async def execute_with_isolation(
        self, component_name: str, func: Callable[..., T], *args, **kwargs
    ) -> Optional[T]:
        """Execute function with isolation protection."""
        isolator = self.get_isolator(component_name)
        return await isolator.execute_with_isolation(component_name, func, *args, **kwargs)

    def get_isolation_stats(self) -> Dict[str, Any]:
        """Get isolation statistics."""
        stats = {
            "total_components": len(self._isolators),
            "isolated_components": len(self._global_isolation_status),
            "isolation_rate": len(self._global_isolation_status) / max(1, len(self._isolators)),
            "components": {},
        }

        for component_name, isolator in self._isolators.items():
            component_health = isolator.get_component_health().get(component_name)
            if component_health:
                stats["components"][component_name] = {
                    "is_healthy": component_health.is_healthy,
                    "error_count": component_health.error_count,
                    "is_isolated": self.is_component_isolated(component_name),
                }

        return stats


@asynccontextmanager
async def isolated_execution(isolator: FailureIsolator, component_name: str):
    """
    Context manager for isolated execution.

    Usage:
        async with isolated_execution(isolator, "my_component"):
            # Code that might fail
            result = await risky_operation()
    """
    try:
        if isolator.is_component_isolated(component_name):
            raise RuntimeError(f"Component '{component_name}' is currently isolated")

        yield

    except Exception as e:
        failure_event = FailureEvent(
            component_name=component_name,
            failure_type=isolator._classify_failure(e),
            error_message=str(e),
        )

        await isolator.isolate_component(component_name, failure_event)
        raise
