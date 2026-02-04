"""
Circuit breaker implementation for external dependencies.

Provides failure isolation and automatic recovery mechanisms
to prevent cascading failures in the adaptive engine system.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, Optional, TypeVar, Generic
import logging

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(Enum):
    """States of a circuit breaker."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, blocking calls
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""

    failure_threshold: int = 5  # Number of failures before opening
    recovery_timeout: float = 60.0  # Seconds before trying half-open
    success_threshold: int = 3  # Successes needed to close from half-open
    timeout: float = 30.0  # Operation timeout in seconds

    # Advanced configuration
    failure_rate_threshold: float = 0.5  # Failure rate to trigger opening
    minimum_requests: int = 10  # Minimum requests before calculating failure rate
    sliding_window_size: int = 100  # Size of sliding window for failure tracking


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker monitoring."""

    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    total_requests: int = 0
    total_failures: int = 0
    total_successes: int = 0
    state_changed_at: datetime = field(default_factory=datetime.now)

    def get_failure_rate(self) -> float:
        """Calculate current failure rate."""
        if self.total_requests == 0:
            return 0.0
        return self.total_failures / self.total_requests

    def reset_counts(self) -> None:
        """Reset failure and success counts."""
        self.failure_count = 0
        self.success_count = 0


class CircuitBreakerError(Exception):
    """Exception raised when circuit breaker is open."""

    def __init__(self, message: str, circuit_name: str, state: CircuitState):
        super().__init__(message)
        self.circuit_name = circuit_name
        self.state = state


class ICircuitBreaker(ABC, Generic[T]):
    """Interface for circuit breaker implementations."""

    @abstractmethod
    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function through circuit breaker."""
        pass

    @abstractmethod
    def get_state(self) -> CircuitState:
        """Get current circuit breaker state."""
        pass

    @abstractmethod
    def get_stats(self) -> CircuitBreakerStats:
        """Get circuit breaker statistics."""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        pass


class CircuitBreaker(ICircuitBreaker[T]):
    """
    Circuit breaker implementation with failure isolation and recovery.

    Implements the circuit breaker pattern to prevent cascading failures
    by monitoring external dependency health and automatically isolating
    failing services.
    """

    def __init__(self, name: str, config: CircuitBreakerConfig):
        self.name = name
        self.config = config
        self.stats = CircuitBreakerStats()
        self._lock = asyncio.Lock()
        self._recent_requests: list[tuple[datetime, bool]] = []  # (timestamp, success)

        logger.info(f"Circuit breaker '{name}' initialized with config: {config}")

    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute function through circuit breaker with failure protection.

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result

        Raises:
            CircuitBreakerError: When circuit is open
            TimeoutError: When operation times out
        """
        async with self._lock:
            await self._update_state()

            if self.stats.state == CircuitState.OPEN:
                raise CircuitBreakerError(
                    f"Circuit breaker '{self.name}' is OPEN", self.name, CircuitState.OPEN
                )

            # For half-open state, only allow limited requests
            if self.stats.state == CircuitState.HALF_OPEN:
                if self.stats.success_count >= self.config.success_threshold:
                    await self._close_circuit()
                elif self.stats.failure_count > 0:
                    await self._open_circuit()
                    raise CircuitBreakerError(
                        f"Circuit breaker '{self.name}' failed in HALF_OPEN state",
                        self.name,
                        CircuitState.OPEN,
                    )

        # Execute the function with timeout
        try:
            start_time = time.time()
            result = await asyncio.wait_for(
                self._execute_async(func, *args, **kwargs), timeout=self.config.timeout
            )
            execution_time = time.time() - start_time

            await self._record_success(execution_time)
            return result

        except asyncio.TimeoutError:
            await self._record_failure("Operation timeout")
            raise TimeoutError(f"Operation timed out after {self.config.timeout}s")

        except Exception as e:
            await self._record_failure(str(e))
            raise

    async def _execute_async(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function, handling both sync and async functions."""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            # Run sync function in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

    async def _record_success(self, execution_time: float) -> None:
        """Record successful operation."""
        async with self._lock:
            self.stats.success_count += 1
            self.stats.total_successes += 1
            self.stats.total_requests += 1
            self.stats.last_success_time = datetime.now()

            # Add to sliding window
            self._recent_requests.append((datetime.now(), True))
            self._cleanup_sliding_window()

            logger.debug(
                f"Circuit breaker '{self.name}' recorded success "
                f"(execution_time={execution_time:.2f}s)"
            )

            # Transition from half-open to closed if enough successes
            if (
                self.stats.state == CircuitState.HALF_OPEN
                and self.stats.success_count >= self.config.success_threshold
            ):
                await self._close_circuit()

    async def _record_failure(self, error_message: str) -> None:
        """Record failed operation."""
        async with self._lock:
            self.stats.failure_count += 1
            self.stats.total_failures += 1
            self.stats.total_requests += 1
            self.stats.last_failure_time = datetime.now()

            # Add to sliding window
            self._recent_requests.append((datetime.now(), False))
            self._cleanup_sliding_window()

            logger.warning(f"Circuit breaker '{self.name}' recorded failure: {error_message}")

            # Check if we should open the circuit
            if await self._should_open_circuit():
                await self._open_circuit()

    async def _should_open_circuit(self) -> bool:
        """Determine if circuit should be opened based on failure patterns."""
        # Simple threshold-based check
        if self.stats.failure_count >= self.config.failure_threshold:
            return True

        # Failure rate-based check (if we have enough requests)
        if len(self._recent_requests) >= self.config.minimum_requests:
            failure_rate = self._calculate_recent_failure_rate()
            if failure_rate >= self.config.failure_rate_threshold:
                return True

        return False

    def _calculate_recent_failure_rate(self) -> float:
        """Calculate failure rate from recent requests."""
        if not self._recent_requests:
            return 0.0

        failures = sum(1 for _, success in self._recent_requests if not success)
        return failures / len(self._recent_requests)

    def _cleanup_sliding_window(self) -> None:
        """Remove old entries from sliding window."""
        cutoff_time = datetime.now() - timedelta(minutes=5)  # Keep last 5 minutes
        self._recent_requests = [
            (timestamp, success)
            for timestamp, success in self._recent_requests
            if timestamp > cutoff_time
        ]

        # Also limit by size
        if len(self._recent_requests) > self.config.sliding_window_size:
            self._recent_requests = self._recent_requests[-self.config.sliding_window_size :]

    async def _open_circuit(self) -> None:
        """Open the circuit breaker."""
        self.stats.state = CircuitState.OPEN
        self.stats.state_changed_at = datetime.now()
        self.stats.reset_counts()

        logger.warning(f"Circuit breaker '{self.name}' opened due to failures")

    async def _close_circuit(self) -> None:
        """Close the circuit breaker."""
        self.stats.state = CircuitState.CLOSED
        self.stats.state_changed_at = datetime.now()
        self.stats.reset_counts()

        logger.info(f"Circuit breaker '{self.name}' closed - service recovered")

    async def _update_state(self) -> None:
        """Update circuit breaker state based on time and conditions."""
        if self.stats.state == CircuitState.OPEN:
            # Check if we should transition to half-open
            time_since_open = (datetime.now() - self.stats.state_changed_at).total_seconds()
            if time_since_open >= self.config.recovery_timeout:
                self.stats.state = CircuitState.HALF_OPEN
                self.stats.state_changed_at = datetime.now()
                self.stats.reset_counts()
                logger.info(f"Circuit breaker '{self.name}' transitioned to HALF_OPEN")

    def get_state(self) -> CircuitState:
        """Get current circuit breaker state."""
        return self.stats.state

    def get_stats(self) -> CircuitBreakerStats:
        """Get circuit breaker statistics."""
        return self.stats

    def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        self.stats = CircuitBreakerStats()
        self._recent_requests.clear()
        logger.info(f"Circuit breaker '{self.name}' reset to CLOSED state")


class CircuitBreakerManager:
    """
    Manager for multiple circuit breakers.

    Provides centralized management and monitoring of circuit breakers
    for different external dependencies.
    """

    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._default_config = CircuitBreakerConfig()

    def get_breaker(
        self, name: str, config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Get or create circuit breaker for named dependency."""
        if name not in self._breakers:
            breaker_config = config or self._default_config
            self._breakers[name] = CircuitBreaker(name, breaker_config)

        return self._breakers[name]

    def get_all_stats(self) -> Dict[str, CircuitBreakerStats]:
        """Get statistics for all circuit breakers."""
        return {name: breaker.get_stats() for name, breaker in self._breakers.items()}

    def reset_all(self) -> None:
        """Reset all circuit breakers."""
        for breaker in self._breakers.values():
            breaker.reset()

    def get_health_summary(self) -> Dict[str, Any]:
        """Get health summary of all circuit breakers."""
        summary = {
            "total_breakers": len(self._breakers),
            "healthy_breakers": 0,
            "open_breakers": 0,
            "half_open_breakers": 0,
            "breaker_details": {},
        }

        for name, breaker in self._breakers.items():
            stats = breaker.get_stats()
            state = stats.state

            if state == CircuitState.CLOSED:
                summary["healthy_breakers"] += 1
            elif state == CircuitState.OPEN:
                summary["open_breakers"] += 1
            elif state == CircuitState.HALF_OPEN:
                summary["half_open_breakers"] += 1

            summary["breaker_details"][name] = {
                "state": state.value,
                "failure_rate": stats.get_failure_rate(),
                "total_requests": stats.total_requests,
                "last_failure": (
                    stats.last_failure_time.isoformat() if stats.last_failure_time else None
                ),
            }

        return summary


# Global circuit breaker manager instance
circuit_breaker_manager = CircuitBreakerManager()


def with_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None):
    """
    Decorator to wrap functions with circuit breaker protection.

    Args:
        name: Circuit breaker name
        config: Optional circuit breaker configuration

    Usage:
        @with_circuit_breaker("external_api")
        async def call_external_api():
            # API call implementation
            pass
    """

    def decorator(func):
        async def wrapper(*args, **kwargs):
            breaker = circuit_breaker_manager.get_breaker(name, config)
            return await breaker.call(func, *args, **kwargs)

        return wrapper

    return decorator
