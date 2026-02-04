"""
Retry mechanisms with exponential backoff and detailed error context.

Provides intelligent retry strategies for transient failures with
comprehensive error reporting and recovery suggestions.
"""

import asyncio
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, Union
import logging

logger = logging.getLogger(__name__)

T = TypeVar("T")


class RetryStrategy(Enum):
    """Different retry strategies available."""

    FIXED_DELAY = "fixed_delay"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    FIBONACCI_BACKOFF = "fibonacci_backoff"
    JITTERED_EXPONENTIAL = "jittered_exponential"


class StopCondition(Enum):
    """Conditions for stopping retry attempts."""

    MAX_ATTEMPTS = "max_attempts"
    MAX_DURATION = "max_duration"
    SPECIFIC_EXCEPTION = "specific_exception"
    CUSTOM_CONDITION = "custom_condition"


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_attempts: int = 3
    base_delay: float = 1.0  # Base delay in seconds
    max_delay: float = 60.0  # Maximum delay in seconds
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    backoff_multiplier: float = 2.0
    jitter: bool = True  # Add randomness to delays

    # Advanced configuration
    max_duration: Optional[float] = None  # Maximum total retry duration
    retryable_exceptions: List[Type[Exception]] = field(default_factory=lambda: [Exception])
    non_retryable_exceptions: List[Type[Exception]] = field(default_factory=list)

    # Context and recovery
    include_error_context: bool = True
    generate_recovery_suggestions: bool = True

    def __post_init__(self):
        """Validate configuration after initialization."""
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.base_delay < 0:
            raise ValueError("base_delay must be non-negative")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must be >= base_delay")


@dataclass
class RetryAttempt:
    """Information about a retry attempt."""

    attempt_number: int
    delay_before_attempt: float
    exception: Optional[Exception] = None
    timestamp: datetime = field(default_factory=datetime.now)
    execution_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert retry attempt to dictionary."""
        return {
            "attempt_number": self.attempt_number,
            "delay_before_attempt": self.delay_before_attempt,
            "exception": str(self.exception) if self.exception else None,
            "timestamp": self.timestamp.isoformat(),
            "execution_time": self.execution_time,
        }


@dataclass
class ErrorContext:
    """Detailed context about an error and retry attempts."""

    operation_name: str
    total_attempts: int
    total_duration: float
    final_exception: Exception
    retry_attempts: List[RetryAttempt] = field(default_factory=list)
    recovery_suggestions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert error context to dictionary."""
        return {
            "operation_name": self.operation_name,
            "total_attempts": self.total_attempts,
            "total_duration": self.total_duration,
            "final_exception": str(self.final_exception),
            "final_exception_type": type(self.final_exception).__name__,
            "retry_attempts": [attempt.to_dict() for attempt in self.retry_attempts],
            "recovery_suggestions": self.recovery_suggestions,
            "metadata": self.metadata,
        }

    def get_failure_pattern(self) -> str:
        """Analyze failure pattern from retry attempts."""
        if not self.retry_attempts:
            return "single_failure"

        exception_types = [
            type(attempt.exception).__name__ for attempt in self.retry_attempts if attempt.exception
        ]

        if len(set(exception_types)) == 1:
            return f"consistent_{exception_types[0].lower()}"
        elif len(exception_types) > len(set(exception_types)):
            return "intermittent_failures"
        else:
            return "varied_failures"


class RetryExhaustedException(Exception):
    """Exception raised when all retry attempts are exhausted."""

    def __init__(self, error_context: ErrorContext):
        self.error_context = error_context
        super().__init__(
            f"Retry exhausted after {error_context.total_attempts} attempts: {error_context.final_exception}"
        )


class IRetryMechanism(ABC):
    """Interface for retry mechanism implementations."""

    @abstractmethod
    async def execute_with_retry(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with retry logic."""
        pass

    @abstractmethod
    def should_retry(self, exception: Exception, attempt_number: int) -> bool:
        """Determine if operation should be retried."""
        pass

    @abstractmethod
    def calculate_delay(self, attempt_number: int) -> float:
        """Calculate delay before next retry attempt."""
        pass


class RetryMechanism(IRetryMechanism):
    """
    Comprehensive retry mechanism with exponential backoff and error context.

    Provides intelligent retry strategies with detailed error reporting,
    recovery suggestions, and failure pattern analysis.
    """

    def __init__(self, config: RetryConfig, operation_name: str = "unknown_operation"):
        self.config = config
        self.operation_name = operation_name
        self._fibonacci_cache = [1, 1]  # For Fibonacci backoff

        logger.debug(f"Retry mechanism initialized for '{operation_name}' with config: {config}")

    async def execute_with_retry(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute function with retry logic and comprehensive error handling.

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result

        Raises:
            RetryExhaustedException: When all retry attempts are exhausted
        """
        start_time = time.time()
        retry_attempts: List[RetryAttempt] = []
        last_exception: Optional[Exception] = None

        for attempt in range(1, self.config.max_attempts + 1):
            # Calculate delay for this attempt (0 for first attempt)
            delay = 0.0 if attempt == 1 else self.calculate_delay(attempt - 1)

            # Check if we've exceeded maximum duration
            if self.config.max_duration:
                elapsed = time.time() - start_time
                if elapsed + delay > self.config.max_duration:
                    logger.warning(
                        f"Stopping retries for '{self.operation_name}' due to max duration"
                    )
                    break

            # Wait before attempt (except first)
            if delay > 0:
                logger.debug(
                    f"Waiting {delay:.2f}s before retry attempt {attempt} for '{self.operation_name}'"
                )
                await asyncio.sleep(delay)

            # Record attempt
            attempt_start = time.time()
            retry_attempt = RetryAttempt(attempt_number=attempt, delay_before_attempt=delay)

            try:
                # Execute the function
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                retry_attempt.execution_time = time.time() - attempt_start
                retry_attempts.append(retry_attempt)

                logger.debug(f"Operation '{self.operation_name}' succeeded on attempt {attempt}")
                return result

            except Exception as e:
                retry_attempt.exception = e
                retry_attempt.execution_time = time.time() - attempt_start
                retry_attempts.append(retry_attempt)
                last_exception = e

                logger.warning(f"Attempt {attempt} failed for '{self.operation_name}': {e}")

                # Check if we should retry
                if attempt < self.config.max_attempts and self.should_retry(e, attempt):
                    continue
                else:
                    break

        # All retries exhausted, create error context
        total_duration = time.time() - start_time
        error_context = ErrorContext(
            operation_name=self.operation_name,
            total_attempts=len(retry_attempts),
            total_duration=total_duration,
            final_exception=last_exception or Exception("Unknown error"),
            retry_attempts=retry_attempts,
        )

        # Generate recovery suggestions if enabled
        if self.config.generate_recovery_suggestions:
            error_context.recovery_suggestions = self._generate_recovery_suggestions(error_context)

        # Add metadata
        error_context.metadata = {
            "retry_strategy": self.config.strategy.value,
            "max_attempts_configured": self.config.max_attempts,
            "base_delay": self.config.base_delay,
            "failure_pattern": error_context.get_failure_pattern(),
        }

        logger.error(
            f"All retry attempts exhausted for '{self.operation_name}': {error_context.to_dict()}"
        )
        raise RetryExhaustedException(error_context)

    def should_retry(self, exception: Exception, attempt_number: int) -> bool:
        """
        Determine if operation should be retried based on exception type and attempt number.

        Args:
            exception: Exception that occurred
            attempt_number: Current attempt number

        Returns:
            True if should retry, False otherwise
        """
        # Check non-retryable exceptions first
        for non_retryable in self.config.non_retryable_exceptions:
            if isinstance(exception, non_retryable):
                logger.debug(
                    f"Not retrying due to non-retryable exception: {type(exception).__name__}"
                )
                return False

        # Check retryable exceptions
        for retryable in self.config.retryable_exceptions:
            if isinstance(exception, retryable):
                return True

        # Default behavior based on exception type
        retryable_by_default = [
            asyncio.TimeoutError,
            ConnectionError,
            OSError,  # Network-related errors
            MemoryError,  # Temporary resource issues
        ]

        return any(isinstance(exception, exc_type) for exc_type in retryable_by_default)

    def calculate_delay(self, attempt_number: int) -> float:
        """
        Calculate delay before next retry attempt based on strategy.

        Args:
            attempt_number: Current attempt number (1-based)

        Returns:
            Delay in seconds
        """
        if self.config.strategy == RetryStrategy.FIXED_DELAY:
            delay = self.config.base_delay

        elif self.config.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = self.config.base_delay * (
                self.config.backoff_multiplier ** (attempt_number - 1)
            )

        elif self.config.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = self.config.base_delay * attempt_number

        elif self.config.strategy == RetryStrategy.FIBONACCI_BACKOFF:
            delay = self.config.base_delay * self._get_fibonacci(attempt_number)

        elif self.config.strategy == RetryStrategy.JITTERED_EXPONENTIAL:
            base_delay = self.config.base_delay * (
                self.config.backoff_multiplier ** (attempt_number - 1)
            )
            jitter = random.uniform(0.5, 1.5)  # ±50% jitter
            delay = base_delay * jitter

        else:
            delay = self.config.base_delay

        # Apply jitter if enabled (except for jittered exponential which already has it)
        if self.config.jitter and self.config.strategy != RetryStrategy.JITTERED_EXPONENTIAL:
            jitter_factor = random.uniform(0.8, 1.2)  # ±20% jitter
            delay *= jitter_factor

        # Ensure delay doesn't exceed maximum
        delay = min(delay, self.config.max_delay)

        return delay

    def _get_fibonacci(self, n: int) -> int:
        """Get nth Fibonacci number (cached for efficiency)."""
        while len(self._fibonacci_cache) <= n:
            next_fib = self._fibonacci_cache[-1] + self._fibonacci_cache[-2]
            self._fibonacci_cache.append(next_fib)

        return self._fibonacci_cache[n]

    def _generate_recovery_suggestions(self, error_context: ErrorContext) -> List[str]:
        """
        Generate recovery suggestions based on error context and failure patterns.

        Args:
            error_context: Context about the failed operation

        Returns:
            List of recovery suggestions
        """
        suggestions = []
        final_exception = error_context.final_exception
        failure_pattern = error_context.get_failure_pattern()

        # Exception-specific suggestions
        if isinstance(final_exception, asyncio.TimeoutError):
            suggestions.extend(
                [
                    "Increase operation timeout values",
                    "Check network connectivity and latency",
                    "Consider using async operations with proper timeout handling",
                    "Verify target service is responsive",
                ]
            )

        elif isinstance(final_exception, ConnectionError):
            suggestions.extend(
                [
                    "Verify network connectivity",
                    "Check if target service is running and accessible",
                    "Review firewall and security group settings",
                    "Consider connection pooling or keep-alive settings",
                ]
            )

        elif isinstance(final_exception, MemoryError):
            suggestions.extend(
                [
                    "Increase available memory or optimize memory usage",
                    "Implement data streaming or chunking",
                    "Review memory leaks in the application",
                    "Consider using memory-efficient data structures",
                ]
            )

        elif isinstance(final_exception, PermissionError):
            suggestions.extend(
                [
                    "Check file/directory permissions",
                    "Verify authentication credentials",
                    "Review access control settings",
                    "Run with appropriate privileges if necessary",
                ]
            )

        # Pattern-specific suggestions
        if failure_pattern.startswith("consistent_"):
            suggestions.append(
                "Consistent failure pattern detected - investigate root cause rather than retrying"
            )

        elif failure_pattern == "intermittent_failures":
            suggestions.extend(
                [
                    "Intermittent failures detected - may be transient issues",
                    "Consider increasing retry attempts or delays",
                    "Monitor system resources and external dependencies",
                ]
            )

        elif failure_pattern == "varied_failures":
            suggestions.extend(
                [
                    "Multiple failure types detected - investigate system stability",
                    "Review logs for common patterns or triggers",
                    "Consider implementing circuit breaker pattern",
                ]
            )

        # Duration-based suggestions
        if error_context.total_duration > 60:  # More than 1 minute
            suggestions.append("Long retry duration - consider reducing max attempts or delays")

        # Attempt-based suggestions
        if error_context.total_attempts >= self.config.max_attempts:
            suggestions.extend(
                [
                    "All retry attempts exhausted - investigate underlying issue",
                    "Consider implementing fallback mechanisms",
                    "Review retry configuration (attempts, delays, strategy)",
                ]
            )

        return suggestions


class RetryManager:
    """
    Manager for multiple retry mechanisms with different configurations.

    Provides centralized retry management for different operation types
    with appropriate retry strategies and configurations.
    """

    def __init__(self, config: Optional["ErrorHandlingConfig"] = None):
        from ..config import ErrorHandlingConfig  # Import here to avoid circular imports

        self._retry_configs: Dict[str, RetryConfig] = {}

        # Create default config from ErrorHandlingConfig if provided
        if config:
            self._default_config = RetryConfig(
                max_attempts=config.max_retries,
                base_delay=config.retry_base_delay,
                max_delay=config.retry_max_delay,
                backoff_multiplier=config.retry_exponential_base,
                strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            )
        else:
            self._default_config = RetryConfig()

        self._retry_stats: Dict[str, Dict[str, Any]] = {}

    def register_config(self, operation_type: str, config: RetryConfig) -> None:
        """Register retry configuration for operation type."""
        self._retry_configs[operation_type] = config
        self._retry_stats[operation_type] = {
            "total_operations": 0,
            "successful_operations": 0,
            "failed_operations": 0,
            "total_retry_attempts": 0,
            "average_attempts_per_operation": 0.0,
        }

        logger.info(f"Registered retry config for operation type '{operation_type}': {config}")

    def get_retry_mechanism(
        self, operation_type: str, operation_name: str = None
    ) -> RetryMechanism:
        """Get retry mechanism for operation type."""
        config = self._retry_configs.get(operation_type, self._default_config)
        name = operation_name or f"{operation_type}_operation"
        return RetryMechanism(config, name)

    async def execute_with_retry(
        self,
        operation_type: str,
        func: Callable[..., T],
        operation_name: str = None,
        *args,
        **kwargs,
    ) -> T:
        """
        Execute function with retry using registered configuration.

        Args:
            operation_type: Type of operation (for config lookup)
            func: Function to execute
            operation_name: Optional specific operation name
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result
        """
        retry_mechanism = self.get_retry_mechanism(operation_type, operation_name)

        # Update stats
        stats = self._retry_stats.get(operation_type, {})
        stats["total_operations"] = stats.get("total_operations", 0) + 1

        try:
            result = await retry_mechanism.execute_with_retry(func, *args, **kwargs)
            stats["successful_operations"] = stats.get("successful_operations", 0) + 1
            return result

        except RetryExhaustedException as e:
            stats["failed_operations"] = stats.get("failed_operations", 0) + 1
            stats["total_retry_attempts"] = (
                stats.get("total_retry_attempts", 0) + e.error_context.total_attempts
            )

            # Update average attempts
            total_ops = stats["total_operations"]
            if total_ops > 0:
                stats["average_attempts_per_operation"] = stats["total_retry_attempts"] / total_ops

            raise

    def get_retry_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get retry statistics for all operation types."""
        return self._retry_stats.copy()

    def reset_stats(self, operation_type: Optional[str] = None) -> None:
        """Reset retry statistics."""
        if operation_type:
            if operation_type in self._retry_stats:
                self._retry_stats[operation_type] = {
                    "total_operations": 0,
                    "successful_operations": 0,
                    "failed_operations": 0,
                    "total_retry_attempts": 0,
                    "average_attempts_per_operation": 0.0,
                }
        else:
            for op_type in self._retry_stats:
                self.reset_stats(op_type)


# Global retry manager instance
retry_manager = RetryManager()


def with_retry(
    operation_type: str, config: Optional[RetryConfig] = None, operation_name: Optional[str] = None
):
    """
    Decorator to add retry functionality to functions.

    Args:
        operation_type: Type of operation for configuration lookup
        config: Optional specific retry configuration
        operation_name: Optional specific operation name

    Usage:
        @with_retry("network_operation", RetryConfig(max_attempts=5))
        async def call_external_api():
            # API call implementation
            pass
    """

    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Register config if provided
            if config:
                retry_manager.register_config(operation_type, config)

            name = operation_name or func.__name__
            return await retry_manager.execute_with_retry(
                operation_type, func, name, *args, **kwargs
            )

        return wrapper

    return decorator


# Predefined retry configurations for common scenarios
NETWORK_RETRY_CONFIG = RetryConfig(
    max_attempts=5,
    base_delay=1.0,
    max_delay=30.0,
    strategy=RetryStrategy.JITTERED_EXPONENTIAL,
    retryable_exceptions=[ConnectionError, asyncio.TimeoutError, OSError],
    non_retryable_exceptions=[PermissionError, ValueError],
)

DATABASE_RETRY_CONFIG = RetryConfig(
    max_attempts=3,
    base_delay=0.5,
    max_delay=10.0,
    strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
    retryable_exceptions=[ConnectionError, OSError],
    non_retryable_exceptions=[ValueError, TypeError],
)

FILE_OPERATION_RETRY_CONFIG = RetryConfig(
    max_attempts=3,
    base_delay=0.1,
    max_delay=5.0,
    strategy=RetryStrategy.LINEAR_BACKOFF,
    retryable_exceptions=[OSError, PermissionError],
    non_retryable_exceptions=[ValueError, FileNotFoundError],
)

STRATEGY_GENERATION_RETRY_CONFIG = RetryConfig(
    max_attempts=3,
    base_delay=2.0,
    max_delay=15.0,
    strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
    max_duration=60.0,  # Don't retry for more than 1 minute
    retryable_exceptions=[ConnectionError, asyncio.TimeoutError, MemoryError],
    non_retryable_exceptions=[ValueError, TypeError, AttributeError],
)

PCAP_ANALYSIS_RETRY_CONFIG = RetryConfig(
    max_attempts=2,
    base_delay=1.0,
    max_delay=10.0,
    strategy=RetryStrategy.FIXED_DELAY,
    retryable_exceptions=[OSError, MemoryError],
    non_retryable_exceptions=[ValueError, FileNotFoundError],
)


def setup_default_retry_configs():
    """Setup default retry configurations for common operation types."""
    retry_manager.register_config("network_operation", NETWORK_RETRY_CONFIG)
    retry_manager.register_config("database_operation", DATABASE_RETRY_CONFIG)
    retry_manager.register_config("file_operation", FILE_OPERATION_RETRY_CONFIG)
    retry_manager.register_config("strategy_generation", STRATEGY_GENERATION_RETRY_CONFIG)
    retry_manager.register_config("pcap_analysis", PCAP_ANALYSIS_RETRY_CONFIG)

    logger.info("Default retry configurations registered")


# Initialize default configurations
setup_default_retry_configs()
