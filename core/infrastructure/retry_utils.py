"""
Retry Utilities with Exponential Backoff

Provides retry configuration and utilities with exponential backoff and jitter
for handling transient failures in network operations and system calls.

Requirements: 9.4 - Implement exponential backoff with jitter for retry operations
"""

import asyncio
import random
import time
import logging
from typing import Callable, TypeVar, Awaitable, Tuple, Type, Union
from dataclasses import dataclass
from functools import wraps

T = TypeVar("T")


@dataclass
class RetryConfig:
    """
    Configuration for retry operations with exponential backoff.

    Requirement 9.4: Exponential backoff with jitter for retry operations.
    """

    max_attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 30.0
    exponential_base: float = 2.0
    jitter_factor: float = 0.1

    def get_delay(self, attempt: int) -> float:
        """
        Calculate delay for given attempt with exponential backoff and jitter.

        Args:
            attempt: Current attempt number (0-based)

        Returns:
            Delay in seconds with jitter applied

        Requirement 9.4: Exponential backoff with jitter.
        """
        # Calculate exponential delay
        delay = min(self.base_delay * (self.exponential_base**attempt), self.max_delay)

        # Apply jitter to avoid thundering herd
        jitter = delay * self.jitter_factor * random.random()

        return delay + jitter

    def validate(self) -> None:
        """Validate configuration parameters."""
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.base_delay < 0:
            raise ValueError("base_delay must be non-negative")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must be >= base_delay")
        if self.exponential_base <= 1:
            raise ValueError("exponential_base must be > 1")
        if not (0 <= self.jitter_factor <= 1):
            raise ValueError("jitter_factor must be between 0 and 1")


async def retry_async(
    func: Callable[[], Awaitable[T]],
    config: RetryConfig = RetryConfig(),
    retryable_exceptions: Tuple[Type[Exception], ...] = (
        asyncio.TimeoutError,
        ConnectionError,
        OSError,
    ),
    logger: logging.Logger = None,
) -> T:
    """
    Async retry with exponential backoff and jitter.

    Args:
        func: Async function to retry
        config: Retry configuration
        retryable_exceptions: Tuple of exception types to retry on
        logger: Optional logger for retry attempts

    Returns:
        Result of successful function call

    Raises:
        Last exception if all attempts fail

    Requirement 9.4: Exponential backoff with jitter for retry operations.
    """
    config.validate()

    if logger is None:
        logger = logging.getLogger(__name__)

    last_exception = None

    for attempt in range(config.max_attempts):
        try:
            result = await func()

            if attempt > 0:
                logger.info(f"Retry succeeded on attempt {attempt + 1}")

            return result

        except retryable_exceptions as e:
            last_exception = e

            if attempt < config.max_attempts - 1:
                delay = config.get_delay(attempt)
                logger.warning(
                    f"Attempt {attempt + 1} failed: {e}. " f"Retrying in {delay:.2f}s..."
                )
                await asyncio.sleep(delay)
            else:
                logger.error(f"All {config.max_attempts} attempts failed. " f"Last error: {e}")

        except Exception as e:
            # Non-retryable exception
            logger.error(f"Non-retryable exception on attempt {attempt + 1}: {e}")
            raise

    # This should never be reached, but just in case
    if last_exception:
        raise last_exception
    else:
        raise RuntimeError("Retry loop completed without result or exception")


def retry_sync(
    func: Callable[[], T],
    config: RetryConfig = RetryConfig(),
    retryable_exceptions: Tuple[Type[Exception], ...] = (ConnectionError, OSError, TimeoutError),
    logger: logging.Logger = None,
) -> T:
    """
    Synchronous retry with exponential backoff and jitter.

    Args:
        func: Function to retry
        config: Retry configuration
        retryable_exceptions: Tuple of exception types to retry on
        logger: Optional logger for retry attempts

    Returns:
        Result of successful function call

    Raises:
        Last exception if all attempts fail

    Requirement 9.4: Exponential backoff with jitter for retry operations.
    """
    config.validate()

    if logger is None:
        logger = logging.getLogger(__name__)

    last_exception = None

    for attempt in range(config.max_attempts):
        try:
            result = func()

            if attempt > 0:
                logger.info(f"Retry succeeded on attempt {attempt + 1}")

            return result

        except retryable_exceptions as e:
            last_exception = e

            if attempt < config.max_attempts - 1:
                delay = config.get_delay(attempt)
                logger.warning(
                    f"Attempt {attempt + 1} failed: {e}. " f"Retrying in {delay:.2f}s..."
                )
                time.sleep(delay)
            else:
                logger.error(f"All {config.max_attempts} attempts failed. " f"Last error: {e}")

        except Exception as e:
            # Non-retryable exception
            logger.error(f"Non-retryable exception on attempt {attempt + 1}: {e}")
            raise

    # This should never be reached, but just in case
    if last_exception:
        raise last_exception
    else:
        raise RuntimeError("Retry loop completed without result or exception")


def retryable_async(
    config: RetryConfig = RetryConfig(),
    retryable_exceptions: Tuple[Type[Exception], ...] = (
        asyncio.TimeoutError,
        ConnectionError,
        OSError,
    ),
):
    """
    Decorator for async functions with retry logic.

    Args:
        config: Retry configuration
        retryable_exceptions: Tuple of exception types to retry on

    Returns:
        Decorated function with retry logic
    """

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            logger = logging.getLogger(func.__module__)

            async def retry_func():
                return await func(*args, **kwargs)

            return await retry_async(
                retry_func, config=config, retryable_exceptions=retryable_exceptions, logger=logger
            )

        return wrapper

    return decorator


def retryable_sync(
    config: RetryConfig = RetryConfig(),
    retryable_exceptions: Tuple[Type[Exception], ...] = (ConnectionError, OSError, TimeoutError),
):
    """
    Decorator for synchronous functions with retry logic.

    Args:
        config: Retry configuration
        retryable_exceptions: Tuple of exception types to retry on

    Returns:
        Decorated function with retry logic
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            logger = logging.getLogger(func.__module__)

            def retry_func():
                return func(*args, **kwargs)

            return retry_sync(
                retry_func, config=config, retryable_exceptions=retryable_exceptions, logger=logger
            )

        return wrapper

    return decorator


# Convenience functions with common configurations


def retry_network_async(
    func: Callable[[], Awaitable[T]],
    max_attempts: int = 3,
    base_delay: float = 1.0,
    logger: logging.Logger = None,
) -> Awaitable[T]:
    """Retry async network operations with common configuration."""
    config = RetryConfig(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=30.0,
        exponential_base=2.0,
        jitter_factor=0.1,
    )

    return retry_async(
        func,
        config=config,
        retryable_exceptions=(asyncio.TimeoutError, ConnectionError, OSError, TimeoutError),
        logger=logger,
    )


def retry_network_sync(
    func: Callable[[], T],
    max_attempts: int = 3,
    base_delay: float = 1.0,
    logger: logging.Logger = None,
) -> T:
    """Retry sync network operations with common configuration."""
    config = RetryConfig(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=30.0,
        exponential_base=2.0,
        jitter_factor=0.1,
    )

    return retry_sync(
        func,
        config=config,
        retryable_exceptions=(ConnectionError, OSError, TimeoutError),
        logger=logger,
    )
