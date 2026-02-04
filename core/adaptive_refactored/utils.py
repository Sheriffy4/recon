"""
Utility functions for the refactored Adaptive Engine.

This module provides common utility functions to reduce code duplication
and improve maintainability across the refactored components.
"""

import logging
import functools
from typing import Any, Callable, Optional, TypeVar, Union
from contextlib import asynccontextmanager, contextmanager


logger = logging.getLogger(__name__)

T = TypeVar("T")


def handle_exceptions(
    default_return: Any = None,
    log_level: str = "error",
    reraise: bool = False,
    operation_name: Optional[str] = None,
):
    """
    Decorator to handle exceptions with consistent logging.

    Args:
        default_return: Value to return if exception occurs
        log_level: Logging level for exceptions (error, warning, info, debug)
        reraise: Whether to reraise the exception after logging
        operation_name: Name of the operation for logging context
    """

    def decorator(func: Callable[..., T]) -> Callable[..., Union[T, Any]]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                op_name = operation_name or func.__name__
                log_message = f"Error in {op_name}: {e}"

                log_func = getattr(logger, log_level, logger.error)
                log_func(log_message)

                if reraise:
                    raise
                return default_return

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                op_name = operation_name or func.__name__
                log_message = f"Error in {op_name}: {e}"

                log_func = getattr(logger, log_level, logger.error)
                log_func(log_message)

                if reraise:
                    raise
                return default_return

        # Return appropriate wrapper based on function type
        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return wrapper

    return decorator


@contextmanager
def log_operation(operation_name: str, log_level: str = "info"):
    """
    Context manager to log operation start and completion.

    Args:
        operation_name: Name of the operation
        log_level: Logging level for operation messages
    """
    log_func = getattr(logger, log_level, logger.info)
    log_func(f"Starting {operation_name}")

    try:
        yield
        log_func(f"Completed {operation_name}")
    except Exception as e:
        logger.error(f"Failed {operation_name}: {e}")
        raise


@asynccontextmanager
async def async_log_operation(operation_name: str, log_level: str = "info"):
    """
    Async context manager to log operation start and completion.

    Args:
        operation_name: Name of the operation
        log_level: Logging level for operation messages
    """
    log_func = getattr(logger, log_level, logger.info)
    log_func(f"Starting {operation_name}")

    try:
        yield
        log_func(f"Completed {operation_name}")
    except Exception as e:
        logger.error(f"Failed {operation_name}: {e}")
        raise


def safe_get_attribute(obj: Any, attr_name: str, default: Any = None) -> Any:
    """
    Safely get attribute from object with default fallback.

    Args:
        obj: Object to get attribute from
        attr_name: Name of the attribute
        default: Default value if attribute doesn't exist

    Returns:
        Attribute value or default
    """
    try:
        return getattr(obj, attr_name, default)
    except Exception as e:
        logger.debug(f"Error getting attribute {attr_name}: {e}")
        return default


def safe_dict_get(dictionary: dict, key: str, default: Any = None) -> Any:
    """
    Safely get value from dictionary with error handling.

    Args:
        dictionary: Dictionary to get value from
        key: Key to look up
        default: Default value if key doesn't exist or error occurs

    Returns:
        Dictionary value or default
    """
    try:
        return dictionary.get(key, default)
    except Exception as e:
        logger.debug(f"Error getting dictionary key {key}: {e}")
        return default


def validate_config_field(
    config: dict, field_name: str, field_type: type, default: Any = None
) -> Any:
    """
    Validate and extract configuration field with type checking.

    Args:
        config: Configuration dictionary
        field_name: Name of the field to validate
        field_type: Expected type of the field
        default: Default value if field is missing or invalid

    Returns:
        Validated field value or default
    """
    try:
        value = config.get(field_name, default)

        if value is None:
            return default

        if not isinstance(value, field_type):
            logger.warning(
                f"Config field {field_name} has wrong type. Expected {field_type.__name__}, got {type(value).__name__}"
            )
            return default

        return value

    except Exception as e:
        logger.error(f"Error validating config field {field_name}: {e}")
        return default


def format_error_message(operation: str, error: Exception, context: Optional[dict] = None) -> str:
    """
    Format consistent error messages with context.

    Args:
        operation: Name of the operation that failed
        error: The exception that occurred
        context: Additional context information

    Returns:
        Formatted error message
    """
    base_message = f"❌ {operation} failed: {error}"

    if context:
        context_str = ", ".join(f"{k}={v}" for k, v in context.items())
        base_message += f" (Context: {context_str})"

    return base_message


def log_performance_metric(operation: str, duration: float, threshold: float = 1.0):
    """
    Log performance metrics with appropriate level based on duration.

    Args:
        operation: Name of the operation
        duration: Duration in seconds
        threshold: Threshold for warning (default 1.0 second)
    """
    if duration > threshold:
        logger.warning(f"⚠️ Slow operation: {operation} took {duration:.2f}s")
    else:
        logger.debug(f"📊 {operation} completed in {duration:.2f}s")


class ServiceResolutionHelper:
    """Helper class for consistent service resolution patterns."""

    @staticmethod
    def resolve_service_safely(container, service_type, service_name: str = None):
        """
        Safely resolve service from DI container with consistent error handling.

        Args:
            container: Dependency injection container
            service_type: Type of service to resolve
            service_name: Optional name for logging

        Returns:
            Resolved service or None if resolution fails
        """
        name = service_name or service_type.__name__

        try:
            service = container.resolve(service_type)
            logger.debug(f"✅ Resolved {name}")
            return service
        except (ValueError, NotImplementedError) as e:
            logger.warning(f"⚠️ {name} not available: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Error resolving {name}: {e}")
            return None


def create_default_stats() -> dict:
    """Create default statistics dictionary with common fields."""
    return {
        "total_operations": 0,
        "successful_operations": 0,
        "failed_operations": 0,
        "average_duration": 0.0,
        "last_operation_time": None,
        "error_count": 0,
        "cache_hits": 0,
        "cache_misses": 0,
    }


def update_operation_stats(stats: dict, success: bool, duration: float = 0.0):
    """
    Update operation statistics with consistent patterns.

    Args:
        stats: Statistics dictionary to update
        success: Whether the operation was successful
        duration: Duration of the operation in seconds
    """
    try:
        stats["total_operations"] += 1

        if success:
            stats["successful_operations"] += 1
        else:
            stats["failed_operations"] += 1
            stats["error_count"] += 1

        # Update average duration
        if duration > 0:
            total_ops = stats["total_operations"]
            current_avg = stats.get("average_duration", 0.0)
            stats["average_duration"] = ((current_avg * (total_ops - 1)) + duration) / total_ops

        from datetime import datetime, timezone

        stats["last_operation_time"] = datetime.now(timezone.utc).isoformat()

    except Exception as e:
        logger.error(f"Error updating operation stats: {e}")
