"""
Integration utilities for adding structured logging and monitoring
to existing adaptive engine components.
"""

import functools
import time
from typing import Any, Callable, Optional, TypeVar, Union

from .structured_logging import get_structured_logger, LogCategory, LogContext, StructuredLogger
from .monitoring_system import MonitoringSystem, HealthStatus
from ..config import AdaptiveEngineConfig

T = TypeVar("T")


def with_structured_logging(
    category: LogCategory = LogCategory.SYSTEM,
    log_args: bool = False,
    log_result: bool = False,
    log_duration: bool = True,
):
    """
    Decorator to add structured logging to methods.

    Args:
        category: Log category for the operation
        log_args: Whether to log method arguments
        log_result: Whether to log method result
        log_duration: Whether to log operation duration
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get logger from the instance if available
            logger = None
            if args and hasattr(args[0], "_logger"):
                logger = args[0]._logger
            elif args and hasattr(args[0], "logger"):
                logger = args[0].logger
            else:
                logger = get_structured_logger(func.__module__)

            operation_name = f"{func.__qualname__}"
            context = LogContext(operation=operation_name, component=func.__module__)

            # Log method arguments if requested
            if log_args:
                arg_info = {"args_count": len(args), "kwargs_keys": list(kwargs.keys())}
                logger.debug(
                    f"Calling {operation_name}",
                    category=category,
                    context=context,
                    metadata=arg_info,
                )

            start_time = time.time()

            try:
                result = func(*args, **kwargs)

                duration_ms = (time.time() - start_time) * 1000 if log_duration else None

                # Log result if requested
                if log_result:
                    result_info = {
                        "result_type": type(result).__name__,
                        "result_size": len(result) if hasattr(result, "__len__") else None,
                    }
                    logger.info(
                        f"Completed {operation_name}",
                        category=category,
                        context=context,
                        duration_ms=duration_ms,
                        metadata=result_info,
                    )
                elif log_duration:
                    logger.debug(
                        f"Completed {operation_name}",
                        category=category,
                        context=context,
                        duration_ms=duration_ms,
                    )

                return result

            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                error_details = {"exception_type": type(e).__name__, "exception_message": str(e)}
                logger.error(
                    f"Failed {operation_name}",
                    category=LogCategory.ERROR,
                    context=context,
                    duration_ms=duration_ms,
                    error_details=error_details,
                )
                raise

        return wrapper

    return decorator


def with_async_structured_logging(
    category: LogCategory = LogCategory.SYSTEM,
    log_args: bool = False,
    log_result: bool = False,
    log_duration: bool = True,
):
    """
    Decorator to add structured logging to async methods.

    Args:
        category: Log category for the operation
        log_args: Whether to log method arguments
        log_result: Whether to log method result
        log_duration: Whether to log operation duration
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Get logger from the instance if available
            logger = None
            if args and hasattr(args[0], "_logger"):
                logger = args[0]._logger
            elif args and hasattr(args[0], "logger"):
                logger = args[0].logger
            else:
                logger = get_structured_logger(func.__module__)

            operation_name = f"{func.__qualname__}"
            context = LogContext(operation=operation_name, component=func.__module__)

            # Log method arguments if requested
            if log_args:
                arg_info = {"args_count": len(args), "kwargs_keys": list(kwargs.keys())}
                logger.debug(
                    f"Calling {operation_name}",
                    category=category,
                    context=context,
                    metadata=arg_info,
                )

            start_time = time.time()

            try:
                result = await func(*args, **kwargs)

                duration_ms = (time.time() - start_time) * 1000 if log_duration else None

                # Log result if requested
                if log_result:
                    result_info = {
                        "result_type": type(result).__name__,
                        "result_size": len(result) if hasattr(result, "__len__") else None,
                    }
                    logger.info(
                        f"Completed {operation_name}",
                        category=category,
                        context=context,
                        duration_ms=duration_ms,
                        metadata=result_info,
                    )
                elif log_duration:
                    logger.debug(
                        f"Completed {operation_name}",
                        category=category,
                        context=context,
                        duration_ms=duration_ms,
                    )

                return result

            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                error_details = {"exception_type": type(e).__name__, "exception_message": str(e)}
                logger.error(
                    f"Failed {operation_name}",
                    category=LogCategory.ERROR,
                    context=context,
                    duration_ms=duration_ms,
                    error_details=error_details,
                )
                raise

        return wrapper

    return decorator


def with_monitoring(
    monitoring_system: Optional[MonitoringSystem] = None,
    component_name: Optional[str] = None,
    health_check: bool = False,
):
    """
    Decorator to add monitoring to methods.

    Args:
        monitoring_system: MonitoringSystem instance
        component_name: Name of the component for monitoring
        health_check: Whether to register this as a health check
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get monitoring system from instance if available
            monitor = monitoring_system
            if not monitor and args and hasattr(args[0], "_monitoring_system"):
                monitor = args[0]._monitoring_system
            elif not monitor and args and hasattr(args[0], "monitoring_system"):
                monitor = args[0].monitoring_system

            component = component_name or func.__module__
            operation_name = f"{func.__qualname__}"

            if monitor:
                # Update component status to healthy when method is called
                monitor.update_component_status(component, HealthStatus.HEALTHY)

                # Record operation timing
                start_time = time.time()

                try:
                    result = func(*args, **kwargs)

                    duration_ms = (time.time() - start_time) * 1000
                    monitor.record_metric(f"{operation_name}_duration_ms", duration_ms, "timer")
                    monitor.record_metric(f"{operation_name}_success_count", 1, "counter")

                    return result

                except Exception as e:
                    duration_ms = (time.time() - start_time) * 1000
                    monitor.record_metric(f"{operation_name}_duration_ms", duration_ms, "timer")
                    monitor.record_metric(f"{operation_name}_error_count", 1, "counter")

                    # Update component status to warning on error
                    monitor.update_component_status(component, HealthStatus.WARNING)

                    raise
            else:
                return func(*args, **kwargs)

        return wrapper

    return decorator


class LoggingMixin:
    """Mixin class to add structured logging capabilities to any class."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._logger = get_structured_logger(
            self.__class__.__module__, getattr(self, "config", None)
        )

    @property
    def logger(self) -> StructuredLogger:
        """Get the structured logger for this instance."""
        return self._logger

    def log_operation(
        self, operation: str, category: LogCategory = LogCategory.SYSTEM, **context_kwargs
    ):
        """Get operation context manager for logging."""
        return self._logger.operation_context(operation, category, **context_kwargs)

    def async_log_operation(
        self, operation: str, category: LogCategory = LogCategory.SYSTEM, **context_kwargs
    ):
        """Get async operation context manager for logging."""
        return self._logger.async_operation_context(operation, category, **context_kwargs)


class MonitoringMixin:
    """Mixin class to add monitoring capabilities to any class."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        config = getattr(self, "config", None)
        if config:
            self._monitoring_system = MonitoringSystem(config)
        else:
            self._monitoring_system = None

    @property
    def monitoring_system(self) -> Optional[MonitoringSystem]:
        """Get the monitoring system for this instance."""
        return self._monitoring_system

    def update_health_status(self, status: HealthStatus):
        """Update the health status of this component."""
        if self._monitoring_system:
            component_name = self.__class__.__name__
            self._monitoring_system.update_component_status(component_name, status)

    def record_metric(self, name: str, value: float, metric_type: str = "gauge"):
        """Record a custom metric."""
        if self._monitoring_system:
            self._monitoring_system.record_metric(name, value, metric_type)

    def create_alert(self, severity, title: str, description: str, metadata: Optional[dict] = None):
        """Create an alert for this component."""
        if self._monitoring_system:
            component_name = self.__class__.__name__
            return self._monitoring_system.create_alert(
                severity, title, description, component_name, metadata
            )


class ObservabilityMixin(LoggingMixin, MonitoringMixin):
    """Combined mixin for both logging and monitoring capabilities."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


def setup_component_observability(
    component_class: type,
    config: AdaptiveEngineConfig,
    enable_logging: bool = True,
    enable_monitoring: bool = True,
) -> type:
    """
    Set up observability (logging and monitoring) for a component class.

    Args:
        component_class: The class to enhance with observability
        config: Configuration for the observability setup
        enable_logging: Whether to enable structured logging
        enable_monitoring: Whether to enable monitoring

    Returns:
        Enhanced class with observability capabilities
    """

    class ObservableComponent(component_class):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

            if enable_logging:
                self._logger = get_structured_logger(self.__class__.__module__, config)

            if enable_monitoring:
                self._monitoring_system = MonitoringSystem(config)

        @property
        def logger(self) -> Optional[StructuredLogger]:
            return getattr(self, "_logger", None)

        @property
        def monitoring_system(self) -> Optional[MonitoringSystem]:
            return getattr(self, "_monitoring_system", None)

    # Copy class metadata
    ObservableComponent.__name__ = component_class.__name__
    ObservableComponent.__qualname__ = component_class.__qualname__
    ObservableComponent.__module__ = component_class.__module__

    return ObservableComponent


# Convenience functions for common logging patterns
def log_strategy_operation(
    logger: StructuredLogger, operation: str, domain: str, strategy_name: str
):
    """Log a strategy-related operation with standard context."""
    context = LogContext(domain=domain, strategy_name=strategy_name, operation=operation)
    return logger.operation_context(operation, LogCategory.STRATEGY, **context.__dict__)


def log_testing_operation(logger: StructuredLogger, operation: str, domain: str, test_mode: str):
    """Log a testing-related operation with standard context."""
    context = LogContext(domain=domain, operation=operation, metadata={"test_mode": test_mode})
    return logger.operation_context(operation, LogCategory.TESTING, **context.__dict__)


def log_cache_operation(logger: StructuredLogger, operation: str, cache_type: str, key: str):
    """Log a cache-related operation with standard context."""
    context = LogContext(operation=operation, metadata={"cache_type": cache_type, "cache_key": key})
    return logger.operation_context(operation, LogCategory.CACHE, **context.__dict__)


def log_performance_operation(logger: StructuredLogger, operation: str, component: str):
    """Log a performance-related operation with standard context."""
    context = LogContext(component=component, operation=operation)
    return logger.operation_context(operation, LogCategory.PERFORMANCE, **context.__dict__)
