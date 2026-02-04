"""
StructuredLogger for Machine-Readable Logging

Provides structured, machine-readable logging with JSON format for
better searchability and analysis of system operations.

Requirements: 8.5 - Provide structured, searchable log entries
"""

import json
import logging
import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path


class LogLevel(Enum):
    """Log levels for structured logging."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class LogCategory(Enum):
    """Categories for structured logging."""

    SYSTEM = "system"
    STRATEGY = "strategy"
    NETWORK = "network"
    VALIDATION = "validation"
    PERFORMANCE = "performance"
    ERROR = "error"


@dataclass
class LogEntry:
    """Structured log entry."""

    timestamp: str
    level: str
    category: str
    message: str
    context: Dict[str, Any]
    session_id: Optional[str] = None
    component: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class StructuredLogger:
    """
    Structured logger for machine-readable logging.

    Provides JSON-formatted logging with contextual information
    as required by Requirement 8.5.
    """

    def __init__(
        self,
        name: str = "UnifiedBypassEngine",
        log_file: Optional[str] = None,
        enable_console: bool = True,
        session_id: Optional[str] = None,
    ):
        """
        Initialize structured logger.

        Args:
            name: Logger name
            log_file: Optional log file path
            enable_console: Whether to enable console output
            session_id: Optional session identifier
        """
        self.name = name
        self.session_id = session_id or f"session_{int(time.time())}"
        self.enable_console = enable_console

        # Thread safety
        self.lock = threading.RLock()

        # Setup Python logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        # Clear existing handlers
        self.logger.handlers.clear()

        # Setup file handler if specified
        if log_file:
            self._setup_file_handler(log_file)

        # Setup console handler if enabled
        if enable_console:
            self._setup_console_handler()

    def _setup_file_handler(self, log_file: str) -> None:
        """Setup file handler for structured logging."""
        try:
            # Ensure directory exists
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # Create file handler
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)

            # Use custom formatter for JSON output
            file_handler.setFormatter(self._create_json_formatter())

            self.logger.addHandler(file_handler)

        except Exception as e:
            print(f"Warning: Failed to setup file logging: {e}")

    def _setup_console_handler(self) -> None:
        """Setup console handler for structured logging."""
        try:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)

            # Use human-readable formatter for console
            console_handler.setFormatter(self._create_console_formatter())

            self.logger.addHandler(console_handler)

        except Exception as e:
            print(f"Warning: Failed to setup console logging: {e}")

    def _create_json_formatter(self) -> logging.Formatter:
        """Create JSON formatter for structured logging."""

        class JSONFormatter(logging.Formatter):
            def format(self, record):
                # Create structured log entry
                log_data = {
                    "timestamp": datetime.fromtimestamp(record.created).isoformat(),
                    "level": record.levelname.lower(),
                    "logger": record.name,
                    "message": record.getMessage(),
                    "module": record.module,
                    "function": record.funcName,
                    "line": record.lineno,
                }

                # Add exception info if present
                if record.exc_info:
                    log_data["exception"] = self.formatException(record.exc_info)

                # Add custom attributes
                for key, value in record.__dict__.items():
                    if key not in [
                        "name",
                        "msg",
                        "args",
                        "levelname",
                        "levelno",
                        "pathname",
                        "filename",
                        "module",
                        "lineno",
                        "funcName",
                        "created",
                        "msecs",
                        "relativeCreated",
                        "thread",
                        "threadName",
                        "processName",
                        "process",
                        "getMessage",
                        "exc_info",
                        "exc_text",
                        "stack_info",
                    ]:
                        log_data[key] = value

                return json.dumps(log_data, default=str)

        return JSONFormatter()

    def _create_console_formatter(self) -> logging.Formatter:
        """Create human-readable formatter for console output."""
        return logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )

    def _log(
        self,
        level: LogLevel,
        category: LogCategory,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        component: Optional[str] = None,
        **kwargs,
    ) -> None:
        """
        Internal logging method.

        Args:
            level: Log level
            category: Log category
            message: Log message
            context: Additional context data
            component: Component name
            **kwargs: Additional keyword arguments
        """
        with self.lock:
            # Prepare context
            log_context = context or {}
            log_context.update(kwargs)

            # Create log entry
            entry = LogEntry(
                timestamp=datetime.now().isoformat(),
                level=level.value,
                category=category.value,
                message=message,
                context=log_context,
                session_id=self.session_id,
                component=component,
            )

            # Convert to logging level
            python_level = getattr(logging, level.name)

            # Log with extra attributes
            self.logger.log(
                python_level,
                message,
                extra={
                    "category": category.value,
                    "context": log_context,
                    "session_id": self.session_id,
                    "component": component,
                },
            )

    def debug(
        self,
        message: str,
        category: LogCategory = LogCategory.SYSTEM,
        context: Optional[Dict[str, Any]] = None,
        component: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Log debug message."""
        self._log(LogLevel.DEBUG, category, message, context, component, **kwargs)

    def info(
        self,
        message: str,
        category: LogCategory = LogCategory.SYSTEM,
        context: Optional[Dict[str, Any]] = None,
        component: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Log info message."""
        self._log(LogLevel.INFO, category, message, context, component, **kwargs)

    def warning(
        self,
        message: str,
        category: LogCategory = LogCategory.SYSTEM,
        context: Optional[Dict[str, Any]] = None,
        component: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Log warning message."""
        self._log(LogLevel.WARNING, category, message, context, component, **kwargs)

    def error(
        self,
        message: str,
        category: LogCategory = LogCategory.ERROR,
        context: Optional[Dict[str, Any]] = None,
        component: Optional[str] = None,
        exception: Optional[Exception] = None,
        **kwargs,
    ) -> None:
        """Log error message."""
        if exception:
            kwargs["exception_type"] = type(exception).__name__
            kwargs["exception_message"] = str(exception)

        self._log(LogLevel.ERROR, category, message, context, component, **kwargs)

    def critical(
        self,
        message: str,
        category: LogCategory = LogCategory.ERROR,
        context: Optional[Dict[str, Any]] = None,
        component: Optional[str] = None,
        exception: Optional[Exception] = None,
        **kwargs,
    ) -> None:
        """Log critical message."""
        if exception:
            kwargs["exception_type"] = type(exception).__name__
            kwargs["exception_message"] = str(exception)

        self._log(LogLevel.CRITICAL, category, message, context, component, **kwargs)

    def log_strategy_test(
        self,
        strategy_name: str,
        domain: str,
        success: bool,
        metrics: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> None:
        """Log strategy test result."""
        context = {
            "strategy_name": strategy_name,
            "domain": domain,
            "success": success,
            "metrics": metrics or {},
        }
        context.update(kwargs)

        message = (
            f"Strategy test {'succeeded' if success else 'failed'}: {strategy_name} on {domain}"
        )
        self.info(message, LogCategory.STRATEGY, context, component="StrategyTester")

    def log_network_request(
        self, method: str, url: str, status_code: int, response_time: float, **kwargs
    ) -> None:
        """Log network request."""
        context = {
            "method": method,
            "url": url,
            "status_code": status_code,
            "response_time_ms": response_time * 1000,
        }
        context.update(kwargs)

        message = f"{method} {url} -> {status_code} ({response_time:.3f}s)"
        self.info(message, LogCategory.NETWORK, context, component="NetworkClient")

    def log_validation_result(
        self,
        validation_type: str,
        success: bool,
        details: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> None:
        """Log validation result."""
        context = {"validation_type": validation_type, "success": success, "details": details or {}}
        context.update(kwargs)

        message = f"Validation {'passed' if success else 'failed'}: {validation_type}"
        level = LogLevel.INFO if success else LogLevel.WARNING
        self._log(level, LogCategory.VALIDATION, message, context, component="Validator")

    def log_performance_metric(
        self, metric_name: str, value: Union[int, float], unit: str = "", **kwargs
    ) -> None:
        """Log performance metric."""
        context = {"metric_name": metric_name, "value": value, "unit": unit}
        context.update(kwargs)

        message = f"Performance metric: {metric_name} = {value} {unit}".strip()
        self.info(message, LogCategory.PERFORMANCE, context, component="PerformanceMonitor")

    def log_baseline_test(
        self, sites: List[str], results: Dict[str, Any], success: bool, **kwargs
    ) -> None:
        """Log baseline connectivity test result."""
        context = {
            "sites": sites,
            "results": results,
            "success": success,
            "total_sites": len(sites),
            "successful_sites": sum(1 for r in results.values() if r[0] == "WORKING"),
        }
        context.update(kwargs)

        message = f"Baseline test {'passed' if success else 'failed'}: {context['successful_sites']}/{context['total_sites']} sites working"
        self.info(message, LogCategory.NETWORK, context, component="BaselineTester")


# Global structured logger instance
_structured_logger: Optional[StructuredLogger] = None


def get_structured_logger() -> StructuredLogger:
    """Get global structured logger instance."""
    global _structured_logger
    if _structured_logger is None:
        _structured_logger = StructuredLogger()
    return _structured_logger


def initialize_structured_logger(
    name: str = "UnifiedBypassEngine",
    log_file: Optional[str] = None,
    enable_console: bool = True,
    session_id: Optional[str] = None,
) -> StructuredLogger:
    """Initialize global structured logger."""
    global _structured_logger
    _structured_logger = StructuredLogger(
        name=name, log_file=log_file, enable_console=enable_console, session_id=session_id
    )
    return _structured_logger
