"""
Structured logging infrastructure for the adaptive engine.

Provides structured logging with consistent formats, context management,
and integration with monitoring systems.
"""

import json
import logging
import time
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Union, List
from uuid import uuid4

from ..config import AdaptiveEngineConfig


class LogLevel(Enum):
    """Log levels for structured logging."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogCategory(Enum):
    """Categories for structured logs."""

    SYSTEM = "system"
    STRATEGY = "strategy"
    TESTING = "testing"
    CACHE = "cache"
    PERFORMANCE = "performance"
    ERROR = "error"
    SECURITY = "security"
    AUDIT = "audit"


@dataclass
class LogContext:
    """Context information for structured logs."""

    request_id: str = field(default_factory=lambda: str(uuid4()))
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    domain: Optional[str] = None
    strategy_name: Optional[str] = None
    component: Optional[str] = None
    operation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StructuredLogEntry:
    """Structured log entry with consistent format."""

    timestamp: str
    level: str
    category: str
    message: str
    context: LogContext
    duration_ms: Optional[float] = None
    error_details: Optional[Dict[str, Any]] = None
    metrics: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "category": self.category,
            "message": self.message,
            "context": asdict(self.context),
            "duration_ms": self.duration_ms,
            "error_details": self.error_details,
            "metrics": self.metrics,
        }

    def to_json(self) -> str:
        """Convert log entry to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class StructuredLogger:
    """Structured logger with context management and monitoring integration."""

    def __init__(self, name: str, config: Optional[AdaptiveEngineConfig] = None):
        self.name = name
        self.config = config
        self.logger = logging.getLogger(name)
        self._context_stack: List[LogContext] = []

        # Configure structured logging format if enabled
        if config and config.error_handling.enable_structured_logging:
            self._setup_structured_logging()

    def _setup_structured_logging(self):
        """Set up structured logging format."""
        formatter = StructuredLogFormatter()

        # Remove existing handlers to avoid duplicates
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        # Add console handler with structured format
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # Set log level from config
        log_level = getattr(logging, self.config.error_handling.log_level.upper(), logging.INFO)
        self.logger.setLevel(log_level)

    def push_context(self, context: LogContext):
        """Push a new context onto the context stack."""
        self._context_stack.append(context)

    def pop_context(self) -> Optional[LogContext]:
        """Pop the current context from the context stack."""
        return self._context_stack.pop() if self._context_stack else None

    def get_current_context(self) -> LogContext:
        """Get the current context, or create a default one."""
        return self._context_stack[-1] if self._context_stack else LogContext()

    def log(
        self,
        level: LogLevel,
        category: LogCategory,
        message: str,
        context: Optional[LogContext] = None,
        duration_ms: Optional[float] = None,
        error_details: Optional[Dict[str, Any]] = None,
        metrics: Optional[Dict[str, Any]] = None,
    ):
        """Log a structured message."""

        log_context = context or self.get_current_context()

        entry = StructuredLogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=level.value,
            category=category.value,
            message=message,
            context=log_context,
            duration_ms=duration_ms,
            error_details=error_details,
            metrics=metrics,
        )

        # Log using standard logger
        log_level = getattr(logging, level.value)
        if self.config and self.config.error_handling.enable_structured_logging:
            self.logger.log(log_level, entry.to_json())
        else:
            self.logger.log(log_level, message)

    def debug(self, message: str, category: LogCategory = LogCategory.SYSTEM, **kwargs):
        """Log debug message."""
        self.log(LogLevel.DEBUG, category, message, **kwargs)

    def info(self, message: str, category: LogCategory = LogCategory.SYSTEM, **kwargs):
        """Log info message."""
        self.log(LogLevel.INFO, category, message, **kwargs)

    def warning(self, message: str, category: LogCategory = LogCategory.SYSTEM, **kwargs):
        """Log warning message."""
        self.log(LogLevel.WARNING, category, message, **kwargs)

    def error(self, message: str, category: LogCategory = LogCategory.ERROR, **kwargs):
        """Log error message."""
        self.log(LogLevel.ERROR, category, message, **kwargs)

    def critical(self, message: str, category: LogCategory = LogCategory.ERROR, **kwargs):
        """Log critical message."""
        self.log(LogLevel.CRITICAL, category, message, **kwargs)

    @contextmanager
    def operation_context(
        self, operation: str, category: LogCategory = LogCategory.SYSTEM, **context_kwargs
    ):
        """Context manager for logging operation start/end with timing."""
        context = LogContext(operation=operation, component=self.name, **context_kwargs)

        self.push_context(context)
        start_time = time.time()

        self.info(f"Starting {operation}", category=category, context=context)

        try:
            yield context
            duration_ms = (time.time() - start_time) * 1000
            self.info(
                f"Completed {operation}",
                category=category,
                context=context,
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            error_details = {"exception_type": type(e).__name__, "exception_message": str(e)}
            self.error(
                f"Failed {operation}",
                category=LogCategory.ERROR,
                context=context,
                duration_ms=duration_ms,
                error_details=error_details,
            )
            raise
        finally:
            self.pop_context()

    @asynccontextmanager
    async def async_operation_context(
        self, operation: str, category: LogCategory = LogCategory.SYSTEM, **context_kwargs
    ):
        """Async context manager for logging operation start/end with timing."""
        context = LogContext(operation=operation, component=self.name, **context_kwargs)

        self.push_context(context)
        start_time = time.time()

        self.info(f"Starting {operation}", category=category, context=context)

        try:
            yield context
            duration_ms = (time.time() - start_time) * 1000
            self.info(
                f"Completed {operation}",
                category=category,
                context=context,
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            error_details = {"exception_type": type(e).__name__, "exception_message": str(e)}
            self.error(
                f"Failed {operation}",
                category=LogCategory.ERROR,
                context=context,
                duration_ms=duration_ms,
                error_details=error_details,
            )
            raise
        finally:
            self.pop_context()


class StructuredLogFormatter(logging.Formatter):
    """Custom formatter for structured logs."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON or plain text."""
        try:
            # Try to parse as JSON (structured log)
            log_data = json.loads(record.getMessage())
            return json.dumps(log_data, indent=None, separators=(",", ":"))
        except (json.JSONDecodeError, ValueError):
            # Fall back to standard formatting
            return super().format(record)


class LogAggregator:
    """Aggregates and analyzes structured logs for monitoring."""

    def __init__(self):
        self.log_entries: List[StructuredLogEntry] = []
        self.error_counts: Dict[str, int] = {}
        self.performance_metrics: Dict[str, List[float]] = {}

    def add_log_entry(self, entry: StructuredLogEntry):
        """Add a log entry for aggregation."""
        self.log_entries.append(entry)

        # Track error counts
        if entry.level in ["ERROR", "CRITICAL"]:
            error_type = (
                entry.error_details.get("exception_type", "Unknown")
                if entry.error_details
                else "Unknown"
            )
            self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1

        # Track performance metrics
        if entry.duration_ms is not None and entry.context.operation:
            operation = entry.context.operation
            if operation not in self.performance_metrics:
                self.performance_metrics[operation] = []
            self.performance_metrics[operation].append(entry.duration_ms)

    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of errors from logs."""
        total_errors = sum(self.error_counts.values())
        return {
            "total_errors": total_errors,
            "error_types": self.error_counts,
            "error_rate": total_errors / len(self.log_entries) if self.log_entries else 0,
        }

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary from logs."""
        summary = {}
        for operation, durations in self.performance_metrics.items():
            if durations:
                summary[operation] = {
                    "count": len(durations),
                    "avg_duration_ms": sum(durations) / len(durations),
                    "min_duration_ms": min(durations),
                    "max_duration_ms": max(durations),
                }
        return summary

    def get_monitoring_report(self) -> Dict[str, Any]:
        """Get comprehensive monitoring report."""
        return {
            "total_log_entries": len(self.log_entries),
            "error_summary": self.get_error_summary(),
            "performance_summary": self.get_performance_summary(),
            "log_categories": self._get_category_counts(),
            "recent_errors": self._get_recent_errors(limit=10),
        }

    def _get_category_counts(self) -> Dict[str, int]:
        """Get counts of log entries by category."""
        counts = {}
        for entry in self.log_entries:
            counts[entry.category] = counts.get(entry.category, 0) + 1
        return counts

    def _get_recent_errors(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent error log entries."""
        error_entries = [
            entry for entry in self.log_entries if entry.level in ["ERROR", "CRITICAL"]
        ]
        # Sort by timestamp (most recent first)
        error_entries.sort(key=lambda x: x.timestamp, reverse=True)
        return [entry.to_dict() for entry in error_entries[:limit]]


# Global log aggregator instance
_log_aggregator = LogAggregator()


def get_structured_logger(
    name: str, config: Optional[AdaptiveEngineConfig] = None
) -> StructuredLogger:
    """Get a structured logger instance."""
    return StructuredLogger(name, config)


def get_log_aggregator() -> LogAggregator:
    """Get the global log aggregator instance."""
    return _log_aggregator
