"""
Accessibility Testing Logging Configuration

This module provides configurable logging for accessibility testing with
different verbosity levels and output formats to aid in troubleshooting
and monitoring.

Requirements: 2.1, 2.3
"""

import logging
import logging.handlers
import sys
import time
from typing import Optional, Dict, Any
from pathlib import Path
from enum import Enum


class LogLevel(Enum):
    """Logging verbosity levels for accessibility testing."""

    SILENT = "silent"  # No logging output
    ERROR = "error"  # Only errors
    WARNING = "warning"  # Errors and warnings
    INFO = "info"  # Errors, warnings, and info (default)
    DEBUG = "debug"  # All messages including debug
    VERBOSE = "verbose"  # Maximum verbosity with detailed tracing


class AccessibilityLoggingConfig:
    """
    Configuration for accessibility testing logging.

    Provides flexible logging configuration with different verbosity levels,
    output destinations, and formatting options to support troubleshooting
    and monitoring of accessibility testing operations.
    """

    def __init__(
        self,
        level: LogLevel = LogLevel.INFO,
        console_output: bool = True,
        file_output: bool = False,
        file_path: Optional[str] = None,
        max_file_size_mb: int = 10,
        backup_count: int = 5,
        include_timestamps: bool = True,
        include_thread_info: bool = False,
        include_function_names: bool = False,
        colored_output: bool = True,
    ):
        """
        Initialize logging configuration.

        Args:
            level: Logging verbosity level
            console_output: Enable console output
            file_output: Enable file output
            file_path: Path for log file (auto-generated if None)
            max_file_size_mb: Maximum log file size in MB
            backup_count: Number of backup log files to keep
            include_timestamps: Include timestamps in log messages
            include_thread_info: Include thread information
            include_function_names: Include function names in debug mode
            colored_output: Use colored console output (if supported)
        """
        self.level = level
        self.console_output = console_output
        self.file_output = file_output
        self.file_path = file_path or self._generate_log_file_path()
        self.max_file_size_mb = max_file_size_mb
        self.backup_count = backup_count
        self.include_timestamps = include_timestamps
        self.include_thread_info = include_thread_info
        self.include_function_names = include_function_names
        self.colored_output = colored_output

        # Internal state
        self._configured_loggers = set()
        self._original_levels = {}

    def _generate_log_file_path(self) -> str:
        """Generate default log file path."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        return f"accessibility_testing_{timestamp}.log"

    def configure_logging(self, logger_name: str = "accessibility") -> logging.Logger:
        """
        Configure logging for accessibility testing.

        Args:
            logger_name: Name of the logger to configure

        Returns:
            Configured logger instance
        """
        logger = logging.getLogger(logger_name)

        # Store original level for restoration
        if logger_name not in self._original_levels:
            self._original_levels[logger_name] = logger.level

        # Clear existing handlers to avoid duplicates
        logger.handlers.clear()

        # Set logging level
        if self.level == LogLevel.SILENT:
            logger.setLevel(logging.CRITICAL + 1)  # Disable all logging
            return logger
        elif self.level == LogLevel.ERROR:
            logger.setLevel(logging.ERROR)
        elif self.level == LogLevel.WARNING:
            logger.setLevel(logging.WARNING)
        elif self.level == LogLevel.INFO:
            logger.setLevel(logging.INFO)
        elif self.level == LogLevel.DEBUG:
            logger.setLevel(logging.DEBUG)
        elif self.level == LogLevel.VERBOSE:
            logger.setLevel(logging.DEBUG)

        # Configure console handler
        if self.console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_formatter = self._create_formatter(for_console=True)
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)

        # Configure file handler
        if self.file_output:
            try:
                # Ensure log directory exists
                log_path = Path(self.file_path)
                log_path.parent.mkdir(parents=True, exist_ok=True)

                # Create rotating file handler
                file_handler = logging.handlers.RotatingFileHandler(
                    self.file_path,
                    maxBytes=self.max_file_size_mb * 1024 * 1024,
                    backupCount=self.backup_count,
                    encoding="utf-8",
                )
                file_formatter = self._create_formatter(for_console=False)
                file_handler.setFormatter(file_formatter)
                logger.addHandler(file_handler)

                logger.info(f"📝 Accessibility testing logging configured: {self.file_path}")

            except Exception as e:
                # Fall back to console-only logging if file setup fails
                logger.error(f"Failed to configure file logging: {e}")

        # Track configured loggers
        self._configured_loggers.add(logger_name)

        return logger

    def _create_formatter(self, for_console: bool = True) -> logging.Formatter:
        """
        Create log formatter based on configuration.

        Args:
            for_console: Whether formatter is for console output

        Returns:
            Configured log formatter
        """
        format_parts = []

        # Timestamp
        if self.include_timestamps:
            if self.level == LogLevel.VERBOSE:
                format_parts.append("%(asctime)s.%(msecs)03d")
            else:
                format_parts.append("%(asctime)s")

        # Thread info (for debugging concurrent operations)
        if self.include_thread_info and self.level in (LogLevel.DEBUG, LogLevel.VERBOSE):
            format_parts.append("[%(threadName)s]")

        # Logger name
        format_parts.append("%(name)s")

        # Log level
        if for_console and self.colored_output:
            # Use colored level names for console
            format_parts.append("%(levelname)s")
        else:
            format_parts.append("%(levelname)s")

        # Function name (for verbose debugging)
        if self.include_function_names and self.level == LogLevel.VERBOSE:
            format_parts.append("%(funcName)s()")

        # Message
        format_parts.append("%(message)s")

        # Join format parts
        if self.level == LogLevel.VERBOSE:
            # More detailed format for verbose mode
            format_string = " | ".join(format_parts)
        else:
            # Compact format for normal modes
            format_string = " - ".join(format_parts)

        # Create formatter
        if self.include_timestamps:
            if self.level == LogLevel.VERBOSE:
                date_format = "%Y-%m-%d %H:%M:%S"
            else:
                date_format = "%H:%M:%S"
            return logging.Formatter(format_string, datefmt=date_format)
        else:
            return logging.Formatter(format_string)

    def add_accessibility_filter(self, logger: logging.Logger) -> None:
        """
        Add accessibility-specific log filtering.

        Args:
            logger: Logger to add filter to
        """

        class AccessibilityFilter(logging.Filter):
            """Filter for accessibility testing log messages."""

            def filter(self, record):
                # Add accessibility context to log records
                if not hasattr(record, "accessibility_context"):
                    record.accessibility_context = "general"

                # Filter out noisy messages in non-verbose modes
                if hasattr(record, "levelno"):
                    message = record.getMessage().lower()

                    # Filter out very verbose curl output in non-debug modes
                    if record.levelno == logging.DEBUG and "curl" in message and len(message) > 200:
                        return False

                    # Filter out repetitive cache messages
                    if "cache hit" in message or "cached result" in message:
                        # Only show every 10th cache message in INFO mode
                        if record.levelno == logging.INFO:
                            return hash(message) % 10 == 0

                return True

        logger.addFilter(AccessibilityFilter())

    def create_test_context_logger(
        self, test_name: str, target_domain: Optional[str] = None
    ) -> logging.Logger:
        """
        Create a context-specific logger for a test.

        Args:
            test_name: Name of the test
            target_domain: Target domain being tested

        Returns:
            Context-specific logger
        """
        if target_domain:
            logger_name = f"accessibility.{test_name}.{target_domain}"
        else:
            logger_name = f"accessibility.{test_name}"

        logger = self.configure_logging(logger_name)

        # Add context information
        class ContextAdapter(logging.LoggerAdapter):
            def process(self, msg, kwargs):
                return f"[{test_name}] {msg}", kwargs

        return ContextAdapter(logger, {})

    def set_verbosity_level(self, level: LogLevel) -> None:
        """
        Change verbosity level for all configured loggers.

        Args:
            level: New verbosity level
        """
        self.level = level

        # Reconfigure all tracked loggers
        for logger_name in self._configured_loggers:
            self.configure_logging(logger_name)

    def enable_debug_mode(self) -> None:
        """Enable debug mode with maximum verbosity."""
        self.set_verbosity_level(LogLevel.VERBOSE)
        self.include_function_names = True
        self.include_thread_info = True

        # Reconfigure loggers
        for logger_name in self._configured_loggers:
            self.configure_logging(logger_name)

    def disable_debug_mode(self) -> None:
        """Disable debug mode and return to normal verbosity."""
        self.set_verbosity_level(LogLevel.INFO)
        self.include_function_names = False
        self.include_thread_info = False

        # Reconfigure loggers
        for logger_name in self._configured_loggers:
            self.configure_logging(logger_name)

    def restore_original_logging(self) -> None:
        """Restore original logging configuration."""
        for logger_name, original_level in self._original_levels.items():
            logger = logging.getLogger(logger_name)
            logger.setLevel(original_level)
            logger.handlers.clear()

        self._configured_loggers.clear()
        self._original_levels.clear()

    def get_log_file_info(self) -> Dict[str, Any]:
        """
        Get information about the current log file.

        Returns:
            Dictionary with log file information
        """
        if not self.file_output:
            return {"file_output_enabled": False}

        log_path = Path(self.file_path)

        info = {
            "file_output_enabled": True,
            "log_file_path": str(log_path.absolute()),
            "file_exists": log_path.exists(),
        }

        if log_path.exists():
            stat = log_path.stat()
            info.update(
                {
                    "file_size_bytes": stat.st_size,
                    "file_size_mb": stat.st_size / (1024 * 1024),
                    "last_modified": time.ctime(stat.st_mtime),
                }
            )

        return info


# Convenience functions for common logging configurations


def configure_silent_logging() -> AccessibilityLoggingConfig:
    """Configure silent logging (no output)."""
    return AccessibilityLoggingConfig(
        level=LogLevel.SILENT, console_output=False, file_output=False
    )


def configure_basic_logging() -> AccessibilityLoggingConfig:
    """Configure basic logging (errors and warnings only)."""
    return AccessibilityLoggingConfig(
        level=LogLevel.WARNING,
        console_output=True,
        file_output=False,
        include_timestamps=False,
        colored_output=True,
    )


def configure_standard_logging(log_to_file: bool = False) -> AccessibilityLoggingConfig:
    """Configure standard logging (info level with optional file output)."""
    return AccessibilityLoggingConfig(
        level=LogLevel.INFO,
        console_output=True,
        file_output=log_to_file,
        include_timestamps=True,
        colored_output=True,
    )


def configure_debug_logging(log_to_file: bool = True) -> AccessibilityLoggingConfig:
    """Configure debug logging (maximum verbosity)."""
    return AccessibilityLoggingConfig(
        level=LogLevel.VERBOSE,
        console_output=True,
        file_output=log_to_file,
        include_timestamps=True,
        include_thread_info=True,
        include_function_names=True,
        colored_output=True,
    )


def configure_troubleshooting_logging() -> AccessibilityLoggingConfig:
    """Configure logging optimized for troubleshooting accessibility issues."""
    return AccessibilityLoggingConfig(
        level=LogLevel.DEBUG,
        console_output=True,
        file_output=True,
        include_timestamps=True,
        include_thread_info=False,
        include_function_names=False,
        colored_output=True,
        max_file_size_mb=50,  # Larger file size for troubleshooting
        backup_count=10,
    )
