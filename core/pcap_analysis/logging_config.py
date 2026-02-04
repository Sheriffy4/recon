"""
Comprehensive logging configuration for PCAP analysis system.

This module provides structured logging, log rotation, and specialized
loggers for different components of the PCAP analysis system.
"""

import logging
import logging.handlers
import json
import sys
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import traceback


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info),
            }

        # Add extra fields from record
        extra_fields = {}
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
                try:
                    # Only include JSON-serializable values
                    json.dumps(value)
                    extra_fields[key] = value
                except (TypeError, ValueError):
                    extra_fields[key] = str(value)

        if extra_fields:
            log_entry["extra"] = extra_fields

        return json.dumps(log_entry, default=str)


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output."""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",  # Reset
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        reset = self.COLORS["RESET"]

        # Format the message
        formatted = super().format(record)

        # Add color
        return f"{color}{formatted}{reset}"


class PCAPAnalysisLogger:
    """Main logger configuration for PCAP analysis system."""

    def __init__(self, log_dir: str = "recon/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.loggers: Dict[str, logging.Logger] = {}
        self.handlers: Dict[str, logging.Handler] = {}

        # Setup root logger
        self._setup_root_logger()

        # Setup component-specific loggers
        self._setup_component_loggers()

    def _setup_root_logger(self):
        """Setup root logger for PCAP analysis."""
        root_logger = logging.getLogger("pcap_analysis")
        root_logger.setLevel(logging.DEBUG)

        # Clear any existing handlers
        root_logger.handlers.clear()

        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = ColoredFormatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "pcap_analysis.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

        # JSON handler for structured logs
        json_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "pcap_analysis.json",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=3,
        )
        json_handler.setLevel(logging.INFO)
        json_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(json_handler)

        self.loggers["root"] = root_logger
        self.handlers.update(
            {"console": console_handler, "file": file_handler, "json": json_handler}
        )

    def _setup_component_loggers(self):
        """Setup loggers for specific components."""

        # Error handler logger
        error_logger = logging.getLogger("pcap_analysis.error_handler")
        error_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "errors.log", maxBytes=5 * 1024 * 1024, backupCount=3  # 5MB
        )
        error_handler.setLevel(logging.WARNING)
        error_handler.setFormatter(JSONFormatter())
        error_logger.addHandler(error_handler)
        self.loggers["error"] = error_logger
        self.handlers["error"] = error_handler

        # Performance logger
        perf_logger = logging.getLogger("pcap_analysis.performance")
        perf_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "performance.log",
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=3,
        )
        perf_handler.setLevel(logging.INFO)
        perf_handler.setFormatter(JSONFormatter())
        perf_logger.addHandler(perf_handler)
        self.loggers["performance"] = perf_logger
        self.handlers["performance"] = perf_handler

        # Debug logger
        debug_logger = logging.getLogger("pcap_analysis.debug")
        debug_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "debug.log", maxBytes=20 * 1024 * 1024, backupCount=2  # 20MB
        )
        debug_handler.setLevel(logging.DEBUG)
        debug_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(funcName)s - %(message)s"
            )
        )
        debug_logger.addHandler(debug_handler)
        self.loggers["debug"] = debug_logger
        self.handlers["debug"] = debug_handler

        # PCAP parser logger
        parser_logger = logging.getLogger("pcap_analysis.parser")
        parser_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "parser.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=3,
        )
        parser_handler.setLevel(logging.DEBUG)
        parser_handler.setFormatter(JSONFormatter())
        parser_logger.addHandler(parser_handler)
        self.loggers["parser"] = parser_logger
        self.handlers["parser"] = parser_handler

        # Analysis logger
        analysis_logger = logging.getLogger("pcap_analysis.analysis")
        analysis_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "analysis.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=3,
        )
        analysis_handler.setLevel(logging.INFO)
        analysis_handler.setFormatter(JSONFormatter())
        analysis_logger.addHandler(analysis_handler)
        self.loggers["analysis"] = analysis_logger
        self.handlers["analysis"] = analysis_handler

    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger by name."""
        if name in self.loggers:
            return self.loggers[name]

        # Create a child logger
        logger = logging.getLogger(f"pcap_analysis.{name}")
        self.loggers[name] = logger
        return logger

    def set_log_level(self, level: str, component: Optional[str] = None):
        """Set log level for all loggers or specific component."""
        log_level = getattr(logging, level.upper())

        if component:
            if component in self.loggers:
                self.loggers[component].setLevel(log_level)
            if component in self.handlers:
                self.handlers[component].setLevel(log_level)
        else:
            # Set for all loggers
            for logger in self.loggers.values():
                logger.setLevel(log_level)
            for handler in self.handlers.values():
                handler.setLevel(log_level)

    def add_file_handler(self, name: str, filename: str, level: str = "INFO"):
        """Add a custom file handler."""
        handler = logging.handlers.RotatingFileHandler(
            self.log_dir / filename, maxBytes=5 * 1024 * 1024, backupCount=2  # 5MB
        )
        handler.setLevel(getattr(logging, level.upper()))
        handler.setFormatter(JSONFormatter())

        logger = self.get_logger(name)
        logger.addHandler(handler)

        self.handlers[f"{name}_file"] = handler
        return handler

    def log_system_info(self):
        """Log system information at startup."""
        import platform
        import sys

        system_info = {
            "platform": platform.platform(),
            "python_version": sys.version,
            "python_executable": sys.executable,
            "working_directory": str(Path.cwd()),
            "log_directory": str(self.log_dir),
        }

        root_logger = self.loggers["root"]
        root_logger.info("PCAP Analysis System Starting", extra={"system_info": system_info})

    def log_configuration(self, config: Dict[str, Any]):
        """Log configuration information."""
        root_logger = self.loggers["root"]
        root_logger.info("System Configuration", extra={"configuration": config})

    def flush_all_handlers(self):
        """Flush all handlers."""
        for handler in self.handlers.values():
            handler.flush()

    def close_all_handlers(self):
        """Close all handlers."""
        for handler in self.handlers.values():
            handler.close()

    def get_log_files(self) -> Dict[str, str]:
        """Get paths to all log files."""
        log_files = {}
        for name, handler in self.handlers.items():
            if hasattr(handler, "baseFilename"):
                log_files[name] = handler.baseFilename
        return log_files

    def rotate_logs(self):
        """Manually rotate all rotating file handlers."""
        for handler in self.handlers.values():
            if isinstance(handler, logging.handlers.RotatingFileHandler):
                handler.doRollover()


class ContextualLogger:
    """Logger that maintains context across operations."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.context: Dict[str, Any] = {}

    def set_context(self, **context):
        """Set context for all subsequent log messages."""
        self.context.update(context)

    def clear_context(self):
        """Clear all context."""
        self.context.clear()

    def debug(self, message: str, **extra):
        """Log debug message with context."""
        self.logger.debug(message, extra={**self.context, **extra})

    def info(self, message: str, **extra):
        """Log info message with context."""
        self.logger.info(message, extra={**self.context, **extra})

    def warning(self, message: str, **extra):
        """Log warning message with context."""
        self.logger.warning(message, extra={**self.context, **extra})

    def error(self, message: str, **extra):
        """Log error message with context."""
        self.logger.error(message, extra={**self.context, **extra})

    def critical(self, message: str, **extra):
        """Log critical message with context."""
        self.logger.critical(message, extra={**self.context, **extra})


# Global logger instance
_pcap_logger = None


def setup_logging(log_dir: str = "recon/logs", log_level: str = "INFO") -> PCAPAnalysisLogger:
    """Setup logging for PCAP analysis system."""
    global _pcap_logger

    _pcap_logger = PCAPAnalysisLogger(log_dir)
    _pcap_logger.set_log_level(log_level)
    _pcap_logger.log_system_info()

    return _pcap_logger


def get_logger(name: str = "root") -> logging.Logger:
    """Get a logger instance."""
    global _pcap_logger

    if _pcap_logger is None:
        _pcap_logger = setup_logging()

    return _pcap_logger.get_logger(name)


def get_contextual_logger(name: str = "root") -> ContextualLogger:
    """Get a contextual logger instance."""
    logger = get_logger(name)
    return ContextualLogger(logger)


def log_operation_start(operation: str, **context):
    """Log the start of an operation."""
    logger = get_logger("analysis")
    logger.info(f"Starting operation: {operation}", extra={"operation": operation, **context})


def log_operation_end(operation: str, duration: float, **results):
    """Log the end of an operation."""
    logger = get_logger("analysis")
    logger.info(
        f"Completed operation: {operation} (duration: {duration:.2f}s)",
        extra={"operation": operation, "duration": duration, **results},
    )


def log_error_with_context(error: Exception, context: str, **extra):
    """Log an error with context information."""
    logger = get_logger("error")
    logger.error(
        f"Error in {context}: {error}",
        extra={
            "error_type": type(error).__name__,
            "error_message": str(error),
            "context": context,
            **extra,
        },
        exc_info=True,
    )


def log_performance_metric(metric_name: str, value: float, **context):
    """Log a performance metric."""
    logger = get_logger("performance")
    logger.info(
        f"Performance metric: {metric_name} = {value}",
        extra={"metric_name": metric_name, "metric_value": value, **context},
    )


def configure_external_loggers():
    """Configure external library loggers."""
    # Reduce scapy logging
    scapy_logger = logging.getLogger("scapy")
    scapy_logger.setLevel(logging.WARNING)

    # Reduce dpkt logging if present
    try:
        dpkt_logger = logging.getLogger("dpkt")
        dpkt_logger.setLevel(logging.WARNING)
    except:
        pass

    # Configure other external loggers as needed
    external_loggers = ["urllib3", "requests", "matplotlib", "numpy"]

    for logger_name in external_loggers:
        try:
            ext_logger = logging.getLogger(logger_name)
            ext_logger.setLevel(logging.WARNING)
        except:
            pass


# Setup logging when module is imported
if _pcap_logger is None:
    try:
        setup_logging()
        configure_external_loggers()
    except Exception as e:
        # Fallback to basic logging if setup fails
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
        logging.getLogger("pcap_analysis").warning(f"Failed to setup advanced logging: {e}")
