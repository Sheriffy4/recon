"""
Logging Module

Enhanced logging configuration for accessibility testing and system diagnostics.
Includes strategy conversion logging management with intelligent deduplication.
"""

try:
    from .accessibility_logging import (
        AccessibilityLoggingConfig,
        LogLevel,
        configure_silent_logging,
        configure_basic_logging,
        configure_standard_logging,
        configure_debug_logging,
        configure_troubleshooting_logging,
    )
except ImportError:
    AccessibilityLoggingConfig = None
    LogLevel = None
    configure_silent_logging = None
    configure_basic_logging = None
    configure_standard_logging = None
    configure_debug_logging = None
    configure_troubleshooting_logging = None

try:
    from .conversion_logging_manager import ConversionLoggingManager
    from .conversion_state import ConversionState
    from .logging_config import LoggingConfig
except ImportError:
    ConversionLoggingManager = None
    ConversionState = None
    LoggingConfig = None

__all__ = []

if AccessibilityLoggingConfig is not None:
    __all__.extend(
        [
            "AccessibilityLoggingConfig",
            "LogLevel",
            "configure_silent_logging",
            "configure_basic_logging",
            "configure_standard_logging",
            "configure_debug_logging",
            "configure_troubleshooting_logging",
        ]
    )

if ConversionLoggingManager is not None:
    __all__.extend(["ConversionLoggingManager", "ConversionState", "LoggingConfig"])
