"""
Enhanced Error Handler for CLI - Graceful Degradation Support

Provides comprehensive error handling with graceful degradation for CLI operations.
Handles various failure scenarios and provides helpful user guidance.
"""

import logging
import sys
import traceback
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass

# Local unicode-safe utilities (same package)
from .unicode_utils import safe_text, safe_console_print

# Rich imports with fallback
try:
    from rich.console import Console
    from rich.panel import Panel

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

    class Console:
        def print(self, *args, **kwargs):
            safe_console_print(self, *args, **kwargs)


LOG = logging.getLogger("CLIErrorHandler")


class ErrorSeverity(Enum):
    """Error severity levels"""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for better handling"""

    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"
    NETWORK = "network"
    PERMISSION = "permission"
    TIMEOUT = "timeout"
    VALIDATION = "validation"
    SYSTEM = "system"
    UNKNOWN = "unknown"


@dataclass
class ErrorContext:
    """Context information for error handling"""

    operation: str
    component: str
    user_action: Optional[str] = None
    debug_info: Optional[Dict[str, Any]] = None
    suggestions: Optional[List[str]] = None


class CLIErrorHandler:
    """
    Enhanced error handler with graceful degradation and user guidance.

    Features:
    - Categorized error handling
    - User-friendly error messages
    - Actionable suggestions
    - Graceful degradation strategies
    - Debug information management
    """

    def __init__(self, console: Optional[Console] = None, debug: bool = False):
        self.console = console or Console()
        self.debug = debug
        self.error_count = 0
        self.warning_count = 0

        # Error message templates
        self.error_templates = {
            ErrorCategory.DEPENDENCY: {"title": "Dependency Error", "icon": "📦", "color": "red"},
            ErrorCategory.CONFIGURATION: {
                "title": "Configuration Error",
                "icon": "⚙️",
                "color": "yellow",
            },
            ErrorCategory.NETWORK: {"title": "Network Error", "icon": "🌐", "color": "red"},
            ErrorCategory.PERMISSION: {"title": "Permission Error", "icon": "🔒", "color": "red"},
            ErrorCategory.TIMEOUT: {"title": "Timeout Error", "icon": "⏱️", "color": "yellow"},
            ErrorCategory.VALIDATION: {
                "title": "Validation Error",
                "icon": "✅",
                "color": "yellow",
            },
            ErrorCategory.SYSTEM: {"title": "System Error", "icon": "💻", "color": "red"},
            ErrorCategory.UNKNOWN: {"title": "Unknown Error", "icon": "❓", "color": "red"},
        }

    def categorize_error(
        self, error: Exception, context: Optional[ErrorContext] = None
    ) -> ErrorCategory:
        """Categorize error based on type and context"""
        error_str = str(error).lower()
        error_type = type(error).__name__.lower()

        # Dependency errors
        if isinstance(error, ImportError) or "import" in error_str or "module" in error_str:
            return ErrorCategory.DEPENDENCY

        # Network errors
        if any(
            keyword in error_str
            for keyword in [
                "connection",
                "network",
                "dns",
                "timeout",
                "unreachable",
                "refused",
                "reset",
                "socket",
                "ssl",
                "tls",
            ]
        ):
            return ErrorCategory.NETWORK

        # Permission errors
        if isinstance(error, PermissionError) or any(
            keyword in error_str
            for keyword in [
                "permission",
                "access denied",
                "administrator",
                "privilege",
                "forbidden",
            ]
        ):
            return ErrorCategory.PERMISSION

        # Timeout errors
        if "timeout" in error_type or "timeout" in error_str:
            return ErrorCategory.TIMEOUT

        # Validation errors
        if isinstance(error, (ValueError, TypeError)) or any(
            keyword in error_str
            for keyword in ["invalid", "validation", "format", "parse", "decode"]
        ):
            return ErrorCategory.VALIDATION

        # Configuration errors
        if any(
            keyword in error_str
            for keyword in ["config", "setting", "parameter", "argument", "option"]
        ):
            return ErrorCategory.CONFIGURATION

        # System errors
        if isinstance(error, (OSError, SystemError)) or any(
            keyword in error_str
            for keyword in ["system", "platform", "driver", "kernel", "hardware"]
        ):
            return ErrorCategory.SYSTEM

        return ErrorCategory.UNKNOWN

    def get_error_suggestions(
        self, error: Exception, category: ErrorCategory, context: Optional[ErrorContext] = None
    ) -> List[str]:
        """Get actionable suggestions based on error category and context"""
        suggestions = []
        error_str = str(error).lower()

        if category == ErrorCategory.DEPENDENCY:
            if "adaptive" in error_str or "engine" in error_str:
                suggestions.extend(
                    [
                        "Ensure all adaptive engine components are installed",
                        "Check if core.adaptive_engine module is available",
                        "Try running in legacy mode as fallback",
                    ]
                )
            elif "rich" in error_str:
                suggestions.extend(
                    [
                        "Install Rich library: pip install rich",
                        "CLI will work without Rich but with reduced formatting",
                    ]
                )
            elif "scapy" in error_str:
                suggestions.extend(
                    [
                        "Install Scapy: pip install scapy",
                        "On Windows, ensure Npcap is installed",
                        "Some features may be limited without Scapy",
                    ]
                )
            else:
                suggestions.extend(
                    [
                        "Install missing dependencies: pip install -r requirements.txt",
                        "Check Python environment and package versions",
                    ]
                )

        elif category == ErrorCategory.NETWORK:
            suggestions.extend(
                [
                    "Check your internet connection",
                    "Verify the target domain is accessible",
                    "Try with a different DNS server (1.1.1.1 or 8.8.8.8)",
                    "Check if domain is blocked by your ISP",
                    "Use --debug for detailed network diagnostics",
                ]
            )

        elif category == ErrorCategory.PERMISSION:
            if sys.platform == "win32":
                suggestions.extend(
                    [
                        "Run as Administrator on Windows",
                        "Install WinDivert driver: python install_pydivert.py",
                        "Check Windows Defender/antivirus settings",
                    ]
                )
            else:
                suggestions.extend(
                    [
                        "Run with sudo on Linux/macOS",
                        "Check file/directory permissions",
                        "Ensure user has network capture privileges",
                    ]
                )

        elif category == ErrorCategory.TIMEOUT:
            suggestions.extend(
                [
                    "Increase timeout with --connect-timeout or --tls-timeout",
                    "Try with --mode quick for faster analysis",
                    "Check network stability and latency",
                    "Use --max-trials to limit analysis scope",
                ]
            )

        elif category == ErrorCategory.VALIDATION:
            if "domain" in error_str:
                suggestions.extend(
                    [
                        "Check domain name format (e.g., example.com)",
                        "Remove protocol prefix (http:// or https://)",
                        "Ensure domain contains valid characters only",
                    ]
                )
            else:
                suggestions.extend(
                    [
                        "Check command line arguments format",
                        "Verify parameter values are within valid ranges",
                        "Use --help for usage information",
                    ]
                )

        elif category == ErrorCategory.CONFIGURATION:
            suggestions.extend(
                [
                    "Check configuration file syntax",
                    "Verify all required parameters are set",
                    "Reset to default configuration if needed",
                    "Use --debug to see configuration details",
                ]
            )

        elif category == ErrorCategory.SYSTEM:
            if "windivert" in error_str:
                suggestions.extend(
                    [
                        "Install WinDivert driver: python install_pydivert.py",
                        "Run as Administrator",
                        "Check if antivirus is blocking WinDivert",
                    ]
                )
            else:
                suggestions.extend(
                    [
                        "Check system compatibility",
                        "Verify required system components are available",
                        "Try restarting the application",
                    ]
                )

        else:  # UNKNOWN
            suggestions.extend(
                [
                    "Use --debug for detailed error information",
                    "Check logs for additional context",
                    "Try with different parameters or modes",
                    "Report issue if problem persists",
                ]
            )

        # Add context-specific suggestions
        if context and context.suggestions:
            suggestions.extend(context.suggestions)

        return suggestions

    def handle_error(
        self,
        error: Exception,
        severity: ErrorSeverity = ErrorSeverity.ERROR,
        context: Optional[ErrorContext] = None,
        fallback_action: Optional[Callable] = None,
    ) -> bool:
        """
        Handle error with appropriate user feedback and graceful degradation.

        Args:
            error: The exception that occurred
            severity: Error severity level
            context: Additional context information
            fallback_action: Optional fallback action to execute

        Returns:
            bool: True if error was handled gracefully, False if critical
        """
        # Update counters
        if severity in [ErrorSeverity.ERROR, ErrorSeverity.CRITICAL]:
            self.error_count += 1
        elif severity == ErrorSeverity.WARNING:
            self.warning_count += 1

        # Categorize error
        category = self.categorize_error(error, context)
        template = self.error_templates[category]

        # Get suggestions
        suggestions = self.get_error_suggestions(error, category, context)

        # Format error message
        self._display_error(error, severity, category, template, suggestions, context)

        # Log error details
        self._log_error(error, severity, category, context)

        # Execute fallback action if provided
        if fallback_action:
            try:
                fallback_action()
                return True
            except Exception as fallback_error:
                LOG.error(f"Fallback action failed: {fallback_error}")

        # Determine if error is recoverable
        return severity not in [ErrorSeverity.CRITICAL] and category != ErrorCategory.SYSTEM

    def _display_error(
        self,
        error: Exception,
        severity: ErrorSeverity,
        category: ErrorCategory,
        template: Dict[str, str],
        suggestions: List[str],
        context: Optional[ErrorContext],
    ):
        """Display formatted error message to user"""
        if RICH_AVAILABLE:
            self._display_error_rich(error, severity, category, template, suggestions, context)
        else:
            self._display_error_plain(error, severity, category, template, suggestions, context)

    def _display_error_rich(
        self,
        error: Exception,
        severity: ErrorSeverity,
        category: ErrorCategory,
        template: Dict[str, str],
        suggestions: List[str],
        context: Optional[ErrorContext],
    ):
        """Display error using Rich formatting"""
        # Determine colors based on severity
        severity_colors = {
            ErrorSeverity.INFO: "blue",
            ErrorSeverity.WARNING: "yellow",
            ErrorSeverity.ERROR: "red",
            ErrorSeverity.CRITICAL: "bold red",
        }

        color = severity_colors.get(severity, "red")

        # Create error message
        # Unicode-safe title/content even in Rich (CI/Windows streams)
        title = safe_text(f"{template['icon']} {template['title']}")
        if context and context.operation:
            title += safe_text(f" - {context.operation}")

        message_parts = [f"[{color}]{safe_text(error)}[/{color}]"]

        if context and context.user_action:
            message_parts.append(f"\n[dim]While: {safe_text(context.user_action)}[/dim]")

        # Add suggestions
        if suggestions:
            message_parts.append("\n[bold]💡 Suggestions:[/bold]")
            for suggestion in suggestions[:5]:  # Limit to 5 suggestions
                message_parts.append(f"  • {safe_text(suggestion)}")

        # Add debug info if available and debug mode is on
        if self.debug and context and context.debug_info:
            message_parts.append("\n[dim]Debug Info:[/dim]")
            for key, value in context.debug_info.items():
                message_parts.append(f"  [dim]{safe_text(key)}: {safe_text(value)}[/dim]")

        content = "\n".join(message_parts)

        # Display panel
        self.console.print(Panel(content, title=title, border_style=color, expand=False))

        # Show traceback in debug mode
        if self.debug and severity in [ErrorSeverity.ERROR, ErrorSeverity.CRITICAL]:
            self.console.print("\n[dim]Traceback:[/dim]")
            self.console.print(traceback.format_exc())

    def _display_error_plain(
        self,
        error: Exception,
        severity: ErrorSeverity,
        category: ErrorCategory,
        template: Dict[str, str],
        suggestions: List[str],
        context: Optional[ErrorContext],
    ):
        """Display error using plain text formatting"""
        # Create header
        header = safe_text(f"{template['icon']} {template['title']}")
        if context and context.operation:
            header += safe_text(f" - {context.operation}")

        print(f"\n{header}")
        print("=" * len(header))

        # Error message
        print(f"Error: {safe_text(error)}")

        if context and context.user_action:
            print(f"While: {safe_text(context.user_action)}")

        # Suggestions
        if suggestions:
            print("\n" + safe_text("💡 Suggestions:"))
            for suggestion in suggestions[:5]:
                print(f"  • {safe_text(suggestion)}")

        # Debug info
        if self.debug and context and context.debug_info:
            print("\nDebug Info:")
            for key, value in context.debug_info.items():
                print(f"  {safe_text(key)}: {safe_text(value)}")

        # Traceback in debug mode
        if self.debug and severity in [ErrorSeverity.ERROR, ErrorSeverity.CRITICAL]:
            print("\nTraceback:")
            traceback.print_exc()

    def _log_error(
        self,
        error: Exception,
        severity: ErrorSeverity,
        category: ErrorCategory,
        context: Optional[ErrorContext],
    ):
        """Log error details for debugging"""
        log_level = {
            ErrorSeverity.INFO: logging.INFO,
            ErrorSeverity.WARNING: logging.WARNING,
            ErrorSeverity.ERROR: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL,
        }.get(severity, logging.ERROR)

        log_message = f"[{category.value}] {error}"
        if context:
            log_message += f" (operation: {context.operation}, component: {context.component})"

        LOG.log(log_level, log_message)

        if self.debug:
            LOG.debug(f"Error details: {traceback.format_exc()}")

    def display_summary(self):
        """Display error summary at the end of execution"""
        if self.error_count == 0 and self.warning_count == 0:
            return

        if RICH_AVAILABLE:
            summary_text = f"Execution completed with {self.warning_count} warnings and {self.error_count} errors"
            color = "yellow" if self.error_count == 0 else "red"

            self.console.print(
                Panel(f"[{color}]{summary_text}[/{color}]", title="📊 Summary", border_style=color)
            )
        else:
            print(f"\n📊 Summary: {self.warning_count} warnings, {self.error_count} errors")


# Global error handler instance
_global_error_handler: Optional[CLIErrorHandler] = None


def get_error_handler(console: Optional[Console] = None, debug: bool = False) -> CLIErrorHandler:
    """Get or create global error handler instance"""
    global _global_error_handler

    if _global_error_handler is None:
        _global_error_handler = CLIErrorHandler(console, debug)

    return _global_error_handler


def handle_cli_error(
    error: Exception,
    operation: str,
    component: str = "CLI",
    severity: ErrorSeverity = ErrorSeverity.ERROR,
    user_action: Optional[str] = None,
    suggestions: Optional[List[str]] = None,
    fallback_action: Optional[Callable] = None,
) -> bool:
    """
    Convenience function for handling CLI errors.

    Args:
        error: The exception that occurred
        operation: Description of the operation that failed
        component: Component where error occurred
        severity: Error severity level
        user_action: What the user was trying to do
        suggestions: Additional suggestions for the user
        fallback_action: Optional fallback action

    Returns:
        bool: True if error was handled gracefully
    """
    handler = get_error_handler()

    context = ErrorContext(
        operation=operation, component=component, user_action=user_action, suggestions=suggestions
    )

    return handler.handle_error(error, severity, context, fallback_action)
