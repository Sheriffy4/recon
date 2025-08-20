# recon/core/bypass/engines/error_handling.py
"""
Comprehensive error handling framework for the engine factory system.

This module provides custom exception classes, error categorization,
handling strategies, and resolution suggestions for engine-related errors.
"""

from typing import Dict, Any, List, Optional, Type
import logging
import platform
from enum import Enum
from dataclasses import dataclass, field

from .base import EngineType


LOG = logging.getLogger("EngineErrorHandling")


class ErrorCategory(Enum):
    """Categories of engine-related errors."""

    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    PERMISSION = "permission"
    PLATFORM = "platform"
    VALIDATION = "validation"
    CREATION = "creation"
    RUNTIME = "runtime"
    NETWORK = "network"
    SYSTEM = "system"


class ErrorSeverity(Enum):
    """Severity levels for errors."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ErrorContext:
    """Context information for errors."""

    engine_type: Optional[EngineType] = None
    operation: Optional[str] = None
    platform: Optional[str] = None
    user_action: Optional[str] = None
    system_state: Dict[str, Any] = field(default_factory=dict)
    additional_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResolutionSuggestion:
    """Suggestion for resolving an error."""

    action: str
    description: str
    priority: int = 1  # Lower = higher priority
    automated: bool = False
    command: Optional[str] = None
    url: Optional[str] = None


class BaseEngineError(Exception):
    """Base exception for all engine-related errors."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        category: Optional[ErrorCategory] = None,
        severity: Optional[ErrorSeverity] = None,
        context: Optional[ErrorContext] = None,
        suggestions: Optional[List[ResolutionSuggestion]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__.upper()
        self.category = category or ErrorCategory.SYSTEM
        self.severity = severity or ErrorSeverity.MEDIUM
        self.context = context or ErrorContext()
        self.suggestions = suggestions or []
        self.cause = cause

        # Auto-detect platform if not provided
        if self.context.platform is None:
            self.context.platform = platform.system()

    def get_detailed_message(self) -> str:
        """Get detailed error message with context."""
        details = [f"Error: {self.message}"]

        if self.error_code:
            details.append(f"Code: {self.error_code}")

        if self.category:
            details.append(f"Category: {self.category.value}")

        if self.severity:
            details.append(f"Severity: {self.severity.value}")

        if self.context.engine_type:
            details.append(f"Engine: {self.context.engine_type.value}")

        if self.context.operation:
            details.append(f"Operation: {self.context.operation}")

        if self.cause:
            details.append(f"Caused by: {self.cause}")

        return " | ".join(details)

    def get_resolution_text(self) -> str:
        """Get formatted resolution suggestions."""
        if not self.suggestions:
            return "No specific resolution suggestions available."

        # Sort by priority
        sorted_suggestions = sorted(self.suggestions, key=lambda x: x.priority)

        resolution_lines = ["Resolution suggestions:"]
        for i, suggestion in enumerate(sorted_suggestions, 1):
            line = f"{i}. {suggestion.action}"
            if suggestion.description:
                line += f" - {suggestion.description}"
            if suggestion.command:
                line += f" (Command: {suggestion.command})"
            resolution_lines.append(line)

        return "\n".join(resolution_lines)

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for serialization."""
        return {
            "message": self.message,
            "error_code": self.error_code,
            "category": self.category.value if self.category else None,
            "severity": self.severity.value if self.severity else None,
            "context": {
                "engine_type": (
                    self.context.engine_type.value if self.context.engine_type else None
                ),
                "operation": self.context.operation,
                "platform": self.context.platform,
                "user_action": self.context.user_action,
                "system_state": self.context.system_state,
                "additional_info": self.context.additional_info,
            },
            "suggestions": [
                {
                    "action": s.action,
                    "description": s.description,
                    "priority": s.priority,
                    "automated": s.automated,
                    "command": s.command,
                    "url": s.url,
                }
                for s in self.suggestions
            ],
            "cause": str(self.cause) if self.cause else None,
        }


class EngineConfigurationError(BaseEngineError):
    """Error related to engine configuration."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.MEDIUM,
            **kwargs,
        )


class EngineDependencyError(BaseEngineError):
    """Error related to missing or invalid dependencies."""

    def __init__(
        self, message: str, missing_dependencies: Optional[List[str]] = None, **kwargs
    ):
        self.missing_dependencies = missing_dependencies or []

        # Add dependency-specific suggestions
        suggestions = kwargs.get("suggestions", [])
        if self.missing_dependencies:
            for dep in self.missing_dependencies:
                if dep == "pydivert":
                    suggestions.append(
                        ResolutionSuggestion(
                            action="Install PyDivert",
                            description="Install PyDivert package for Windows packet interception",
                            command="pip install pydivert",
                            priority=1,
                        )
                    )
                elif dep == "scapy":
                    suggestions.append(
                        ResolutionSuggestion(
                            action="Install Scapy",
                            description="Install Scapy package for packet manipulation",
                            command="pip install scapy",
                            priority=2,
                        )
                    )
                elif dep == "netfilterqueue":
                    suggestions.append(
                        ResolutionSuggestion(
                            action="Install NetfilterQueue",
                            description="Install NetfilterQueue for Linux packet interception",
                            command="pip install netfilterqueue",
                            priority=1,
                        )
                    )

        kwargs["suggestions"] = suggestions

        super().__init__(
            message,
            category=ErrorCategory.DEPENDENCY,
            severity=ErrorSeverity.HIGH,
            **kwargs,
        )


class EnginePermissionError(BaseEngineError):
    """Error related to insufficient permissions."""

    def __init__(
        self, message: str, required_permissions: Optional[List[str]] = None, **kwargs
    ):
        self.required_permissions = required_permissions or []

        # Add permission-specific suggestions
        suggestions = kwargs.get("suggestions", [])
        current_platform = platform.system()

        if (
            "administrator" in self.required_permissions
            or "admin" in self.required_permissions
        ):
            if current_platform == "Windows":
                suggestions.append(
                    ResolutionSuggestion(
                        action="Run as Administrator",
                        description="Right-click and select 'Run as administrator'",
                        priority=1,
                    )
                )
            else:
                suggestions.append(
                    ResolutionSuggestion(
                        action="Run with sudo",
                        description="Use sudo to run with elevated privileges",
                        command="sudo python your_script.py",
                        priority=1,
                    )
                )

        if "root" in self.required_permissions:
            suggestions.append(
                ResolutionSuggestion(
                    action="Run as root",
                    description="Switch to root user or use sudo",
                    command="sudo su -",
                    priority=1,
                )
            )

        kwargs["suggestions"] = suggestions

        super().__init__(
            message,
            category=ErrorCategory.PERMISSION,
            severity=ErrorSeverity.HIGH,
            **kwargs,
        )


class EnginePlatformError(BaseEngineError):
    """Error related to platform compatibility."""

    def __init__(
        self,
        message: str,
        required_platform: Optional[str] = None,
        current_platform: Optional[str] = None,
        **kwargs,
    ):
        self.required_platform = required_platform
        self.current_platform = current_platform or platform.system()

        # Add platform-specific suggestions
        suggestions = kwargs.get("suggestions", [])

        if required_platform:
            suggestions.append(
                ResolutionSuggestion(
                    action=f"Use {required_platform} system",
                    description=f"This engine requires {required_platform}, current: {self.current_platform}",
                    priority=1,
                )
            )

            # Suggest alternative engines
            if required_platform == "Windows" and self.current_platform != "Windows":
                suggestions.append(
                    ResolutionSuggestion(
                        action="Use External Tool engine",
                        description="External Tool engine works on all platforms",
                        priority=2,
                    )
                )
            elif required_platform == "Linux" and self.current_platform != "Linux":
                suggestions.append(
                    ResolutionSuggestion(
                        action="Use External Tool engine",
                        description="External Tool engine works on all platforms",
                        priority=2,
                    )
                )

        kwargs["suggestions"] = suggestions

        super().__init__(
            message,
            category=ErrorCategory.PLATFORM,
            severity=ErrorSeverity.HIGH,
            **kwargs,
        )


class EngineValidationError(BaseEngineError):
    """Error related to validation failures."""

    def __init__(
        self, message: str, validation_errors: Optional[List[str]] = None, **kwargs
    ):
        self.validation_errors = validation_errors or []

        super().__init__(
            message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.MEDIUM,
            **kwargs,
        )


class EngineCreationError(BaseEngineError):
    """Error during engine creation process."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.CREATION,
            severity=ErrorSeverity.HIGH,
            **kwargs,
        )


class EngineRuntimeError(BaseEngineError):
    """Error during engine runtime operation."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.RUNTIME,
            severity=ErrorSeverity.MEDIUM,
            **kwargs,
        )


class EngineNetworkError(BaseEngineError):
    """Error related to network operations."""

    def __init__(self, message: str, **kwargs):
        suggestions = kwargs.get("suggestions", [])
        suggestions.extend(
            [
                ResolutionSuggestion(
                    action="Check network connectivity",
                    description="Verify internet connection and network settings",
                    priority=1,
                ),
                ResolutionSuggestion(
                    action="Check firewall settings",
                    description="Ensure firewall allows the application",
                    priority=2,
                ),
                ResolutionSuggestion(
                    action="Check proxy settings",
                    description="Verify proxy configuration if applicable",
                    priority=3,
                ),
            ]
        )
        kwargs["suggestions"] = suggestions

        super().__init__(
            message,
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.MEDIUM,
            **kwargs,
        )


class ErrorHandler:
    """
    Centralized error handler for engine-related errors.

    This class provides error categorization, logging, and resolution
    suggestion functionality for the engine factory system.
    """

    def __init__(self):
        self.logger = LOG
        self._error_templates = self._load_error_templates()
        self._resolution_database = self._load_resolution_database()

    def handle_error(
        self, error: BaseEngineError, context: Optional[ErrorContext] = None
    ) -> Dict[str, Any]:
        """
        Handle an engine error with logging and resolution suggestions.

        Args:
            error: The error to handle
            context: Additional context information

        Returns:
            Error handling result
        """
        # Update context if provided
        if context:
            if context.engine_type:
                error.context.engine_type = context.engine_type
            if context.operation:
                error.context.operation = context.operation
            if context.user_action:
                error.context.user_action = context.user_action
            error.context.system_state.update(context.system_state)
            error.context.additional_info.update(context.additional_info)

        # Log the error
        self._log_error(error)

        # Enhance suggestions if needed
        self._enhance_suggestions(error)

        # Return handling result
        return {
            "error": error.to_dict(),
            "handled": True,
            "logged": True,
            "suggestions_count": len(error.suggestions),
            "severity": error.severity.value,
            "category": error.category.value,
        }

    def create_error_from_exception(
        self,
        exception: Exception,
        error_type: Type[BaseEngineError] = BaseEngineError,
        context: Optional[ErrorContext] = None,
    ) -> BaseEngineError:
        """
        Create a structured error from a generic exception.

        Args:
            exception: The original exception
            error_type: Type of structured error to create
            context: Error context

        Returns:
            Structured error object
        """
        message = str(exception)

        # Try to categorize the error based on exception type and message
        if isinstance(exception, ImportError):
            return EngineDependencyError(
                f"Dependency error: {message}", context=context, cause=exception
            )
        elif isinstance(exception, PermissionError):
            return EnginePermissionError(
                f"Permission error: {message}", context=context, cause=exception
            )
        elif isinstance(exception, (ValueError, TypeError)):
            return EngineValidationError(
                f"Validation error: {message}", context=context, cause=exception
            )
        elif isinstance(exception, (ConnectionError, TimeoutError)):
            return EngineNetworkError(
                f"Network error: {message}", context=context, cause=exception
            )
        else:
            return error_type(message, context=context, cause=exception)

    def get_error_template(self, error_code: str) -> Optional[str]:
        """Get error message template by error code."""
        return self._error_templates.get(error_code)

    def get_resolution_suggestions(
        self, error_code: str, context: Optional[ErrorContext] = None
    ) -> List[ResolutionSuggestion]:
        """Get resolution suggestions for an error code."""
        suggestions = self._resolution_database.get(error_code, [])

        # Filter suggestions based on context
        if context and context.platform:
            suggestions = [
                s
                for s in suggestions
                if not hasattr(s, "platform") or s.platform == context.platform
            ]

        return suggestions

    def _log_error(self, error: BaseEngineError):
        """Log an error with appropriate level."""
        if error.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(error.get_detailed_message())
        elif error.severity == ErrorSeverity.HIGH:
            self.logger.error(error.get_detailed_message())
        elif error.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(error.get_detailed_message())
        else:
            self.logger.info(error.get_detailed_message())

        # Log resolution suggestions at debug level
        if error.suggestions:
            self.logger.debug(error.get_resolution_text())

    def _enhance_suggestions(self, error: BaseEngineError):
        """Enhance error suggestions based on context and error type."""
        # Add general suggestions based on category
        if error.category == ErrorCategory.DEPENDENCY:
            if not any(s.action.startswith("Check Python") for s in error.suggestions):
                error.suggestions.append(
                    ResolutionSuggestion(
                        action="Check Python environment",
                        description="Verify Python version and package installation",
                        priority=10,
                    )
                )

        elif error.category == ErrorCategory.PERMISSION:
            if not any(s.action.startswith("Check user") for s in error.suggestions):
                error.suggestions.append(
                    ResolutionSuggestion(
                        action="Check user permissions",
                        description="Verify current user has required permissions",
                        priority=10,
                    )
                )

        elif error.category == ErrorCategory.CONFIGURATION:
            if not any(s.action.startswith("Check config") for s in error.suggestions):
                error.suggestions.append(
                    ResolutionSuggestion(
                        action="Check configuration files",
                        description="Verify configuration file syntax and values",
                        priority=10,
                    )
                )

    def _load_error_templates(self) -> Dict[str, str]:
        """Load error message templates."""
        return {
            "PYDIVERT_NOT_FOUND": "PyDivert package is not installed. This is required for Windows packet interception.",
            "ADMIN_REQUIRED": "Administrator privileges are required for this engine type.",
            "PLATFORM_MISMATCH": "Engine type {engine_type} is not supported on {platform}.",
            "INVALID_CONFIG": "Configuration validation failed: {details}",
            "ENGINE_CREATION_FAILED": "Failed to create engine of type {engine_type}: {reason}",
            "DEPENDENCY_MISSING": "Required dependency '{dependency}' is not available.",
            "PERMISSION_DENIED": "Permission denied for operation '{operation}'. Required permissions: {permissions}",
            "NETWORK_ERROR": "Network operation failed: {details}",
            "VALIDATION_ERROR": "Validation failed: {details}",
        }

    def _load_resolution_database(self) -> Dict[str, List[ResolutionSuggestion]]:
        """Load resolution suggestions database."""
        return {
            "PYDIVERT_NOT_FOUND": [
                ResolutionSuggestion(
                    action="Install PyDivert",
                    description="Install PyDivert package using pip",
                    command="pip install pydivert",
                    priority=1,
                ),
                ResolutionSuggestion(
                    action="Use alternative engine",
                    description="Consider using External Tool engine instead",
                    priority=2,
                ),
            ],
            "ADMIN_REQUIRED": [
                ResolutionSuggestion(
                    action="Run as administrator",
                    description="Restart the application with administrator privileges",
                    priority=1,
                ),
                ResolutionSuggestion(
                    action="Use unprivileged engine",
                    description="Switch to an engine that doesn't require admin privileges",
                    priority=2,
                ),
            ],
            "PLATFORM_MISMATCH": [
                ResolutionSuggestion(
                    action="Use compatible engine",
                    description="Select an engine compatible with your platform",
                    priority=1,
                ),
                ResolutionSuggestion(
                    action="Check platform requirements",
                    description="Review engine documentation for platform requirements",
                    priority=2,
                ),
            ],
        }


# Global error handler instance
_error_handler = ErrorHandler()


def get_error_handler() -> ErrorHandler:
    """Get the global error handler instance."""
    return _error_handler


def handle_engine_error(
    error: BaseEngineError, context: Optional[ErrorContext] = None
) -> Dict[str, Any]:
    """Convenience function to handle an engine error."""
    return _error_handler.handle_error(error, context)


def create_error_from_exception(
    exception: Exception,
    error_type: Type[BaseEngineError] = BaseEngineError,
    context: Optional[ErrorContext] = None,
) -> BaseEngineError:
    """Convenience function to create structured error from exception."""
    return _error_handler.create_error_from_exception(exception, error_type, context)


# Convenience functions for creating specific error types
def create_dependency_error(
    message: str,
    missing_dependencies: Optional[List[str]] = None,
    context: Optional[ErrorContext] = None,
) -> EngineDependencyError:
    """Create a dependency error."""
    return EngineDependencyError(message, missing_dependencies, context=context)


def create_permission_error(
    message: str,
    required_permissions: Optional[List[str]] = None,
    context: Optional[ErrorContext] = None,
) -> EnginePermissionError:
    """Create a permission error."""
    return EnginePermissionError(message, required_permissions, context=context)


def create_platform_error(
    message: str,
    required_platform: Optional[str] = None,
    context: Optional[ErrorContext] = None,
) -> EnginePlatformError:
    """Create a platform error."""
    return EnginePlatformError(message, required_platform, context=context)


def create_configuration_error(
    message: str, context: Optional[ErrorContext] = None
) -> EngineConfigurationError:
    """Create a configuration error."""
    return EngineConfigurationError(message, context=context)


def create_validation_error(
    message: str,
    validation_errors: Optional[List[str]] = None,
    context: Optional[ErrorContext] = None,
) -> EngineValidationError:
    """Create a validation error."""
    return EngineValidationError(message, validation_errors, context=context)
