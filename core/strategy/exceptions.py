"""
Custom exceptions for strategy parameter handling.

This module defines custom error classes for better diagnostics when
strategy parameters are invalid, not propagated correctly, or when
features are not implemented.

Requirements: 6.5, 7.5
"""

from typing import Any, Dict, Optional


class ValidationError(Exception):
    """
    Raised when strategy parameter values are invalid.

    This error indicates that a parameter value does not meet the
    required constraints (e.g., TTL out of range, invalid fooling method).

    Attributes:
        parameter_name: Name of the invalid parameter
        expected: Expected value or constraint description
        actual: Actual value that was provided
        message: Human-readable error message
    """

    def __init__(
        self,
        message: str,
        parameter_name: Optional[str] = None,
        expected: Optional[Any] = None,
        actual: Optional[Any] = None,
    ):
        """
        Initialize ValidationError.

        Args:
            message: Human-readable error message
            parameter_name: Name of the invalid parameter
            expected: Expected value or constraint description
            actual: Actual value that was provided
        """
        super().__init__(message)
        self.parameter_name = parameter_name
        self.expected = expected
        self.actual = actual
        self.message = message

    def __str__(self) -> str:
        """Format error message with context."""
        if self.parameter_name:
            return (
                f"ValidationError: {self.message}\n"
                f"  Parameter: {self.parameter_name}\n"
                f"  Expected: {self.expected}\n"
                f"  Actual: {self.actual}"
            )
        return f"ValidationError: {self.message}"


class ParameterPropagationError(Exception):
    """
    Raised when parameters do not reach their target component.

    This error indicates that a parameter was specified in the configuration
    but was lost or not passed through the execution chain to the component
    that needs it (e.g., TTL not reaching PacketModifier).

    Attributes:
        parameter_name: Name of the parameter that was not propagated
        source: Component where parameter was expected to originate
        target: Component where parameter was expected to arrive
        trace: List of components in the propagation chain
        message: Human-readable error message
    """

    def __init__(
        self,
        message: str,
        parameter_name: Optional[str] = None,
        source: Optional[str] = None,
        target: Optional[str] = None,
        trace: Optional[list] = None,
    ):
        """
        Initialize ParameterPropagationError.

        Args:
            message: Human-readable error message
            parameter_name: Name of the parameter that was not propagated
            source: Component where parameter was expected to originate
            target: Component where parameter was expected to arrive
            trace: List of components in the propagation chain
        """
        super().__init__(message)
        self.parameter_name = parameter_name
        self.source = source
        self.target = target
        self.trace = trace or []
        self.message = message

    def __str__(self) -> str:
        """Format error message with propagation trace."""
        if self.parameter_name:
            trace_str = " → ".join(self.trace) if self.trace else "unknown"
            return (
                f"ParameterPropagationError: {self.message}\n"
                f"  Parameter: {self.parameter_name}\n"
                f"  Source: {self.source}\n"
                f"  Target: {self.target}\n"
                f"  Trace: {trace_str}"
            )
        return f"ParameterPropagationError: {self.message}"


class ImplementationError(Exception):
    """
    Raised when a feature is not implemented.

    This error indicates that a strategy specifies an attack type or
    parameter that is not yet implemented in the system. This is a
    non-fatal error - the system should log a warning and continue
    with other attacks.

    Attributes:
        feature_name: Name of the unimplemented feature
        suggested_alternative: Suggested alternative feature to use
        message: Human-readable error message
    """

    def __init__(
        self,
        message: str,
        feature_name: Optional[str] = None,
        suggested_alternative: Optional[str] = None,
    ):
        """
        Initialize ImplementationError.

        Args:
            message: Human-readable error message
            feature_name: Name of the unimplemented feature
            suggested_alternative: Suggested alternative feature to use
        """
        super().__init__(message)
        self.feature_name = feature_name
        self.suggested_alternative = suggested_alternative
        self.message = message

    def __str__(self) -> str:
        """Format error message with suggestions."""
        if self.feature_name:
            msg = f"ImplementationError: {self.message}\n" f"  Feature: {self.feature_name}"
            if self.suggested_alternative:
                msg += f"\n  Suggested alternative: {self.suggested_alternative}"
            return msg
        return f"ImplementationError: {self.message}"
