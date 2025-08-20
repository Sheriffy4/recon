#!/usr/bin/env python3
"""
Error handling framework for Advanced Attacks integration.
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

LOG = logging.getLogger("advanced_attack_errors")


class ErrorSeverity(Enum):
    """Error severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for advanced attacks."""

    INTEGRATION = "integration"
    ML_FEEDBACK = "ml_feedback"
    LEARNING_MEMORY = "learning_memory"
    ATTACK_EXECUTION = "attack_execution"
    PERFORMANCE_MONITORING = "performance_monitoring"
    CONFIGURATION = "configuration"
    NETWORK = "network"
    SYSTEM = "system"


class RecoveryAction(Enum):
    """Recovery actions for errors."""

    RETRY = "retry"
    FALLBACK = "fallback"
    SKIP = "skip"
    ABORT = "abort"
    ESCALATE = "escalate"
    IGNORE = "ignore"


@dataclass
class ErrorContext:
    """Context information for errors."""

    attack_name: Optional[str] = None
    target: Optional[str] = None
    operation: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class RecoveryResult:
    """Result of error recovery attempt."""

    action: RecoveryAction
    success: bool
    message: str
    retry_count: int = 0
    fallback_used: Optional[str] = None


class AdvancedAttackError(Exception):
    """Base exception for advanced attack errors."""

    def __init__(
        self,
        message: str,
        category: ErrorCategory,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.context = context or ErrorContext()
        self.cause = cause
        self.timestamp = datetime.now()


class IntegrationError(AdvancedAttackError):
    """Error in Phase 1 system integration."""

    def __init__(
        self,
        message: str,
        integration_type: str,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message, ErrorCategory.INTEGRATION, ErrorSeverity.HIGH, context, cause
        )
        self.integration_type = integration_type


class MLFeedbackError(AdvancedAttackError):
    """Error in ML system communication."""

    def __init__(
        self,
        message: str,
        ml_component: str,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message, ErrorCategory.ML_FEEDBACK, ErrorSeverity.MEDIUM, context, cause
        )
        self.ml_component = ml_component


class LearningError(AdvancedAttackError):
    """Error in learning memory system."""

    def __init__(
        self,
        message: str,
        learning_operation: str,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message, ErrorCategory.LEARNING_MEMORY, ErrorSeverity.MEDIUM, context, cause
        )
        self.learning_operation = learning_operation


class ExecutionError(AdvancedAttackError):
    """Error in advanced attack execution."""

    def __init__(
        self,
        message: str,
        attack_name: str,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message, ErrorCategory.ATTACK_EXECUTION, ErrorSeverity.HIGH, context, cause
        )
        self.attack_name = attack_name


class MonitoringError(AdvancedAttackError):
    """Error in performance monitoring."""

    def __init__(
        self,
        message: str,
        monitoring_component: str,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message,
            ErrorCategory.PERFORMANCE_MONITORING,
            ErrorSeverity.LOW,
            context,
            cause,
        )
        self.monitoring_component = monitoring_component


class ConfigurationError(AdvancedAttackError):
    """Error in attack configuration."""

    def __init__(
        self,
        message: str,
        config_parameter: str,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message, ErrorCategory.CONFIGURATION, ErrorSeverity.HIGH, context, cause
        )
        self.config_parameter = config_parameter


class NetworkError(AdvancedAttackError):
    """Network-related error."""

    def __init__(
        self,
        message: str,
        network_operation: str,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message, ErrorCategory.NETWORK, ErrorSeverity.MEDIUM, context, cause
        )
        self.network_operation = network_operation


class SystemError(AdvancedAttackError):
    """System-level error."""

    def __init__(
        self,
        message: str,
        system_component: str,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message, ErrorCategory.SYSTEM, ErrorSeverity.CRITICAL, context, cause
        )
        self.system_component = system_component


class AdvancedAttackErrorHandler:
    """
    Centralized error handler for advanced attacks.
    Provides error recovery, fallback mechanisms, and error reporting.
    """

    def __init__(self):
        self.error_history: List[AdvancedAttackError] = []
        self.recovery_strategies: Dict[ErrorCategory, List[RecoveryAction]] = {
            ErrorCategory.INTEGRATION: [
                RecoveryAction.FALLBACK,
                RecoveryAction.RETRY,
                RecoveryAction.SKIP,
            ],
            ErrorCategory.ML_FEEDBACK: [RecoveryAction.FALLBACK, RecoveryAction.IGNORE],
            ErrorCategory.LEARNING_MEMORY: [
                RecoveryAction.FALLBACK,
                RecoveryAction.IGNORE,
            ],
            ErrorCategory.ATTACK_EXECUTION: [
                RecoveryAction.RETRY,
                RecoveryAction.FALLBACK,
                RecoveryAction.ABORT,
            ],
            ErrorCategory.PERFORMANCE_MONITORING: [
                RecoveryAction.IGNORE,
                RecoveryAction.FALLBACK,
            ],
            ErrorCategory.CONFIGURATION: [
                RecoveryAction.FALLBACK,
                RecoveryAction.ABORT,
            ],
            ErrorCategory.NETWORK: [RecoveryAction.RETRY, RecoveryAction.FALLBACK],
            ErrorCategory.SYSTEM: [RecoveryAction.ESCALATE, RecoveryAction.ABORT],
        }
        self.max_retry_attempts = 3
        self.retry_counts: Dict[str, int] = {}

        LOG.info("Advanced Attack Error Handler initialized")

    async def handle_error(self, error: AdvancedAttackError) -> RecoveryResult:
        """
        Handle an advanced attack error with appropriate recovery strategy.

        Args:
            error: The error to handle

        Returns:
            RecoveryResult with recovery action and outcome
        """

        LOG.error(f"Handling {error.category.value} error: {error.message}")

        # Store error in history
        self.error_history.append(error)

        # Determine recovery strategy
        recovery_actions = self.recovery_strategies.get(
            error.category, [RecoveryAction.ABORT]
        )

        # Try recovery actions in order
        for action in recovery_actions:
            try:
                result = await self._execute_recovery_action(error, action)
                if result.success:
                    LOG.info(f"Error recovery successful: {action.value}")
                    return result
                else:
                    LOG.warning(
                        f"Error recovery failed: {action.value} - {result.message}"
                    )
            except Exception as e:
                LOG.error(f"Recovery action {action.value} failed: {e}")

        # All recovery actions failed
        LOG.error(f"All recovery actions failed for error: {error.message}")
        return RecoveryResult(
            action=RecoveryAction.ABORT,
            success=False,
            message="All recovery actions failed",
        )

    async def _execute_recovery_action(
        self, error: AdvancedAttackError, action: RecoveryAction
    ) -> RecoveryResult:
        """Execute a specific recovery action."""

        if action == RecoveryAction.RETRY:
            return await self._handle_retry(error)
        elif action == RecoveryAction.FALLBACK:
            return await self._handle_fallback(error)
        elif action == RecoveryAction.SKIP:
            return await self._handle_skip(error)
        elif action == RecoveryAction.ABORT:
            return await self._handle_abort(error)
        elif action == RecoveryAction.ESCALATE:
            return await self._handle_escalate(error)
        elif action == RecoveryAction.IGNORE:
            return await self._handle_ignore(error)
        else:
            return RecoveryResult(
                action=action,
                success=False,
                message=f"Unknown recovery action: {action.value}",
            )

    async def _handle_retry(self, error: AdvancedAttackError) -> RecoveryResult:
        """Handle retry recovery action."""

        error_key = f"{error.category.value}_{error.context.attack_name}_{error.context.operation}"
        current_retries = self.retry_counts.get(error_key, 0)

        if current_retries >= self.max_retry_attempts:
            return RecoveryResult(
                action=RecoveryAction.RETRY,
                success=False,
                message=f"Max retry attempts ({self.max_retry_attempts}) exceeded",
                retry_count=current_retries,
            )

        # Increment retry count
        self.retry_counts[error_key] = current_retries + 1

        # Add delay based on retry count
        import asyncio

        delay = min(2**current_retries, 30)  # Exponential backoff, max 30 seconds
        await asyncio.sleep(delay)

        return RecoveryResult(
            action=RecoveryAction.RETRY,
            success=True,
            message=f"Retry attempt {current_retries + 1}",
            retry_count=current_retries + 1,
        )

    async def _handle_fallback(self, error: AdvancedAttackError) -> RecoveryResult:
        """Handle fallback recovery action."""

        fallback_strategy = None

        if error.category == ErrorCategory.INTEGRATION:
            fallback_strategy = self._get_integration_fallback(error)
        elif error.category == ErrorCategory.ML_FEEDBACK:
            fallback_strategy = "basic_strategy_selection"
        elif error.category == ErrorCategory.LEARNING_MEMORY:
            fallback_strategy = "default_parameters"
        elif error.category == ErrorCategory.ATTACK_EXECUTION:
            fallback_strategy = self._get_attack_fallback(error)
        elif error.category == ErrorCategory.PERFORMANCE_MONITORING:
            fallback_strategy = "basic_monitoring"
        elif error.category == ErrorCategory.CONFIGURATION:
            fallback_strategy = "default_configuration"
        elif error.category == ErrorCategory.NETWORK:
            fallback_strategy = "basic_network_handling"

        if fallback_strategy:
            return RecoveryResult(
                action=RecoveryAction.FALLBACK,
                success=True,
                message=f"Using fallback strategy: {fallback_strategy}",
                fallback_used=fallback_strategy,
            )
        else:
            return RecoveryResult(
                action=RecoveryAction.FALLBACK,
                success=False,
                message="No fallback strategy available",
            )

    def _get_integration_fallback(self, error: IntegrationError) -> Optional[str]:
        """Get fallback strategy for integration errors."""

        if error.integration_type == "ml_prediction":
            return "rule_based_prediction"
        elif error.integration_type == "fingerprinting":
            return "basic_fingerprinting"
        elif error.integration_type == "performance_monitoring":
            return "basic_monitoring"
        elif error.integration_type == "evolutionary_optimization":
            return "static_optimization"
        else:
            return "basic_operation"

    def _get_attack_fallback(self, error: ExecutionError) -> Optional[str]:
        """Get fallback strategy for attack execution errors."""

        # Map attack types to fallback strategies
        attack_fallbacks = {
            "adaptive_combo": "basic_combo_attack",
            "learning_memory": "static_memory",
            "ech_attacks": "basic_tls_attacks",
            "quic_attacks": "basic_http_attacks",
            "traffic_mimicry": "basic_obfuscation",
        }

        return attack_fallbacks.get(error.attack_name, "basic_attack")

    async def _handle_skip(self, error: AdvancedAttackError) -> RecoveryResult:
        """Handle skip recovery action."""

        return RecoveryResult(
            action=RecoveryAction.SKIP,
            success=True,
            message="Operation skipped due to error",
        )

    async def _handle_abort(self, error: AdvancedAttackError) -> RecoveryResult:
        """Handle abort recovery action."""

        return RecoveryResult(
            action=RecoveryAction.ABORT,
            success=False,
            message="Operation aborted due to error",
        )

    async def _handle_escalate(self, error: AdvancedAttackError) -> RecoveryResult:
        """Handle escalate recovery action."""

        # Log critical error for escalation
        LOG.critical(f"ESCALATED ERROR: {error.category.value} - {error.message}")

        # In a real system, this would notify administrators
        # For now, just log and continue

        return RecoveryResult(
            action=RecoveryAction.ESCALATE,
            success=True,
            message="Error escalated to administrators",
        )

    async def _handle_ignore(self, error: AdvancedAttackError) -> RecoveryResult:
        """Handle ignore recovery action."""

        LOG.debug(f"Ignoring error: {error.message}")

        return RecoveryResult(
            action=RecoveryAction.IGNORE, success=True, message="Error ignored"
        )

    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics."""

        if not self.error_history:
            return {
                "total_errors": 0,
                "by_category": {},
                "by_severity": {},
                "recent_errors": [],
            }

        # Count by category
        category_counts = {}
        for error in self.error_history:
            category = error.category.value
            category_counts[category] = category_counts.get(category, 0) + 1

        # Count by severity
        severity_counts = {}
        for error in self.error_history:
            severity = error.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Get recent errors (last 10)
        recent_errors = []
        for error in self.error_history[-10:]:
            recent_errors.append(
                {
                    "category": error.category.value,
                    "severity": error.severity.value,
                    "message": error.message,
                    "timestamp": error.timestamp.isoformat(),
                    "attack_name": error.context.attack_name if error.context else None,
                }
            )

        return {
            "total_errors": len(self.error_history),
            "by_category": category_counts,
            "by_severity": severity_counts,
            "recent_errors": recent_errors,
            "retry_counts": dict(self.retry_counts),
        }

    def clear_error_history(self):
        """Clear error history."""

        self.error_history.clear()
        self.retry_counts.clear()
        LOG.info("Error history cleared")

    def reset_retry_count(self, error_key: str):
        """Reset retry count for a specific error key."""

        if error_key in self.retry_counts:
            del self.retry_counts[error_key]
            LOG.debug(f"Reset retry count for: {error_key}")


# Global instance for easy access
_global_error_handler = None


def get_error_handler() -> AdvancedAttackErrorHandler:
    """Get global error handler instance."""
    global _global_error_handler
    if _global_error_handler is None:
        _global_error_handler = AdvancedAttackErrorHandler()
    return _global_error_handler


# Convenience functions for creating specific errors


def create_integration_error(
    message: str,
    integration_type: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> IntegrationError:
    """Create an integration error."""
    return IntegrationError(message, integration_type, context, cause)


def create_ml_feedback_error(
    message: str,
    ml_component: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> MLFeedbackError:
    """Create an ML feedback error."""
    return MLFeedbackError(message, ml_component, context, cause)


def create_learning_error(
    message: str,
    learning_operation: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> LearningError:
    """Create a learning error."""
    return LearningError(message, learning_operation, context, cause)


def create_execution_error(
    message: str,
    attack_name: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> ExecutionError:
    """Create an execution error."""
    return ExecutionError(message, attack_name, context, cause)


def create_monitoring_error(
    message: str,
    monitoring_component: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> MonitoringError:
    """Create a monitoring error."""
    return MonitoringError(message, monitoring_component, context, cause)


def create_configuration_error(
    message: str,
    config_parameter: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> ConfigurationError:
    """Create a configuration error."""
    return ConfigurationError(message, config_parameter, context, cause)


def create_network_error(
    message: str,
    network_operation: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> NetworkError:
    """Create a network error."""
    return NetworkError(message, network_operation, context, cause)


def create_system_error(
    message: str,
    system_component: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> SystemError:
    """Create a system error."""
    return SystemError(message, system_component, context, cause)
