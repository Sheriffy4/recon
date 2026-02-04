"""
Core data models and exception hierarchy for UnifiedBypassEngine refactoring.

This module provides the foundational data structures and exception types
for the modular UnifiedBypassEngine architecture.

Feature: unified-engine-refactoring
Requirements: 8.1, 8.2, 8.4, 9.3
"""

import logging
import random
import socket
import asyncio
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Union, Tuple
from enum import Enum, auto
from contextlib import contextmanager
from abc import ABC, abstractmethod


# ============================================================================
# Configuration Constants (Requirement 9.3)
# ============================================================================


@dataclass(frozen=True)
class BypassDefaults:
    """
    Configuration constants with documentation.

    Requirement 9.3: Use named constants rather than magic numbers.
    All default values are centralized here for maintainability.
    """

    FAKE_TTL: int = 3
    WINDOW_DIV_DISORDER: int = 8
    WINDOW_DIV_DEFAULT: int = 2
    IPID_STEP: int = 2048
    SEQOVL_OVERLAP_SIZE: int = 336
    WINDIVERT_WARMUP_SEC: float = 3.0
    CDN_TIMEOUT_SEC: float = 15.0
    RETRANSMISSION_THRESHOLD_PERCENT: float = 10.0
    MIN_PACKETS_FOR_VALIDATION: int = 2

    # Circuit breaker defaults
    CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = 3
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT_SEC: float = 300.0  # 5 minutes

    # Retry defaults
    DEFAULT_MAX_RETRIES: int = 3
    DEFAULT_BASE_DELAY_SEC: float = 0.5
    DEFAULT_MAX_DELAY_SEC: float = 30.0
    DEFAULT_EXPONENTIAL_BASE: float = 2.0
    DEFAULT_JITTER_FACTOR: float = 0.1

    # Connection pooling
    DEFAULT_POOL_SIZE: int = 10
    DEFAULT_POOL_TIMEOUT_SEC: float = 30.0

    # Cache defaults
    DEFAULT_CACHE_TTL_SEC: float = 3600.0  # 1 hour
    DEFAULT_CACHE_MAX_SIZE: int = 1000


# ============================================================================
# Enums (Requirements 8.1, 8.4)
# ============================================================================


class EngineState(Enum):
    """
    Engine state machine states.

    Requirement 8.1: Consistent result types across all methods.
    """

    IDLE = auto()
    STARTING = auto()
    RUNNING = auto()
    STOPPING = auto()
    ERROR = auto()


class ValidationStatus(Enum):
    """
    Validation result status types.

    Requirement 8.1: Consistent result types across all methods.
    """

    SUCCESS = auto()
    FALSE_POSITIVE = auto()
    HIGH_RETRANSMISSIONS = auto()
    NO_TRAFFIC = auto()
    NO_HANDSHAKE = auto()
    HTTP_FAILED = auto()


# ============================================================================
# Core Data Models (Requirements 8.1, 8.4)
# ============================================================================


@dataclass
class ValidationResult:
    """
    Structured validation result.

    Requirement 8.1: Consistent result types across all methods.
    Requirement 8.4: Strongly-typed data structures rather than tuples or loose dictionaries.
    """

    success: bool
    status: ValidationStatus
    error: Optional[str] = None
    metrics: Dict[str, int] = field(default_factory=dict)
    confidence: float = 1.0
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format for serialization."""
        return {
            "success": self.success,
            "status": self.status.name,
            "error": self.error,
            "metrics": self.metrics,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
        }


@dataclass
class StrategyTestResult:
    """
    Comprehensive strategy test result.

    Requirement 8.1: Consistent result types across all methods.
    Requirement 8.4: Strongly-typed data structures rather than tuples or loose dictionaries.
    """

    success: bool
    successful_sites: int
    total_sites: int
    avg_latency: float
    site_results: Dict[str, Tuple[str, str, float, int]]
    telemetry: Dict[str, Any]
    validation: ValidationResult
    strategy_id: str
    timestamp: float = 0.0
    duration_sec: float = 0.0
    error: Optional[str] = None
    test_duration: float = 0.0
    validation_result: Optional[ValidationResult] = None
    connectivity_details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format for serialization."""
        result = {
            "success": self.success,
            "successful_sites": self.successful_sites,
            "total_sites": self.total_sites,
            "avg_latency": self.avg_latency,
            "site_results": self.site_results,
            "telemetry": self.telemetry,
            "validation": self.validation.to_dict() if self.validation else None,
            "strategy_id": self.strategy_id,
            "timestamp": self.timestamp,
            "duration_sec": self.duration_sec,
            "error": self.error,
            "test_duration": self.test_duration,
        }

        if self.validation_result:
            result["validation_result"] = self.validation_result.to_dict()
        if self.connectivity_details:
            result["connectivity_details"] = self.connectivity_details

        return result


@dataclass
class TelemetrySnapshot:
    """
    Structured telemetry data snapshot.

    Requirement 8.1: Consistent result types across all methods.
    Requirement 8.4: Strongly-typed data structures rather than tuples or loose dictionaries.
    """

    timestamp: float
    client_hellos: int
    server_hellos: int
    retransmissions: int
    total_packets: int
    fake_packets_sent: int
    bytes_processed: int
    connection_attempts: int
    successful_connections: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format for serialization."""
        return {
            "timestamp": self.timestamp,
            "client_hellos": self.client_hellos,
            "server_hellos": self.server_hellos,
            "retransmissions": self.retransmissions,
            "total_packets": self.total_packets,
            "fake_packets_sent": self.fake_packets_sent,
            "bytes_processed": self.bytes_processed,
            "connection_attempts": self.connection_attempts,
            "successful_connections": self.successful_connections,
        }

    @classmethod
    def from_engine(cls, engine: Any) -> "TelemetrySnapshot":
        """
        Create telemetry snapshot from engine.

        This method extracts telemetry data from the bypass engine
        and creates a structured snapshot.
        """
        import time

        # Default values if engine doesn't have telemetry
        if not hasattr(engine, "get_telemetry"):
            return cls(
                timestamp=time.time(),
                client_hellos=0,
                server_hellos=0,
                retransmissions=0,
                total_packets=0,
                fake_packets_sent=0,
                bytes_processed=0,
                connection_attempts=0,
                successful_connections=0,
            )

        telemetry = engine.get_telemetry()
        return cls(
            timestamp=time.time(),
            client_hellos=telemetry.get("client_hellos", 0),
            server_hellos=telemetry.get("server_hellos", 0),
            retransmissions=telemetry.get("retransmissions", 0),
            total_packets=telemetry.get("total_packets", 0),
            fake_packets_sent=telemetry.get("fake_packets_sent", 0),
            bytes_processed=telemetry.get("bytes_processed", 0),
            connection_attempts=telemetry.get("connection_attempts", 0),
            successful_connections=telemetry.get("successful_connections", 0),
        )


@dataclass
class CircuitBreakerState:
    """
    Circuit breaker state for a strategy.

    Requirement 8.1: Consistent result types across all methods.
    Requirement 8.4: Strongly-typed data structures rather than tuples or loose dictionaries.
    """

    strategy_id: str
    failure_count: int = 0
    last_failure_time: float = 0.0
    state: str = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    success_count: int = 0
    total_attempts: int = 0
    _failure_threshold: int = BypassDefaults.CIRCUIT_BREAKER_FAILURE_THRESHOLD

    def should_allow_request(
        self, current_time: Optional[float] = None, recovery_timeout: Optional[float] = None
    ) -> bool:
        """
        Check if strategy should be tested based on circuit breaker state.

        Args:
            current_time: Current timestamp (defaults to time.time())
            recovery_timeout: Recovery timeout in seconds (defaults to class default)

        Returns True if the strategy should be allowed to run.
        """
        import time

        if current_time is None:
            current_time = time.time()

        if recovery_timeout is None:
            recovery_timeout = BypassDefaults.CIRCUIT_BREAKER_RECOVERY_TIMEOUT_SEC

        if self.state == "CLOSED":
            return True
        elif self.state == "OPEN":
            # Check if recovery timeout has passed
            if (current_time - self.last_failure_time) > recovery_timeout:
                self.state = "HALF_OPEN"
                return True
            return False
        elif self.state == "HALF_OPEN":
            return True

        return False

    def record_success(self) -> None:
        """Record successful test execution."""
        self.success_count += 1
        self.total_attempts += 1

        if self.state == "HALF_OPEN":
            # Recovery successful, close circuit
            self.state = "CLOSED"
            self.failure_count = 0
        elif self.state == "CLOSED" and self.failure_count > 0:
            # Reduce failure count on success
            self.failure_count = max(0, self.failure_count - 1)

    def record_failure(self) -> None:
        """Record failed test execution."""
        import time

        self.failure_count += 1
        self.total_attempts += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self._failure_threshold:
            self.state = "OPEN"


# ============================================================================
# Exception Hierarchy (Requirements 8.2, 8.3)
# ============================================================================


class BypassEngineError(Exception):
    """
    Base exception for all bypass engine errors.

    Requirement 8.2: Structured error information with specific error types.
    Requirement 8.3: Specific exception types rather than broad Exception catches.
    """

    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.context = context or {}
        self.timestamp = self._get_timestamp()

    def _get_timestamp(self) -> float:
        """Get current timestamp for error tracking."""
        import time

        return time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for structured logging."""
        return {
            "error_type": self.__class__.__name__,
            "message": str(self),
            "context": self.context,
            "timestamp": self.timestamp,
        }


class StrategyError(BypassEngineError):
    """
    Strategy-related errors.

    Requirement 8.2: Structured error information with specific error types.
    """

    pass


class ValidationError(BypassEngineError):
    """
    Validation-related errors.

    Requirement 8.2: Structured error information with specific error types.
    """

    pass


class ConnectionError(BypassEngineError):
    """
    Network connection errors.

    Requirement 8.2: Structured error information with specific error types.
    """

    pass


class ResourceError(BypassEngineError):
    """
    Resource management errors.

    Requirement 8.2: Structured error information with specific error types.
    """

    pass


class StateError(BypassEngineError):
    """
    State management errors.

    Requirement 8.2: Structured error information with specific error types.
    """

    pass


# ============================================================================
# Error Context Management (Requirement 8.2)
# ============================================================================


@contextmanager
def error_context(operation: str, logger: logging.Logger):
    """
    Structured error handling context.

    Requirement 8.2: Structured error information with specific error types.

    Usage:
        with error_context("test_strategy", logger):
            # operation code here
            pass
    """
    try:
        yield
    except BypassEngineError:
        # Re-raise our specific errors
        raise
    except (asyncio.TimeoutError, socket.timeout) as e:
        raise ConnectionError(f"{operation}: timeout", {"original_error": str(e)})
    except ConnectionResetError as e:
        raise ConnectionError(f"{operation}: connection reset", {"original_error": str(e)})
    except Exception as e:
        logger.error(f"Unexpected error in {operation}: {e}", exc_info=True)
        raise BypassEngineError(f"{operation} failed", {"original_error": str(e)})


# ============================================================================
# Retry Configuration (Requirement 9.4)
# ============================================================================


@dataclass
class RetryConfig:
    """
    Configuration for retry operations with exponential backoff.

    Requirement 9.4: Exponential backoff with jitter for retry operations.
    """

    max_attempts: int = BypassDefaults.DEFAULT_MAX_RETRIES
    base_delay: float = BypassDefaults.DEFAULT_BASE_DELAY_SEC
    max_delay: float = BypassDefaults.DEFAULT_MAX_DELAY_SEC
    exponential_base: float = BypassDefaults.DEFAULT_EXPONENTIAL_BASE
    jitter: float = BypassDefaults.DEFAULT_JITTER_FACTOR

    def get_delay(self, attempt: int) -> float:
        """
        Calculate delay for given attempt with exponential backoff and jitter.

        Requirement 9.4: Exponential backoff with jitter.
        """
        delay = min(self.base_delay * (self.exponential_base**attempt), self.max_delay)
        jitter = delay * self.jitter * random.random()
        return delay + jitter


# ============================================================================
# Utility Functions
# ============================================================================


def create_validation_result(
    success: bool, status: ValidationStatus, error: Optional[str] = None, **kwargs
) -> ValidationResult:
    """
    Factory function for creating ValidationResult instances.

    Requirement 8.1: Consistent result types across all methods.
    """
    return ValidationResult(success=success, status=status, error=error, **kwargs)


def create_strategy_test_result(
    success: bool, strategy_id: str, validation: ValidationResult, **kwargs
) -> StrategyTestResult:
    """
    Factory function for creating StrategyTestResult instances.

    Requirement 8.1: Consistent result types across all methods.
    """
    return StrategyTestResult(
        success=success,
        strategy_id=strategy_id,
        validation=validation,
        successful_sites=kwargs.get("successful_sites", 0),
        total_sites=kwargs.get("total_sites", 0),
        avg_latency=kwargs.get("avg_latency", 0.0),
        site_results=kwargs.get("site_results", {}),
        telemetry=kwargs.get("telemetry", {}),
        **{
            k: v
            for k, v in kwargs.items()
            if k
            not in ["successful_sites", "total_sites", "avg_latency", "site_results", "telemetry"]
        },
    )
