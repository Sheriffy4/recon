"""
Circuit breaker component for strategy failure management.

This module implements the circuit breaker pattern to prevent repeated testing
of failing strategies and provides adaptive strategy learning and ranking.

Feature: unified-engine-refactoring
Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
"""

import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from threading import Lock

from core.unified_engine_models import (
    CircuitBreakerState,
    BypassDefaults,
    StrategyError,
    StrategyTestResult,
)


# ============================================================================
# Strategy Performance Tracking
# ============================================================================


@dataclass
class StrategyPerformance:
    """
    Performance metrics for a strategy.

    Requirement 7.2: Learn and adapt strategy selection based on patterns.
    """

    strategy_id: str
    success_rate: float = 0.0
    avg_latency: float = 0.0
    total_tests: int = 0
    recent_successes: int = 0
    recent_failures: int = 0
    last_success_time: float = 0.0
    last_test_time: float = 0.0
    priority_score: float = 0.0

    def update_from_result(self, result: StrategyTestResult) -> None:
        """Update performance metrics from test result."""
        self.total_tests += 1
        self.last_test_time = time.time()

        if result.success:
            self.recent_successes += 1
            self.last_success_time = time.time()
        else:
            self.recent_failures += 1

        # Update success rate (recent window of last 10 tests)
        recent_total = self.recent_successes + self.recent_failures
        if recent_total > 10:
            # Keep only recent 10 tests
            scale_factor = 10 / recent_total
            self.recent_successes = int(self.recent_successes * scale_factor)
            self.recent_failures = int(self.recent_failures * scale_factor)

        recent_total = self.recent_successes + self.recent_failures
        self.success_rate = self.recent_successes / recent_total if recent_total > 0 else 0.0

        # Update average latency
        if result.success and result.avg_latency > 0:
            if self.avg_latency == 0.0:
                self.avg_latency = result.avg_latency
            else:
                # Exponential moving average
                self.avg_latency = 0.7 * self.avg_latency + 0.3 * result.avg_latency

        # Calculate priority score (higher is better)
        # Factors: success rate (70%), recency (20%), low latency (10%)
        recency_score = max(
            0, 1.0 - (time.time() - self.last_success_time) / 3600.0
        )  # 1 hour decay
        latency_score = max(0, 1.0 - (self.avg_latency / 10.0)) if self.avg_latency > 0 else 0.5

        self.priority_score = 0.7 * self.success_rate + 0.2 * recency_score + 0.1 * latency_score


# ============================================================================
# Circuit Breaker Interface
# ============================================================================


class ICircuitBreaker(ABC):
    """
    Interface for circuit breaker functionality.

    Requirement 7.1: Circuit breaker pattern for failing strategies.
    """

    @abstractmethod
    def should_allow_test(self, strategy_id: str) -> bool:
        """Check if strategy should be allowed to run."""
        pass

    @abstractmethod
    def record_result(self, strategy_id: str, result: StrategyTestResult) -> None:
        """Record test result for strategy."""
        pass

    @abstractmethod
    def get_prioritized_strategies(self, strategy_ids: List[str]) -> List[str]:
        """Get strategies ordered by priority."""
        pass

    @abstractmethod
    def get_strategy_performance(self, strategy_id: str) -> Optional[StrategyPerformance]:
        """Get performance metrics for strategy."""
        pass

    @abstractmethod
    def reset_strategy(self, strategy_id: str) -> None:
        """Reset circuit breaker state for strategy."""
        pass


# ============================================================================
# Circuit Breaker Implementation
# ============================================================================


class CircuitBreaker(ICircuitBreaker):
    """
    Circuit breaker implementation for strategy failure management.

    Requirements:
    - 7.1: Circuit breaker pattern for failing strategies
    - 7.2: Learn and adapt strategy selection
    - 7.3: Prioritize strategies with higher success rates
    - 7.4: Recovery mechanisms after timeout periods
    - 7.5: Update strategy rankings dynamically
    """

    def __init__(
        self,
        failure_threshold: int = BypassDefaults.CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        recovery_timeout: float = BypassDefaults.CIRCUIT_BREAKER_RECOVERY_TIMEOUT_SEC,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            logger: Logger instance for structured logging
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.logger = logger or logging.getLogger(__name__)

        # Thread-safe storage
        self._lock = Lock()
        self._circuit_states: Dict[str, CircuitBreakerState] = {}
        self._performance_metrics: Dict[str, StrategyPerformance] = {}

        self.logger.info(
            "CircuitBreaker initialized",
            extra={"failure_threshold": failure_threshold, "recovery_timeout": recovery_timeout},
        )

    def should_allow_test(self, strategy_id: str) -> bool:
        """
        Check if strategy should be allowed to run.

        Requirement 7.1: Circuit breaker pattern for failing strategies.
        Requirement 7.4: Recovery mechanisms after timeout periods.

        Args:
            strategy_id: Strategy identifier

        Returns:
            True if strategy should be tested, False otherwise
        """
        import time

        with self._lock:
            circuit_state = self._get_or_create_circuit_state(strategy_id)
            allowed = circuit_state.should_allow_request(
                current_time=time.time(), recovery_timeout=self.recovery_timeout
            )

            if not allowed:
                self.logger.debug(
                    "Strategy blocked by circuit breaker",
                    extra={
                        "strategy_id": strategy_id,
                        "state": circuit_state.state,
                        "failure_count": circuit_state.failure_count,
                    },
                )

            return allowed

    def record_result(self, strategy_id: str, result: StrategyTestResult) -> None:
        """
        Record test result for strategy.

        Requirements:
        - 7.1: Circuit breaker pattern for failing strategies
        - 7.2: Learn and adapt strategy selection
        - 7.5: Update strategy rankings dynamically

        Args:
            strategy_id: Strategy identifier
            result: Test result to record
        """
        with self._lock:
            # Update circuit breaker state
            circuit_state = self._get_or_create_circuit_state(strategy_id)

            if result.success:
                circuit_state.record_success()
                self.logger.debug(
                    "Strategy success recorded",
                    extra={
                        "strategy_id": strategy_id,
                        "circuit_state": circuit_state.state,
                        "success_count": circuit_state.success_count,
                    },
                )
            else:
                circuit_state.record_failure()
                self.logger.warning(
                    "Strategy failure recorded",
                    extra={
                        "strategy_id": strategy_id,
                        "circuit_state": circuit_state.state,
                        "failure_count": circuit_state.failure_count,
                    },
                )

            # Update performance metrics
            performance = self._get_or_create_performance(strategy_id)
            performance.update_from_result(result)

            self.logger.info(
                "Strategy performance updated",
                extra={
                    "strategy_id": strategy_id,
                    "success_rate": performance.success_rate,
                    "priority_score": performance.priority_score,
                    "avg_latency": performance.avg_latency,
                },
            )

    def get_prioritized_strategies(self, strategy_ids: List[str]) -> List[str]:
        """
        Get strategies ordered by priority.

        Requirement 7.3: Prioritize strategies with higher success rates.
        Requirement 7.5: Update strategy rankings dynamically.

        Args:
            strategy_ids: List of strategy identifiers

        Returns:
            List of strategy IDs ordered by priority (highest first)
        """
        with self._lock:
            # Filter out strategies blocked by circuit breaker
            available_strategies = [sid for sid in strategy_ids if self.should_allow_test(sid)]

            # Sort by priority score (highest first)
            prioritized = sorted(
                available_strategies,
                key=lambda sid: self._get_or_create_performance(sid).priority_score,
                reverse=True,
            )

            self.logger.debug(
                "Strategies prioritized",
                extra={
                    "total_strategies": len(strategy_ids),
                    "available_strategies": len(available_strategies),
                    "prioritized_order": prioritized[:5],  # Log top 5
                },
            )

            return prioritized

    def get_strategy_performance(self, strategy_id: str) -> Optional[StrategyPerformance]:
        """
        Get performance metrics for strategy.

        Args:
            strategy_id: Strategy identifier

        Returns:
            StrategyPerformance instance or None if not found
        """
        with self._lock:
            return self._performance_metrics.get(strategy_id)

    def reset_strategy(self, strategy_id: str) -> None:
        """
        Reset circuit breaker state for strategy.

        Args:
            strategy_id: Strategy identifier to reset
        """
        with self._lock:
            if strategy_id in self._circuit_states:
                del self._circuit_states[strategy_id]
            if strategy_id in self._performance_metrics:
                del self._performance_metrics[strategy_id]

            self.logger.info("Strategy reset", extra={"strategy_id": strategy_id})

    def get_circuit_state(self, strategy_id: str) -> Optional[CircuitBreakerState]:
        """
        Get circuit breaker state for strategy.

        Args:
            strategy_id: Strategy identifier

        Returns:
            CircuitBreakerState instance or None if not found
        """
        with self._lock:
            return self._circuit_states.get(strategy_id)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get overall circuit breaker statistics.

        Returns:
            Dictionary with circuit breaker statistics
        """
        with self._lock:
            total_strategies = len(self._circuit_states)
            open_circuits = sum(
                1 for state in self._circuit_states.values() if state.state == "OPEN"
            )
            half_open_circuits = sum(
                1 for state in self._circuit_states.values() if state.state == "HALF_OPEN"
            )

            avg_success_rate = 0.0
            if self._performance_metrics:
                avg_success_rate = sum(
                    perf.success_rate for perf in self._performance_metrics.values()
                ) / len(self._performance_metrics)

            return {
                "total_strategies": total_strategies,
                "open_circuits": open_circuits,
                "half_open_circuits": half_open_circuits,
                "closed_circuits": total_strategies - open_circuits - half_open_circuits,
                "avg_success_rate": avg_success_rate,
                "failure_threshold": self.failure_threshold,
                "recovery_timeout": self.recovery_timeout,
            }

    def _get_or_create_circuit_state(self, strategy_id: str) -> CircuitBreakerState:
        """Get or create circuit breaker state for strategy."""
        if strategy_id not in self._circuit_states:
            state = CircuitBreakerState(strategy_id=strategy_id)
            # Set the failure threshold for this circuit breaker instance
            state._failure_threshold = self.failure_threshold
            self._circuit_states[strategy_id] = state
        return self._circuit_states[strategy_id]

    def _get_or_create_performance(self, strategy_id: str) -> StrategyPerformance:
        """Get or create performance metrics for strategy."""
        if strategy_id not in self._performance_metrics:
            self._performance_metrics[strategy_id] = StrategyPerformance(strategy_id=strategy_id)
        return self._performance_metrics[strategy_id]


# ============================================================================
# Factory Functions
# ============================================================================


def create_circuit_breaker(
    failure_threshold: Optional[int] = None,
    recovery_timeout: Optional[float] = None,
    logger: Optional[logging.Logger] = None,
) -> ICircuitBreaker:
    """
    Factory function for creating circuit breaker instances.

    Args:
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds to wait before attempting recovery
        logger: Logger instance

    Returns:
        ICircuitBreaker implementation
    """
    return CircuitBreaker(
        failure_threshold=failure_threshold or BypassDefaults.CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        recovery_timeout=recovery_timeout or BypassDefaults.CIRCUIT_BREAKER_RECOVERY_TIMEOUT_SEC,
        logger=logger,
    )


# ============================================================================
# Utility Functions
# ============================================================================


def calculate_strategy_priority(
    success_rate: float,
    avg_latency: float,
    last_success_time: float,
    current_time: Optional[float] = None,
) -> float:
    """
    Calculate priority score for a strategy.

    Args:
        success_rate: Success rate (0.0 to 1.0)
        avg_latency: Average latency in seconds
        last_success_time: Timestamp of last success
        current_time: Current timestamp (defaults to now)

    Returns:
        Priority score (higher is better)
    """
    if current_time is None:
        current_time = time.time()

    # Recency score (decays over 1 hour)
    recency_score = max(0, 1.0 - (current_time - last_success_time) / 3600.0)

    # Latency score (lower latency is better)
    latency_score = max(0, 1.0 - (avg_latency / 10.0)) if avg_latency > 0 else 0.5

    # Weighted combination
    priority_score = 0.7 * success_rate + 0.2 * recency_score + 0.1 * latency_score

    return priority_score
