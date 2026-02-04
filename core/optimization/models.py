"""
Data models for strategy optimization and auto-recovery.

This module defines the core data structures used in the optimization
and auto-recovery systems.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


@dataclass
class Strategy:
    """
    Strategy configuration for DPI bypass.

    Attributes:
        type: Strategy type identifier (e.g., "split", "multisplit", "disorder")
        attacks: List of attack types to apply
        params: Dictionary of strategy-specific parameters
    """

    type: str
    attacks: List[str]
    params: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate strategy fields."""
        if not self.type:
            raise ValueError("Strategy type cannot be empty")
        if not self.attacks:
            raise ValueError("Strategy must have at least one attack")


@dataclass
class PerformanceMetrics:
    """
    Performance metrics for a single strategy test.

    Attributes:
        retransmission_count: Number of TCP retransmissions
        ttfb_ms: Time to first byte in milliseconds
        total_time_ms: Total connection time in milliseconds
        packets_sent: Number of packets sent
        packets_received: Number of packets received
        success: Whether the strategy test succeeded
        error_message: Optional error message if test failed
    """

    retransmission_count: int
    ttfb_ms: float
    total_time_ms: float
    packets_sent: int
    packets_received: int
    success: bool
    error_message: Optional[str] = None

    def __post_init__(self):
        """Validate metrics have non-negative values."""
        if self.retransmission_count < 0:
            raise ValueError(
                f"retransmission_count must be non-negative, got {self.retransmission_count}"
            )
        if self.ttfb_ms < 0:
            raise ValueError(f"ttfb_ms must be non-negative, got {self.ttfb_ms}")
        if self.total_time_ms < 0:
            raise ValueError(f"total_time_ms must be non-negative, got {self.total_time_ms}")
        if self.packets_sent < 0:
            raise ValueError(f"packets_sent must be non-negative, got {self.packets_sent}")
        if self.packets_received < 0:
            raise ValueError(f"packets_received must be non-negative, got {self.packets_received}")
        if self.total_time_ms < self.ttfb_ms:
            raise ValueError(
                f"total_time_ms ({self.total_time_ms}) must be >= ttfb_ms ({self.ttfb_ms})"
            )

    def validate(self) -> bool:
        """
        Validate that all metrics are within acceptable ranges.

        Returns:
            True if all metrics are valid
        """
        return (
            self.retransmission_count >= 0
            and self.ttfb_ms >= 0
            and self.total_time_ms >= 0
            and self.packets_sent >= 0
            and self.packets_received >= 0
            and self.total_time_ms >= self.ttfb_ms
        )


@dataclass
class RankedStrategy:
    """
    Strategy with ranking information.

    Attributes:
        strategy: The strategy configuration
        rank: Rank position (1 = best)
        score: Optimization score
        metrics: Performance metrics for this strategy
    """

    strategy: Strategy
    rank: int
    score: float
    metrics: PerformanceMetrics

    def __post_init__(self):
        """Validate ranking fields."""
        if self.rank < 1:
            raise ValueError(f"Rank must be >= 1, got {self.rank}")


@dataclass
class OptimizationResult:
    """
    Result of strategy optimization.

    Attributes:
        domain: Target domain that was optimized
        strategies: List of ranked strategies
        best_strategy: The highest-ranked strategy (if any)
        total_tested: Total number of strategies tested
        total_working: Number of strategies that worked
        optimization_time: Time taken for optimization in seconds
    """

    domain: str
    strategies: List[RankedStrategy]
    best_strategy: Optional[RankedStrategy]
    total_tested: int
    total_working: int
    optimization_time: float

    def __post_init__(self):
        """Validate optimization result fields."""
        if not self.domain:
            raise ValueError("Domain cannot be empty")
        if self.total_tested < 0:
            raise ValueError(f"total_tested must be non-negative, got {self.total_tested}")
        if self.total_working < 0:
            raise ValueError(f"total_working must be non-negative, got {self.total_working}")
        if self.total_working > self.total_tested:
            raise ValueError(
                f"total_working ({self.total_working}) cannot exceed total_tested ({self.total_tested})"
            )
        if self.optimization_time < 0:
            raise ValueError(
                f"optimization_time must be non-negative, got {self.optimization_time}"
            )
        if self.best_strategy is not None and self.best_strategy not in self.strategies:
            raise ValueError("best_strategy must be in strategies list")


@dataclass
class DomainHealth:
    """
    Health status for a monitored domain.

    Attributes:
        domain: Domain name
        consecutive_failures: Number of consecutive connection failures
        recent_retransmissions: List of recent retransmission counts
        last_success_time: Timestamp of last successful connection (Unix time)
        is_blocked: Whether domain is currently flagged as blocked
        block_reason: Reason for blocking flag (if blocked)
    """

    domain: str
    consecutive_failures: int = 0
    recent_retransmissions: List[int] = field(default_factory=list)
    last_success_time: Optional[float] = None
    is_blocked: bool = False
    block_reason: Optional[str] = None

    def __post_init__(self):
        """Validate domain health fields."""
        if not self.domain:
            raise ValueError("Domain cannot be empty")
        if self.consecutive_failures < 0:
            raise ValueError(
                f"consecutive_failures must be non-negative, got {self.consecutive_failures}"
            )
        for i, retrans in enumerate(self.recent_retransmissions):
            if retrans < 0:
                raise ValueError(
                    f"retransmission count at index {i} must be non-negative, got {retrans}"
                )
        if self.last_success_time is not None and self.last_success_time < 0:
            raise ValueError(
                f"last_success_time must be non-negative, got {self.last_success_time}"
            )


@dataclass
class RecoveryEvent:
    """
    Record of a recovery attempt.

    Attributes:
        domain: Domain that required recovery
        timestamp: Unix timestamp of recovery event
        reason: Reason for triggering recovery
        old_strategy: Strategy that was failing (if any)
        new_strategy: New strategy that was applied (if found)
        success: Whether recovery was successful
    """

    domain: str
    timestamp: float
    reason: str
    old_strategy: Optional[Strategy]
    new_strategy: Optional[Strategy]
    success: bool

    def __post_init__(self):
        """Validate recovery event fields."""
        if not self.domain:
            raise ValueError("Domain cannot be empty")
        if self.timestamp < 0:
            raise ValueError(f"timestamp must be non-negative, got {self.timestamp}")
        if not self.reason:
            raise ValueError("Reason cannot be empty")
