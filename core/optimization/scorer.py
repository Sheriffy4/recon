"""
Optimization scorer for strategy performance evaluation.

This module provides scoring functionality to rank strategies based on
their performance metrics (retransmissions, latency, success rate).
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.optimization.models import PerformanceMetrics


class OptimizationScorer:
    """
    Calculates optimization scores from performance metrics.

    Score formula:
    score = success_weight - (retrans_weight * retransmissions) - (latency_weight * ttfb)

    Lower retransmissions and latency = higher score
    Higher success rate = higher score

    Attributes:
        success_weight: Weight for successful connections (default: 100.0)
        retrans_weight: Penalty weight for retransmissions (default: 5.0)
        latency_weight: Penalty weight for latency (default: 0.1)
    """

    def __init__(
        self,
        success_weight: float = 100.0,
        retrans_weight: float = 5.0,
        latency_weight: float = 0.1,
    ):
        """
        Initialize the optimization scorer with configurable weights.

        Args:
            success_weight: Weight for successful connections
            retrans_weight: Penalty weight for retransmissions
            latency_weight: Penalty weight for latency (per ms)
        """
        self.success_weight = success_weight
        self.retrans_weight = retrans_weight
        self.latency_weight = latency_weight

    def calculate_score(self, metrics: "PerformanceMetrics") -> float:
        """
        Calculate optimization score from performance metrics.

        The score is calculated as:
        - Start with success_weight if successful, or return -1000 if failed
        - Subtract retrans_weight * retransmission_count
        - Subtract latency_weight * ttfb_ms

        Higher scores indicate better performance.

        Args:
            metrics: Performance metrics from a strategy test

        Returns:
            Optimization score where higher is better.
            Returns -1000 for failed strategies.
        """
        # Failed strategies get a very low score
        if not metrics.success:
            return -1000.0

        # Start with base success weight
        score = self.success_weight

        # Penalize retransmissions
        score -= self.retrans_weight * metrics.retransmission_count

        # Penalize latency
        score -= self.latency_weight * metrics.ttfb_ms

        return score
