"""
Statistics and Health Scoring Module

Provides statistics management and health score calculation
for diagnostic system monitoring.
"""

import logging
import statistics
from typing import Dict, Optional, Any


class StatisticsManager:
    """Manages statistics collection and health score calculations."""

    def __init__(self, thresholds: Dict[str, float], debug: bool = False):
        """
        Initialize StatisticsManager.

        Args:
            thresholds: Dictionary of threshold values for health calculations
            debug: Enable debug logging
        """
        self.thresholds = thresholds
        self.debug = debug
        self.logger = logging.getLogger("StatisticsManager")
        if debug:
            self.logger.setLevel(logging.DEBUG)

    def calculate_health_score(
        self,
        effectiveness: float,
        processing_time: float,
        packet_events,
        error_events,
        category_performance: Optional[Dict[str, float]] = None,
    ) -> float:
        """
        Calculate system health score (0.0 to 1.0).

        Args:
            effectiveness: Overall bypass effectiveness
            processing_time: Average processing time in ms
            packet_events: Collection of packet processing events
            error_events: Collection of error events
            category_performance: Optional category performance scores

        Returns:
            Health score between 0.0 and 1.0
        """
        try:
            # Calculate effectiveness score
            effectiveness_score = min(effectiveness, 1.0)

            # Calculate performance score
            performance_score = self._calculate_performance_score(processing_time)

            # Calculate error score
            error_score = self._calculate_error_score(packet_events, error_events)

            # Calculate category score
            category_score = self._calculate_category_score(category_performance)

            # Weighted combination
            health_score = (
                effectiveness_score * 0.4
                + performance_score * 0.25
                + error_score * 0.2
                + category_score * 0.15
            )

            return min(max(health_score, 0.0), 1.0)

        except Exception as e:
            self.logger.error(f"Error calculating health score: {e}")
            return 0.0

    def calculate_comprehensive_health_score(
        self,
        effectiveness: float,
        avg_time_ms: float,
        error_rate: float,
        num_techniques: int,
    ) -> float:
        """
        Calculate comprehensive system health score with technique diversity.

        Args:
            effectiveness: Overall effectiveness
            avg_time_ms: Average processing time
            error_rate: Error rate
            num_techniques: Number of techniques used

        Returns:
            Health score between 0.0 and 1.0
        """
        base_score = effectiveness
        time_penalty = min(avg_time_ms / 200.0, 0.3)
        error_penalty = min(error_rate * 2, 0.4)
        diversity_bonus = min(num_techniques / 10.0, 0.1)
        health_score = base_score - time_penalty - error_penalty + diversity_bonus
        return max(0.0, min(1.0, health_score))

    def calculate_technique_performance_score(
        self, effectiveness: float, avg_time_ms: float
    ) -> float:
        """
        Calculate performance score for a technique.

        Args:
            effectiveness: Technique effectiveness
            avg_time_ms: Average processing time

        Returns:
            Performance score
        """
        time_penalty = min(avg_time_ms / 100.0, 0.5)
        return max(0.0, effectiveness - time_penalty)

    def calculate_percentile(self, values: list, percentile: int) -> float:
        """
        Calculate percentile of values.

        Args:
            values: List of numeric values
            percentile: Percentile to calculate (0-100)

        Returns:
            Percentile value
        """
        if not values:
            return 0.0

        sorted_values = sorted(values)
        index = percentile / 100.0 * (len(sorted_values) - 1)

        if index.is_integer():
            return sorted_values[int(index)]
        else:
            lower = sorted_values[int(index)]
            upper = sorted_values[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))

    def _calculate_performance_score(self, processing_time: float) -> float:
        """Calculate performance score based on processing time."""
        max_acceptable_time = self.thresholds.get("max_processing_time_ms", 100.0)

        if processing_time <= max_acceptable_time:
            return 1.0
        else:
            return max(
                0.0,
                1.0 - (processing_time - max_acceptable_time) / max_acceptable_time,
            )

    def _calculate_error_score(self, packet_events, error_events) -> float:
        """Calculate error score based on error rate."""
        total_events = len(packet_events)
        total_errors = len(error_events)
        error_rate = total_errors / total_events if total_events > 0 else 0.0
        max_error_rate = self.thresholds.get("max_error_rate", 0.1)
        return max(0.0, 1.0 - error_rate / max_error_rate)

    def _calculate_category_score(self, category_performance: Optional[Dict[str, float]]) -> float:
        """Calculate category performance score."""
        if not category_performance:
            return 1.0

        category_scores = list(category_performance.values())
        if not category_scores:
            return 1.0

        return statistics.mean(category_scores)

    def get_statistics_summary(self, stats: Dict[str, int]) -> Dict[str, Any]:
        """
        Get formatted statistics summary.

        Args:
            stats: Raw statistics dictionary

        Returns:
            Formatted statistics summary
        """
        return {
            "total_events_logged": stats.get("events_logged", 0),
            "total_errors_detected": stats.get("errors_detected", 0),
            "patterns_identified": stats.get("patterns_identified", 0),
            "reports_generated": stats.get("reports_generated", 0),
            "monitoring_cycles": stats.get("monitoring_cycles", 0),
            "attack_results_logged": stats.get("attack_results_logged", 0),
            "attack_failures_analyzed": stats.get("attack_failures_analyzed", 0),
            "registry_validations": stats.get("registry_validations", 0),
        }
