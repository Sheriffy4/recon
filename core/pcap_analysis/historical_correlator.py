"""
Historical data correlation for root causes.

This module contains the HistoricalCorrelator class that correlates
root causes with historical strategy data.
"""

from typing import List, Dict, Any
import statistics
from .models import RootCause, CorrelatedCause, RootCauseType


class HistoricalCorrelator:
    """Correlator for matching root causes with historical data."""

    def correlate_single_cause(
        self, cause: RootCause, summary_data: Dict[str, Any]
    ) -> CorrelatedCause:
        """Correlate a single root cause with historical data."""
        correlation = CorrelatedCause(root_cause=cause)

        # Analyze strategy effectiveness data
        strategy_data = summary_data.get("strategy_effectiveness", {})
        failing_strategies = strategy_data.get("top_failing", [])

        # Look for patterns in failing strategies
        correlation.historical_matches = self._find_historical_matches(cause, failing_strategies)
        correlation.correlation_strength = self._calculate_correlation_strength(
            cause, correlation.historical_matches
        )

        # Calculate pattern frequency
        total_strategies = summary_data.get("total_strategies_tested", 1)
        correlation.pattern_frequency = len(correlation.historical_matches) / max(
            1, total_strategies
        )

        # Analyze success rate impact
        correlation.success_rate_impact = self._calculate_success_rate_impact(cause, summary_data)

        return correlation

    def _find_historical_matches(
        self, cause: RootCause, failing_strategies: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Find historical matches for a root cause."""
        matches = []

        for strategy in failing_strategies:
            if self._strategy_matches_cause(strategy, cause):
                matches.append(strategy)

        return matches

    def _strategy_matches_cause(self, strategy: Dict[str, Any], cause: RootCause) -> bool:
        """Check if a strategy failure matches a root cause."""
        strategy_str = strategy.get("strategy", "").lower()
        telemetry = strategy.get("engine_telemetry", {})

        # Match based on cause type
        if cause.cause_type == RootCauseType.MISSING_FAKE_PACKETS:
            return telemetry.get("fake_packets_sent", 0) == 0

        elif cause.cause_type == RootCauseType.INCORRECT_TTL:
            return "ttl=" in strategy_str

        elif cause.cause_type == RootCauseType.WRONG_SPLIT_POSITION:
            return "split-pos=" in strategy_str or "split_pos=" in strategy_str

        elif cause.cause_type == RootCauseType.MISSING_FOOLING_METHOD:
            return (
                "fooling=" in strategy_str or "badsum" in strategy_str or "badseq" in strategy_str
            )

        elif cause.cause_type == RootCauseType.ENGINE_TELEMETRY_ANOMALY:
            return (
                telemetry.get("segments_sent", 0) == 0
                and telemetry.get("fake_packets_sent", 0) == 0
            )

        return False

    def _calculate_correlation_strength(
        self, cause: RootCause, matches: List[Dict[str, Any]]
    ) -> float:
        """Calculate correlation strength between cause and historical data."""
        if not matches:
            return 0.0

        # Base correlation on number of matches and cause confidence
        match_score = min(1.0, len(matches) * 0.2)
        confidence_score = cause.confidence

        # Adjust based on match quality
        quality_scores = []
        for match in matches:
            quality = self._assess_match_quality(match)
            quality_scores.append(quality)

        avg_quality = statistics.mean(quality_scores) if quality_scores else 0.5

        return match_score * 0.4 + confidence_score * 0.3 + avg_quality * 0.3

    def _assess_match_quality(self, match: Dict[str, Any]) -> float:
        """Assess the quality of a historical match."""
        quality = 0.5  # Base quality

        # Higher quality if strategy has detailed telemetry
        telemetry = match.get("engine_telemetry", {})
        if telemetry:
            quality += 0.2

        # Higher quality if strategy has specific parameters
        strategy_str = match.get("strategy", "")
        if any(param in strategy_str for param in ["ttl=", "split-pos=", "fooling="]):
            quality += 0.2

        # Higher quality if failure is consistent (0% success rate)
        if match.get("success_rate", 0) == 0.0:
            quality += 0.1

        return min(1.0, quality)

    def _calculate_success_rate_impact(
        self, cause: RootCause, summary_data: Dict[str, Any]
    ) -> float:
        """Calculate the impact of this cause on success rate."""
        overall_success_rate = summary_data.get("key_metrics", {}).get("overall_success_rate", 0.0)

        # If overall success rate is 0, this cause has high impact
        if overall_success_rate == 0.0:
            return cause.impact_on_success

        # Otherwise, estimate impact based on cause severity
        return cause.impact_on_success * (1.0 - overall_success_rate)
