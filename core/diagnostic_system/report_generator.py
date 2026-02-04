"""
Report Generation Module

Provides performance report generation with comprehensive metrics analysis
and optimization recommendations.
"""

import logging
import statistics
from typing import Dict, List, Any, Tuple

from core.diagnostic_system.types import PerformanceReport


class ReportGenerator:
    """Handles performance report generation and metrics analysis."""

    def __init__(self, recommendation_engine, debug: bool = False):
        """
        Initialize ReportGenerator.

        Args:
            recommendation_engine: RecommendationEngine instance for generating recommendations
            debug: Enable debug logging
        """
        self.recommendation_engine = recommendation_engine
        self.debug = debug
        self.logger = logging.getLogger("ReportGenerator")
        if debug:
            self.logger.setLevel(logging.DEBUG)

    def generate_performance_report(
        self,
        packet_events,
        attack_results,
        technique_metrics,
        attack_metrics,
        category_health,
        stats,
        health_calculator,
    ) -> PerformanceReport:
        """
        Generate comprehensive performance report.

        Args:
            packet_events: Collection of packet processing events
            attack_results: Collection of attack results
            technique_metrics: Dictionary of technique performance metrics
            attack_metrics: Dictionary of attack performance metrics
            category_health: Dictionary of category health scores
            stats: Statistics dictionary to update
            health_calculator: Function to calculate health score

        Returns:
            PerformanceReport instance
        """
        import time

        try:
            current_time = time.time()
            total_events = len(packet_events)
            total_attack_results = len(attack_results)

            # Check if we have data
            if total_events == 0 and total_attack_results == 0:
                return self._create_empty_report(current_time)

            # Calculate basic metrics
            bypass_success_rate, avg_processing_time = self._calculate_basic_metrics(packet_events)

            # Analyze technique performance
            (
                top_performing_techniques,
                problematic_techniques,
                technique_performance,
            ) = self._analyze_technique_performance(technique_metrics)

            # Analyze attack performance
            top_performing_attacks, problematic_attacks, attack_performance = (
                self._analyze_attack_performance(attack_metrics)
            )

            # Get category performance
            attack_category_performance = category_health.copy()

            # Generate recommendations
            recommendations = self.recommendation_engine.generate_optimization_recommendations(
                bypass_success_rate,
                avg_processing_time,
                technique_performance,
                attack_performance,
            )

            # Calculate health score
            health_score = health_calculator(
                bypass_success_rate, avg_processing_time, attack_category_performance
            )

            # Create report
            report = PerformanceReport(
                report_timestamp=current_time,
                total_packets_processed=total_events,
                bypass_success_rate=bypass_success_rate,
                avg_processing_time_ms=avg_processing_time,
                top_performing_techniques=top_performing_techniques,
                problematic_techniques=problematic_techniques,
                top_performing_attacks=top_performing_attacks,
                problematic_attacks=problematic_attacks,
                attack_category_performance=attack_category_performance,
                optimization_recommendations=recommendations,
                system_health_score=health_score,
            )

            # Update stats
            stats["reports_generated"] += 1

            if self.debug:
                self.logger.debug(f"📊 Performance report generated: Health={health_score:.2f}")

            return report

        except Exception as e:
            self.logger.error(f"Error generating performance report: {e}")
            return self._create_error_report(current_time, e)

    def _create_empty_report(self, timestamp: float) -> PerformanceReport:
        """Create empty report when no data is available."""
        return PerformanceReport(
            report_timestamp=timestamp,
            total_packets_processed=0,
            bypass_success_rate=0.0,
            avg_processing_time_ms=0.0,
            top_performing_techniques=[],
            problematic_techniques=[],
            top_performing_attacks=[],
            problematic_attacks=[],
            attack_category_performance={},
            optimization_recommendations=["No data available for analysis"],
            system_health_score=0.0,
        )

    def _create_error_report(self, timestamp: float, error: Exception) -> PerformanceReport:
        """Create error report when generation fails."""
        return PerformanceReport(
            report_timestamp=timestamp,
            total_packets_processed=0,
            bypass_success_rate=0.0,
            avg_processing_time_ms=0.0,
            top_performing_techniques=[],
            problematic_techniques=[],
            top_performing_attacks=[],
            problematic_attacks=[],
            attack_category_performance={},
            optimization_recommendations=[f"Error generating report: {error}"],
            system_health_score=0.0,
        )

    def _calculate_basic_metrics(self, packet_events) -> Tuple[float, float]:
        """
        Calculate basic bypass and processing metrics.

        Returns:
            Tuple of (bypass_success_rate, avg_processing_time)
        """
        total_events = len(packet_events)
        successful_events = [e for e in packet_events if e.success]
        bypass_success_rate = len(successful_events) / total_events if total_events > 0 else 0.0

        processing_times = [e.processing_time_ms for e in packet_events if e.processing_time_ms > 0]
        avg_processing_time = statistics.mean(processing_times) if processing_times else 0.0

        return bypass_success_rate, avg_processing_time

    def _analyze_technique_performance(
        self, technique_metrics
    ) -> Tuple[List[str], List[str], List[Tuple[str, float]]]:
        """
        Analyze technique performance.

        Returns:
            Tuple of (top_performing, problematic, all_performance)
        """
        technique_performance = []
        for technique_name, metrics in technique_metrics.items():
            technique_performance.append((technique_name, metrics.success_rate))

        technique_performance.sort(key=lambda x: x[1], reverse=True)

        top_performing_techniques = [t[0] for t in technique_performance[:5] if t[1] > 0.8]
        problematic_techniques = [t[0] for t in technique_performance if t[1] < 0.5]

        return top_performing_techniques, problematic_techniques, technique_performance

    def _analyze_attack_performance(
        self, attack_metrics
    ) -> Tuple[List[str], List[str], List[Tuple[str, float]]]:
        """
        Analyze attack performance.

        Returns:
            Tuple of (top_performing, problematic, all_performance)
        """
        attack_performance = []
        for attack_name, metrics in attack_metrics.items():
            attack_performance.append((attack_name, metrics.success_rate))

        attack_performance.sort(key=lambda x: x[1], reverse=True)

        top_performing_attacks = [a[0] for a in attack_performance[:5] if a[1] > 0.8]
        problematic_attacks = [a[0] for a in attack_performance if a[1] < 0.5]

        return top_performing_attacks, problematic_attacks, attack_performance
