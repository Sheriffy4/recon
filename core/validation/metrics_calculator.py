"""
Metrics Calculator for Results Validation System.

Extracted from results_validation_system.py to reduce god class complexity.
Handles calculation of various quality and performance metrics.
"""

import statistics
import logging
from typing import List

LOG = logging.getLogger("ValidationMetricsCalculator")


class ValidationMetricsCalculator:
    """Calculates validation metrics from reports."""

    @staticmethod
    def calculate_overall_success_rate(reports: List) -> float:
        """
        Calculate overall success rate across all reports.

        Args:
            reports: List of ValidationReport instances

        Returns:
            Success rate as float between 0.0 and 1.0
        """
        if not reports:
            return 0.0

        total_tests = sum(report.total_tests for report in reports)
        passed_tests = sum(report.passed_tests for report in reports)

        return passed_tests / total_tests if total_tests > 0 else 0.0

    @staticmethod
    def calculate_avg_trials_to_success() -> float:
        """
        Calculate average number of trials to success.

        Returns:
            Average trials count (simulated for now)
        """
        # TODO: Replace with real calculation from historical data
        return 3.5

    @staticmethod
    def calculate_fingerprint_accuracy(reports: List) -> float:
        """
        Calculate fingerprint accuracy across reports.

        Args:
            reports: List of ValidationReport instances

        Returns:
            Average accuracy score
        """
        if not reports:
            return 0.0

        accuracies = []
        for report in reports:
            for fp_validation in report.fingerprint_validations:
                accuracies.append(fp_validation.accuracy_score)

        return statistics.mean(accuracies) if accuracies else 0.0

    @staticmethod
    def calculate_strategy_reuse_rate() -> float:
        """
        Calculate strategy reuse rate.

        Returns:
            Reuse rate (simulated for now)
        """
        # TODO: Replace with real calculation from strategy usage data
        return 0.65

    @staticmethod
    def calculate_false_positive_rate(reports: List) -> float:
        """
        Calculate false positive rate across reports.

        Args:
            reports: List of ValidationReport instances

        Returns:
            Average false positive rate
        """
        if not reports:
            return 0.0

        fp_rates = []
        for report in reports:
            for fp_validation in report.fingerprint_validations:
                fp_rates.append(fp_validation.false_positive_rate)

        return statistics.mean(fp_rates) if fp_rates else 0.0

    @staticmethod
    def calculate_false_negative_rate(reports: List) -> float:
        """
        Calculate false negative rate across reports.

        Args:
            reports: List of ValidationReport instances

        Returns:
            Average false negative rate
        """
        if not reports:
            return 0.0

        fn_rates = []
        for report in reports:
            for fp_validation in report.fingerprint_validations:
                fn_rates.append(fp_validation.false_negative_rate)

        return statistics.mean(fn_rates) if fn_rates else 0.0

    @staticmethod
    def calculate_system_reliability(reports: List) -> float:
        """
        Calculate system reliability score.

        Args:
            reports: List of ValidationReport instances

        Returns:
            Average reliability score
        """
        if not reports:
            return 0.0

        reliability_scores = []
        for report in reports:
            for strategy_validation in report.strategy_validations:
                reliability_scores.append(strategy_validation.reliability_score)

        return statistics.mean(reliability_scores) if reliability_scores else 0.0

    @staticmethod
    def calculate_performance_score(reports: List) -> float:
        """
        Calculate performance score based on response times.

        Args:
            reports: List of ValidationReport instances

        Returns:
            Normalized performance score (0.0 to 1.0)
        """
        if not reports:
            return 0.0

        response_times = []
        for report in reports:
            for strategy_validation in report.strategy_validations:
                response_times.append(strategy_validation.avg_response_time)

        if not response_times:
            return 0.0

        avg_response_time = statistics.mean(response_times)
        # Normalize: 10 seconds = 0 score, 1 second = 1 score
        performance_score = max(0.0, 1.0 - (avg_response_time - 1.0) / 9.0)

        return min(1.0, performance_score)

    @staticmethod
    def calculate_improvement_trend(reports: List) -> float:
        """
        Calculate improvement trend over time.

        Args:
            reports: List of ValidationReport instances

        Returns:
            Trend value (positive = improving, negative = declining)
        """
        if len(reports) < 2:
            return 0.0

        # Sort by time
        sorted_reports = sorted(reports, key=lambda r: r.generated_at)

        # Compare first and second halves
        mid_point = len(sorted_reports) // 2
        early_scores = [r.overall_score for r in sorted_reports[:mid_point]]
        recent_scores = [r.overall_score for r in sorted_reports[mid_point:]]

        if not early_scores or not recent_scores:
            return 0.0

        early_avg = statistics.mean(early_scores)
        recent_avg = statistics.mean(recent_scores)

        # Trend as difference of averages
        return recent_avg - early_avg
