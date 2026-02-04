"""
Performance monitoring and degradation detection.

Monitors attack execution performance and detects anomalies
and degradation patterns.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, List
from collections import deque
from enum import Enum


class DegradationType(Enum):
    """Types of performance degradation."""

    EXECUTION_TIME = "execution_time"
    SUCCESS_RATE = "success_rate"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"


class DegradationSeverity(Enum):
    """Severity of performance degradation."""

    MINOR = "minor"
    MODERATE = "moderate"
    SEVERE = "severe"
    CRITICAL = "critical"


@dataclass
class PerformanceDegradation:
    """Information about detected performance degradation."""

    timestamp: datetime
    attack_name: str
    degradation_type: DegradationType
    severity: DegradationSeverity
    current_value: float
    baseline_value: float
    threshold_exceeded: float
    diagnostic_info: Dict[str, Any] = field(default_factory=dict)

    @property
    def degradation_percentage(self) -> float:
        """Calculate degradation as percentage."""
        if self.baseline_value == 0:
            return 0.0
        return ((self.current_value - self.baseline_value) / self.baseline_value) * 100


@dataclass
class PerformanceBaseline:
    """Baseline performance metrics for an attack."""

    attack_name: str
    avg_execution_time_ms: float
    avg_success_rate: float
    avg_throughput_pps: float
    avg_error_rate: float
    sample_count: int
    last_updated: datetime


class PerformanceMonitor:
    """
    Monitor for detecting performance degradation.

    Features:
    - Baseline establishment from historical data
    - Real-time anomaly detection
    - Trend analysis
    - Automatic threshold adjustment
    - Diagnostic information collection
    """

    def __init__(
        self,
        baseline_window_size: int = 100,
        degradation_threshold: float = 0.5,  # 50% degradation
        logger_name: str = "performance_monitor",
    ):
        """
        Initialize performance monitor.

        Args:
            baseline_window_size: Number of samples for baseline calculation
            degradation_threshold: Threshold for degradation detection (0.0-1.0)
            logger_name: Name for the logger
        """
        self.logger = logging.getLogger(logger_name)
        self.baseline_window_size = baseline_window_size
        self.degradation_threshold = degradation_threshold

        # Baselines for each attack
        self._baselines: Dict[str, PerformanceBaseline] = {}

        # Recent samples for baseline calculation
        self._execution_times: Dict[str, deque] = {}
        self._success_rates: Dict[str, deque] = {}
        self._throughputs: Dict[str, deque] = {}
        self._error_rates: Dict[str, deque] = {}

        # Detected degradations
        self._degradations: List[PerformanceDegradation] = []

    def record_execution(
        self,
        attack_name: str,
        execution_time_ms: float,
        success: bool,
        throughput_pps: float,
        is_error: bool = False,
    ):
        """
        Record an execution and check for degradation.

        Args:
            attack_name: Name of the attack
            execution_time_ms: Execution time in milliseconds
            success: Whether execution was successful
            throughput_pps: Throughput in packets per second
            is_error: Whether this was an error
        """
        # Initialize deques if needed
        if attack_name not in self._execution_times:
            self._execution_times[attack_name] = deque(maxlen=self.baseline_window_size)
            self._success_rates[attack_name] = deque(maxlen=self.baseline_window_size)
            self._throughputs[attack_name] = deque(maxlen=self.baseline_window_size)
            self._error_rates[attack_name] = deque(maxlen=self.baseline_window_size)

        # Record samples
        self._execution_times[attack_name].append(execution_time_ms)
        self._success_rates[attack_name].append(1.0 if success else 0.0)
        self._throughputs[attack_name].append(throughput_pps)
        self._error_rates[attack_name].append(1.0 if is_error else 0.0)

        # Update baseline if we have enough samples
        if len(self._execution_times[attack_name]) >= self.baseline_window_size:
            self._update_baseline(attack_name)

        # Check for degradation
        self._check_degradation(attack_name, execution_time_ms, success, throughput_pps, is_error)

    def _update_baseline(self, attack_name: str):
        """
        Update baseline metrics for an attack.

        Args:
            attack_name: Name of the attack
        """
        exec_times = self._execution_times[attack_name]
        success_rates = self._success_rates[attack_name]
        throughputs = self._throughputs[attack_name]
        error_rates = self._error_rates[attack_name]

        baseline = PerformanceBaseline(
            attack_name=attack_name,
            avg_execution_time_ms=sum(exec_times) / len(exec_times),
            avg_success_rate=sum(success_rates) / len(success_rates),
            avg_throughput_pps=sum(throughputs) / len(throughputs),
            avg_error_rate=sum(error_rates) / len(error_rates),
            sample_count=len(exec_times),
            last_updated=datetime.now(),
        )

        self._baselines[attack_name] = baseline

        self.logger.debug(
            f"Updated baseline for {attack_name}: "
            f"exec_time={baseline.avg_execution_time_ms:.2f}ms, "
            f"success_rate={baseline.avg_success_rate:.2%}"
        )

    def _check_degradation(
        self,
        attack_name: str,
        execution_time_ms: float,
        success: bool,
        throughput_pps: float,
        is_error: bool,
    ):
        """
        Check for performance degradation.

        Args:
            attack_name: Name of the attack
            execution_time_ms: Current execution time
            success: Current success status
            throughput_pps: Current throughput
            is_error: Whether this was an error
        """
        # Need baseline to check degradation
        if attack_name not in self._baselines:
            return

        baseline = self._baselines[attack_name]

        # Check execution time degradation
        if execution_time_ms > baseline.avg_execution_time_ms * (1 + self.degradation_threshold):
            severity = self._assess_severity(
                execution_time_ms, baseline.avg_execution_time_ms, self.degradation_threshold
            )

            degradation = PerformanceDegradation(
                timestamp=datetime.now(),
                attack_name=attack_name,
                degradation_type=DegradationType.EXECUTION_TIME,
                severity=severity,
                current_value=execution_time_ms,
                baseline_value=baseline.avg_execution_time_ms,
                threshold_exceeded=(execution_time_ms / baseline.avg_execution_time_ms) - 1,
                diagnostic_info={
                    "recent_avg": sum(list(self._execution_times[attack_name])[-10:]) / 10,
                    "baseline_samples": baseline.sample_count,
                },
            )

            self._record_degradation(degradation)

        # Check success rate degradation
        current_success_rate = sum(list(self._success_rates[attack_name])[-10:]) / 10
        if current_success_rate < baseline.avg_success_rate * (1 - self.degradation_threshold):
            severity = self._assess_severity(
                baseline.avg_success_rate, current_success_rate, self.degradation_threshold
            )

            degradation = PerformanceDegradation(
                timestamp=datetime.now(),
                attack_name=attack_name,
                degradation_type=DegradationType.SUCCESS_RATE,
                severity=severity,
                current_value=current_success_rate,
                baseline_value=baseline.avg_success_rate,
                threshold_exceeded=(baseline.avg_success_rate - current_success_rate)
                / baseline.avg_success_rate,
                diagnostic_info={
                    "recent_failures": sum(
                        1 for x in list(self._success_rates[attack_name])[-10:] if x == 0
                    ),
                    "baseline_samples": baseline.sample_count,
                },
            )

            self._record_degradation(degradation)

        # Check throughput degradation
        if throughput_pps < baseline.avg_throughput_pps * (1 - self.degradation_threshold):
            severity = self._assess_severity(
                baseline.avg_throughput_pps, throughput_pps, self.degradation_threshold
            )

            degradation = PerformanceDegradation(
                timestamp=datetime.now(),
                attack_name=attack_name,
                degradation_type=DegradationType.THROUGHPUT,
                severity=severity,
                current_value=throughput_pps,
                baseline_value=baseline.avg_throughput_pps,
                threshold_exceeded=(baseline.avg_throughput_pps - throughput_pps)
                / baseline.avg_throughput_pps,
                diagnostic_info={
                    "recent_avg": sum(list(self._throughputs[attack_name])[-10:]) / 10,
                    "baseline_samples": baseline.sample_count,
                },
            )

            self._record_degradation(degradation)

        # Check error rate increase
        current_error_rate = sum(list(self._error_rates[attack_name])[-10:]) / 10
        if current_error_rate > baseline.avg_error_rate * (1 + self.degradation_threshold):
            severity = self._assess_severity(
                current_error_rate, baseline.avg_error_rate, self.degradation_threshold
            )

            degradation = PerformanceDegradation(
                timestamp=datetime.now(),
                attack_name=attack_name,
                degradation_type=DegradationType.ERROR_RATE,
                severity=severity,
                current_value=current_error_rate,
                baseline_value=baseline.avg_error_rate,
                threshold_exceeded=(current_error_rate - baseline.avg_error_rate)
                / (baseline.avg_error_rate + 0.01),
                diagnostic_info={
                    "recent_errors": sum(
                        1 for x in list(self._error_rates[attack_name])[-10:] if x == 1
                    ),
                    "baseline_samples": baseline.sample_count,
                },
            )

            self._record_degradation(degradation)

    def _assess_severity(
        self, current: float, baseline: float, threshold: float
    ) -> DegradationSeverity:
        """
        Assess severity of degradation.

        Args:
            current: Current value
            baseline: Baseline value
            threshold: Degradation threshold

        Returns:
            Degradation severity
        """
        if baseline == 0:
            return DegradationSeverity.MINOR

        ratio = abs(current - baseline) / baseline

        if ratio > threshold * 3:
            return DegradationSeverity.CRITICAL
        elif ratio > threshold * 2:
            return DegradationSeverity.SEVERE
        elif ratio > threshold * 1.5:
            return DegradationSeverity.MODERATE
        else:
            return DegradationSeverity.MINOR

    def _record_degradation(self, degradation: PerformanceDegradation):
        """
        Record and log a performance degradation.

        Args:
            degradation: Degradation information
        """
        self._degradations.append(degradation)

        # Log based on severity
        severity_emoji = {
            DegradationSeverity.MINOR: "⚠️",
            DegradationSeverity.MODERATE: "⚠️⚠️",
            DegradationSeverity.SEVERE: "🔥",
            DegradationSeverity.CRITICAL: "💥",
        }
        emoji = severity_emoji.get(degradation.severity, "❓")

        self.logger.warning(
            f"{emoji} Performance degradation detected for {degradation.attack_name}"
        )
        self.logger.warning(
            f"📊 Type: {degradation.degradation_type.value}, "
            f"Severity: {degradation.severity.value}"
        )
        self.logger.warning(
            f"📈 Current: {degradation.current_value:.2f}, "
            f"Baseline: {degradation.baseline_value:.2f}, "
            f"Degradation: {degradation.degradation_percentage:.1f}%"
        )

        if degradation.diagnostic_info:
            self.logger.debug(f"🔍 Diagnostic info: {degradation.diagnostic_info}")

    def get_baseline(self, attack_name: str) -> Optional[PerformanceBaseline]:
        """
        Get baseline for an attack.

        Args:
            attack_name: Name of the attack

        Returns:
            Performance baseline or None
        """
        return self._baselines.get(attack_name)

    def get_all_baselines(self) -> Dict[str, PerformanceBaseline]:
        """
        Get all baselines.

        Returns:
            Dictionary of baselines
        """
        return dict(self._baselines)

    def get_recent_degradations(
        self,
        attack_name: Optional[str] = None,
        severity: Optional[DegradationSeverity] = None,
        limit: Optional[int] = None,
    ) -> List[PerformanceDegradation]:
        """
        Get recent degradations with optional filtering.

        Args:
            attack_name: Filter by attack name
            severity: Filter by severity
            limit: Maximum number of results

        Returns:
            List of degradations
        """
        filtered = self._degradations

        if attack_name:
            filtered = [d for d in filtered if d.attack_name == attack_name]

        if severity:
            filtered = [d for d in filtered if d.severity == severity]

        if limit:
            filtered = filtered[-limit:]

        return filtered

    def clear_degradations(self):
        """Clear degradation history."""
        self._degradations.clear()

    def reset_baseline(self, attack_name: Optional[str] = None):
        """
        Reset baseline for an attack or all attacks.

        Args:
            attack_name: Name of attack to reset, or None for all
        """
        if attack_name:
            if attack_name in self._baselines:
                del self._baselines[attack_name]
            if attack_name in self._execution_times:
                self._execution_times[attack_name].clear()
                self._success_rates[attack_name].clear()
                self._throughputs[attack_name].clear()
                self._error_rates[attack_name].clear()
        else:
            self._baselines.clear()
            self._execution_times.clear()
            self._success_rates.clear()
            self._throughputs.clear()
            self._error_rates.clear()
