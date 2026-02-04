"""
Accessibility Testing Metrics Collection

This module provides detailed metrics collection for site accessibility testing,
enabling monitoring and analysis of testing performance and reliability.

Requirements: 2.1, 2.3
"""

import time
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
import logging
from enum import Enum


class TestMethod(Enum):
    """Test methods used for accessibility testing."""

    CURL = "curl"
    TCP_SOCKET = "tcp_socket"
    REQUESTS = "requests"
    CACHED = "cached"


class TestResult(Enum):
    """Test result outcomes."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class AccessibilityTestMetric:
    """Individual accessibility test metric."""

    timestamp: float
    target_ip: str
    domain: Optional[str]
    method: TestMethod
    result: TestResult
    duration_ms: float
    http_status_code: Optional[int] = None
    error_reason: Optional[str] = None
    retry_count: int = 0
    cache_hit: bool = False


@dataclass
class AccessibilityMetricsSummary:
    """Summary of accessibility testing metrics."""

    total_tests: int = 0
    successful_tests: int = 0
    failed_tests: int = 0
    timeout_tests: int = 0
    error_tests: int = 0
    cache_hits: int = 0
    average_duration_ms: float = 0.0
    success_rate: float = 0.0
    cache_hit_rate: float = 0.0
    method_distribution: Dict[str, int] = field(default_factory=dict)
    error_distribution: Dict[str, int] = field(default_factory=dict)
    domain_performance: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class AccessibilityMetricsCollector:
    """
    Collector for detailed accessibility testing metrics.

    Provides comprehensive monitoring of accessibility testing performance,
    including success rates, timing, error patterns, and method effectiveness.
    """

    def __init__(self, max_metrics: int = 10000, logger: Optional[logging.Logger] = None):
        """
        Initialize metrics collector.

        Args:
            max_metrics: Maximum number of metrics to keep in memory
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self.max_metrics = max_metrics
        self._metrics: deque = deque(maxlen=max_metrics)
        self._lock = threading.Lock()

        # Real-time counters for quick access
        self._counters = {
            "total_tests": 0,
            "successful_tests": 0,
            "failed_tests": 0,
            "timeout_tests": 0,
            "error_tests": 0,
            "cache_hits": 0,
            "total_duration_ms": 0.0,
        }

        # Method and error tracking
        self._method_counts = defaultdict(int)
        self._error_counts = defaultdict(int)
        self._domain_stats = defaultdict(
            lambda: {
                "tests": 0,
                "successes": 0,
                "total_duration_ms": 0.0,
                "errors": defaultdict(int),
            }
        )

        self.logger.info("📊 AccessibilityMetricsCollector initialized")

    def record_test(
        self,
        target_ip: str,
        domain: Optional[str],
        method: TestMethod,
        result: TestResult,
        duration_ms: float,
        http_status_code: Optional[int] = None,
        error_reason: Optional[str] = None,
        retry_count: int = 0,
        cache_hit: bool = False,
    ) -> None:
        """
        Record an accessibility test metric.

        Args:
            target_ip: Target IP address tested
            domain: Domain name tested (if any)
            method: Test method used
            result: Test result outcome
            duration_ms: Test duration in milliseconds
            http_status_code: HTTP status code received (if any)
            error_reason: Error reason (if failed)
            retry_count: Number of retries performed
            cache_hit: Whether result came from cache
        """
        metric = AccessibilityTestMetric(
            timestamp=time.time(),
            target_ip=target_ip,
            domain=domain,
            method=method,
            result=result,
            duration_ms=duration_ms,
            http_status_code=http_status_code,
            error_reason=error_reason,
            retry_count=retry_count,
            cache_hit=cache_hit,
        )

        with self._lock:
            self._metrics.append(metric)
            self._update_counters(metric)
            self._update_method_stats(metric)
            self._update_domain_stats(metric)

        # Log significant events
        if result == TestResult.SUCCESS:
            self.logger.debug(
                f"✅ Test success: {domain or target_ip} via {method.value} "
                f"({duration_ms:.1f}ms, HTTP {http_status_code or 'N/A'})"
            )
        elif result == TestResult.FAILURE:
            self.logger.info(
                f"❌ Test failure: {domain or target_ip} via {method.value} "
                f"({duration_ms:.1f}ms) - {error_reason or 'Unknown error'}"
            )
        elif result == TestResult.TIMEOUT:
            self.logger.warning(
                f"⏰ Test timeout: {domain or target_ip} via {method.value} "
                f"({duration_ms:.1f}ms)"
            )

    def _update_counters(self, metric: AccessibilityTestMetric) -> None:
        """Update real-time counters."""
        self._counters["total_tests"] += 1
        self._counters["total_duration_ms"] += metric.duration_ms

        if metric.result == TestResult.SUCCESS:
            self._counters["successful_tests"] += 1
        elif metric.result == TestResult.FAILURE:
            self._counters["failed_tests"] += 1
        elif metric.result == TestResult.TIMEOUT:
            self._counters["timeout_tests"] += 1
        elif metric.result == TestResult.ERROR:
            self._counters["error_tests"] += 1

        if metric.cache_hit:
            self._counters["cache_hits"] += 1

    def _update_method_stats(self, metric: AccessibilityTestMetric) -> None:
        """Update method usage statistics."""
        self._method_counts[metric.method.value] += 1

        if metric.error_reason:
            self._error_counts[metric.error_reason] += 1

    def _update_domain_stats(self, metric: AccessibilityTestMetric) -> None:
        """Update per-domain statistics."""
        domain_key = metric.domain or metric.target_ip
        stats = self._domain_stats[domain_key]

        stats["tests"] += 1
        stats["total_duration_ms"] += metric.duration_ms

        if metric.result == TestResult.SUCCESS:
            stats["successes"] += 1

        if metric.error_reason:
            stats["errors"][metric.error_reason] += 1

    def get_summary(
        self, time_window_seconds: Optional[float] = None
    ) -> AccessibilityMetricsSummary:
        """
        Get summary of accessibility testing metrics.

        Args:
            time_window_seconds: Optional time window to filter metrics (None for all)

        Returns:
            AccessibilityMetricsSummary: Comprehensive metrics summary
        """
        with self._lock:
            # Filter metrics by time window if specified
            if time_window_seconds is not None:
                cutoff_time = time.time() - time_window_seconds
                filtered_metrics = [m for m in self._metrics if m.timestamp >= cutoff_time]
            else:
                filtered_metrics = list(self._metrics)

            if not filtered_metrics:
                return AccessibilityMetricsSummary()

            # Calculate summary statistics
            total_tests = len(filtered_metrics)
            successful_tests = sum(1 for m in filtered_metrics if m.result == TestResult.SUCCESS)
            failed_tests = sum(1 for m in filtered_metrics if m.result == TestResult.FAILURE)
            timeout_tests = sum(1 for m in filtered_metrics if m.result == TestResult.TIMEOUT)
            error_tests = sum(1 for m in filtered_metrics if m.result == TestResult.ERROR)
            cache_hits = sum(1 for m in filtered_metrics if m.cache_hit)

            total_duration = sum(m.duration_ms for m in filtered_metrics)
            average_duration = total_duration / total_tests if total_tests > 0 else 0.0

            success_rate = successful_tests / total_tests if total_tests > 0 else 0.0
            cache_hit_rate = cache_hits / total_tests if total_tests > 0 else 0.0

            # Method distribution
            method_dist = defaultdict(int)
            for metric in filtered_metrics:
                method_dist[metric.method.value] += 1

            # Error distribution
            error_dist = defaultdict(int)
            for metric in filtered_metrics:
                if metric.error_reason:
                    error_dist[metric.error_reason] += 1

            # Domain performance
            domain_perf = defaultdict(lambda: {"tests": 0, "successes": 0, "avg_duration_ms": 0.0})
            domain_durations = defaultdict(list)

            for metric in filtered_metrics:
                domain_key = metric.domain or metric.target_ip
                domain_perf[domain_key]["tests"] += 1
                domain_durations[domain_key].append(metric.duration_ms)

                if metric.result == TestResult.SUCCESS:
                    domain_perf[domain_key]["successes"] += 1

            # Calculate average durations
            for domain_key, durations in domain_durations.items():
                domain_perf[domain_key]["avg_duration_ms"] = sum(durations) / len(durations)
                domain_perf[domain_key]["success_rate"] = (
                    domain_perf[domain_key]["successes"] / domain_perf[domain_key]["tests"]
                )

            return AccessibilityMetricsSummary(
                total_tests=total_tests,
                successful_tests=successful_tests,
                failed_tests=failed_tests,
                timeout_tests=timeout_tests,
                error_tests=error_tests,
                cache_hits=cache_hits,
                average_duration_ms=average_duration,
                success_rate=success_rate,
                cache_hit_rate=cache_hit_rate,
                method_distribution=dict(method_dist),
                error_distribution=dict(error_dist),
                domain_performance=dict(domain_perf),
            )

    def get_recent_failures(self, count: int = 10) -> List[AccessibilityTestMetric]:
        """
        Get recent test failures for troubleshooting.

        Args:
            count: Number of recent failures to return

        Returns:
            List of recent failure metrics
        """
        with self._lock:
            failures = [
                m
                for m in reversed(self._metrics)
                if m.result in (TestResult.FAILURE, TestResult.TIMEOUT, TestResult.ERROR)
            ]
            return failures[:count]

    def get_domain_stats(self, domain: str) -> Dict[str, Any]:
        """
        Get detailed statistics for a specific domain.

        Args:
            domain: Domain name to get stats for

        Returns:
            Dictionary with domain-specific statistics
        """
        with self._lock:
            if domain not in self._domain_stats:
                return {}

            stats = self._domain_stats[domain].copy()

            # Calculate derived metrics
            if stats["tests"] > 0:
                stats["success_rate"] = stats["successes"] / stats["tests"]
                stats["average_duration_ms"] = stats["total_duration_ms"] / stats["tests"]
            else:
                stats["success_rate"] = 0.0
                stats["average_duration_ms"] = 0.0

            # Convert defaultdict to regular dict for JSON serialization
            stats["errors"] = dict(stats["errors"])

            return stats

    def clear_metrics(self) -> None:
        """Clear all collected metrics."""
        with self._lock:
            self._metrics.clear()
            self._counters = {key: 0 for key in self._counters}
            self._method_counts.clear()
            self._error_counts.clear()
            self._domain_stats.clear()

        self.logger.info("📊 All accessibility metrics cleared")

    def export_metrics(self, format: str = "json") -> str:
        """
        Export metrics in specified format.

        Args:
            format: Export format ("json" or "csv")

        Returns:
            Exported metrics as string
        """
        if format.lower() == "json":
            return self._export_json()
        elif format.lower() == "csv":
            return self._export_csv()
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def _export_json(self) -> str:
        """Export metrics as JSON."""
        import json

        with self._lock:
            data = {
                "summary": self.get_summary().__dict__,
                "recent_failures": [
                    {
                        "timestamp": m.timestamp,
                        "target_ip": m.target_ip,
                        "domain": m.domain,
                        "method": m.method.value,
                        "result": m.result.value,
                        "duration_ms": m.duration_ms,
                        "error_reason": m.error_reason,
                        "retry_count": m.retry_count,
                    }
                    for m in self.get_recent_failures(20)
                ],
            }

            return json.dumps(data, indent=2, default=str)

    def _export_csv(self) -> str:
        """Export metrics as CSV."""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(
            [
                "timestamp",
                "target_ip",
                "domain",
                "method",
                "result",
                "duration_ms",
                "http_status_code",
                "error_reason",
                "retry_count",
                "cache_hit",
            ]
        )

        # Write metrics
        with self._lock:
            for metric in self._metrics:
                writer.writerow(
                    [
                        metric.timestamp,
                        metric.target_ip,
                        metric.domain or "",
                        metric.method.value,
                        metric.result.value,
                        metric.duration_ms,
                        metric.http_status_code or "",
                        metric.error_reason or "",
                        metric.retry_count,
                        metric.cache_hit,
                    ]
                )

        return output.getvalue()
