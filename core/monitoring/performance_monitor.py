#!/usr/bin/env python3
"""
Performance Monitoring System
Provides comprehensive monitoring and observability for the recon system.
"""

import time
import threading
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import psutil


@dataclass
class PerformanceMetrics:
    """Performance metrics data structure."""

    timestamp: float
    bypass_success_rate: float
    fingerprint_success_rate: float
    avg_fingerprint_time: float
    cache_hit_rate: float
    total_requests: int
    successful_bypasses: int
    failed_bypasses: int
    errors_by_component: Dict[str, int]
    memory_usage_mb: float
    cpu_usage_percent: float
    active_connections: int


@dataclass
class ComponentMetrics:
    """Metrics for individual components."""

    component_name: str
    operation_count: int
    success_count: int
    failure_count: int
    avg_duration_ms: float
    max_duration_ms: float
    min_duration_ms: float
    last_error: Optional[str]
    last_success: Optional[float]


class PerformanceMonitor:
    """
    Comprehensive performance monitoring system for recon.
    Tracks success rates, timing, errors, and system resources.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Metrics storage
        self.metrics_history: deque = deque(maxlen=1000)  # Keep last 1000 metrics
        self.component_metrics: Dict[str, ComponentMetrics] = {}
        self.error_counts: Dict[str, int] = defaultdict(int)

        # Performance tracking
        self.operation_timings: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.success_counts: Dict[str, int] = defaultdict(int)
        self.failure_counts: Dict[str, int] = defaultdict(int)

        # Cache metrics
        self.cache_hits = 0
        self.cache_misses = 0

        # System metrics
        self.process = psutil.Process()

        # Monitoring thread
        self._monitoring_active = False
        self._monitoring_thread: Optional[threading.Thread] = None

        # Callbacks for custom metrics
        self.metric_callbacks: List[Callable[[], Dict[str, Any]]] = []

    def start_monitoring(self, interval_seconds: float = 30.0):
        """Start the monitoring thread."""
        if self._monitoring_active:
            return

        self._monitoring_active = True
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop, args=(interval_seconds,), daemon=True
        )
        self._monitoring_thread.start()
        self.logger.info(f"Performance monitoring started with {interval_seconds}s interval")

    def stop_monitoring(self):
        """Stop the monitoring thread."""
        self._monitoring_active = False
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5.0)
        self.logger.info("Performance monitoring stopped")

    def _monitoring_loop(self, interval_seconds: float):
        """Main monitoring loop."""
        while self._monitoring_active:
            try:
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)

                # Check for alerts
                self._check_alerts(metrics)

                time.sleep(interval_seconds)
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(interval_seconds)

    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics."""
        now = time.time()

        # Calculate success rates
        total_bypasses = sum(self.success_counts.values()) + sum(self.failure_counts.values())
        bypass_success_rate = (
            sum(self.success_counts.values()) / total_bypasses if total_bypasses > 0 else 0.0
        )

        # Calculate fingerprint metrics
        fingerprint_timings = self.operation_timings.get("fingerprint", deque())
        avg_fingerprint_time = (
            sum(fingerprint_timings) / len(fingerprint_timings) if fingerprint_timings else 0.0
        )

        fingerprint_successes = self.success_counts.get("fingerprint", 0)
        fingerprint_failures = self.failure_counts.get("fingerprint", 0)
        fingerprint_total = fingerprint_successes + fingerprint_failures
        fingerprint_success_rate = (
            fingerprint_successes / fingerprint_total if fingerprint_total > 0 else 0.0
        )

        # Calculate cache hit rate
        total_cache_requests = self.cache_hits + self.cache_misses
        cache_hit_rate = self.cache_hits / total_cache_requests if total_cache_requests > 0 else 0.0

        # System metrics
        memory_info = self.process.memory_info()
        memory_usage_mb = memory_info.rss / 1024 / 1024
        cpu_usage_percent = self.process.cpu_percent()

        # Active connections (estimate based on open files)
        try:
            active_connections = len(
                [f for f in self.process.open_files() if f.path.startswith("/proc")]
            )
        except:
            active_connections = 0

        # Collect custom metrics
        custom_metrics = {}
        for callback in self.metric_callbacks:
            try:
                custom_metrics.update(callback())
            except Exception as e:
                self.logger.warning(f"Error collecting custom metrics: {e}")

        return PerformanceMetrics(
            timestamp=now,
            bypass_success_rate=bypass_success_rate,
            fingerprint_success_rate=fingerprint_success_rate,
            avg_fingerprint_time=avg_fingerprint_time,
            cache_hit_rate=cache_hit_rate,
            total_requests=total_bypasses,
            successful_bypasses=sum(self.success_counts.values()),
            failed_bypasses=sum(self.failure_counts.values()),
            errors_by_component=dict(self.error_counts),
            memory_usage_mb=memory_usage_mb,
            cpu_usage_percent=cpu_usage_percent,
            active_connections=active_connections,
        )

    def _check_alerts(self, metrics: PerformanceMetrics):
        """Check for alert conditions."""
        alerts = []

        # Success rate alerts
        if metrics.bypass_success_rate < 0.1:  # Less than 10% success
            alerts.append(
                {
                    "severity": "CRITICAL",
                    "component": "bypass_engine",
                    "message": f"Bypass success rate critically low: {metrics.bypass_success_rate:.1%}",
                    "metric": "bypass_success_rate",
                    "value": metrics.bypass_success_rate,
                }
            )
        elif metrics.bypass_success_rate < 0.3:  # Less than 30% success
            alerts.append(
                {
                    "severity": "WARNING",
                    "component": "bypass_engine",
                    "message": f"Bypass success rate low: {metrics.bypass_success_rate:.1%}",
                    "metric": "bypass_success_rate",
                    "value": metrics.bypass_success_rate,
                }
            )

        # Performance alerts
        if metrics.avg_fingerprint_time > 60000:  # More than 60 seconds
            alerts.append(
                {
                    "severity": "WARNING",
                    "component": "fingerprinter",
                    "message": f"Fingerprinting taking too long: {metrics.avg_fingerprint_time/1000:.1f}s",
                    "metric": "avg_fingerprint_time",
                    "value": metrics.avg_fingerprint_time,
                }
            )

        # Memory alerts
        if metrics.memory_usage_mb > 1000:  # More than 1GB
            alerts.append(
                {
                    "severity": "WARNING",
                    "component": "system",
                    "message": f"High memory usage: {metrics.memory_usage_mb:.1f}MB",
                    "metric": "memory_usage_mb",
                    "value": metrics.memory_usage_mb,
                }
            )

        # Log alerts
        for alert in alerts:
            if alert["severity"] == "CRITICAL":
                self.logger.critical(alert["message"])
            else:
                self.logger.warning(alert["message"])

    def record_operation(
        self,
        component: str,
        operation: str,
        duration_ms: float,
        success: bool,
        error: Optional[str] = None,
    ):
        """Record an operation's performance metrics."""
        key = f"{component}.{operation}"

        # Record timing
        self.operation_timings[key].append(duration_ms)

        # Record success/failure
        if success:
            self.success_counts[key] += 1
        else:
            self.failure_counts[key] += 1
            if error:
                self.error_counts[f"{component}.{error}"] += 1

        # Update component metrics
        if component not in self.component_metrics:
            self.component_metrics[component] = ComponentMetrics(
                component_name=component,
                operation_count=0,
                success_count=0,
                failure_count=0,
                avg_duration_ms=0.0,
                max_duration_ms=0.0,
                min_duration_ms=float("inf"),
                last_error=None,
                last_success=None,
            )

        comp_metrics = self.component_metrics[component]
        comp_metrics.operation_count += 1

        if success:
            comp_metrics.success_count += 1
            comp_metrics.last_success = time.time()
        else:
            comp_metrics.failure_count += 1
            comp_metrics.last_error = error

        # Update duration stats
        timings = self.operation_timings[key]
        comp_metrics.avg_duration_ms = sum(timings) / len(timings)
        comp_metrics.max_duration_ms = max(comp_metrics.max_duration_ms, duration_ms)
        comp_metrics.min_duration_ms = min(comp_metrics.min_duration_ms, duration_ms)

    def record_cache_hit(self):
        """Record a cache hit."""
        self.cache_hits += 1

    def record_cache_miss(self):
        """Record a cache miss."""
        self.cache_misses += 1

    def add_metric_callback(self, callback: Callable[[], Dict[str, Any]]):
        """Add a custom metric collection callback."""
        self.metric_callbacks.append(callback)

    def get_current_metrics(self) -> Optional[PerformanceMetrics]:
        """Get the most recent metrics."""
        return self.metrics_history[-1] if self.metrics_history else None

    def get_metrics_history(self, minutes: int = 60) -> List[PerformanceMetrics]:
        """Get metrics history for the specified time period."""
        cutoff_time = time.time() - (minutes * 60)
        return [m for m in self.metrics_history if m.timestamp >= cutoff_time]

    def get_component_summary(self) -> Dict[str, Dict[str, Any]]:
        """Get summary of all component metrics."""
        summary = {}
        for component, metrics in self.component_metrics.items():
            summary[component] = {
                "success_rate": (
                    metrics.success_count / metrics.operation_count
                    if metrics.operation_count > 0
                    else 0
                ),
                "avg_duration_ms": metrics.avg_duration_ms,
                "total_operations": metrics.operation_count,
                "last_error": metrics.last_error,
                "time_since_last_success": (
                    time.time() - metrics.last_success if metrics.last_success else None
                ),
            }
        return summary

    def export_metrics(self, filepath: str, format: str = "json"):
        """Export metrics to file."""
        try:
            data = {
                "export_timestamp": datetime.now().isoformat(),
                "current_metrics": (
                    asdict(self.get_current_metrics()) if self.get_current_metrics() else None
                ),
                "component_summary": self.get_component_summary(),
                "metrics_history": [asdict(m) for m in self.metrics_history],
                "error_counts": dict(self.error_counts),
            }

            if format.lower() == "json":
                with open(filepath, "w") as f:
                    json.dump(data, f, indent=2)
            else:
                raise ValueError(f"Unsupported format: {format}")

            self.logger.info(f"Metrics exported to {filepath}")
        except Exception as e:
            self.logger.error(f"Error exporting metrics: {e}")


# Context manager for operation timing
class OperationTimer:
    """Context manager for timing operations."""

    def __init__(self, monitor: PerformanceMonitor, component: str, operation: str):
        self.monitor = monitor
        self.component = component
        self.operation = operation
        self.start_time = None
        self.error = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = (time.time() - self.start_time) * 1000
        success = exc_type is None
        error = str(exc_val) if exc_val else None

        self.monitor.record_operation(self.component, self.operation, duration_ms, success, error)

        return False  # Don't suppress exceptions


# Global monitor instance
_global_monitor: Optional[PerformanceMonitor] = None


def get_global_monitor() -> PerformanceMonitor:
    """Get or create the global performance monitor."""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = PerformanceMonitor()
        _global_monitor.start_monitoring()
    return _global_monitor


def monitor_operation(component: str, operation: str):
    """Decorator for monitoring operation performance."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            monitor = get_global_monitor()
            with OperationTimer(monitor, component, operation):
                return func(*args, **kwargs)

        return wrapper

    return decorator
