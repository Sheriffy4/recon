#!/usr/bin/env python3
"""
Production Monitoring System for Native Attack Orchestration.

This module provides comprehensive monitoring, alerting, and observability
for the segment-based attack system in production environments.
"""

import asyncio
import time
import json
import logging
import statistics
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from collections import deque, defaultdict

# Core imports
from core.bypass.monitoring.segment_execution_stats import (
    SegmentExecutionStatsCollector,
)
from core.bypass.diagnostics.segment_diagnostics import SegmentDiagnostics


@dataclass
class MonitoringConfig:
    """Configuration for production monitoring."""

    # Monitoring intervals (seconds)
    performance_check_interval: int = 30
    health_check_interval: int = 60
    alert_check_interval: int = 15
    metrics_collection_interval: int = 10

    # Alert thresholds
    failure_rate_threshold: float = 0.15  # 15%
    response_time_threshold_ms: float = 200.0
    memory_usage_threshold_mb: float = 100.0
    cpu_usage_threshold_percent: float = 80.0

    # Data retention
    metrics_retention_hours: int = 24
    alert_retention_days: int = 7

    # Output settings
    monitoring_data_dir: str = "/var/lib/native_attack_orchestration/monitoring"
    enable_real_time_dashboard: bool = True
    enable_prometheus_metrics: bool = False

    # Alerting
    enable_email_alerts: bool = False
    enable_webhook_alerts: bool = False
    alert_cooldown_minutes: int = 5


@dataclass
class SystemMetrics:
    """System performance metrics."""

    timestamp: float

    # Attack execution metrics
    attacks_per_minute: float = 0.0
    success_rate: float = 0.0
    average_response_time_ms: float = 0.0
    p95_response_time_ms: float = 0.0

    # Segment metrics
    segments_per_attack: float = 0.0
    segment_execution_success_rate: float = 0.0
    timing_accuracy_percent: float = 0.0

    # System resource metrics
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0

    # Performance optimizer metrics
    cache_hit_rate: float = 0.0
    optimization_effectiveness: float = 0.0

    # Error metrics
    error_rate: float = 0.0
    critical_errors: int = 0
    warnings: int = 0


@dataclass
class Alert:
    """System alert."""

    id: str
    type: str
    severity: str  # critical, warning, info
    title: str
    message: str
    timestamp: float
    resolved: bool = False
    resolved_timestamp: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class AnomalyDetector:
    """Simple anomaly detection for monitoring."""

    def __init__(self, window_size: int = 20):
        self.window_size = window_size
        self.metric_windows = defaultdict(lambda: deque(maxlen=window_size))

    def add_metric(self, metric_name: str, value: float):
        """Add a metric value to the detection window."""
        self.metric_windows[metric_name].append(value)

    def is_anomaly(
        self, metric_name: str, value: float, threshold_factor: float = 2.0
    ) -> bool:
        """Check if a value is anomalous compared to recent history."""
        window = self.metric_windows[metric_name]

        if len(window) < 5:  # Need minimum data
            return False

        mean = statistics.mean(window)
        stdev = statistics.stdev(window) if len(window) > 1 else 0

        if stdev == 0:
            return False

        z_score = abs(value - mean) / stdev
        return z_score > threshold_factor


class ProductionMonitoringSystem:
    """Comprehensive production monitoring system."""

    def __init__(self, config: MonitoringConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Monitoring components
        self.stats_collector = SegmentExecutionStatsCollector()
        self.diagnostics = SegmentDiagnostics()

        # Metrics storage
        self.metrics_history = deque(
            maxlen=int(
                config.metrics_retention_hours
                * 3600
                / config.metrics_collection_interval
            )
        )
        self.active_alerts = {}
        self.alert_history = deque(maxlen=1000)
        self.alert_cooldowns = {}

        # Performance tracking
        self.performance_baseline = None
        self.anomaly_detector = AnomalyDetector()

        # Monitoring state
        self.monitoring_active = False
        self.monitoring_tasks = []

        # Setup monitoring directory
        Path(self.config.monitoring_data_dir).mkdir(parents=True, exist_ok=True)

    async def start_monitoring(self):
        """Start production monitoring."""

        if self.monitoring_active:
            self.logger.warning("Monitoring already active")
            return

        self.logger.info("🔍 Starting production monitoring system")
        self.monitoring_active = True

        # Start monitoring tasks
        self.monitoring_tasks = [
            asyncio.create_task(self._metrics_collection_loop()),
            asyncio.create_task(self._performance_monitoring_loop()),
            asyncio.create_task(self._health_monitoring_loop()),
            asyncio.create_task(self._alert_processing_loop()),
            asyncio.create_task(self._dashboard_update_loop()),
        ]

        # Initialize baseline
        await self._establish_performance_baseline()

        self.logger.info("✅ Production monitoring system started")

    async def stop_monitoring(self):
        """Stop production monitoring."""

        if not self.monitoring_active:
            return

        self.logger.info("🛑 Stopping production monitoring system")
        self.monitoring_active = False

        # Cancel monitoring tasks
        for task in self.monitoring_tasks:
            task.cancel()

        # Wait for tasks to complete
        await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)

        self.logger.info("✅ Production monitoring system stopped")

    async def _metrics_collection_loop(self):
        """Collect system metrics periodically."""

        while self.monitoring_active:
            try:
                metrics = await self._collect_current_metrics()
                self.metrics_history.append(metrics)

                # Save metrics to file
                await self._save_metrics_snapshot(metrics)

                # Check for anomalies
                await self._check_for_anomalies(metrics)

                await asyncio.sleep(self.config.metrics_collection_interval)

            except Exception as e:
                self.logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(self.config.metrics_collection_interval)

    async def _collect_current_metrics(self) -> SystemMetrics:
        """Collect current system metrics."""

        current_time = time.time()

        # Get execution statistics
        stats_summary = self.stats_collector.get_execution_summary()
        completed_executions = stats_summary.get("completed_executions", [])

        # Calculate attack metrics
        recent_executions = [
            ex
            for ex in completed_executions
            if current_time - ex.get("timestamp", 0) <= 60  # Last minute
        ]

        attacks_per_minute = len(recent_executions)

        if recent_executions:
            successful = sum(1 for ex in recent_executions if ex.get("success", False))
            success_rate = successful / len(recent_executions)

            execution_times = [
                ex.get("execution_time", 0) * 1000 for ex in recent_executions
            ]
            avg_response_time = (
                statistics.mean(execution_times) if execution_times else 0
            )
            p95_response_time = (
                statistics.quantiles(execution_times, n=20)[18]
                if len(execution_times) > 5
                else avg_response_time
            )
        else:
            success_rate = 1.0
            avg_response_time = 0.0
            p95_response_time = 0.0

        # Get segment metrics
        segment_metrics = await self._collect_segment_metrics(recent_executions)

        # Get system resource metrics
        resource_metrics = await self._collect_resource_metrics()

        # Get performance optimizer metrics
        optimizer_metrics = await self._collect_optimizer_metrics()

        # Get error metrics
        error_metrics = await self._collect_error_metrics(recent_executions)

        return SystemMetrics(
            timestamp=current_time,
            attacks_per_minute=attacks_per_minute,
            success_rate=success_rate,
            average_response_time_ms=avg_response_time,
            p95_response_time_ms=p95_response_time,
            **segment_metrics,
            **resource_metrics,
            **optimizer_metrics,
            **error_metrics,
        )

    async def _collect_segment_metrics(
        self, recent_executions: List[Dict]
    ) -> Dict[str, float]:
        """Collect segment-specific metrics."""

        if not recent_executions:
            return {
                "segments_per_attack": 0.0,
                "segment_execution_success_rate": 1.0,
                "timing_accuracy_percent": 100.0,
            }

        # Calculate segments per attack
        segment_counts = []
        for ex in recent_executions:
            segments_info = ex.get("segments_info", {})
            if segments_info:
                segment_counts.append(segments_info.get("count", 0))

        segments_per_attack = statistics.mean(segment_counts) if segment_counts else 0.0

        # Get timing accuracy from diagnostics
        global_summary = self.diagnostics.get_global_summary()
        timing_analysis = global_summary.get("timing_analysis", {})
        timing_accuracy = timing_analysis.get("average_accuracy", 1.0) * 100

        return {
            "segments_per_attack": segments_per_attack,
            "segment_execution_success_rate": 1.0,  # Placeholder
            "timing_accuracy_percent": timing_accuracy,
        }

    async def _collect_resource_metrics(self) -> Dict[str, float]:
        """Collect system resource metrics."""

        try:
            import psutil
            import os

            process = psutil.Process(os.getpid())

            # Memory usage
            memory_mb = process.memory_info().rss / 1024 / 1024

            # CPU usage
            cpu_percent = process.cpu_percent()

            return {"memory_usage_mb": memory_mb, "cpu_usage_percent": cpu_percent}

        except ImportError:
            return {"memory_usage_mb": 0.0, "cpu_usage_percent": 0.0}

    async def _collect_optimizer_metrics(self) -> Dict[str, float]:
        """Collect performance optimizer metrics."""

        # This would integrate with actual performance optimizer
        return {
            "cache_hit_rate": 0.85,  # Placeholder
            "optimization_effectiveness": 0.75,  # Placeholder
        }

    async def _collect_error_metrics(
        self, recent_executions: List[Dict]
    ) -> Dict[str, Any]:
        """Collect error metrics."""

        if not recent_executions:
            return {"error_rate": 0.0, "critical_errors": 0, "warnings": 0}

        failed_executions = [
            ex for ex in recent_executions if not ex.get("success", True)
        ]
        error_rate = len(failed_executions) / len(recent_executions)

        # Count critical errors and warnings
        critical_errors = sum(
            1 for ex in failed_executions if ex.get("error_severity") == "critical"
        )
        warnings = sum(
            1 for ex in failed_executions if ex.get("error_severity") == "warning"
        )

        return {
            "error_rate": error_rate,
            "critical_errors": critical_errors,
            "warnings": warnings,
        }

    async def _performance_monitoring_loop(self):
        """Monitor system performance and generate alerts."""

        while self.monitoring_active:
            try:
                if self.metrics_history:
                    latest_metrics = self.metrics_history[-1]
                    await self._check_performance_thresholds(latest_metrics)

                await asyncio.sleep(self.config.performance_check_interval)

            except Exception as e:
                self.logger.error(f"Performance monitoring error: {e}")
                await asyncio.sleep(self.config.performance_check_interval)

    async def _health_monitoring_loop(self):
        """Monitor system health."""

        while self.monitoring_active:
            try:
                health_status = await self._check_system_health()

                if health_status["status"] != "healthy":
                    await self._create_alert(
                        alert_type="system_health",
                        severity=(
                            "warning"
                            if health_status["status"] == "degraded"
                            else "critical"
                        ),
                        title="System Health Issue",
                        message=f"System health: {health_status['status']}",
                        metadata=health_status,
                    )

                await asyncio.sleep(self.config.health_check_interval)

            except Exception as e:
                self.logger.error(f"Health monitoring error: {e}")
                await asyncio.sleep(self.config.health_check_interval)

    async def _alert_processing_loop(self):
        """Process and manage alerts."""

        while self.monitoring_active:
            try:
                # Check for alert resolution
                await self._check_alert_resolution()

                # Clean up old alerts
                await self._cleanup_old_alerts()

                # Send pending notifications
                await self._process_alert_notifications()

                await asyncio.sleep(self.config.alert_check_interval)

            except Exception as e:
                self.logger.error(f"Alert processing error: {e}")
                await asyncio.sleep(self.config.alert_check_interval)

    async def _dashboard_update_loop(self):
        """Update monitoring dashboard data."""

        while self.monitoring_active:
            try:
                if self.config.enable_real_time_dashboard:
                    await self._update_dashboard_data()

                await asyncio.sleep(30)  # Update dashboard every 30 seconds

            except Exception as e:
                self.logger.error(f"Dashboard update error: {e}")
                await asyncio.sleep(30)

    async def _check_performance_thresholds(self, metrics: SystemMetrics):
        """Check performance metrics against thresholds."""

        # Check failure rate
        if metrics.success_rate < (1.0 - self.config.failure_rate_threshold):
            await self._create_alert(
                alert_type="high_failure_rate",
                severity="critical",
                title="High Failure Rate",
                message=f"Success rate dropped to {metrics.success_rate:.1%}",
                metadata={
                    "success_rate": metrics.success_rate,
                    "threshold": 1.0 - self.config.failure_rate_threshold,
                },
            )

        # Check response time
        if metrics.average_response_time_ms > self.config.response_time_threshold_ms:
            await self._create_alert(
                alert_type="high_response_time",
                severity="warning",
                title="High Response Time",
                message=f"Average response time: {metrics.average_response_time_ms:.1f}ms",
                metadata={
                    "response_time_ms": metrics.average_response_time_ms,
                    "threshold_ms": self.config.response_time_threshold_ms,
                },
            )

        # Check memory usage
        if metrics.memory_usage_mb > self.config.memory_usage_threshold_mb:
            await self._create_alert(
                alert_type="high_memory_usage",
                severity="warning",
                title="High Memory Usage",
                message=f"Memory usage: {metrics.memory_usage_mb:.1f}MB",
                metadata={
                    "memory_mb": metrics.memory_usage_mb,
                    "threshold_mb": self.config.memory_usage_threshold_mb,
                },
            )

        # Check CPU usage
        if metrics.cpu_usage_percent > self.config.cpu_usage_threshold_percent:
            await self._create_alert(
                alert_type="high_cpu_usage",
                severity="warning",
                title="High CPU Usage",
                message=f"CPU usage: {metrics.cpu_usage_percent:.1f}%",
                metadata={
                    "cpu_percent": metrics.cpu_usage_percent,
                    "threshold_percent": self.config.cpu_usage_threshold_percent,
                },
            )

    async def _check_system_health(self) -> Dict[str, Any]:
        """Check overall system health."""

        health_status = {"status": "healthy", "components": {}, "issues": []}

        # Check stats collector
        try:
            summary = self.stats_collector.get_execution_summary()
            health_status["components"]["stats_collector"] = "healthy"
        except Exception as e:
            health_status["components"]["stats_collector"] = "unhealthy"
            health_status["issues"].append(f"Stats collector error: {e}")

        # Check diagnostics
        try:
            global_summary = self.diagnostics.get_global_summary()
            health_status["components"]["diagnostics"] = "healthy"
        except Exception as e:
            health_status["components"]["diagnostics"] = "unhealthy"
            health_status["issues"].append(f"Diagnostics error: {e}")

        # Determine overall health
        unhealthy_components = [
            comp
            for comp, status in health_status["components"].items()
            if status == "unhealthy"
        ]

        if unhealthy_components:
            if len(unhealthy_components) == 1:
                health_status["status"] = "degraded"
            else:
                health_status["status"] = "unhealthy"

        return health_status

    async def _create_alert(
        self,
        alert_type: str,
        severity: str,
        title: str,
        message: str,
        metadata: Dict[str, Any] = None,
    ):
        """Create a new alert."""

        # Check cooldown
        cooldown_key = f"{alert_type}_{severity}"
        current_time = time.time()

        if cooldown_key in self.alert_cooldowns:
            last_alert_time = self.alert_cooldowns[cooldown_key]
            if current_time - last_alert_time < self.config.alert_cooldown_minutes * 60:
                return  # Skip alert due to cooldown

        # Create alert
        alert_id = f"{alert_type}_{int(current_time)}"
        alert = Alert(
            id=alert_id,
            type=alert_type,
            severity=severity,
            title=title,
            message=message,
            timestamp=current_time,
            metadata=metadata or {},
        )

        # Store alert
        self.active_alerts[alert_id] = alert
        self.alert_history.append(alert)
        self.alert_cooldowns[cooldown_key] = current_time

        # Log alert
        log_level = logging.CRITICAL if severity == "critical" else logging.WARNING
        self.logger.log(
            log_level, f"🚨 ALERT [{severity.upper()}]: {title} - {message}"
        )

        # Save alert to file
        await self._save_alert(alert)

    async def _check_alert_resolution(self):
        """Check if active alerts should be resolved."""

        if not self.metrics_history:
            return

        latest_metrics = self.metrics_history[-1]
        resolved_alerts = []

        for alert_id, alert in self.active_alerts.items():
            if alert.resolved:
                continue

            should_resolve = False

            # Check resolution conditions based on alert type
            if alert.type == "high_failure_rate":
                should_resolve = latest_metrics.success_rate >= (
                    1.0 - self.config.failure_rate_threshold * 0.8
                )
            elif alert.type == "high_response_time":
                should_resolve = (
                    latest_metrics.average_response_time_ms
                    <= self.config.response_time_threshold_ms * 0.9
                )
            elif alert.type == "high_memory_usage":
                should_resolve = (
                    latest_metrics.memory_usage_mb
                    <= self.config.memory_usage_threshold_mb * 0.9
                )
            elif alert.type == "high_cpu_usage":
                should_resolve = (
                    latest_metrics.cpu_usage_percent
                    <= self.config.cpu_usage_threshold_percent * 0.9
                )

            if should_resolve:
                alert.resolved = True
                alert.resolved_timestamp = time.time()
                resolved_alerts.append(alert_id)

                self.logger.info(f"✅ RESOLVED: {alert.title}")

        # Remove resolved alerts from active list
        for alert_id in resolved_alerts:
            del self.active_alerts[alert_id]

    async def _cleanup_old_alerts(self):
        """Clean up old alerts from history."""

        cutoff_time = time.time() - (self.config.alert_retention_days * 24 * 3600)

        # Remove old alerts from history
        while self.alert_history and self.alert_history[0].timestamp < cutoff_time:
            self.alert_history.popleft()

    async def _process_alert_notifications(self):
        """Process alert notifications."""

        # This would integrate with actual notification systems
        # For now, just log unresolved alerts

        if self.active_alerts:
            critical_alerts = [
                alert
                for alert in self.active_alerts.values()
                if alert.severity == "critical"
            ]
            if critical_alerts:
                self.logger.critical(
                    f"🚨 {len(critical_alerts)} critical alerts active"
                )

    async def _save_metrics_snapshot(self, metrics: SystemMetrics):
        """Save metrics snapshot to file."""

        metrics_file = (
            Path(self.config.monitoring_data_dir)
            / "metrics"
            / f"metrics_{int(metrics.timestamp)}.json"
        )
        metrics_file.parent.mkdir(exist_ok=True)

        metrics_data = {
            "timestamp": metrics.timestamp,
            "attacks_per_minute": metrics.attacks_per_minute,
            "success_rate": metrics.success_rate,
            "average_response_time_ms": metrics.average_response_time_ms,
            "p95_response_time_ms": metrics.p95_response_time_ms,
            "segments_per_attack": metrics.segments_per_attack,
            "segment_execution_success_rate": metrics.segment_execution_success_rate,
            "timing_accuracy_percent": metrics.timing_accuracy_percent,
            "memory_usage_mb": metrics.memory_usage_mb,
            "cpu_usage_percent": metrics.cpu_usage_percent,
            "cache_hit_rate": metrics.cache_hit_rate,
            "optimization_effectiveness": metrics.optimization_effectiveness,
            "error_rate": metrics.error_rate,
            "critical_errors": metrics.critical_errors,
            "warnings": metrics.warnings,
        }

        try:
            with open(metrics_file, "w") as f:
                json.dump(metrics_data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save metrics snapshot: {e}")

    async def _save_alert(self, alert: Alert):
        """Save alert to file."""

        alert_file = (
            Path(self.config.monitoring_data_dir) / "alerts" / f"alert_{alert.id}.json"
        )
        alert_file.parent.mkdir(exist_ok=True)

        alert_data = {
            "id": alert.id,
            "type": alert.type,
            "severity": alert.severity,
            "title": alert.title,
            "message": alert.message,
            "timestamp": alert.timestamp,
            "resolved": alert.resolved,
            "resolved_timestamp": alert.resolved_timestamp,
            "metadata": alert.metadata,
        }

        try:
            with open(alert_file, "w") as f:
                json.dump(alert_data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save alert: {e}")

    async def _update_dashboard_data(self):
        """Update real-time dashboard data."""

        if not self.metrics_history:
            return

        latest_metrics = self.metrics_history[-1]

        dashboard_data = {
            "timestamp": latest_metrics.timestamp,
            "system_status": "healthy" if not self.active_alerts else "degraded",
            "active_alerts_count": len(self.active_alerts),
            "critical_alerts_count": sum(
                1
                for alert in self.active_alerts.values()
                if alert.severity == "critical"
            ),
            "current_metrics": {
                "attacks_per_minute": latest_metrics.attacks_per_minute,
                "success_rate": latest_metrics.success_rate,
                "average_response_time_ms": latest_metrics.average_response_time_ms,
                "memory_usage_mb": latest_metrics.memory_usage_mb,
                "cpu_usage_percent": latest_metrics.cpu_usage_percent,
            },
            "recent_alerts": [
                {
                    "id": alert.id,
                    "type": alert.type,
                    "severity": alert.severity,
                    "title": alert.title,
                    "timestamp": alert.timestamp,
                }
                for alert in list(self.active_alerts.values())[-5:]  # Last 5 alerts
            ],
        }

        dashboard_file = Path(self.config.monitoring_data_dir) / "dashboard.json"

        try:
            with open(dashboard_file, "w") as f:
                json.dump(dashboard_data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to update dashboard data: {e}")

    async def _establish_performance_baseline(self):
        """Establish performance baseline for anomaly detection."""

        self.logger.info("📊 Establishing performance baseline...")

        # Wait for some metrics to be collected
        baseline_duration = 300  # 5 minutes
        await asyncio.sleep(
            min(baseline_duration, 60)
        )  # Wait up to 1 minute for initial data

        if len(self.metrics_history) >= 5:
            recent_metrics = list(self.metrics_history)[-5:]

            self.performance_baseline = {
                "avg_response_time_ms": statistics.mean(
                    [m.average_response_time_ms for m in recent_metrics]
                ),
                "avg_success_rate": statistics.mean(
                    [m.success_rate for m in recent_metrics]
                ),
                "avg_attacks_per_minute": statistics.mean(
                    [m.attacks_per_minute for m in recent_metrics]
                ),
            }

            self.logger.info(
                f"✅ Performance baseline established: {self.performance_baseline}"
            )
        else:
            self.logger.warning("⚠️ Insufficient data for performance baseline")

    async def _check_for_anomalies(self, metrics: SystemMetrics):
        """Check for performance anomalies."""

        if not self.performance_baseline or len(self.metrics_history) < 10:
            return

        # Check for significant deviations from baseline
        baseline = self.performance_baseline

        # Response time anomaly
        if metrics.average_response_time_ms > baseline["avg_response_time_ms"] * 2:
            await self._create_alert(
                alert_type="performance_anomaly",
                severity="warning",
                title="Response Time Anomaly",
                message=f"Response time {metrics.average_response_time_ms:.1f}ms significantly higher than baseline {baseline['avg_response_time_ms']:.1f}ms",
                metadata={
                    "current": metrics.average_response_time_ms,
                    "baseline": baseline["avg_response_time_ms"],
                },
            )

        # Success rate anomaly
        if metrics.success_rate < baseline["avg_success_rate"] * 0.8:
            await self._create_alert(
                alert_type="effectiveness_anomaly",
                severity="critical",
                title="Success Rate Anomaly",
                message=f"Success rate {metrics.success_rate:.1%} significantly lower than baseline {baseline['avg_success_rate']:.1%}",
                metadata={
                    "current": metrics.success_rate,
                    "baseline": baseline["avg_success_rate"],
                },
            )

    def get_current_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""

        if not self.metrics_history:
            return {"status": "no_data", "message": "No metrics available"}

        latest_metrics = self.metrics_history[-1]

        return {
            "status": "healthy" if not self.active_alerts else "degraded",
            "monitoring_active": self.monitoring_active,
            "metrics_count": len(self.metrics_history),
            "active_alerts": len(self.active_alerts),
            "latest_metrics": {
                "timestamp": latest_metrics.timestamp,
                "attacks_per_minute": latest_metrics.attacks_per_minute,
                "success_rate": latest_metrics.success_rate,
                "average_response_time_ms": latest_metrics.average_response_time_ms,
                "memory_usage_mb": latest_metrics.memory_usage_mb,
            },
        }

    def get_metrics_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get metrics summary for the specified time period."""

        if not self.metrics_history:
            return {"error": "No metrics available"}

        cutoff_time = time.time() - (hours * 3600)
        recent_metrics = [m for m in self.metrics_history if m.timestamp >= cutoff_time]

        if not recent_metrics:
            return {"error": f"No metrics available for the last {hours} hours"}

        return {
            "period_hours": hours,
            "metrics_count": len(recent_metrics),
            "avg_attacks_per_minute": statistics.mean(
                [m.attacks_per_minute for m in recent_metrics]
            ),
            "avg_success_rate": statistics.mean(
                [m.success_rate for m in recent_metrics]
            ),
            "avg_response_time_ms": statistics.mean(
                [m.average_response_time_ms for m in recent_metrics]
            ),
            "max_response_time_ms": max(
                [m.average_response_time_ms for m in recent_metrics]
            ),
            "avg_memory_usage_mb": statistics.mean(
                [m.memory_usage_mb for m in recent_metrics]
            ),
            "max_memory_usage_mb": max([m.memory_usage_mb for m in recent_metrics]),
            "total_errors": sum(
                [m.critical_errors + m.warnings for m in recent_metrics]
            ),
        }

    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of alerts."""

        return {
            "active_alerts": len(self.active_alerts),
            "critical_alerts": sum(
                1
                for alert in self.active_alerts.values()
                if alert.severity == "critical"
            ),
            "warning_alerts": sum(
                1
                for alert in self.active_alerts.values()
                if alert.severity == "warning"
            ),
            "total_alerts_today": sum(
                1
                for alert in self.alert_history
                if time.time() - alert.timestamp <= 86400
            ),
            "recent_alerts": [
                {
                    "id": alert.id,
                    "type": alert.type,
                    "severity": alert.severity,
                    "title": alert.title,
                    "timestamp": alert.timestamp,
                    "resolved": alert.resolved,
                }
                for alert in list(self.alert_history)[-10:]  # Last 10 alerts
            ],
        }


# Example usage and testing
async def main():
    """Example usage of the production monitoring system."""

    # Configure monitoring
    config = MonitoringConfig(
        monitoring_data_dir="./monitoring_data",
        metrics_collection_interval=5,  # Faster for demo
        performance_check_interval=10,
        health_check_interval=15,
    )

    # Create monitoring system
    monitoring = ProductionMonitoringSystem(config)

    try:
        # Start monitoring
        await monitoring.start_monitoring()

        # Let it run for a while
        await asyncio.sleep(60)

        # Check status
        status = monitoring.get_current_status()
        print(f"Monitoring Status: {json.dumps(status, indent=2)}")

        # Get metrics summary
        summary = monitoring.get_metrics_summary(hours=1)
        print(f"Metrics Summary: {json.dumps(summary, indent=2)}")

        # Get alert summary
        alerts = monitoring.get_alert_summary()
        print(f"Alert Summary: {json.dumps(alerts, indent=2)}")

    finally:
        # Stop monitoring
        await monitoring.stop_monitoring()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
