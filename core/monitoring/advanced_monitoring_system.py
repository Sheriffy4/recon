#!/usr/bin/env python3
"""
Advanced Monitoring and Alerting System.

Provides comprehensive monitoring of system performance, effectiveness,
and health with alerting capabilities for degradation detection.
"""

import logging
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable
from enum import Enum
import statistics
from datetime import datetime, timedelta

from core.bypass.attacks.base import AttackResult, AttackStatus


class AlertLevel(Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MetricType(Enum):
    """Types of metrics to monitor."""

    PERFORMANCE = "performance"
    EFFECTIVENESS = "effectiveness"
    SYSTEM_HEALTH = "system_health"
    ERROR_RATE = "error_rate"
    LATENCY = "latency"
    SUCCESS_RATE = "success_rate"


@dataclass
class Alert:
    """Alert notification."""

    level: AlertLevel
    metric_type: MetricType
    message: str
    value: float
    threshold: float
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MetricThreshold:
    """Threshold configuration for metrics."""

    metric_name: str
    warning_threshold: float
    error_threshold: float
    critical_threshold: float
    comparison: str = "greater_than"  # greater_than, less_than, equals
    enabled: bool = True


@dataclass
class MonitoringConfig:
    """Configuration for monitoring system."""

    collection_interval_seconds: float = 10.0
    alert_cooldown_seconds: float = 300.0  # 5 minutes
    max_metric_history: int = 1000
    enable_performance_monitoring: bool = True
    enable_effectiveness_monitoring: bool = True
    enable_system_health_monitoring: bool = True
    enable_alerting: bool = True
    alert_handlers: List[str] = field(default_factory=lambda: ["console", "log"])


class MetricCollector:
    """Collects and stores metrics."""

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self._metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_history))
        self._lock = threading.RLock()

    def record_metric(
        self, name: str, value: float, timestamp: Optional[datetime] = None
    ) -> None:
        """Record a metric value."""
        if timestamp is None:
            timestamp = datetime.now()

        with self._lock:
            self._metrics[name].append({"value": value, "timestamp": timestamp})

    def get_metric_history(
        self, name: str, limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get metric history."""
        with self._lock:
            history = list(self._metrics[name])
            if limit:
                history = history[-limit:]
            return history

    def get_metric_stats(
        self, name: str, time_window_minutes: Optional[int] = None
    ) -> Dict[str, float]:
        """Get statistical summary of a metric."""
        with self._lock:
            history = list(self._metrics[name])

            if time_window_minutes:
                cutoff_time = datetime.now() - timedelta(minutes=time_window_minutes)
                history = [h for h in history if h["timestamp"] >= cutoff_time]

            if not history:
                return {}

            values = [h["value"] for h in history]

            return {
                "count": len(values),
                "min": min(values),
                "max": max(values),
                "mean": statistics.mean(values),
                "median": statistics.median(values),
                "std_dev": statistics.stdev(values) if len(values) > 1 else 0.0,
                "latest": values[-1] if values else 0.0,
            }

    def clear_metrics(self, name: Optional[str] = None) -> None:
        """Clear metric history."""
        with self._lock:
            if name:
                self._metrics[name].clear()
            else:
                self._metrics.clear()


class AlertManager:
    """Manages alerts and notifications."""

    def __init__(self, config: MonitoringConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._alert_history: deque = deque(maxlen=1000)
        self._last_alert_time: Dict[str, datetime] = {}
        self._alert_handlers: Dict[str, Callable] = {
            "console": self._console_alert_handler,
            "log": self._log_alert_handler,
        }
        self._lock = threading.RLock()

    def add_alert_handler(self, name: str, handler: Callable[[Alert], None]) -> None:
        """Add custom alert handler."""
        self._alert_handlers[name] = handler

    def trigger_alert(self, alert: Alert) -> None:
        """Trigger an alert."""
        if not self.config.enable_alerting:
            return

        # Check cooldown
        alert_key = f"{alert.metric_type.value}_{alert.message}"
        with self._lock:
            last_alert = self._last_alert_time.get(alert_key)
            if last_alert:
                time_since_last = (datetime.now() - last_alert).total_seconds()
                if time_since_last < self.config.alert_cooldown_seconds:
                    return  # Still in cooldown

            self._last_alert_time[alert_key] = datetime.now()
            self._alert_history.append(alert)

        # Send to all configured handlers
        for handler_name in self.config.alert_handlers:
            if handler_name in self._alert_handlers:
                try:
                    self._alert_handlers[handler_name](alert)
                except Exception as e:
                    self.logger.error(f"Alert handler '{handler_name}' failed: {e}")

    def _console_alert_handler(self, alert: Alert) -> None:
        """Console alert handler."""
        level_emoji = {
            AlertLevel.INFO: "ℹ️",
            AlertLevel.WARNING: "⚠️",
            AlertLevel.ERROR: "❌",
            AlertLevel.CRITICAL: "🚨",
        }

        emoji = level_emoji.get(alert.level, "📊")
        print(f"{emoji} [{alert.level.value.upper()}] {alert.message}")
        print(f"   Value: {alert.value}, Threshold: {alert.threshold}")
        print(f"   Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")

    def _log_alert_handler(self, alert: Alert) -> None:
        """Log alert handler."""
        log_level = {
            AlertLevel.INFO: logging.INFO,
            AlertLevel.WARNING: logging.WARNING,
            AlertLevel.ERROR: logging.ERROR,
            AlertLevel.CRITICAL: logging.CRITICAL,
        }

        level = log_level.get(alert.level, logging.INFO)
        self.logger.log(
            level,
            f"ALERT: {alert.message} (Value: {alert.value}, Threshold: {alert.threshold})",
        )

    def get_alert_history(self, limit: Optional[int] = None) -> List[Alert]:
        """Get alert history."""
        with self._lock:
            history = list(self._alert_history)
            if limit:
                history = history[-limit:]
            return history

    def get_alert_summary(self, time_window_minutes: int = 60) -> Dict[str, Any]:
        """Get alert summary for time window."""
        cutoff_time = datetime.now() - timedelta(minutes=time_window_minutes)

        with self._lock:
            recent_alerts = [
                a for a in self._alert_history if a.timestamp >= cutoff_time
            ]

        summary = {
            "total_alerts": len(recent_alerts),
            "by_level": defaultdict(int),
            "by_metric_type": defaultdict(int),
            "latest_alert": None,
        }

        for alert in recent_alerts:
            summary["by_level"][alert.level.value] += 1
            summary["by_metric_type"][alert.metric_type.value] += 1

        if recent_alerts:
            summary["latest_alert"] = recent_alerts[-1]

        return summary


class AdvancedMonitoringSystem:
    """
    Advanced monitoring and alerting system.

    Provides comprehensive monitoring of:
    - Attack performance metrics
    - Effectiveness measurements
    - System health indicators
    - Error rates and patterns
    """

    def __init__(self, config: Optional[MonitoringConfig] = None):
        self.config = config or MonitoringConfig()
        self.logger = logging.getLogger(__name__)

        # Core components
        self.metric_collector = MetricCollector(self.config.max_metric_history)
        self.alert_manager = AlertManager(self.config)

        # Monitoring state
        self._monitoring_active = False
        self._monitoring_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Thresholds
        self._thresholds: Dict[str, MetricThreshold] = {}
        self._setup_default_thresholds()

        # Performance tracking
        self._attack_results: deque = deque(maxlen=1000)
        self._system_stats = {
            "total_attacks": 0,
            "successful_attacks": 0,
            "failed_attacks": 0,
            "average_latency": 0.0,
            "last_update": datetime.now(),
        }

    def _setup_default_thresholds(self) -> None:
        """Setup default monitoring thresholds."""
        default_thresholds = [
            MetricThreshold("success_rate", 0.8, 0.6, 0.4, "less_than"),
            MetricThreshold("average_latency", 1000.0, 2000.0, 5000.0, "greater_than"),
            MetricThreshold("error_rate", 0.1, 0.2, 0.5, "greater_than"),
            MetricThreshold("system_health_score", 0.8, 0.6, 0.4, "less_than"),
        ]

        for threshold in default_thresholds:
            self._thresholds[threshold.metric_name] = threshold

    def start_monitoring(self) -> None:
        """Start the monitoring system."""
        if self._monitoring_active:
            self.logger.warning("Monitoring is already active")
            return

        self._monitoring_active = True
        self._stop_event.clear()

        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop, name="AdvancedMonitoringSystem", daemon=True
        )
        self._monitoring_thread.start()

        self.logger.info("🔍 Advanced monitoring system started")

    def stop_monitoring(self) -> None:
        """Stop the monitoring system."""
        if not self._monitoring_active:
            return

        self._monitoring_active = False
        self._stop_event.set()

        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self._monitoring_thread.join(timeout=5.0)

        self.logger.info("🔍 Advanced monitoring system stopped")

    def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self._monitoring_active and not self._stop_event.is_set():
            try:
                self._collect_metrics()
                self._check_thresholds()

                # Wait for next collection interval
                self._stop_event.wait(self.config.collection_interval_seconds)

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1.0)  # Brief pause before retrying

    def _collect_metrics(self) -> None:
        """Collect current metrics."""
        now = datetime.now()

        # Performance metrics
        if self.config.enable_performance_monitoring:
            self._collect_performance_metrics(now)

        # Effectiveness metrics
        if self.config.enable_effectiveness_monitoring:
            self._collect_effectiveness_metrics(now)

        # System health metrics
        if self.config.enable_system_health_monitoring:
            self._collect_system_health_metrics(now)

    def _collect_performance_metrics(self, timestamp: datetime) -> None:
        """Collect performance-related metrics."""
        # Calculate success rate
        recent_results = list(self._attack_results)[-100:]  # Last 100 results
        if recent_results:
            successful = sum(
                1 for r in recent_results if r.status == AttackStatus.SUCCESS
            )
            success_rate = successful / len(recent_results)
            self.metric_collector.record_metric("success_rate", success_rate, timestamp)

            # Calculate average latency
            latencies = [r.latency_ms for r in recent_results if r.latency_ms > 0]
            if latencies:
                avg_latency = statistics.mean(latencies)
                self.metric_collector.record_metric(
                    "average_latency", avg_latency, timestamp
                )

            # Calculate error rate
            errors = sum(
                1
                for r in recent_results
                if r.status in [AttackStatus.ERROR, AttackStatus.FAILED]
            )
            error_rate = errors / len(recent_results)
            self.metric_collector.record_metric("error_rate", error_rate, timestamp)

    def _collect_effectiveness_metrics(self, timestamp: datetime) -> None:
        """Collect effectiveness-related metrics."""
        # This would integrate with effectiveness validation system
        # For now, record a placeholder metric
        self.metric_collector.record_metric("effectiveness_score", 0.85, timestamp)

    def _collect_system_health_metrics(self, timestamp: datetime) -> None:
        """Collect system health metrics."""
        # Calculate overall system health score
        health_score = self._calculate_system_health_score()
        self.metric_collector.record_metric(
            "system_health_score", health_score, timestamp
        )

    def _calculate_system_health_score(self) -> float:
        """Calculate overall system health score (0.0 to 1.0)."""
        # Simple health calculation based on recent performance
        recent_results = list(self._attack_results)[-50:]
        if not recent_results:
            return 1.0

        # Factors: success rate, average latency, error patterns
        successful = sum(1 for r in recent_results if r.status == AttackStatus.SUCCESS)
        success_rate = successful / len(recent_results)

        # Weight success rate heavily in health score
        health_score = success_rate * 0.7

        # Add latency factor (lower latency = better health)
        latencies = [r.latency_ms for r in recent_results if r.latency_ms > 0]
        if latencies:
            avg_latency = statistics.mean(latencies)
            latency_factor = max(0, 1.0 - (avg_latency / 5000.0))  # Normalize to 5s max
            health_score += latency_factor * 0.3
        else:
            health_score += 0.3  # No latency data = assume good

        return min(1.0, max(0.0, health_score))

    def _check_thresholds(self) -> None:
        """Check metrics against thresholds and trigger alerts."""
        for metric_name, threshold in self._thresholds.items():
            if not threshold.enabled:
                continue

            stats = self.metric_collector.get_metric_stats(
                metric_name, time_window_minutes=10
            )
            if not stats:
                continue

            current_value = stats["latest"]
            alert_level = self._evaluate_threshold(current_value, threshold)

            if alert_level:
                alert = Alert(
                    level=alert_level,
                    metric_type=self._get_metric_type(metric_name),
                    message=f"{metric_name} threshold exceeded",
                    value=current_value,
                    threshold=self._get_threshold_value(threshold, alert_level),
                    metadata={"stats": stats},
                )
                self.alert_manager.trigger_alert(alert)

    def _evaluate_threshold(
        self, value: float, threshold: MetricThreshold
    ) -> Optional[AlertLevel]:
        """Evaluate if a value exceeds threshold."""
        if threshold.comparison == "greater_than":
            if value >= threshold.critical_threshold:
                return AlertLevel.CRITICAL
            elif value >= threshold.error_threshold:
                return AlertLevel.ERROR
            elif value >= threshold.warning_threshold:
                return AlertLevel.WARNING
        elif threshold.comparison == "less_than":
            if value <= threshold.critical_threshold:
                return AlertLevel.CRITICAL
            elif value <= threshold.error_threshold:
                return AlertLevel.ERROR
            elif value <= threshold.warning_threshold:
                return AlertLevel.WARNING

        return None

    def _get_threshold_value(
        self, threshold: MetricThreshold, level: AlertLevel
    ) -> float:
        """Get threshold value for alert level."""
        if level == AlertLevel.CRITICAL:
            return threshold.critical_threshold
        elif level == AlertLevel.ERROR:
            return threshold.error_threshold
        elif level == AlertLevel.WARNING:
            return threshold.warning_threshold
        return 0.0

    def _get_metric_type(self, metric_name: str) -> MetricType:
        """Get metric type from metric name."""
        if "latency" in metric_name or "performance" in metric_name:
            return MetricType.PERFORMANCE
        elif "effectiveness" in metric_name or "success" in metric_name:
            return MetricType.EFFECTIVENESS
        elif "health" in metric_name:
            return MetricType.SYSTEM_HEALTH
        elif "error" in metric_name:
            return MetricType.ERROR_RATE
        else:
            return MetricType.PERFORMANCE

    def record_attack_result(self, result: AttackResult) -> None:
        """Record an attack result for monitoring."""
        self._attack_results.append(result)

        # Update system stats
        self._system_stats["total_attacks"] += 1
        if result.status == AttackStatus.SUCCESS:
            self._system_stats["successful_attacks"] += 1
        else:
            self._system_stats["failed_attacks"] += 1

        self._system_stats["last_update"] = datetime.now()

    def get_monitoring_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive monitoring dashboard data."""
        dashboard = {
            "system_status": "healthy" if self._monitoring_active else "stopped",
            "monitoring_active": self._monitoring_active,
            "last_update": datetime.now().isoformat(),
            "system_stats": self._system_stats.copy(),
            "recent_metrics": {},
            "alert_summary": self.alert_manager.get_alert_summary(60),
            "thresholds": {
                name: {
                    "warning": t.warning_threshold,
                    "error": t.error_threshold,
                    "critical": t.critical_threshold,
                    "enabled": t.enabled,
                }
                for name, t in self._thresholds.items()
            },
        }

        # Add recent metrics
        for metric_name in [
            "success_rate",
            "average_latency",
            "error_rate",
            "system_health_score",
        ]:
            stats = self.metric_collector.get_metric_stats(
                metric_name, time_window_minutes=30
            )
            if stats:
                dashboard["recent_metrics"][metric_name] = stats

        return dashboard

    def update_threshold(self, metric_name: str, threshold: MetricThreshold) -> None:
        """Update monitoring threshold."""
        self._thresholds[metric_name] = threshold
        self.logger.info(f"Updated threshold for {metric_name}")

    def get_metric_history(
        self, metric_name: str, limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get metric history."""
        return self.metric_collector.get_metric_history(metric_name, limit)

    def cleanup(self) -> None:
        """Cleanup monitoring system."""
        self.stop_monitoring()
        self.metric_collector.clear_metrics()


# Export main classes
__all__ = [
    "AdvancedMonitoringSystem",
    "MonitoringConfig",
    "MetricThreshold",
    "Alert",
    "AlertLevel",
    "MetricType",
]
