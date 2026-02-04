# recon/core/bypass/filtering/rollout_monitor.py

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import threading

from .feature_flags import FeatureFlagManager, RolloutStage, get_feature_flags

LOG = logging.getLogger("RolloutMonitor")


class AlertLevel(Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MetricType(Enum):
    """Types of metrics to monitor."""

    ERROR_RATE = "error_rate"
    PERFORMANCE = "performance"
    SUCCESS_RATE = "success_rate"
    MEMORY_USAGE = "memory_usage"
    PACKET_RATE = "packet_rate"


@dataclass
class Alert:
    """Alert information."""

    level: AlertLevel
    message: str
    feature_name: str
    metric_type: MetricType
    value: float
    threshold: float
    timestamp: str

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class MetricThreshold:
    """Threshold configuration for monitoring metrics."""

    metric_type: MetricType
    warning_threshold: float
    error_threshold: float
    critical_threshold: float
    check_interval: int = 60  # seconds
    sample_size: int = 10  # number of samples to consider


@dataclass
class RolloutHealth:
    """Health status of a feature rollout."""

    feature_name: str
    rollout_stage: RolloutStage
    health_score: float  # 0.0 to 1.0
    error_rate: float
    performance_impact: float
    success_rate: float
    last_check: str
    alerts: List[Alert]

    def __post_init__(self):
        if not self.last_check:
            self.last_check = datetime.now().isoformat()
        if not self.alerts:
            self.alerts = []


class RolloutMonitor:
    """
    Monitors feature rollout health and triggers alerts for issues.

    Provides functionality for:
    - Real-time monitoring of rollout metrics
    - Automatic alerting when thresholds are exceeded
    - Rollback recommendations for critical issues
    - Performance impact tracking
    - Health scoring for rollout stages
    """

    def __init__(
        self,
        feature_flags: Optional[FeatureFlagManager] = None,
        alert_handlers: Optional[List[Callable[[Alert], None]]] = None,
    ):
        self.feature_flags = feature_flags or get_feature_flags()
        self.alert_handlers = alert_handlers or []

        # Monitoring configuration
        self.thresholds: Dict[str, Dict[MetricType, MetricThreshold]] = {}
        self.metrics_history: Dict[str, Dict[MetricType, List[float]]] = {}
        self.health_status: Dict[str, RolloutHealth] = {}

        # Monitoring state
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None

        # Initialize default thresholds
        self._initialize_default_thresholds()

    def start_monitoring(self, check_interval: int = 60) -> None:
        """
        Start continuous monitoring of rollout health.

        Args:
            check_interval: Interval between health checks in seconds
        """
        if self.monitoring_active:
            LOG.warning("Monitoring is already active")
            return

        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop, args=(check_interval,), daemon=True
        )
        self.monitor_thread.start()

        LOG.info(f"Started rollout monitoring with {check_interval}s interval")

    def stop_monitoring(self) -> None:
        """Stop continuous monitoring."""
        self.monitoring_active = False

        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)

        LOG.info("Stopped rollout monitoring")

    def record_metric(self, feature_name: str, metric_type: MetricType, value: float) -> None:
        """
        Record a metric value for monitoring.

        Args:
            feature_name: Name of the feature
            metric_type: Type of metric
            value: Metric value
        """
        if feature_name not in self.metrics_history:
            self.metrics_history[feature_name] = {}

        if metric_type not in self.metrics_history[feature_name]:
            self.metrics_history[feature_name][metric_type] = []

        # Add new value and maintain history size
        history = self.metrics_history[feature_name][metric_type]
        history.append(value)

        # Keep only recent samples
        max_samples = 100
        if len(history) > max_samples:
            history[:] = history[-max_samples:]

        LOG.debug(f"Recorded {metric_type.value} = {value} for {feature_name}")

    def check_health(self, feature_name: str) -> RolloutHealth:
        """
        Check the health of a feature rollout.

        Args:
            feature_name: Name of the feature to check

        Returns:
            RolloutHealth object with current status
        """
        if feature_name not in self.feature_flags.features:
            raise ValueError(f"Unknown feature: {feature_name}")

        feature = self.feature_flags.features[feature_name]
        alerts = []

        # Calculate metrics
        error_rate = self._calculate_error_rate(feature_name)
        performance_impact = self._calculate_performance_impact(feature_name)
        success_rate = self._calculate_success_rate(feature_name)

        # Check thresholds and generate alerts
        if feature_name in self.thresholds:
            alerts.extend(
                self._check_thresholds(feature_name, error_rate, performance_impact, success_rate)
            )

        # Calculate health score
        health_score = self._calculate_health_score(error_rate, performance_impact, success_rate)

        health = RolloutHealth(
            feature_name=feature_name,
            rollout_stage=feature.rollout_stage,
            health_score=health_score,
            error_rate=error_rate,
            performance_impact=performance_impact,
            success_rate=success_rate,
            last_check=datetime.now().isoformat(),
            alerts=alerts,
        )

        self.health_status[feature_name] = health

        # Send alerts
        for alert in alerts:
            self._send_alert(alert)

        return health

    def get_rollout_recommendation(self, feature_name: str) -> Dict[str, Any]:
        """
        Get recommendation for rollout progression or rollback.

        Args:
            feature_name: Name of the feature

        Returns:
            Dictionary with recommendation details
        """
        health = self.check_health(feature_name)
        feature = self.feature_flags.features[feature_name]

        recommendation = {
            "feature_name": feature_name,
            "current_stage": feature.rollout_stage.value,
            "health_score": health.health_score,
            "recommendation": "maintain",
            "reason": "Health metrics are within acceptable ranges",
            "suggested_action": None,
        }

        # Critical issues - immediate rollback
        if health.health_score < 0.3 or health.error_rate > 0.1:
            recommendation.update(
                {
                    "recommendation": "rollback",
                    "reason": f"Critical issues detected (health: {health.health_score:.2f}, error rate: {health.error_rate:.2%})",
                    "suggested_action": "Disable feature immediately and investigate",
                }
            )

        # Warning issues - pause rollout
        elif health.health_score < 0.6 or health.error_rate > 0.05:
            recommendation.update(
                {
                    "recommendation": "pause",
                    "reason": f"Warning issues detected (health: {health.health_score:.2f}, error rate: {health.error_rate:.2%})",
                    "suggested_action": "Pause rollout and monitor for improvement",
                }
            )

        # Good health - consider progression
        elif health.health_score > 0.8 and health.error_rate < 0.01:
            if feature.rollout_stage == RolloutStage.TESTING:
                recommendation.update(
                    {
                        "recommendation": "progress",
                        "reason": "Testing stage showing good results",
                        "suggested_action": "Progress to canary stage (5% rollout)",
                    }
                )
            elif feature.rollout_stage == RolloutStage.CANARY:
                recommendation.update(
                    {
                        "recommendation": "progress",
                        "reason": "Canary stage showing good results",
                        "suggested_action": "Progress to partial stage (25% rollout)",
                    }
                )
            elif feature.rollout_stage == RolloutStage.PARTIAL:
                recommendation.update(
                    {
                        "recommendation": "progress",
                        "reason": "Partial stage showing good results",
                        "suggested_action": "Progress to full rollout (100%)",
                    }
                )

        return recommendation

    def add_alert_handler(self, handler: Callable[[Alert], None]) -> None:
        """
        Add an alert handler function.

        Args:
            handler: Function that takes an Alert object
        """
        self.alert_handlers.append(handler)
        LOG.info(f"Added alert handler: {handler.__name__}")

    def set_threshold(
        self, feature_name: str, metric_type: MetricType, threshold: MetricThreshold
    ) -> None:
        """
        Set monitoring threshold for a feature metric.

        Args:
            feature_name: Name of the feature
            metric_type: Type of metric
            threshold: Threshold configuration
        """
        if feature_name not in self.thresholds:
            self.thresholds[feature_name] = {}

        self.thresholds[feature_name][metric_type] = threshold
        LOG.info(f"Set {metric_type.value} threshold for {feature_name}")

    def get_monitoring_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive monitoring report.

        Returns:
            Dictionary with monitoring report data
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "features": {},
            "summary": {
                "total_features": len(self.feature_flags.features),
                "healthy_features": 0,
                "warning_features": 0,
                "critical_features": 0,
                "total_alerts": 0,
            },
        }

        for feature_name in self.feature_flags.features.keys():
            health = self.health_status.get(feature_name)
            if not health:
                health = self.check_health(feature_name)

            report["features"][feature_name] = {
                "health_score": health.health_score,
                "rollout_stage": health.rollout_stage.value,
                "error_rate": health.error_rate,
                "performance_impact": health.performance_impact,
                "success_rate": health.success_rate,
                "alerts_count": len(health.alerts),
                "recommendation": self.get_rollout_recommendation(feature_name),
            }

            # Update summary
            if health.health_score >= 0.8:
                report["summary"]["healthy_features"] += 1
            elif health.health_score >= 0.6:
                report["summary"]["warning_features"] += 1
            else:
                report["summary"]["critical_features"] += 1

            report["summary"]["total_alerts"] += len(health.alerts)

        return report

    def _monitoring_loop(self, check_interval: int) -> None:
        """Main monitoring loop (runs in separate thread)."""
        LOG.info("Started monitoring loop")

        while self.monitoring_active:
            try:
                # Check health for all features
                for feature_name in self.feature_flags.features.keys():
                    if self.feature_flags.features[feature_name].enabled:
                        self.check_health(feature_name)

                # Sleep until next check
                time.sleep(check_interval)

            except Exception as e:
                LOG.error(f"Error in monitoring loop: {e}")
                time.sleep(check_interval)

        LOG.info("Monitoring loop stopped")

    def _initialize_default_thresholds(self) -> None:
        """Initialize default monitoring thresholds."""
        default_thresholds = {
            MetricType.ERROR_RATE: MetricThreshold(
                metric_type=MetricType.ERROR_RATE,
                warning_threshold=0.02,  # 2%
                error_threshold=0.05,  # 5%
                critical_threshold=0.10,  # 10%
            ),
            MetricType.PERFORMANCE: MetricThreshold(
                metric_type=MetricType.PERFORMANCE,
                warning_threshold=10.0,  # 10% performance impact
                error_threshold=25.0,  # 25% performance impact
                critical_threshold=50.0,  # 50% performance impact
            ),
            MetricType.SUCCESS_RATE: MetricThreshold(
                metric_type=MetricType.SUCCESS_RATE,
                warning_threshold=0.95,  # 95% success rate
                error_threshold=0.90,  # 90% success rate
                critical_threshold=0.80,  # 80% success rate
            ),
        }

        # Apply default thresholds to runtime filtering
        self.thresholds["runtime_filtering"] = default_thresholds.copy()
        self.thresholds["custom_sni"] = default_thresholds.copy()

    def _calculate_error_rate(self, feature_name: str) -> float:
        """Calculate error rate for a feature."""
        if feature_name not in self.metrics_history:
            return 0.0

        error_history = self.metrics_history[feature_name].get(MetricType.ERROR_RATE, [])
        if not error_history:
            return 0.0

        # Return average of recent samples
        recent_samples = error_history[-10:]  # Last 10 samples
        return sum(recent_samples) / len(recent_samples)

    def _calculate_performance_impact(self, feature_name: str) -> float:
        """Calculate performance impact for a feature."""
        if feature_name not in self.metrics_history:
            return 0.0

        perf_history = self.metrics_history[feature_name].get(MetricType.PERFORMANCE, [])
        if not perf_history:
            return 0.0

        # Return average of recent samples
        recent_samples = perf_history[-10:]  # Last 10 samples
        return sum(recent_samples) / len(recent_samples)

    def _calculate_success_rate(self, feature_name: str) -> float:
        """Calculate success rate for a feature."""
        if feature_name not in self.metrics_history:
            return 1.0  # Assume 100% if no data

        success_history = self.metrics_history[feature_name].get(MetricType.SUCCESS_RATE, [])
        if not success_history:
            return 1.0

        # Return average of recent samples
        recent_samples = success_history[-10:]  # Last 10 samples
        return sum(recent_samples) / len(recent_samples)

    def _calculate_health_score(
        self, error_rate: float, performance_impact: float, success_rate: float
    ) -> float:
        """
        Calculate overall health score (0.0 to 1.0).

        Args:
            error_rate: Error rate (0.0 to 1.0)
            performance_impact: Performance impact percentage (0.0 to 100.0)
            success_rate: Success rate (0.0 to 1.0)

        Returns:
            Health score from 0.0 (critical) to 1.0 (excellent)
        """
        # Weight factors
        error_weight = 0.4
        performance_weight = 0.3
        success_weight = 0.3

        # Calculate component scores (higher is better)
        error_score = max(0.0, 1.0 - (error_rate * 10))  # 10% error = 0 score
        performance_score = max(0.0, 1.0 - (performance_impact / 100))  # 100% impact = 0 score
        success_score = success_rate  # Direct mapping

        # Weighted average
        health_score = (
            error_score * error_weight
            + performance_score * performance_weight
            + success_score * success_weight
        )

        return min(1.0, max(0.0, health_score))

    def _check_thresholds(
        self, feature_name: str, error_rate: float, performance_impact: float, success_rate: float
    ) -> List[Alert]:
        """Check if metrics exceed thresholds and generate alerts."""
        alerts = []

        if feature_name not in self.thresholds:
            return alerts

        thresholds = self.thresholds[feature_name]

        # Check error rate
        if MetricType.ERROR_RATE in thresholds:
            threshold = thresholds[MetricType.ERROR_RATE]
            if error_rate >= threshold.critical_threshold:
                alerts.append(
                    Alert(
                        level=AlertLevel.CRITICAL,
                        message=f"Critical error rate: {error_rate:.2%} >= {threshold.critical_threshold:.2%}",
                        feature_name=feature_name,
                        metric_type=MetricType.ERROR_RATE,
                        value=error_rate,
                        threshold=threshold.critical_threshold,
                        timestamp=datetime.now().isoformat(),
                    )
                )
            elif error_rate >= threshold.error_threshold:
                alerts.append(
                    Alert(
                        level=AlertLevel.ERROR,
                        message=f"High error rate: {error_rate:.2%} >= {threshold.error_threshold:.2%}",
                        feature_name=feature_name,
                        metric_type=MetricType.ERROR_RATE,
                        value=error_rate,
                        threshold=threshold.error_threshold,
                        timestamp=datetime.now().isoformat(),
                    )
                )
            elif error_rate >= threshold.warning_threshold:
                alerts.append(
                    Alert(
                        level=AlertLevel.WARNING,
                        message=f"Elevated error rate: {error_rate:.2%} >= {threshold.warning_threshold:.2%}",
                        feature_name=feature_name,
                        metric_type=MetricType.ERROR_RATE,
                        value=error_rate,
                        threshold=threshold.warning_threshold,
                        timestamp=datetime.now().isoformat(),
                    )
                )

        # Check performance impact
        if MetricType.PERFORMANCE in thresholds:
            threshold = thresholds[MetricType.PERFORMANCE]
            if performance_impact >= threshold.critical_threshold:
                alerts.append(
                    Alert(
                        level=AlertLevel.CRITICAL,
                        message=f"Critical performance impact: {performance_impact:.1f}% >= {threshold.critical_threshold:.1f}%",
                        feature_name=feature_name,
                        metric_type=MetricType.PERFORMANCE,
                        value=performance_impact,
                        threshold=threshold.critical_threshold,
                        timestamp=datetime.now().isoformat(),
                    )
                )
            elif performance_impact >= threshold.error_threshold:
                alerts.append(
                    Alert(
                        level=AlertLevel.ERROR,
                        message=f"High performance impact: {performance_impact:.1f}% >= {threshold.error_threshold:.1f}%",
                        feature_name=feature_name,
                        metric_type=MetricType.PERFORMANCE,
                        value=performance_impact,
                        threshold=threshold.error_threshold,
                        timestamp=datetime.now().isoformat(),
                    )
                )
            elif performance_impact >= threshold.warning_threshold:
                alerts.append(
                    Alert(
                        level=AlertLevel.WARNING,
                        message=f"Elevated performance impact: {performance_impact:.1f}% >= {threshold.warning_threshold:.1f}%",
                        feature_name=feature_name,
                        metric_type=MetricType.PERFORMANCE,
                        value=performance_impact,
                        threshold=threshold.warning_threshold,
                        timestamp=datetime.now().isoformat(),
                    )
                )

        # Check success rate (lower is worse)
        if MetricType.SUCCESS_RATE in thresholds:
            threshold = thresholds[MetricType.SUCCESS_RATE]
            if success_rate <= threshold.critical_threshold:
                alerts.append(
                    Alert(
                        level=AlertLevel.CRITICAL,
                        message=f"Critical success rate: {success_rate:.2%} <= {threshold.critical_threshold:.2%}",
                        feature_name=feature_name,
                        metric_type=MetricType.SUCCESS_RATE,
                        value=success_rate,
                        threshold=threshold.critical_threshold,
                        timestamp=datetime.now().isoformat(),
                    )
                )
            elif success_rate <= threshold.error_threshold:
                alerts.append(
                    Alert(
                        level=AlertLevel.ERROR,
                        message=f"Low success rate: {success_rate:.2%} <= {threshold.error_threshold:.2%}",
                        feature_name=feature_name,
                        metric_type=MetricType.SUCCESS_RATE,
                        value=success_rate,
                        threshold=threshold.error_threshold,
                        timestamp=datetime.now().isoformat(),
                    )
                )
            elif success_rate <= threshold.warning_threshold:
                alerts.append(
                    Alert(
                        level=AlertLevel.WARNING,
                        message=f"Reduced success rate: {success_rate:.2%} <= {threshold.warning_threshold:.2%}",
                        feature_name=feature_name,
                        metric_type=MetricType.SUCCESS_RATE,
                        value=success_rate,
                        threshold=threshold.warning_threshold,
                        timestamp=datetime.now().isoformat(),
                    )
                )

        return alerts

    def _send_alert(self, alert: Alert) -> None:
        """Send alert to all registered handlers."""
        LOG.log(
            (
                logging.CRITICAL
                if alert.level == AlertLevel.CRITICAL
                else (
                    logging.ERROR
                    if alert.level == AlertLevel.ERROR
                    else logging.WARNING if alert.level == AlertLevel.WARNING else logging.INFO
                )
            ),
            f"ALERT [{alert.level.value.upper()}] {alert.feature_name}: {alert.message}",
        )

        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                LOG.error(f"Alert handler failed: {e}")


def log_alert_handler(alert: Alert) -> None:
    """Default alert handler that logs alerts."""
    LOG.log(
        (
            logging.CRITICAL
            if alert.level == AlertLevel.CRITICAL
            else (
                logging.ERROR
                if alert.level == AlertLevel.ERROR
                else logging.WARNING if alert.level == AlertLevel.WARNING else logging.INFO
            )
        ),
        f"ROLLOUT ALERT: {alert.message}",
    )


def email_alert_handler(alert: Alert, email_config: Dict[str, str]) -> None:
    """
    Alert handler that sends email notifications.

    Args:
        alert: Alert to send
        email_config: Email configuration (smtp_server, username, password, recipients)
    """
    # This is a placeholder - implement actual email sending based on your requirements
    LOG.info(
        f"EMAIL ALERT: Would send email about {alert.feature_name} to {email_config.get('recipients', [])}"
    )


# Global monitor instance
_rollout_monitor = None


def get_rollout_monitor() -> RolloutMonitor:
    """Get the global rollout monitor instance."""
    global _rollout_monitor
    if _rollout_monitor is None:
        _rollout_monitor = RolloutMonitor()
    return _rollout_monitor
