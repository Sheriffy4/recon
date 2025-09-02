"""
Production monitoring system for bypass engine.
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from collections import deque
from core.bypass.performance.performance_models import (
    SystemHealth,
    PerformanceMetrics,
    Alert,
    AlertSeverity,
    ProductionConfig,
)


class ProductionMonitor:
    """Production monitoring and health checking system."""

    def __init__(self, config: ProductionConfig):
        self.config = config
        self.health_history = deque(maxlen=1000)
        self.alerts = deque(maxlen=500)
        self.active_alerts = {}
        self.monitoring_active = False
        self.alert_callbacks = []
        self.logger = logging.getLogger(__name__)
        self.thresholds = {
            "cpu_critical": 90.0,
            "cpu_warning": 75.0,
            "memory_critical": 85.0,
            "memory_warning": 70.0,
            "disk_critical": 95.0,
            "disk_warning": 80.0,
            "latency_critical": 10.0,
            "latency_warning": 5.0,
            "success_rate_critical": 50.0,
            "success_rate_warning": 70.0,
        }
        if hasattr(config, "alert_thresholds"):
            self.thresholds.update(config.alert_thresholds)

    async def start_monitoring(self) -> None:
        """Start production monitoring."""
        try:
            self.monitoring_active = True
            self.logger.info("Starting production monitoring")
            monitoring_tasks = [
                asyncio.create_task(self._monitor_system_health()),
                asyncio.create_task(self._monitor_performance_metrics()),
                asyncio.create_task(self._process_alerts()),
                asyncio.create_task(self._cleanup_old_data()),
            ]
            await asyncio.gather(*monitoring_tasks, return_exceptions=True)
        except Exception as e:
            self.logger.error(f"Error starting production monitoring: {e}")
            raise

    async def stop_monitoring(self) -> None:
        """Stop production monitoring."""
        self.monitoring_active = False
        self.logger.info("Stopping production monitoring")

    async def _monitor_system_health(self) -> None:
        """Monitor system health continuously."""
        while self.monitoring_active:
            try:
                from core.bypass.performance.performance_optimizer import (
                    PerformanceOptimizer,
                )

                optimizer = PerformanceOptimizer()
                health = await optimizer.get_system_health()
                self.health_history.append(health)
                await self._check_health_alerts(health)
                await asyncio.sleep(self.config.monitoring_interval)
            except Exception as e:
                self.logger.error(f"Error monitoring system health: {e}")
                await asyncio.sleep(self.config.monitoring_interval)

    async def _monitor_performance_metrics(self) -> None:
        """Monitor performance metrics continuously."""
        while self.monitoring_active:
            try:
                from core.bypass.performance.performance_optimizer import (
                    PerformanceOptimizer,
                )

                optimizer = PerformanceOptimizer()
                metrics = await optimizer.collect_performance_metrics()
                await self._check_performance_alerts(metrics)
                await asyncio.sleep(self.config.monitoring_interval * 2)
            except Exception as e:
                self.logger.error(f"Error monitoring performance metrics: {e}")
                await asyncio.sleep(self.config.monitoring_interval * 2)

    async def _check_health_alerts(self, health: SystemHealth) -> None:
        """Check system health for alert conditions."""
        try:
            if health.cpu_usage >= self.thresholds["cpu_critical"]:
                await self._create_alert(
                    AlertSeverity.CRITICAL,
                    "High CPU Usage",
                    f"CPU usage is {health.cpu_usage:.1f}% (critical threshold: {self.thresholds['cpu_critical']}%)",
                    "system_health",
                    {"cpu_usage": health.cpu_usage},
                )
            elif health.cpu_usage >= self.thresholds["cpu_warning"]:
                await self._create_alert(
                    AlertSeverity.WARNING,
                    "Elevated CPU Usage",
                    f"CPU usage is {health.cpu_usage:.1f}% (warning threshold: {self.thresholds['cpu_warning']}%)",
                    "system_health",
                    {"cpu_usage": health.cpu_usage},
                )
            if health.memory_usage >= self.thresholds["memory_critical"]:
                await self._create_alert(
                    AlertSeverity.CRITICAL,
                    "High Memory Usage",
                    f"Memory usage is {health.memory_usage:.1f}% (critical threshold: {self.thresholds['memory_critical']}%)",
                    "system_health",
                    {"memory_usage": health.memory_usage},
                )
            elif health.memory_usage >= self.thresholds["memory_warning"]:
                await self._create_alert(
                    AlertSeverity.WARNING,
                    "Elevated Memory Usage",
                    f"Memory usage is {health.memory_usage:.1f}% (warning threshold: {self.thresholds['memory_warning']}%)",
                    "system_health",
                    {"memory_usage": health.memory_usage},
                )
            if health.disk_usage >= self.thresholds["disk_critical"]:
                await self._create_alert(
                    AlertSeverity.CRITICAL,
                    "High Disk Usage",
                    f"Disk usage is {health.disk_usage:.1f}% (critical threshold: {self.thresholds['disk_critical']}%)",
                    "system_health",
                    {"disk_usage": health.disk_usage},
                )
            elif health.disk_usage >= self.thresholds["disk_warning"]:
                await self._create_alert(
                    AlertSeverity.WARNING,
                    "Elevated Disk Usage",
                    f"Disk usage is {health.disk_usage:.1f}% (warning threshold: {self.thresholds['disk_warning']}%)",
                    "system_health",
                    {"disk_usage": health.disk_usage},
                )
        except Exception as e:
            self.logger.error(f"Error checking health alerts: {e}")

    async def _check_performance_alerts(self, metrics: PerformanceMetrics) -> None:
        """Check performance metrics for alert conditions."""
        try:
            if metrics.latency >= self.thresholds["latency_critical"]:
                await self._create_alert(
                    AlertSeverity.CRITICAL,
                    "High Latency",
                    f"Average latency is {metrics.latency:.2f}s (critical threshold: {self.thresholds['latency_critical']}s)",
                    "performance",
                    {"latency": metrics.latency},
                )
            elif metrics.latency >= self.thresholds["latency_warning"]:
                await self._create_alert(
                    AlertSeverity.WARNING,
                    "Elevated Latency",
                    f"Average latency is {metrics.latency:.2f}s (warning threshold: {self.thresholds['latency_warning']}s)",
                    "performance",
                    {"latency": metrics.latency},
                )
            if metrics.success_rate <= self.thresholds["success_rate_critical"]:
                await self._create_alert(
                    AlertSeverity.CRITICAL,
                    "Low Success Rate",
                    f"Success rate is {metrics.success_rate:.1f}% (critical threshold: {self.thresholds['success_rate_critical']}%)",
                    "performance",
                    {"success_rate": metrics.success_rate},
                )
            elif metrics.success_rate <= self.thresholds["success_rate_warning"]:
                await self._create_alert(
                    AlertSeverity.WARNING,
                    "Reduced Success Rate",
                    f"Success rate is {metrics.success_rate:.1f}% (warning threshold: {self.thresholds['success_rate_warning']}%)",
                    "performance",
                    {"success_rate": metrics.success_rate},
                )
        except Exception as e:
            self.logger.error(f"Error checking performance alerts: {e}")

    async def _create_alert(
        self,
        severity: AlertSeverity,
        title: str,
        message: str,
        component: str,
        metrics: Dict[str, Any],
    ) -> None:
        """Create a new alert."""
        try:
            alert_id = (
                f"{component}_{title.lower().replace(' ', '_')}_{int(time.time())}"
            )
            existing_alert_key = f"{component}_{title}"
            if existing_alert_key in self.active_alerts:
                existing_alert = self.active_alerts[existing_alert_key]
                existing_alert.message = message
                existing_alert.metrics = metrics
                existing_alert.timestamp = datetime.now()
                return
            alert = Alert(
                id=alert_id,
                severity=severity,
                title=title,
                message=message,
                component=component,
                metrics=metrics,
            )
            self.alerts.append(alert)
            self.active_alerts[existing_alert_key] = alert
            for callback in self.alert_callbacks:
                try:
                    await callback(alert)
                except Exception as e:
                    self.logger.error(f"Error in alert callback: {e}")
            self.logger.warning(f"Alert created: {title} - {message}")
        except Exception as e:
            self.logger.error(f"Error creating alert: {e}")

    async def _process_alerts(self) -> None:
        """Process and manage alerts."""
        while self.monitoring_active:
            try:
                current_time = datetime.now()
                alerts_to_resolve = []
                for key, alert in self.active_alerts.items():
                    if (current_time - alert.timestamp).total_seconds() > 3600:
                        alerts_to_resolve.append(key)
                for key in alerts_to_resolve:
                    alert = self.active_alerts[key]
                    alert.resolved = True
                    del self.active_alerts[key]
                    self.logger.info(f"Auto-resolved alert: {alert.title}")
                await asyncio.sleep(300)
            except Exception as e:
                self.logger.error(f"Error processing alerts: {e}")
                await asyncio.sleep(300)

    async def _cleanup_old_data(self) -> None:
        """Clean up old monitoring data."""
        while self.monitoring_active:
            try:
                cutoff_time = datetime.now() - timedelta(hours=24)
                while (
                    self.health_history
                    and self.health_history[0].timestamp < cutoff_time
                ):
                    self.health_history.popleft()
                while (
                    self.alerts
                    and self.alerts[0].resolved
                    and (self.alerts[0].timestamp < cutoff_time)
                ):
                    self.alerts.popleft()
                await asyncio.sleep(3600)
            except Exception as e:
                self.logger.error(f"Error cleaning up old data: {e}")
                await asyncio.sleep(3600)

    def add_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        """Add callback for alert notifications."""
        self.alert_callbacks.append(callback)

    def remove_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        """Remove alert callback."""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)

    async def get_current_health(self) -> Optional[SystemHealth]:
        """Get current system health."""
        if self.health_history:
            return self.health_history[-1]
        return None

    async def get_health_history(self, hours: int = 24) -> List[SystemHealth]:
        """Get system health history."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [
            health for health in self.health_history if health.timestamp >= cutoff_time
        ]

    async def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts."""
        return list(self.active_alerts.values())

    async def get_alert_history(self, hours: int = 24) -> List[Alert]:
        """Get alert history."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [alert for alert in self.alerts if alert.timestamp >= cutoff_time]

    async def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        try:
            for alert in self.alerts:
                if alert.id == alert_id:
                    alert.acknowledged = True
                    self.logger.info(f"Alert acknowledged: {alert.title}")
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Error acknowledging alert: {e}")
            return False

    async def resolve_alert(self, alert_id: str) -> bool:
        """Manually resolve an alert."""
        try:
            for alert in self.alerts:
                if alert.id == alert_id:
                    alert.resolved = True
                    keys_to_remove = [
                        key
                        for key, active_alert in self.active_alerts.items()
                        if active_alert.id == alert_id
                    ]
                    for key in keys_to_remove:
                        del self.active_alerts[key]
                    self.logger.info(f"Alert resolved: {alert.title}")
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Error resolving alert: {e}")
            return False

    async def get_monitoring_status(self) -> Dict[str, Any]:
        """Get monitoring system status."""
        try:
            current_health = await self.get_current_health()
            active_alerts = await self.get_active_alerts()
            status = {
                "monitoring_active": self.monitoring_active,
                "monitoring_interval": self.config.monitoring_interval,
                "health_records": len(self.health_history),
                "total_alerts": len(self.alerts),
                "active_alerts": len(active_alerts),
                "critical_alerts": len(
                    [a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]
                ),
                "warning_alerts": len(
                    [a for a in active_alerts if a.severity == AlertSeverity.WARNING]
                ),
                "current_health": current_health.__dict__ if current_health else None,
                "thresholds": self.thresholds,
                "uptime": time.time()
                - (current_health.uptime if current_health else 0),
            }
            return status
        except Exception as e:
            self.logger.error(f"Error getting monitoring status: {e}")
            return {"error": str(e)}
