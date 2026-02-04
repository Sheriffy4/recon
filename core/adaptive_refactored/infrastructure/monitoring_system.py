"""
Comprehensive monitoring system for the adaptive engine.

Provides real-time monitoring, alerting, and health checks
for all major operations and components.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Set
from collections import defaultdict, deque

from .structured_logging import get_structured_logger, LogCategory, LogContext
from ..config import AdaptiveEngineConfig


class HealthStatus(Enum):
    """Health status levels."""

    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class AlertSeverity(Enum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class HealthCheck:
    """Health check definition."""

    name: str
    check_function: Callable[[], bool]
    description: str
    timeout_seconds: float = 30.0
    enabled: bool = True


@dataclass
class HealthCheckResult:
    """Result of a health check."""

    name: str
    status: HealthStatus
    message: str
    timestamp: datetime
    duration_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    """System alert."""

    id: str
    severity: AlertSeverity
    title: str
    description: str
    timestamp: datetime
    component: str
    resolved: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemMetrics:
    """System-wide metrics."""

    timestamp: datetime
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    active_strategies: int = 0
    successful_tests: int = 0
    failed_tests: int = 0
    cache_hit_rate: float = 0.0
    average_response_time_ms: float = 0.0
    error_rate: float = 0.0
    custom_metrics: Dict[str, float] = field(default_factory=dict)


class MonitoringSystem:
    """Comprehensive monitoring system for the adaptive engine."""

    def __init__(self, config: AdaptiveEngineConfig):
        self.config = config
        self.logger = get_structured_logger(__name__, config)

        # Health checks
        self.health_checks: Dict[str, HealthCheck] = {}
        self.health_results: Dict[str, HealthCheckResult] = {}

        # Alerts
        self.alerts: List[Alert] = []
        self.alert_handlers: List[Callable[[Alert], None]] = []

        # Metrics
        self.metrics_history: deque = deque(maxlen=1000)  # Keep last 1000 metric snapshots
        self.custom_counters: Dict[str, int] = defaultdict(int)
        self.custom_gauges: Dict[str, float] = defaultdict(float)
        self.custom_timers: Dict[str, List[float]] = defaultdict(list)

        # Monitoring state
        self.monitoring_active = False
        self.monitoring_task: Optional[asyncio.Task] = None

        # Component status tracking
        self.component_status: Dict[str, HealthStatus] = {}
        self.component_last_seen: Dict[str, datetime] = {}

        self._setup_default_health_checks()

    def _setup_default_health_checks(self):
        """Set up default health checks."""
        self.register_health_check(
            "system_startup",
            lambda: True,  # Always healthy once system is running
            "System startup and initialization",
        )

        self.register_health_check(
            "memory_usage", self._check_memory_usage, "System memory usage check"
        )

        self.register_health_check("error_rate", self._check_error_rate, "System error rate check")

    def register_health_check(
        self,
        name: str,
        check_function: Callable[[], bool],
        description: str,
        timeout_seconds: float = 30.0,
    ):
        """Register a new health check."""
        self.health_checks[name] = HealthCheck(
            name=name,
            check_function=check_function,
            description=description,
            timeout_seconds=timeout_seconds,
        )

        self.logger.info(f"Registered health check: {name}", category=LogCategory.SYSTEM)

    def unregister_health_check(self, name: str):
        """Unregister a health check."""
        if name in self.health_checks:
            del self.health_checks[name]
            if name in self.health_results:
                del self.health_results[name]

            self.logger.info(f"Unregistered health check: {name}", category=LogCategory.SYSTEM)

    async def run_health_check(self, name: str) -> HealthCheckResult:
        """Run a specific health check."""
        if name not in self.health_checks:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNKNOWN,
                message=f"Health check '{name}' not found",
                timestamp=datetime.now(timezone.utc),
                duration_ms=0.0,
            )

        health_check = self.health_checks[name]
        if not health_check.enabled:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNKNOWN,
                message=f"Health check '{name}' is disabled",
                timestamp=datetime.now(timezone.utc),
                duration_ms=0.0,
            )

        start_time = time.time()

        try:
            # Run health check with timeout
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(None, health_check.check_function),
                timeout=health_check.timeout_seconds,
            )

            duration_ms = (time.time() - start_time) * 1000

            health_result = HealthCheckResult(
                name=name,
                status=HealthStatus.HEALTHY if result else HealthStatus.CRITICAL,
                message="Health check passed" if result else "Health check failed",
                timestamp=datetime.now(timezone.utc),
                duration_ms=duration_ms,
            )

        except asyncio.TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            health_result = HealthCheckResult(
                name=name,
                status=HealthStatus.CRITICAL,
                message=f"Health check timed out after {health_check.timeout_seconds}s",
                timestamp=datetime.now(timezone.utc),
                duration_ms=duration_ms,
            )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            health_result = HealthCheckResult(
                name=name,
                status=HealthStatus.CRITICAL,
                message=f"Health check failed with error: {str(e)}",
                timestamp=datetime.now(timezone.utc),
                duration_ms=duration_ms,
            )

        self.health_results[name] = health_result

        # Log health check result
        if health_result.status == HealthStatus.HEALTHY:
            self.logger.info(
                f"Health check {name}: {health_result.status.value}",
                category=LogCategory.SYSTEM,
                metrics={"duration_ms": health_result.duration_ms},
            )
        else:
            self.logger.warning(
                f"Health check {name}: {health_result.status.value}",
                category=LogCategory.SYSTEM,
                metrics={"duration_ms": health_result.duration_ms},
            )

        return health_result

    async def run_all_health_checks(self) -> Dict[str, HealthCheckResult]:
        """Run all registered health checks."""
        tasks = []
        for name in self.health_checks:
            tasks.append(self.run_health_check(name))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        health_results = {}
        for i, result in enumerate(results):
            name = list(self.health_checks.keys())[i]
            if isinstance(result, Exception):
                health_results[name] = HealthCheckResult(
                    name=name,
                    status=HealthStatus.CRITICAL,
                    message=f"Health check failed: {str(result)}",
                    timestamp=datetime.now(timezone.utc),
                    duration_ms=0.0,
                )
            else:
                health_results[name] = result

        return health_results

    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status."""
        if not self.health_results:
            return {
                "overall_status": HealthStatus.UNKNOWN.value,
                "message": "No health checks have been run",
                "checks": {},
            }

        # Determine overall status
        statuses = [result.status for result in self.health_results.values()]
        if any(status == HealthStatus.CRITICAL for status in statuses):
            overall_status = HealthStatus.CRITICAL
        elif any(status == HealthStatus.WARNING for status in statuses):
            overall_status = HealthStatus.WARNING
        else:
            overall_status = HealthStatus.HEALTHY

        return {
            "overall_status": overall_status.value,
            "message": f"System is {overall_status.value}",
            "checks": {
                name: {
                    "status": result.status.value,
                    "message": result.message,
                    "timestamp": result.timestamp.isoformat(),
                    "duration_ms": result.duration_ms,
                }
                for name, result in self.health_results.items()
            },
            "component_status": {
                name: status.value for name, status in self.component_status.items()
            },
        }

    def create_alert(
        self,
        severity: AlertSeverity,
        title: str,
        description: str,
        component: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        """Create and register a new alert."""
        alert = Alert(
            id=f"alert_{int(time.time() * 1000)}",
            severity=severity,
            title=title,
            description=description,
            timestamp=datetime.now(timezone.utc),
            component=component,
            metadata=metadata or {},
        )

        self.alerts.append(alert)

        # Trigger alert handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                self.logger.error(f"Alert handler failed: {e}", category=LogCategory.ERROR)

        # Log the alert
        alert_context = LogContext(component=component)
        alert_context.metadata.update({"alert_id": alert.id, "severity": severity.value})

        self.logger.warning(
            f"Alert created: {title}", category=LogCategory.SYSTEM, context=alert_context
        )

        return alert

    def resolve_alert(self, alert_id: str):
        """Resolve an alert by ID."""
        for alert in self.alerts:
            if alert.id == alert_id and not alert.resolved:
                alert.resolved = True

                alert_context = LogContext()
                alert_context.metadata.update({"alert_id": alert_id})

                self.logger.info(
                    f"Alert resolved: {alert.title}",
                    category=LogCategory.SYSTEM,
                    context=alert_context,
                )
                break

    def get_active_alerts(self) -> List[Alert]:
        """Get all active (unresolved) alerts."""
        return [alert for alert in self.alerts if not alert.resolved]

    def register_alert_handler(self, handler: Callable[[Alert], None]):
        """Register an alert handler function."""
        self.alert_handlers.append(handler)

    def record_metric(self, name: str, value: float, metric_type: str = "gauge"):
        """Record a custom metric."""
        if metric_type == "counter":
            self.custom_counters[name] += value
        elif metric_type == "gauge":
            self.custom_gauges[name] = value
        elif metric_type == "timer":
            self.custom_timers[name].append(value)
            # Keep only last 1000 timer values
            if len(self.custom_timers[name]) > 1000:
                self.custom_timers[name] = self.custom_timers[name][-1000:]

    def get_metrics_snapshot(self) -> SystemMetrics:
        """Get current system metrics snapshot."""
        return SystemMetrics(
            timestamp=datetime.now(timezone.utc),
            custom_metrics={
                **self.custom_gauges,
                **{f"{name}_count": len(values) for name, values in self.custom_timers.items()},
                **{
                    f"{name}_avg": sum(values) / len(values) if values else 0
                    for name, values in self.custom_timers.items()
                },
                **{f"{name}_total": count for name, count in self.custom_counters.items()},
            },
        )

    def update_component_status(self, component: str, status: HealthStatus):
        """Update the status of a system component."""
        self.component_status[component] = status
        self.component_last_seen[component] = datetime.now(timezone.utc)

        if status in [HealthStatus.WARNING, HealthStatus.CRITICAL]:
            self.create_alert(
                severity=(
                    AlertSeverity.HIGH if status == HealthStatus.CRITICAL else AlertSeverity.MEDIUM
                ),
                title=f"Component {component} is {status.value}",
                description=f"Component {component} status changed to {status.value}",
                component=component,
            )

    async def start_monitoring(self, interval_seconds: float = 60.0):
        """Start the monitoring system."""
        if self.monitoring_active:
            self.logger.warning("Monitoring system is already active", category=LogCategory.SYSTEM)
            return

        self.monitoring_active = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop(interval_seconds))

        self.logger.info(
            "Monitoring system started",
            category=LogCategory.SYSTEM,
            metadata={"interval_seconds": interval_seconds},
        )

    async def stop_monitoring(self):
        """Stop the monitoring system."""
        if not self.monitoring_active:
            return

        self.monitoring_active = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass

        self.logger.info("Monitoring system stopped", category=LogCategory.SYSTEM)

    async def _monitoring_loop(self, interval_seconds: float):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                # Run health checks
                await self.run_all_health_checks()

                # Collect metrics
                metrics = self.get_metrics_snapshot()
                self.metrics_history.append(metrics)

                # Check for stale components
                self._check_stale_components()

                # Log monitoring cycle
                self.logger.debug(
                    "Monitoring cycle completed",
                    category=LogCategory.SYSTEM,
                    metrics={"active_alerts": len(self.get_active_alerts())},
                )

            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}", category=LogCategory.ERROR)

            await asyncio.sleep(interval_seconds)

    def _check_stale_components(self):
        """Check for components that haven't reported in recently."""
        stale_threshold = timedelta(minutes=5)
        current_time = datetime.now(timezone.utc)

        for component, last_seen in self.component_last_seen.items():
            if current_time - last_seen > stale_threshold:
                if self.component_status.get(component) != HealthStatus.CRITICAL:
                    self.update_component_status(component, HealthStatus.WARNING)

    def _check_memory_usage(self) -> bool:
        """Check system memory usage."""
        try:
            import psutil

            memory_percent = psutil.virtual_memory().percent
            return memory_percent < 90.0  # Alert if memory usage > 90%
        except ImportError:
            return True  # Assume healthy if psutil not available

    def _check_error_rate(self) -> bool:
        """Check system error rate."""
        # Simple error rate check based on recent metrics
        if len(self.metrics_history) < 2:
            return True

        recent_metrics = list(self.metrics_history)[-10:]  # Last 10 snapshots
        error_rates = [m.error_rate for m in recent_metrics if hasattr(m, "error_rate")]

        if error_rates:
            avg_error_rate = sum(error_rates) / len(error_rates)
            return avg_error_rate < 0.1  # Alert if error rate > 10%

        return True

    def get_monitoring_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive monitoring dashboard data."""
        return {
            "system_health": self.get_system_health(),
            "active_alerts": [
                {
                    "id": alert.id,
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "description": alert.description,
                    "timestamp": alert.timestamp.isoformat(),
                    "component": alert.component,
                }
                for alert in self.get_active_alerts()
            ],
            "metrics": self.get_metrics_snapshot().custom_metrics,
            "monitoring_status": {
                "active": self.monitoring_active,
                "health_checks_count": len(self.health_checks),
                "alerts_count": len(self.alerts),
                "components_count": len(self.component_status),
            },
        }
