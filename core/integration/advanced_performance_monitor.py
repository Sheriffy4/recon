#!/usr/bin/env python3
"""
Advanced Performance Monitor for Phase 2 Advanced Attacks.
Provides comprehensive performance metrics collection and analysis.
"""

import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import statistics

# Setup logging
LOG = logging.getLogger(__name__)


@dataclass
class AttackPerformanceMetrics:
    """Performance metrics for individual attacks."""

    attack_name: str
    execution_time_ms: float
    success: bool
    effectiveness_score: float
    memory_usage_mb: float
    cpu_usage_percent: float
    network_latency_ms: float
    timestamp: datetime
    target_domain: str
    dpi_type: str
    error_message: Optional[str] = None


@dataclass
class SystemPerformanceMetrics:
    """System-wide performance metrics."""

    timestamp: datetime
    total_attacks_executed: int
    successful_attacks: int
    failed_attacks: int
    average_execution_time_ms: float
    average_effectiveness_score: float
    total_memory_usage_mb: float
    cpu_usage_percent: float
    active_connections: int
    error_rate_percent: float


@dataclass
class PerformanceAlert:
    """Performance alert for monitoring."""

    alert_type: str  # 'high_latency', 'low_success_rate', 'high_memory', 'high_cpu'
    severity: str  # 'low', 'medium', 'high', 'critical'
    message: str
    timestamp: datetime
    metrics: Dict[str, Any]
    threshold_exceeded: float


class AdvancedPerformanceMonitor:
    """Advanced performance monitoring system for Phase 2 attacks."""

    def __init__(self, max_history_size: int = 1000):
        self.max_history_size = max_history_size
        self.attack_metrics_history: deque = deque(maxlen=max_history_size)
        self.system_metrics_history: deque = deque(maxlen=max_history_size)
        self.performance_alerts: deque = deque(maxlen=100)

        # Performance thresholds
        self.thresholds = {
            "max_execution_time_ms": 5000.0,
            "min_success_rate_percent": 70.0,
            "max_memory_usage_mb": 500.0,
            "max_cpu_usage_percent": 80.0,
            "max_error_rate_percent": 30.0,
            "max_network_latency_ms": 2000.0,
        }

        # Real-time metrics
        self.current_metrics = {
            "active_attacks": 0,
            "total_executed": 0,
            "total_successful": 0,
            "start_time": datetime.now(),
        }

        # Performance aggregation
        self.attack_performance_by_type = defaultdict(list)
        self.dpi_performance_by_type = defaultdict(list)

        LOG.info("Advanced Performance Monitor initialized")

    async def record_attack_performance(
        self,
        attack_name: str,
        execution_time_ms: float,
        success: bool,
        effectiveness_score: float,
        target_domain: str,
        dpi_type: str,
        error_message: Optional[str] = None,
    ) -> None:
        """Record performance metrics for an attack execution."""

        try:
            # Get system metrics
            memory_usage = await self._get_memory_usage()
            cpu_usage = await self._get_cpu_usage()
            network_latency = await self._measure_network_latency(target_domain)

            # Create attack metrics
            metrics = AttackPerformanceMetrics(
                attack_name=attack_name,
                execution_time_ms=execution_time_ms,
                success=success,
                effectiveness_score=effectiveness_score,
                memory_usage_mb=memory_usage,
                cpu_usage_percent=cpu_usage,
                network_latency_ms=network_latency,
                timestamp=datetime.now(),
                target_domain=target_domain,
                dpi_type=dpi_type,
                error_message=error_message,
            )

            # Store metrics
            self.attack_metrics_history.append(metrics)
            self.attack_performance_by_type[attack_name].append(metrics)
            self.dpi_performance_by_type[dpi_type].append(metrics)

            # Update current metrics
            self.current_metrics["total_executed"] += 1
            if success:
                self.current_metrics["total_successful"] += 1

            # Check for performance alerts
            await self._check_performance_alerts(metrics)

            LOG.debug(
                f"Recorded performance metrics for {attack_name}: "
                f"success={success}, time={execution_time_ms:.1f}ms, "
                f"effectiveness={effectiveness_score:.2f}"
            )

        except Exception as e:
            LOG.error(f"Failed to record attack performance: {e}")

    async def record_system_performance(self) -> SystemPerformanceMetrics:
        """Record current system-wide performance metrics."""

        try:
            current_time = datetime.now()

            # Calculate metrics from recent history
            recent_attacks = [
                m
                for m in self.attack_metrics_history
                if (current_time - m.timestamp).seconds < 300
            ]  # Last 5 minutes

            if recent_attacks:
                total_attacks = len(recent_attacks)
                successful_attacks = sum(1 for m in recent_attacks if m.success)
                failed_attacks = total_attacks - successful_attacks

                avg_execution_time = statistics.mean(
                    m.execution_time_ms for m in recent_attacks
                )
                avg_effectiveness = statistics.mean(
                    m.effectiveness_score for m in recent_attacks
                )
                error_rate = (failed_attacks / total_attacks) * 100
            else:
                total_attacks = successful_attacks = failed_attacks = 0
                avg_execution_time = avg_effectiveness = error_rate = 0.0

            # Get current system metrics
            memory_usage = await self._get_memory_usage()
            cpu_usage = await self._get_cpu_usage()
            active_connections = await self._get_active_connections()

            # Create system metrics
            system_metrics = SystemPerformanceMetrics(
                timestamp=current_time,
                total_attacks_executed=total_attacks,
                successful_attacks=successful_attacks,
                failed_attacks=failed_attacks,
                average_execution_time_ms=avg_execution_time,
                average_effectiveness_score=avg_effectiveness,
                total_memory_usage_mb=memory_usage,
                cpu_usage_percent=cpu_usage,
                active_connections=active_connections,
                error_rate_percent=error_rate,
            )

            # Store system metrics
            self.system_metrics_history.append(system_metrics)

            # Check for system-level alerts
            await self._check_system_alerts(system_metrics)

            return system_metrics

        except Exception as e:
            LOG.error(f"Failed to record system performance: {e}")
            return None

    async def get_attack_performance_summary(self, attack_name: str) -> Dict[str, Any]:
        """Get performance summary for a specific attack type."""

        try:
            attack_metrics = self.attack_performance_by_type.get(attack_name, [])

            if not attack_metrics:
                return {
                    "attack_name": attack_name,
                    "total_executions": 0,
                    "message": "No performance data available",
                }

            # Calculate statistics
            total_executions = len(attack_metrics)
            successful_executions = sum(1 for m in attack_metrics if m.success)
            success_rate = (successful_executions / total_executions) * 100

            execution_times = [m.execution_time_ms for m in attack_metrics]
            effectiveness_scores = [m.effectiveness_score for m in attack_metrics]

            summary = {
                "attack_name": attack_name,
                "total_executions": total_executions,
                "successful_executions": successful_executions,
                "success_rate_percent": success_rate,
                "execution_time_stats": {
                    "mean_ms": statistics.mean(execution_times),
                    "median_ms": statistics.median(execution_times),
                    "min_ms": min(execution_times),
                    "max_ms": max(execution_times),
                    "stdev_ms": (
                        statistics.stdev(execution_times)
                        if len(execution_times) > 1
                        else 0
                    ),
                },
                "effectiveness_stats": {
                    "mean_score": statistics.mean(effectiveness_scores),
                    "median_score": statistics.median(effectiveness_scores),
                    "min_score": min(effectiveness_scores),
                    "max_score": max(effectiveness_scores),
                },
                "recent_performance": self._get_recent_performance_trend(attack_name),
                "performance_grade": self._calculate_performance_grade(attack_name),
            }

            return summary

        except Exception as e:
            LOG.error(
                f"Failed to get attack performance summary for {attack_name}: {e}"
            )
            return {"error": str(e)}

    async def get_dpi_performance_analysis(self, dpi_type: str) -> Dict[str, Any]:
        """Get performance analysis for attacks against specific DPI type."""

        try:
            dpi_metrics = self.dpi_performance_by_type.get(dpi_type, [])

            if not dpi_metrics:
                return {
                    "dpi_type": dpi_type,
                    "total_attacks": 0,
                    "message": "No performance data available for this DPI type",
                }

            # Group by attack type
            attack_performance = defaultdict(list)
            for metric in dpi_metrics:
                attack_performance[metric.attack_name].append(metric)

            # Calculate performance by attack type
            attack_analysis = {}
            for attack_name, metrics in attack_performance.items():
                success_rate = (
                    sum(1 for m in metrics if m.success) / len(metrics)
                ) * 100
                avg_effectiveness = statistics.mean(
                    m.effectiveness_score for m in metrics
                )
                avg_execution_time = statistics.mean(
                    m.execution_time_ms for m in metrics
                )

                attack_analysis[attack_name] = {
                    "executions": len(metrics),
                    "success_rate_percent": success_rate,
                    "average_effectiveness": avg_effectiveness,
                    "average_execution_time_ms": avg_execution_time,
                }

            # Overall DPI analysis
            total_attacks = len(dpi_metrics)
            overall_success_rate = (
                sum(1 for m in dpi_metrics if m.success) / total_attacks
            ) * 100
            overall_effectiveness = statistics.mean(
                m.effectiveness_score for m in dpi_metrics
            )

            analysis = {
                "dpi_type": dpi_type,
                "total_attacks": total_attacks,
                "overall_success_rate_percent": overall_success_rate,
                "overall_effectiveness": overall_effectiveness,
                "attack_performance": attack_analysis,
                "best_attack": (
                    max(
                        attack_analysis.items(),
                        key=lambda x: x[1]["success_rate_percent"],
                    )[0]
                    if attack_analysis
                    else None
                ),
                "dpi_difficulty_rating": self._calculate_dpi_difficulty(dpi_type),
            }

            return analysis

        except Exception as e:
            LOG.error(f"Failed to get DPI performance analysis for {dpi_type}: {e}")
            return {"error": str(e)}

    async def get_system_health_report(self) -> Dict[str, Any]:
        """Get comprehensive system health report."""

        try:
            current_time = datetime.now()

            # Get recent system metrics
            recent_system_metrics = [
                m
                for m in self.system_metrics_history
                if (current_time - m.timestamp).seconds < 3600
            ]  # Last hour

            if not recent_system_metrics:
                return {"message": "No recent system metrics available"}

            # Calculate system health indicators
            latest_metrics = recent_system_metrics[-1]

            # Performance trends
            execution_time_trend = self._calculate_trend(
                [m.average_execution_time_ms for m in recent_system_metrics]
            )
            effectiveness_trend = self._calculate_trend(
                [m.average_effectiveness_score for m in recent_system_metrics]
            )
            error_rate_trend = self._calculate_trend(
                [m.error_rate_percent for m in recent_system_metrics]
            )

            # System health score
            health_score = self._calculate_system_health_score(latest_metrics)

            # Active alerts
            recent_alerts = [
                alert
                for alert in self.performance_alerts
                if (current_time - alert.timestamp).seconds < 3600
            ]

            health_report = {
                "timestamp": current_time.isoformat(),
                "system_health_score": health_score,
                "health_status": self._get_health_status(health_score),
                "current_metrics": asdict(latest_metrics),
                "performance_trends": {
                    "execution_time_trend": execution_time_trend,
                    "effectiveness_trend": effectiveness_trend,
                    "error_rate_trend": error_rate_trend,
                },
                "active_alerts": len(recent_alerts),
                "alert_summary": self._summarize_alerts(recent_alerts),
                "recommendations": self._generate_health_recommendations(
                    latest_metrics, recent_alerts
                ),
                "uptime_hours": (
                    current_time - self.current_metrics["start_time"]
                ).total_seconds()
                / 3600,
            }

            return health_report

        except Exception as e:
            LOG.error(f"Failed to generate system health report: {e}")
            return {"error": str(e)}

    async def get_performance_alerts(
        self, severity_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get current performance alerts."""

        try:
            alerts = list(self.performance_alerts)

            if severity_filter:
                alerts = [
                    alert for alert in alerts if alert.severity == severity_filter
                ]

            return [asdict(alert) for alert in alerts]

        except Exception as e:
            LOG.error(f"Failed to get performance alerts: {e}")
            return []

    async def export_performance_data(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Export performance data for analysis."""

        try:
            if not start_time:
                start_time = datetime.now() - timedelta(hours=24)
            if not end_time:
                end_time = datetime.now()

            # Filter metrics by time range
            filtered_attack_metrics = [
                asdict(m)
                for m in self.attack_metrics_history
                if start_time <= m.timestamp <= end_time
            ]

            filtered_system_metrics = [
                asdict(m)
                for m in self.system_metrics_history
                if start_time <= m.timestamp <= end_time
            ]

            export_data = {
                "export_timestamp": datetime.now().isoformat(),
                "time_range": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                },
                "attack_metrics": filtered_attack_metrics,
                "system_metrics": filtered_system_metrics,
                "performance_summary": {
                    "total_attacks": len(filtered_attack_metrics),
                    "unique_attack_types": len(
                        set(m["attack_name"] for m in filtered_attack_metrics)
                    ),
                    "unique_dpi_types": len(
                        set(m["dpi_type"] for m in filtered_attack_metrics)
                    ),
                    "overall_success_rate": (
                        (
                            sum(1 for m in filtered_attack_metrics if m["success"])
                            / len(filtered_attack_metrics)
                            * 100
                        )
                        if filtered_attack_metrics
                        else 0
                    ),
                },
            }

            return export_data

        except Exception as e:
            LOG.error(f"Failed to export performance data: {e}")
            return {"error": str(e)}

    # Private helper methods

    async def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil
            import os

            process = psutil.Process(os.getpid())
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            return 0.0
        except Exception:
            return 0.0

    async def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        try:
            import psutil

            return psutil.cpu_percent(interval=0.1)
        except ImportError:
            return 0.0
        except Exception:
            return 0.0

    async def _measure_network_latency(self, target_domain: str) -> float:
        """Measure network latency to target domain."""
        try:
            import socket

            start_time = time.time()
            socket.gethostbyname(target_domain)
            return (time.time() - start_time) * 1000
        except Exception:
            return 0.0

    async def _get_active_connections(self) -> int:
        """Get number of active network connections."""
        try:
            import psutil

            connections = psutil.net_connections()
            return len([c for c in connections if c.status == "ESTABLISHED"])
        except ImportError:
            return 0
        except Exception:
            return 0

    async def _check_performance_alerts(
        self, metrics: AttackPerformanceMetrics
    ) -> None:
        """Check for performance alerts based on attack metrics."""

        try:
            # High execution time alert
            if metrics.execution_time_ms > self.thresholds["max_execution_time_ms"]:
                alert = PerformanceAlert(
                    alert_type="high_latency",
                    severity=(
                        "high"
                        if metrics.execution_time_ms
                        > self.thresholds["max_execution_time_ms"] * 2
                        else "medium"
                    ),
                    message=f"High execution time for {metrics.attack_name}: {metrics.execution_time_ms:.1f}ms",
                    timestamp=datetime.now(),
                    metrics={
                        "execution_time_ms": metrics.execution_time_ms,
                        "attack_name": metrics.attack_name,
                    },
                    threshold_exceeded=metrics.execution_time_ms,
                )
                self.performance_alerts.append(alert)

            # High memory usage alert
            if metrics.memory_usage_mb > self.thresholds["max_memory_usage_mb"]:
                alert = PerformanceAlert(
                    alert_type="high_memory",
                    severity="high",
                    message=f"High memory usage during {metrics.attack_name}: {metrics.memory_usage_mb:.1f}MB",
                    timestamp=datetime.now(),
                    metrics={
                        "memory_usage_mb": metrics.memory_usage_mb,
                        "attack_name": metrics.attack_name,
                    },
                    threshold_exceeded=metrics.memory_usage_mb,
                )
                self.performance_alerts.append(alert)

            # High network latency alert
            if metrics.network_latency_ms > self.thresholds["max_network_latency_ms"]:
                alert = PerformanceAlert(
                    alert_type="high_network_latency",
                    severity="medium",
                    message=f"High network latency to {metrics.target_domain}: {metrics.network_latency_ms:.1f}ms",
                    timestamp=datetime.now(),
                    metrics={
                        "network_latency_ms": metrics.network_latency_ms,
                        "target_domain": metrics.target_domain,
                    },
                    threshold_exceeded=metrics.network_latency_ms,
                )
                self.performance_alerts.append(alert)

        except Exception as e:
            LOG.error(f"Failed to check performance alerts: {e}")

    async def _check_system_alerts(
        self, system_metrics: SystemPerformanceMetrics
    ) -> None:
        """Check for system-level performance alerts."""

        try:
            # Low success rate alert
            success_rate = (
                (
                    system_metrics.successful_attacks
                    / system_metrics.total_attacks_executed
                    * 100
                )
                if system_metrics.total_attacks_executed > 0
                else 100
            )
            if success_rate < self.thresholds["min_success_rate_percent"]:
                alert = PerformanceAlert(
                    alert_type="low_success_rate",
                    severity="high" if success_rate < 50 else "medium",
                    message=f"Low system success rate: {success_rate:.1f}%",
                    timestamp=datetime.now(),
                    metrics={"success_rate_percent": success_rate},
                    threshold_exceeded=self.thresholds["min_success_rate_percent"]
                    - success_rate,
                )
                self.performance_alerts.append(alert)

            # High error rate alert
            if (
                system_metrics.error_rate_percent
                > self.thresholds["max_error_rate_percent"]
            ):
                alert = PerformanceAlert(
                    alert_type="high_error_rate",
                    severity="high",
                    message=f"High system error rate: {system_metrics.error_rate_percent:.1f}%",
                    timestamp=datetime.now(),
                    metrics={"error_rate_percent": system_metrics.error_rate_percent},
                    threshold_exceeded=system_metrics.error_rate_percent,
                )
                self.performance_alerts.append(alert)

        except Exception as e:
            LOG.error(f"Failed to check system alerts: {e}")

    def _get_recent_performance_trend(self, attack_name: str) -> str:
        """Get recent performance trend for an attack."""

        try:
            recent_metrics = [
                m for m in self.attack_performance_by_type[attack_name][-10:]
            ]
            if len(recent_metrics) < 3:
                return "insufficient_data"

            recent_success_rates = []
            for i in range(len(recent_metrics) - 2):
                batch = recent_metrics[i : i + 3]
                success_rate = sum(1 for m in batch if m.success) / len(batch)
                recent_success_rates.append(success_rate)

            if len(recent_success_rates) < 2:
                return "stable"

            trend = recent_success_rates[-1] - recent_success_rates[0]
            if trend > 0.1:
                return "improving"
            elif trend < -0.1:
                return "declining"
            else:
                return "stable"

        except Exception:
            return "unknown"

    def _calculate_performance_grade(self, attack_name: str) -> str:
        """Calculate performance grade for an attack."""

        try:
            metrics = self.attack_performance_by_type[attack_name]
            if not metrics:
                return "N/A"

            success_rate = sum(1 for m in metrics if m.success) / len(metrics)
            avg_effectiveness = statistics.mean(m.effectiveness_score for m in metrics)
            avg_execution_time = statistics.mean(m.execution_time_ms for m in metrics)

            # Calculate grade based on multiple factors
            grade_score = 0

            # Success rate (40% weight)
            if success_rate >= 0.9:
                grade_score += 40
            elif success_rate >= 0.8:
                grade_score += 35
            elif success_rate >= 0.7:
                grade_score += 30
            elif success_rate >= 0.6:
                grade_score += 25
            else:
                grade_score += 20

            # Effectiveness (30% weight)
            if avg_effectiveness >= 0.8:
                grade_score += 30
            elif avg_effectiveness >= 0.6:
                grade_score += 25
            elif avg_effectiveness >= 0.4:
                grade_score += 20
            else:
                grade_score += 15

            # Execution time (30% weight)
            if avg_execution_time <= 1000:
                grade_score += 30
            elif avg_execution_time <= 2000:
                grade_score += 25
            elif avg_execution_time <= 3000:
                grade_score += 20
            else:
                grade_score += 15

            # Convert to letter grade
            if grade_score >= 90:
                return "A"
            elif grade_score >= 80:
                return "B"
            elif grade_score >= 70:
                return "C"
            elif grade_score >= 60:
                return "D"
            else:
                return "F"

        except Exception:
            return "N/A"

    def _calculate_dpi_difficulty(self, dpi_type: str) -> str:
        """Calculate difficulty rating for DPI type."""

        try:
            metrics = self.dpi_performance_by_type[dpi_type]
            if not metrics:
                return "unknown"

            success_rate = sum(1 for m in metrics if m.success) / len(metrics)
            avg_execution_time = statistics.mean(m.execution_time_ms for m in metrics)

            # Calculate difficulty based on success rate and execution time
            if success_rate >= 0.8 and avg_execution_time <= 2000:
                return "easy"
            elif success_rate >= 0.6 and avg_execution_time <= 3000:
                return "medium"
            elif success_rate >= 0.4:
                return "hard"
            else:
                return "very_hard"

        except Exception:
            return "unknown"

    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction from a list of values."""

        if len(values) < 3:
            return "stable"

        try:
            # Simple linear trend calculation
            recent_avg = statistics.mean(values[-3:])
            older_avg = statistics.mean(values[:3])

            change_percent = (
                ((recent_avg - older_avg) / older_avg) * 100 if older_avg != 0 else 0
            )

            if change_percent > 10:
                return "increasing"
            elif change_percent < -10:
                return "decreasing"
            else:
                return "stable"

        except Exception:
            return "stable"

    def _calculate_system_health_score(
        self, metrics: SystemPerformanceMetrics
    ) -> float:
        """Calculate overall system health score (0-100)."""

        try:
            score = 100.0

            # Success rate impact (40% weight)
            success_rate = (
                (metrics.successful_attacks / metrics.total_attacks_executed * 100)
                if metrics.total_attacks_executed > 0
                else 100
            )
            if success_rate < 90:
                score -= (90 - success_rate) * 0.4

            # Error rate impact (30% weight)
            if metrics.error_rate_percent > 10:
                score -= (metrics.error_rate_percent - 10) * 0.3

            # Performance impact (20% weight)
            if metrics.average_execution_time_ms > 2000:
                score -= ((metrics.average_execution_time_ms - 2000) / 1000) * 20

            # Resource usage impact (10% weight)
            if metrics.cpu_usage_percent > 80:
                score -= (metrics.cpu_usage_percent - 80) * 0.1

            return max(0.0, min(100.0, score))

        except Exception:
            return 50.0  # Default neutral score

    def _get_health_status(self, health_score: float) -> str:
        """Get health status based on health score."""

        if health_score >= 90:
            return "excellent"
        elif health_score >= 80:
            return "good"
        elif health_score >= 70:
            return "fair"
        elif health_score >= 60:
            return "poor"
        else:
            return "critical"

    def _summarize_alerts(self, alerts: List[PerformanceAlert]) -> Dict[str, int]:
        """Summarize alerts by type and severity."""

        summary = {"by_type": defaultdict(int), "by_severity": defaultdict(int)}

        for alert in alerts:
            summary["by_type"][alert.alert_type] += 1
            summary["by_severity"][alert.severity] += 1

        return dict(summary)

    def _generate_health_recommendations(
        self, metrics: SystemPerformanceMetrics, alerts: List[PerformanceAlert]
    ) -> List[str]:
        """Generate health recommendations based on metrics and alerts."""

        recommendations = []

        try:
            # Success rate recommendations
            success_rate = (
                (metrics.successful_attacks / metrics.total_attacks_executed * 100)
                if metrics.total_attacks_executed > 0
                else 100
            )
            if success_rate < 70:
                recommendations.append(
                    "Consider reviewing attack configurations and target compatibility"
                )

            # Performance recommendations
            if metrics.average_execution_time_ms > 3000:
                recommendations.append(
                    "Optimize attack execution performance or increase timeout thresholds"
                )

            # Error rate recommendations
            if metrics.error_rate_percent > 20:
                recommendations.append("Investigate and fix recurring attack failures")

            # Resource usage recommendations
            if metrics.cpu_usage_percent > 80:
                recommendations.append(
                    "Consider reducing concurrent attack execution or optimizing CPU usage"
                )

            if metrics.total_memory_usage_mb > 400:
                recommendations.append(
                    "Monitor memory usage and consider implementing memory optimization"
                )

            # Alert-based recommendations
            alert_types = [alert.alert_type for alert in alerts]
            if "high_latency" in alert_types:
                recommendations.append(
                    "Check network connectivity and target responsiveness"
                )

            if "low_success_rate" in alert_types:
                recommendations.append(
                    "Review attack selection algorithms and DPI detection accuracy"
                )

            if not recommendations:
                recommendations.append(
                    "System performance is within acceptable parameters"
                )

        except Exception as e:
            recommendations.append(f"Unable to generate recommendations: {e}")

        return recommendations


# Global performance monitor instance
_performance_monitor = None


def get_performance_monitor() -> AdvancedPerformanceMonitor:
    """Get the global performance monitor instance."""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = AdvancedPerformanceMonitor()
    return _performance_monitor


async def initialize_performance_monitoring() -> bool:
    """Initialize the performance monitoring system."""
    try:
        monitor = get_performance_monitor()
        LOG.info("Advanced performance monitoring initialized successfully")
        return True
    except Exception as e:
        LOG.error(f"Failed to initialize performance monitoring: {e}")
        return False
