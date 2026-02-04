"""
Performance Monitor for Adaptive Monitoring System - Task 7.4 Implementation

Provides comprehensive performance monitoring and metrics collection for
detailed analysis of system performance and bottlenecks.
"""

import time
import psutil
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
import json
from pathlib import Path
import asyncio
from contextlib import contextmanager


@dataclass
class SystemMetrics:
    """System-level performance metrics"""

    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_bytes_sent: int
    network_bytes_recv: int
    active_threads: int
    open_files: int


@dataclass
class OperationMetrics:
    """Metrics for a specific operation"""

    operation_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    success: bool = True
    error_message: Optional[str] = None

    # Resource usage
    cpu_usage_percent: Optional[float] = None
    memory_delta_mb: Optional[float] = None
    network_bytes_sent: Optional[int] = None
    network_bytes_recv: Optional[int] = None

    # Custom metrics
    custom_metrics: Dict[str, Any] = field(default_factory=dict)

    # Context information
    domain: Optional[str] = None
    strategy_name: Optional[str] = None
    component: Optional[str] = None


@dataclass
class PerformanceAlert:
    """Performance alert definition"""

    alert_id: str
    alert_type: str
    threshold: float
    current_value: float
    message: str
    timestamp: datetime
    severity: str  # "low", "medium", "high", "critical"


class PerformanceMonitor:
    """
    Comprehensive performance monitoring system for adaptive engine.

    Features:
    - Real-time system metrics collection
    - Operation-level performance tracking
    - Performance alerts and thresholds
    - Historical data analysis
    - Bottleneck identification
    - Resource usage optimization suggestions
    """

    def __init__(
        self,
        collection_interval: float = 1.0,
        history_retention_hours: int = 24,
        enable_alerts: bool = True,
        metrics_file: str = "performance_metrics.json",
    ):

        self.collection_interval = collection_interval
        self.history_retention_hours = history_retention_hours
        self.enable_alerts = enable_alerts
        self.metrics_file = Path(metrics_file)

        # Thread safety
        self._lock = threading.RLock()

        # Metrics storage
        self.system_metrics_history = deque(
            maxlen=int(3600 * history_retention_hours / collection_interval)
        )
        self.operation_metrics = {}
        self.active_operations = {}

        # Performance statistics
        self.stats = {
            "monitoring_start": datetime.now(),
            "total_operations": 0,
            "successful_operations": 0,
            "failed_operations": 0,
            "alerts_triggered": 0,
            "peak_cpu_usage": 0.0,
            "peak_memory_usage": 0.0,
            "average_operation_duration": 0.0,
        }

        # Alert configuration
        self.alert_thresholds = {
            "cpu_usage_percent": 80.0,
            "memory_usage_percent": 85.0,
            "operation_duration_ms": 30000.0,  # 30 seconds
            "error_rate_percent": 10.0,
            "disk_io_mb_per_sec": 100.0,
        }

        self.alerts_history = deque(maxlen=1000)

        # Monitoring control
        self._monitoring_active = False
        self._monitoring_thread = None

        # Performance baselines
        self.baselines = {}

        # Initialize system monitoring
        self._initialize_system_monitoring()

    def _initialize_system_monitoring(self):
        """Initialize system monitoring capabilities"""
        try:
            # Test psutil availability
            psutil.cpu_percent()
            psutil.virtual_memory()
            self._psutil_available = True
        except Exception:
            self._psutil_available = False
            print("Warning: psutil not available, system metrics will be limited")

    def start_monitoring(self):
        """Start continuous system metrics collection"""
        if self._monitoring_active:
            return

        self._monitoring_active = True
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop, daemon=True, name="PerformanceMonitor"
        )
        self._monitoring_thread.start()

        print(f"Performance monitoring started (interval: {self.collection_interval}s)")

    def stop_monitoring(self):
        """Stop continuous system metrics collection"""
        self._monitoring_active = False

        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self._monitoring_thread.join(timeout=5.0)

        print("Performance monitoring stopped")

    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self._monitoring_active:
            try:
                # Collect system metrics
                metrics = self._collect_system_metrics()

                with self._lock:
                    self.system_metrics_history.append(metrics)

                    # Update peak usage statistics
                    self.stats["peak_cpu_usage"] = max(
                        self.stats["peak_cpu_usage"], metrics.cpu_percent
                    )
                    self.stats["peak_memory_usage"] = max(
                        self.stats["peak_memory_usage"], metrics.memory_percent
                    )

                # Check for alerts
                if self.enable_alerts:
                    self._check_system_alerts(metrics)

                # Sleep until next collection
                time.sleep(self.collection_interval)

            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(self.collection_interval)

    def _collect_system_metrics(self) -> SystemMetrics:
        """Collect current system metrics"""
        timestamp = datetime.now()

        if not self._psutil_available:
            # Return minimal metrics if psutil not available
            return SystemMetrics(
                timestamp=timestamp,
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_used_mb=0.0,
                memory_available_mb=0.0,
                disk_io_read_mb=0.0,
                disk_io_write_mb=0.0,
                network_bytes_sent=0,
                network_bytes_recv=0,
                active_threads=threading.active_count(),
                open_files=0,
            )

        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=None)

            # Memory metrics
            memory = psutil.virtual_memory()
            memory_used_mb = memory.used / (1024 * 1024)
            memory_available_mb = memory.available / (1024 * 1024)

            # Disk I/O metrics
            disk_io = psutil.disk_io_counters()
            disk_read_mb = disk_io.read_bytes / (1024 * 1024) if disk_io else 0.0
            disk_write_mb = disk_io.write_bytes / (1024 * 1024) if disk_io else 0.0

            # Network metrics
            network_io = psutil.net_io_counters()
            network_sent = network_io.bytes_sent if network_io else 0
            network_recv = network_io.bytes_recv if network_io else 0

            # Process metrics
            process = psutil.Process()
            open_files = len(process.open_files())

            return SystemMetrics(
                timestamp=timestamp,
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_used_mb=memory_used_mb,
                memory_available_mb=memory_available_mb,
                disk_io_read_mb=disk_read_mb,
                disk_io_write_mb=disk_write_mb,
                network_bytes_sent=network_sent,
                network_bytes_recv=network_recv,
                active_threads=threading.active_count(),
                open_files=open_files,
            )

        except Exception as e:
            print(f"Error collecting system metrics: {e}")
            return SystemMetrics(
                timestamp=timestamp,
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_used_mb=0.0,
                memory_available_mb=0.0,
                disk_io_read_mb=0.0,
                disk_io_write_mb=0.0,
                network_bytes_sent=0,
                network_bytes_recv=0,
                active_threads=threading.active_count(),
                open_files=0,
            )

    def _check_system_alerts(self, metrics: SystemMetrics):
        """Check system metrics against alert thresholds"""
        alerts = []

        # CPU usage alert
        if metrics.cpu_percent > self.alert_thresholds["cpu_usage_percent"]:
            alerts.append(
                PerformanceAlert(
                    alert_id=f"cpu_high_{int(time.time())}",
                    alert_type="cpu_usage",
                    threshold=self.alert_thresholds["cpu_usage_percent"],
                    current_value=metrics.cpu_percent,
                    message=f"High CPU usage: {metrics.cpu_percent:.1f}%",
                    timestamp=metrics.timestamp,
                    severity="high" if metrics.cpu_percent > 90 else "medium",
                )
            )

        # Memory usage alert
        if metrics.memory_percent > self.alert_thresholds["memory_usage_percent"]:
            alerts.append(
                PerformanceAlert(
                    alert_id=f"memory_high_{int(time.time())}",
                    alert_type="memory_usage",
                    threshold=self.alert_thresholds["memory_usage_percent"],
                    current_value=metrics.memory_percent,
                    message=f"High memory usage: {metrics.memory_percent:.1f}%",
                    timestamp=metrics.timestamp,
                    severity="critical" if metrics.memory_percent > 95 else "high",
                )
            )

        # Process alerts
        for alert in alerts:
            with self._lock:
                self.alerts_history.append(alert)
                self.stats["alerts_triggered"] += 1

            print(f"PERFORMANCE ALERT [{alert.severity.upper()}]: {alert.message}")

    @contextmanager
    def track_operation(
        self,
        operation_name: str,
        domain: Optional[str] = None,
        strategy_name: Optional[str] = None,
        component: Optional[str] = None,
    ):
        """Context manager for tracking operation performance"""

        operation_id = f"{operation_name}_{int(time.time() * 1000)}"
        start_time = datetime.now()

        # Collect initial system state
        initial_metrics = self._collect_system_metrics() if self._psutil_available else None

        # Create operation metrics
        op_metrics = OperationMetrics(
            operation_name=operation_name,
            start_time=start_time,
            domain=domain,
            strategy_name=strategy_name,
            component=component,
        )

        with self._lock:
            self.active_operations[operation_id] = op_metrics

        try:
            yield operation_id

        except Exception as e:
            # Mark operation as failed
            op_metrics.success = False
            op_metrics.error_message = str(e)
            raise

        finally:
            # Complete operation tracking
            end_time = datetime.now()
            duration_ms = (end_time - start_time).total_seconds() * 1000

            op_metrics.end_time = end_time
            op_metrics.duration_ms = duration_ms

            # Collect final system state and calculate deltas
            if self._psutil_available and initial_metrics:
                final_metrics = self._collect_system_metrics()
                op_metrics.memory_delta_mb = (
                    final_metrics.memory_used_mb - initial_metrics.memory_used_mb
                )
                op_metrics.network_bytes_sent = (
                    final_metrics.network_bytes_sent - initial_metrics.network_bytes_sent
                )
                op_metrics.network_bytes_recv = (
                    final_metrics.network_bytes_recv - initial_metrics.network_bytes_recv
                )

            # Move to completed operations
            with self._lock:
                if operation_id in self.active_operations:
                    del self.active_operations[operation_id]

                self.operation_metrics[operation_id] = op_metrics

                # Update statistics
                self.stats["total_operations"] += 1
                if op_metrics.success:
                    self.stats["successful_operations"] += 1
                else:
                    self.stats["failed_operations"] += 1

                # Update average duration
                total_ops = self.stats["total_operations"]
                current_avg = self.stats["average_operation_duration"]
                self.stats["average_operation_duration"] = (
                    current_avg * (total_ops - 1) + duration_ms
                ) / total_ops

            # Check for operation-level alerts
            if self.enable_alerts:
                self._check_operation_alerts(op_metrics)

    def _check_operation_alerts(self, op_metrics: OperationMetrics):
        """Check operation metrics against alert thresholds"""

        # Duration alert
        if (
            op_metrics.duration_ms
            and op_metrics.duration_ms > self.alert_thresholds["operation_duration_ms"]
        ):

            alert = PerformanceAlert(
                alert_id=f"slow_operation_{int(time.time())}",
                alert_type="slow_operation",
                threshold=self.alert_thresholds["operation_duration_ms"],
                current_value=op_metrics.duration_ms,
                message=f"Slow operation: {op_metrics.operation_name} took {op_metrics.duration_ms:.0f}ms",
                timestamp=op_metrics.end_time or datetime.now(),
                severity="medium" if op_metrics.duration_ms < 60000 else "high",
            )

            with self._lock:
                self.alerts_history.append(alert)
                self.stats["alerts_triggered"] += 1

            print(f"PERFORMANCE ALERT: {alert.message}")

    def add_custom_metric(self, operation_id: str, metric_name: str, value: Any):
        """Add custom metric to an active operation"""

        with self._lock:
            if operation_id in self.active_operations:
                self.active_operations[operation_id].custom_metrics[metric_name] = value
            elif operation_id in self.operation_metrics:
                self.operation_metrics[operation_id].custom_metrics[metric_name] = value

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary"""

        with self._lock:
            # Calculate error rate
            total_ops = self.stats["total_operations"]
            error_rate = (
                (self.stats["failed_operations"] / total_ops * 100) if total_ops > 0 else 0.0
            )

            # Get recent system metrics
            recent_metrics = (
                list(self.system_metrics_history)[-10:] if self.system_metrics_history else []
            )

            current_cpu = recent_metrics[-1].cpu_percent if recent_metrics else 0.0
            current_memory = recent_metrics[-1].memory_percent if recent_metrics else 0.0

            # Operation statistics by name
            operation_stats = self._calculate_operation_statistics()

            return {
                "monitoring_duration_minutes": (
                    datetime.now() - self.stats["monitoring_start"]
                ).total_seconds()
                / 60,
                "system_metrics": {
                    "current_cpu_percent": current_cpu,
                    "current_memory_percent": current_memory,
                    "peak_cpu_percent": self.stats["peak_cpu_usage"],
                    "peak_memory_percent": self.stats["peak_memory_usage"],
                    "active_threads": threading.active_count(),
                },
                "operation_metrics": {
                    "total_operations": total_ops,
                    "successful_operations": self.stats["successful_operations"],
                    "failed_operations": self.stats["failed_operations"],
                    "success_rate_percent": (
                        (self.stats["successful_operations"] / total_ops * 100)
                        if total_ops > 0
                        else 0.0
                    ),
                    "error_rate_percent": error_rate,
                    "average_duration_ms": self.stats["average_operation_duration"],
                    "active_operations": len(self.active_operations),
                },
                "operation_statistics": operation_stats,
                "alerts": {
                    "total_alerts": self.stats["alerts_triggered"],
                    "recent_alerts": len(
                        [
                            a
                            for a in self.alerts_history
                            if a.timestamp > datetime.now() - timedelta(hours=1)
                        ]
                    ),
                },
            }

    def _calculate_operation_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Calculate statistics grouped by operation name"""

        stats_by_name = defaultdict(
            lambda: {
                "count": 0,
                "successful": 0,
                "failed": 0,
                "total_duration_ms": 0.0,
                "min_duration_ms": float("inf"),
                "max_duration_ms": 0.0,
                "avg_duration_ms": 0.0,
            }
        )

        for op_metrics in self.operation_metrics.values():
            name = op_metrics.operation_name
            stats = stats_by_name[name]

            stats["count"] += 1
            if op_metrics.success:
                stats["successful"] += 1
            else:
                stats["failed"] += 1

            if op_metrics.duration_ms:
                stats["total_duration_ms"] += op_metrics.duration_ms
                stats["min_duration_ms"] = min(stats["min_duration_ms"], op_metrics.duration_ms)
                stats["max_duration_ms"] = max(stats["max_duration_ms"], op_metrics.duration_ms)

        # Calculate averages
        for name, stats in stats_by_name.items():
            if stats["count"] > 0:
                stats["avg_duration_ms"] = stats["total_duration_ms"] / stats["count"]
                stats["success_rate_percent"] = (stats["successful"] / stats["count"]) * 100

        return dict(stats_by_name)

    def get_bottleneck_analysis(self) -> Dict[str, Any]:
        """Analyze performance bottlenecks"""

        analysis = {
            "timestamp": datetime.now().isoformat(),
            "bottlenecks": [],
            "recommendations": [],
        }

        with self._lock:
            # Analyze slow operations
            slow_operations = [
                op
                for op in self.operation_metrics.values()
                if op.duration_ms
                and op.duration_ms > self.alert_thresholds["operation_duration_ms"]
            ]

            if slow_operations:
                analysis["bottlenecks"].append(
                    {
                        "type": "slow_operations",
                        "count": len(slow_operations),
                        "description": f"{len(slow_operations)} operations exceeded duration threshold",
                    }
                )

                analysis["recommendations"].append(
                    "Consider optimizing slow operations or increasing timeout thresholds"
                )

            # Analyze system resource usage
            if self.system_metrics_history:
                recent_metrics = list(self.system_metrics_history)[-60:]  # Last minute
                avg_cpu = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics)
                avg_memory = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)

                if avg_cpu > 70:
                    analysis["bottlenecks"].append(
                        {
                            "type": "high_cpu_usage",
                            "value": avg_cpu,
                            "description": f"Average CPU usage is {avg_cpu:.1f}%",
                        }
                    )
                    analysis["recommendations"].append(
                        "Consider reducing parallel operations or optimizing CPU-intensive tasks"
                    )

                if avg_memory > 80:
                    analysis["bottlenecks"].append(
                        {
                            "type": "high_memory_usage",
                            "value": avg_memory,
                            "description": f"Average memory usage is {avg_memory:.1f}%",
                        }
                    )
                    analysis["recommendations"].append(
                        "Consider implementing memory optimization or increasing available RAM"
                    )

            # Analyze error rates
            total_ops = self.stats["total_operations"]
            if total_ops > 0:
                error_rate = (self.stats["failed_operations"] / total_ops) * 100
                if error_rate > self.alert_thresholds["error_rate_percent"]:
                    analysis["bottlenecks"].append(
                        {
                            "type": "high_error_rate",
                            "value": error_rate,
                            "description": f"Error rate is {error_rate:.1f}%",
                        }
                    )
                    analysis["recommendations"].append(
                        "Investigate failed operations and improve error handling"
                    )

        return analysis

    def export_metrics(self, output_file: Optional[str] = None) -> bool:
        """Export performance metrics to file"""

        if output_file is None:
            output_file = self.metrics_file

        try:
            export_data = {
                "export_timestamp": datetime.now().isoformat(),
                "monitoring_session": {
                    "start_time": self.stats["monitoring_start"].isoformat(),
                    "duration_minutes": (
                        datetime.now() - self.stats["monitoring_start"]
                    ).total_seconds()
                    / 60,
                },
                "performance_summary": self.get_performance_summary(),
                "bottleneck_analysis": self.get_bottleneck_analysis(),
                "recent_alerts": [
                    {
                        "alert_id": alert.alert_id,
                        "alert_type": alert.alert_type,
                        "message": alert.message,
                        "severity": alert.severity,
                        "timestamp": alert.timestamp.isoformat(),
                        "threshold": alert.threshold,
                        "current_value": alert.current_value,
                    }
                    for alert in list(self.alerts_history)[-50:]  # Last 50 alerts
                ],
            }

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)

            print(f"Performance metrics exported to: {output_file}")
            return True

        except Exception as e:
            print(f"Failed to export performance metrics: {e}")
            return False

    def reset_statistics(self):
        """Reset all performance statistics"""

        with self._lock:
            self.stats = {
                "monitoring_start": datetime.now(),
                "total_operations": 0,
                "successful_operations": 0,
                "failed_operations": 0,
                "alerts_triggered": 0,
                "peak_cpu_usage": 0.0,
                "peak_memory_usage": 0.0,
                "average_operation_duration": 0.0,
            }

            self.operation_metrics.clear()
            self.active_operations.clear()
            self.alerts_history.clear()
            self.system_metrics_history.clear()

        print("Performance statistics reset")

    def __del__(self):
        """Cleanup when monitor is destroyed"""
        self.stop_monitoring()


# Global performance monitor instance
_performance_monitor: Optional[PerformanceMonitor] = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get global performance monitor instance"""
    global _performance_monitor

    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
        _performance_monitor.start_monitoring()

    return _performance_monitor


def initialize_performance_monitoring(
    collection_interval: float = 1.0, enable_alerts: bool = True
) -> PerformanceMonitor:
    """Initialize global performance monitoring"""
    global _performance_monitor

    if _performance_monitor is not None:
        _performance_monitor.stop_monitoring()

    _performance_monitor = PerformanceMonitor(
        collection_interval=collection_interval, enable_alerts=enable_alerts
    )
    _performance_monitor.start_monitoring()

    return _performance_monitor
