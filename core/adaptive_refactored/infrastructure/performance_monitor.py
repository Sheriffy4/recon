"""
Performance Monitor implementation for the refactored Adaptive Engine.

This component provides performance monitoring and profiling capabilities.
"""

import time
import psutil
import logging
import gc
import threading
import tracemalloc
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone
from collections import defaultdict, deque
from ..interfaces import IPerformanceMonitor
from ..config import AnalyticsConfig


logger = logging.getLogger(__name__)


class PerformanceMonitor(IPerformanceMonitor):
    """
    Implementation of performance monitoring and profiling.

    Provides system resource monitoring, operation profiling,
    memory usage optimization, and performance analysis capabilities.
    """

    def __init__(self, config: AnalyticsConfig):
        self.config = config
        self._active_profiles: Dict[str, Dict[str, Any]] = {}
        self._profile_counter = 0
        self._process = psutil.Process()
        self._lock = threading.RLock()

        # Memory optimization tracking
        self._memory_snapshots: deque = deque(maxlen=100)
        self._gc_stats: Dict[str, Any] = defaultdict(int)
        self._memory_alerts: List[Dict[str, Any]] = []

        # Performance baselines
        self._performance_baselines: Dict[str, Dict[str, float]] = {}
        self._operation_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

        # Memory profiling with tracemalloc
        self._tracemalloc_enabled = False
        if config.enable_profiling:
            try:
                tracemalloc.start()
                self._tracemalloc_enabled = True
                logger.info("Memory tracing enabled with tracemalloc")
            except Exception as e:
                logger.warning(f"Failed to enable tracemalloc: {e}")

        if config.enable_profiling:
            logger.info("Performance monitor initialized with profiling enabled")
        else:
            logger.info("Performance monitor initialized with profiling disabled")

        # Start memory monitoring thread
        self._memory_monitor_thread = None
        if config.enable_profiling:
            self._start_memory_monitoring()

    def start_profiling(self, operation: str) -> str:
        """Start profiling an operation and return profile ID."""
        if not self.config.enable_profiling:
            return ""

        self._profile_counter += 1
        profile_id = f"{operation}_{self._profile_counter}_{int(time.time())}"

        profile_data = {
            "operation": operation,
            "start_time": time.time(),
            "start_memory": self._get_memory_usage_mb(),
            "start_cpu_time": self._process.cpu_times(),
            "profile_id": profile_id,
        }

        self._active_profiles[profile_id] = profile_data
        logger.debug(f"Started profiling: {operation} (ID: {profile_id})")

        return profile_id

    def start_operation(self, operation: str) -> str:
        """Start operation timing tracking and return operation ID."""
        return self.start_profiling(operation)

    def end_operation(self, operation_id: str) -> Dict[str, Any]:
        """End operation timing tracking and return performance data."""
        return self.stop_profiling(operation_id)

    def stop_profiling(self, profile_id: str) -> Dict[str, Any]:
        """Stop profiling and return performance data."""
        if not self.config.enable_profiling or profile_id not in self._active_profiles:
            return {}

        profile_data = self._active_profiles.pop(profile_id)

        end_time = time.time()
        end_memory = self._get_memory_usage_mb()
        end_cpu_time = self._process.cpu_times()

        duration = end_time - profile_data["start_time"]
        memory_delta = end_memory - profile_data["start_memory"]

        # Calculate CPU time delta
        start_cpu = profile_data["start_cpu_time"]
        cpu_time_delta = (end_cpu_time.user - start_cpu.user) + (
            end_cpu_time.system - start_cpu.system
        )

        performance_data = {
            "profile_id": profile_id,
            "operation": profile_data["operation"],
            "duration_seconds": duration,
            "memory_delta_mb": memory_delta,
            "cpu_time_seconds": cpu_time_delta,
            "cpu_utilization": (cpu_time_delta / duration) * 100 if duration > 0 else 0,
            "start_time": profile_data["start_time"],
            "end_time": end_time,
            "start_memory_mb": profile_data["start_memory"],
            "end_memory_mb": end_memory,
        }

        # Record in operation history for trend analysis
        with self._lock:
            self._operation_history[profile_data["operation"]].append(
                {
                    "timestamp": end_time,
                    "duration": duration,
                    "memory_delta": memory_delta,
                    "cpu_utilization": performance_data["cpu_utilization"],
                }
            )

        logger.debug(
            f"Stopped profiling: {profile_data['operation']} "
            f"(Duration: {duration:.3f}s, Memory: {memory_delta:+.1f}MB)"
        )

        return performance_data

    def get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage statistics."""
        try:
            memory_info = self._process.memory_info()
            memory_percent = self._process.memory_percent()

            # Get system memory info
            system_memory = psutil.virtual_memory()

            return {
                "rss_mb": memory_info.rss / 1024 / 1024,  # Resident Set Size
                "vms_mb": memory_info.vms / 1024 / 1024,  # Virtual Memory Size
                "percent": memory_percent,
                "available_system_mb": system_memory.available / 1024 / 1024,
                "total_system_mb": system_memory.total / 1024 / 1024,
                "system_percent": system_memory.percent,
            }
        except Exception as e:
            logger.error(f"Failed to get memory usage: {e}")
            return {}

    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        try:
            # Get CPU usage over a short interval
            return self._process.cpu_percent(interval=0.1)
        except Exception as e:
            logger.error(f"Failed to get CPU usage: {e}")
            return 0.0

    def _get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB."""
        try:
            return self._process.memory_info().rss / 1024 / 1024
        except Exception as e:
            logger.error(f"Failed to get memory usage: {e}")
            return 0.0

    def get_system_performance(self) -> Dict[str, Any]:
        """Get comprehensive system performance metrics."""
        try:
            # CPU information
            cpu_count = psutil.cpu_count()
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            cpu_freq = psutil.cpu_freq()

            # Memory information
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()

            # Disk information
            disk_usage = psutil.disk_usage("/")
            disk_io = psutil.disk_io_counters()

            # Network information
            network_io = psutil.net_io_counters()

            # Process-specific information
            process_info = {
                "pid": self._process.pid,
                "cpu_percent": self._process.cpu_percent(),
                "memory_info": self._process.memory_info()._asdict(),
                "memory_percent": self._process.memory_percent(),
                "num_threads": self._process.num_threads(),
                "create_time": self._process.create_time(),
            }

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "cpu": {
                    "count": cpu_count,
                    "percent_per_core": cpu_percent,
                    "percent_total": sum(cpu_percent) / len(cpu_percent),
                    "frequency_mhz": cpu_freq.current if cpu_freq else None,
                },
                "memory": {
                    "total_mb": memory.total / 1024 / 1024,
                    "available_mb": memory.available / 1024 / 1024,
                    "used_mb": memory.used / 1024 / 1024,
                    "percent": memory.percent,
                },
                "swap": {
                    "total_mb": swap.total / 1024 / 1024,
                    "used_mb": swap.used / 1024 / 1024,
                    "percent": swap.percent,
                },
                "disk": {
                    "total_gb": disk_usage.total / 1024 / 1024 / 1024,
                    "used_gb": disk_usage.used / 1024 / 1024 / 1024,
                    "free_gb": disk_usage.free / 1024 / 1024 / 1024,
                    "percent": (disk_usage.used / disk_usage.total) * 100,
                    "io_read_mb": disk_io.read_bytes / 1024 / 1024 if disk_io else 0,
                    "io_write_mb": disk_io.write_bytes / 1024 / 1024 if disk_io else 0,
                },
                "network": {
                    "bytes_sent_mb": network_io.bytes_sent / 1024 / 1024,
                    "bytes_recv_mb": network_io.bytes_recv / 1024 / 1024,
                    "packets_sent": network_io.packets_sent,
                    "packets_recv": network_io.packets_recv,
                },
                "process": process_info,
            }

        except Exception as e:
            logger.error(f"Failed to get system performance metrics: {e}")
            return {"error": str(e)}

    def get_active_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Get information about currently active profiles."""
        active_profiles = {}
        current_time = time.time()

        for profile_id, profile_data in self._active_profiles.items():
            duration = current_time - profile_data["start_time"]
            active_profiles[profile_id] = {
                "operation": profile_data["operation"],
                "duration_so_far": duration,
                "start_time": profile_data["start_time"],
            }

        return active_profiles

    def cleanup_stale_profiles(self, max_age_seconds: int = 3600) -> int:
        """Clean up profiles that have been running too long."""
        current_time = time.time()
        stale_profiles = []

        for profile_id, profile_data in self._active_profiles.items():
            age = current_time - profile_data["start_time"]
            if age > max_age_seconds:
                stale_profiles.append(profile_id)

        for profile_id in stale_profiles:
            del self._active_profiles[profile_id]
            logger.warning(f"Cleaned up stale profile: {profile_id}")

        return len(stale_profiles)

    def get_performance_alerts(self) -> List[Dict[str, Any]]:
        """Get performance alerts based on configured thresholds."""
        alerts = []

        if not self.config.enable_performance_alerts:
            return alerts

        thresholds = self.config.performance_alert_thresholds

        try:
            # Check CPU usage
            cpu_usage = self.get_cpu_usage()
            if cpu_usage > thresholds.get("cpu_usage_percent", 80):
                alerts.append(
                    {
                        "type": "cpu_usage",
                        "severity": "warning",
                        "message": f"High CPU usage: {cpu_usage:.1f}%",
                        "value": cpu_usage,
                        "threshold": thresholds.get("cpu_usage_percent", 80),
                    }
                )

            # Check memory usage
            memory_info = self.get_memory_usage()
            memory_mb = memory_info.get("rss_mb", 0)
            if memory_mb > thresholds.get("memory_usage_mb", 1024):
                alerts.append(
                    {
                        "type": "memory_usage",
                        "severity": "warning",
                        "message": f"High memory usage: {memory_mb:.1f}MB",
                        "value": memory_mb,
                        "threshold": thresholds.get("memory_usage_mb", 1024),
                    }
                )

        except Exception as e:
            logger.error(f"Failed to generate performance alerts: {e}")

        return alerts

    def _start_memory_monitoring(self) -> None:
        """Start background memory monitoring thread."""

        def monitor_memory():
            while self.config.enable_profiling:
                try:
                    memory_info = self.get_memory_usage()
                    with self._lock:
                        self._memory_snapshots.append(
                            {
                                "timestamp": time.time(),
                                "memory_mb": memory_info.get("rss_mb", 0),
                                "memory_percent": memory_info.get("percent", 0),
                            }
                        )

                        # Check for memory leaks (increasing trend)
                        if len(self._memory_snapshots) >= 10:
                            recent_memory = [
                                s["memory_mb"] for s in list(self._memory_snapshots)[-10:]
                            ]
                            if self._detect_memory_leak(recent_memory):
                                self._memory_alerts.append(
                                    {
                                        "type": "memory_leak",
                                        "timestamp": time.time(),
                                        "message": "Potential memory leak detected",
                                        "memory_trend": recent_memory,
                                    }
                                )

                    time.sleep(30)  # Monitor every 30 seconds
                except Exception as e:
                    logger.error(f"Memory monitoring error: {e}")
                    time.sleep(60)  # Wait longer on error

        self._memory_monitor_thread = threading.Thread(target=monitor_memory, daemon=True)
        self._memory_monitor_thread.start()
        logger.info("Memory monitoring thread started")

    def _detect_memory_leak(self, memory_samples: List[float]) -> bool:
        """Detect potential memory leak from memory samples."""
        if len(memory_samples) < 5:
            return False

        # Calculate trend - if memory consistently increases
        increases = 0
        for i in range(1, len(memory_samples)):
            if memory_samples[i] > memory_samples[i - 1]:
                increases += 1

        # If more than 70% of samples show increase, potential leak
        return (increases / (len(memory_samples) - 1)) > 0.7

    def optimize_memory_usage(self) -> Dict[str, Any]:
        """Optimize memory usage and return optimization results."""
        if not self.config.enable_profiling:
            return {"optimization_enabled": False}

        optimization_results = {
            "optimization_enabled": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "before_optimization": {},
            "after_optimization": {},
            "actions_taken": [],
        }

        # Get memory usage before optimization
        before_memory = self.get_memory_usage()
        optimization_results["before_optimization"] = before_memory

        try:
            # Force garbage collection
            gc_before = len(gc.get_objects())
            collected = gc.collect()
            gc_after = len(gc.get_objects())

            optimization_results["actions_taken"].append(
                {
                    "action": "garbage_collection",
                    "objects_before": gc_before,
                    "objects_after": gc_after,
                    "objects_collected": collected,
                }
            )

            # Clear old profile data
            with self._lock:
                old_profiles = []
                current_time = time.time()
                for profile_id, profile_data in list(self._active_profiles.items()):
                    age = current_time - profile_data["start_time"]
                    if age > 3600:  # Remove profiles older than 1 hour
                        old_profiles.append(profile_id)

                for profile_id in old_profiles:
                    del self._active_profiles[profile_id]

                if old_profiles:
                    optimization_results["actions_taken"].append(
                        {"action": "clear_old_profiles", "profiles_cleared": len(old_profiles)}
                    )

            # Clear old memory snapshots beyond limit
            with self._lock:
                snapshots_before = len(self._memory_snapshots)
                # Keep only last 50 snapshots
                while len(self._memory_snapshots) > 50:
                    self._memory_snapshots.popleft()

                snapshots_cleared = snapshots_before - len(self._memory_snapshots)
                if snapshots_cleared > 0:
                    optimization_results["actions_taken"].append(
                        {"action": "clear_memory_snapshots", "snapshots_cleared": snapshots_cleared}
                    )

            # Update GC statistics
            self._gc_stats["optimizations_performed"] += 1
            self._gc_stats["total_objects_collected"] += collected

            # Get memory usage after optimization
            after_memory = self.get_memory_usage()
            optimization_results["after_optimization"] = after_memory

            # Calculate memory saved
            memory_saved = before_memory.get("rss_mb", 0) - after_memory.get("rss_mb", 0)
            optimization_results["memory_saved_mb"] = memory_saved

            logger.info(
                f"Memory optimization completed. Saved: {memory_saved:.2f}MB, "
                f"Objects collected: {collected}"
            )

        except Exception as e:
            logger.error(f"Memory optimization failed: {e}")
            optimization_results["error"] = str(e)

        return optimization_results

    def get_memory_optimization_stats(self) -> Dict[str, Any]:
        """Get memory optimization statistics."""
        with self._lock:
            return {
                "gc_stats": dict(self._gc_stats),
                "memory_alerts": list(self._memory_alerts),
                "memory_snapshots_count": len(self._memory_snapshots),
                "active_profiles_count": len(self._active_profiles),
                "tracemalloc_enabled": self._tracemalloc_enabled,
            }

    def get_memory_trace_top(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top memory allocations using tracemalloc."""
        if not self._tracemalloc_enabled:
            return []

        try:
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics("lineno")

            trace_data = []
            for index, stat in enumerate(top_stats[:limit]):
                trace_data.append(
                    {
                        "rank": index + 1,
                        "filename": (
                            stat.traceback.format()[0] if stat.traceback.format() else "unknown"
                        ),
                        "size_mb": stat.size / 1024 / 1024,
                        "count": stat.count,
                        "average_size_kb": (stat.size / stat.count) / 1024 if stat.count > 0 else 0,
                    }
                )

            return trace_data

        except Exception as e:
            logger.error(f"Failed to get memory trace: {e}")
            return []

    def set_performance_baseline(self, operation: str, baseline_metrics: Dict[str, float]) -> None:
        """Set performance baseline for an operation."""
        with self._lock:
            self._performance_baselines[operation] = baseline_metrics.copy()
            logger.info(f"Performance baseline set for operation: {operation}")

    def compare_with_baseline(
        self, operation: str, current_metrics: Dict[str, float]
    ) -> Dict[str, Any]:
        """Compare current performance with baseline."""
        with self._lock:
            if operation not in self._performance_baselines:
                return {"baseline_available": False}

            baseline = self._performance_baselines[operation]
            comparison = {
                "baseline_available": True,
                "operation": operation,
                "baseline": baseline.copy(),
                "current": current_metrics.copy(),
                "comparison": {},
                "regression_detected": False,
            }

            for metric, baseline_value in baseline.items():
                if metric in current_metrics:
                    current_value = current_metrics[metric]
                    change_percent = ((current_value - baseline_value) / baseline_value) * 100

                    comparison["comparison"][metric] = {
                        "baseline_value": baseline_value,
                        "current_value": current_value,
                        "change_percent": change_percent,
                        "regression": change_percent > 10,  # 10% threshold
                    }

                    if change_percent > 10:
                        comparison["regression_detected"] = True

            return comparison

    def get_performance_trends(self, operation: str, hours: int = 24) -> Dict[str, Any]:
        """Get performance trends for an operation over time."""
        with self._lock:
            if operation not in self._operation_history:
                return {"data_available": False}

            history = list(self._operation_history[operation])
            cutoff_time = time.time() - (hours * 3600)

            # Filter to requested time window
            recent_history = [h for h in history if h.get("timestamp", 0) >= cutoff_time]

            if not recent_history:
                return {"data_available": False}

            # Calculate trends
            durations = [h["duration"] for h in recent_history]
            timestamps = [h["timestamp"] for h in recent_history]

            return {
                "data_available": True,
                "operation": operation,
                "time_window_hours": hours,
                "sample_count": len(recent_history),
                "duration_stats": {
                    "min": min(durations),
                    "max": max(durations),
                    "average": sum(durations) / len(durations),
                    "median": sorted(durations)[len(durations) // 2],
                },
                "time_range": {"start": min(timestamps), "end": max(timestamps)},
                "trend_analysis": self._analyze_trend(durations),
            }

    def _analyze_trend(self, values: List[float]) -> Dict[str, Any]:
        """Analyze trend in performance values."""
        if len(values) < 3:
            return {"trend": "insufficient_data"}

        # Simple linear regression to detect trend
        n = len(values)
        x_values = list(range(n))

        # Calculate slope
        x_mean = sum(x_values) / n
        y_mean = sum(values) / n

        numerator = sum((x_values[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x_values[i] - x_mean) ** 2 for i in range(n))

        if denominator == 0:
            slope = 0
        else:
            slope = numerator / denominator

        # Determine trend
        if abs(slope) < 0.001:
            trend = "stable"
        elif slope > 0:
            trend = "degrading"
        else:
            trend = "improving"

        return {
            "trend": trend,
            "slope": slope,
            "confidence": min(abs(slope) * 1000, 1.0),  # Simple confidence measure
        }
