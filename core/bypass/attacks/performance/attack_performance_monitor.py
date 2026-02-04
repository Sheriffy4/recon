"""
Attack Performance Monitor for tracking and analyzing attack execution metrics.

This module provides comprehensive performance monitoring for DPI bypass attacks:
- Execution time tracking with microsecond precision
- Throughput measurement (packets/second)
- Memory usage monitoring
- Performance report generation
- Metrics export in multiple formats
"""

import logging
import time
import psutil
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass
class AttackExecutionMetrics:
    """Metrics for a single attack execution."""

    attack_name: str
    execution_time_ms: float
    memory_used_mb: float
    timestamp: str
    success: bool
    payload_size: int
    segments_generated: int
    error_message: Optional[str] = None


@dataclass
class AttackPerformanceStats:
    """Aggregated performance statistics for an attack type."""

    attack_name: str
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    total_execution_time_ms: float = 0.0
    min_execution_time_ms: float = float("inf")
    max_execution_time_ms: float = 0.0
    avg_execution_time_ms: float = 0.0
    p95_execution_time_ms: float = 0.0
    p99_execution_time_ms: float = 0.0
    total_memory_used_mb: float = 0.0
    avg_memory_used_mb: float = 0.0
    total_payload_size: int = 0
    total_segments_generated: int = 0
    throughput_pps: float = 0.0  # packets per second
    success_rate: float = 0.0
    execution_times: List[float] = field(default_factory=list)


class AttackPerformanceMonitor:
    """
    Monitor and track performance metrics for DPI bypass attacks.

    Features:
    - Execution time tracking with microsecond precision
    - Throughput measurement (packets/second)
    - Memory usage monitoring
    - Performance report generation
    - Metrics export to JSON/CSV
    - Real-time statistics aggregation
    """

    def __init__(self, enable_memory_tracking: bool = True):
        """
        Initialize the performance monitor.

        Args:
            enable_memory_tracking: Enable memory usage tracking (may have overhead)
        """
        self.enable_memory_tracking = enable_memory_tracking
        self._metrics: List[AttackExecutionMetrics] = []
        self._stats: Dict[str, AttackPerformanceStats] = defaultdict(
            lambda: AttackPerformanceStats(attack_name="")
        )
        self._start_time = time.time()
        self._process = psutil.Process() if enable_memory_tracking else None

        logger.info(
            f"AttackPerformanceMonitor initialized (memory_tracking={enable_memory_tracking})"
        )

    def record_execution(
        self,
        attack_name: str,
        execution_time_ms: float,
        success: bool,
        payload_size: int,
        segments_generated: int,
        error_message: Optional[str] = None,
    ) -> None:
        """
        Record metrics for a single attack execution.

        Args:
            attack_name: Name of the attack
            execution_time_ms: Execution time in milliseconds
            success: Whether the attack succeeded
            payload_size: Size of the payload in bytes
            segments_generated: Number of segments generated
            error_message: Error message if failed
        """
        # Measure memory usage
        memory_used_mb = 0.0
        if self.enable_memory_tracking and self._process:
            try:
                memory_info = self._process.memory_info()
                memory_used_mb = memory_info.rss / (1024 * 1024)  # Convert to MB
            except Exception as e:
                logger.debug(f"Failed to get memory info: {e}")

        # Create metrics record
        metrics = AttackExecutionMetrics(
            attack_name=attack_name,
            execution_time_ms=execution_time_ms,
            memory_used_mb=memory_used_mb,
            timestamp=datetime.now().isoformat(),
            success=success,
            payload_size=payload_size,
            segments_generated=segments_generated,
            error_message=error_message,
        )

        self._metrics.append(metrics)
        self._update_stats(metrics)

        logger.debug(
            f"Recorded execution: {attack_name} - {execution_time_ms:.2f}ms, "
            f"success={success}, segments={segments_generated}"
        )

    def _update_stats(self, metrics: AttackExecutionMetrics) -> None:
        """Update aggregated statistics with new metrics."""
        stats = self._stats[metrics.attack_name]

        # Initialize attack name if first execution
        if stats.attack_name == "":
            stats.attack_name = metrics.attack_name

        # Update counters
        stats.total_executions += 1
        if metrics.success:
            stats.successful_executions += 1
        else:
            stats.failed_executions += 1

        # Update execution time stats
        stats.total_execution_time_ms += metrics.execution_time_ms
        stats.min_execution_time_ms = min(stats.min_execution_time_ms, metrics.execution_time_ms)
        stats.max_execution_time_ms = max(stats.max_execution_time_ms, metrics.execution_time_ms)
        stats.execution_times.append(metrics.execution_time_ms)
        stats.avg_execution_time_ms = stats.total_execution_time_ms / stats.total_executions

        # Calculate percentiles
        if len(stats.execution_times) > 0:
            sorted_times = sorted(stats.execution_times)
            p95_idx = int(len(sorted_times) * 0.95)
            p99_idx = int(len(sorted_times) * 0.99)
            stats.p95_execution_time_ms = (
                sorted_times[p95_idx] if p95_idx < len(sorted_times) else sorted_times[-1]
            )
            stats.p99_execution_time_ms = (
                sorted_times[p99_idx] if p99_idx < len(sorted_times) else sorted_times[-1]
            )

        # Update memory stats
        stats.total_memory_used_mb += metrics.memory_used_mb
        stats.avg_memory_used_mb = stats.total_memory_used_mb / stats.total_executions

        # Update payload and segment stats
        stats.total_payload_size += metrics.payload_size
        stats.total_segments_generated += metrics.segments_generated

        # Calculate throughput (packets per second)
        elapsed_time = time.time() - self._start_time
        if elapsed_time > 0:
            stats.throughput_pps = stats.total_segments_generated / elapsed_time

        # Calculate success rate
        stats.success_rate = stats.successful_executions / stats.total_executions * 100

    def get_attack_stats(self, attack_name: str) -> Optional[AttackPerformanceStats]:
        """
        Get performance statistics for a specific attack.

        Args:
            attack_name: Name of the attack

        Returns:
            Performance statistics or None if not found
        """
        return self._stats.get(attack_name)

    def get_all_stats(self) -> Dict[str, AttackPerformanceStats]:
        """
        Get performance statistics for all attacks.

        Returns:
            Dictionary mapping attack names to their statistics
        """
        return dict(self._stats)

    def get_performance_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive performance report.

        Returns:
            Dictionary containing performance report data
        """
        total_executions = sum(s.total_executions for s in self._stats.values())
        total_successful = sum(s.successful_executions for s in self._stats.values())
        total_failed = sum(s.failed_executions for s in self._stats.values())

        elapsed_time = time.time() - self._start_time
        overall_throughput = (
            sum(s.total_segments_generated for s in self._stats.values()) / elapsed_time
            if elapsed_time > 0
            else 0
        )

        report = {
            "summary": {
                "total_executions": total_executions,
                "successful_executions": total_successful,
                "failed_executions": total_failed,
                "overall_success_rate": (
                    total_successful / total_executions * 100 if total_executions > 0 else 0
                ),
                "overall_throughput_pps": overall_throughput,
                "monitoring_duration_seconds": elapsed_time,
                "unique_attacks": len(self._stats),
                "memory_tracking_enabled": self.enable_memory_tracking,
            },
            "by_attack": {},
            "top_performers": {
                "fastest_avg": [],
                "highest_throughput": [],
                "most_reliable": [],
            },
            "performance_issues": [],
            "timestamp": datetime.now().isoformat(),
        }

        # Add per-attack statistics
        for attack_name, stats in self._stats.items():
            report["by_attack"][attack_name] = {
                "total_executions": stats.total_executions,
                "success_rate": stats.success_rate,
                "avg_execution_time_ms": stats.avg_execution_time_ms,
                "min_execution_time_ms": stats.min_execution_time_ms,
                "max_execution_time_ms": stats.max_execution_time_ms,
                "p95_execution_time_ms": stats.p95_execution_time_ms,
                "p99_execution_time_ms": stats.p99_execution_time_ms,
                "throughput_pps": stats.throughput_pps,
                "avg_memory_used_mb": stats.avg_memory_used_mb,
                "total_segments_generated": stats.total_segments_generated,
            }

        # Identify top performers
        if self._stats:
            # Fastest average execution time
            fastest = sorted(self._stats.values(), key=lambda s: s.avg_execution_time_ms)[:5]
            report["top_performers"]["fastest_avg"] = [
                {"attack": s.attack_name, "avg_time_ms": s.avg_execution_time_ms} for s in fastest
            ]

            # Highest throughput
            highest_throughput = sorted(
                self._stats.values(), key=lambda s: s.throughput_pps, reverse=True
            )[:5]
            report["top_performers"]["highest_throughput"] = [
                {"attack": s.attack_name, "throughput_pps": s.throughput_pps}
                for s in highest_throughput
            ]

            # Most reliable (highest success rate)
            most_reliable = sorted(
                self._stats.values(), key=lambda s: s.success_rate, reverse=True
            )[:5]
            report["top_performers"]["most_reliable"] = [
                {"attack": s.attack_name, "success_rate": s.success_rate} for s in most_reliable
            ]

        # Identify performance issues
        for attack_name, stats in self._stats.items():
            # Check if p95 exceeds 100ms target
            if stats.p95_execution_time_ms > 100:
                report["performance_issues"].append(
                    {
                        "attack": attack_name,
                        "issue": "p95_latency_high",
                        "value": stats.p95_execution_time_ms,
                        "threshold": 100,
                        "message": f"P95 latency ({stats.p95_execution_time_ms:.2f}ms) exceeds 100ms target",
                    }
                )

            # Check if success rate is below 95%
            if stats.success_rate < 95 and stats.total_executions >= 10:
                report["performance_issues"].append(
                    {
                        "attack": attack_name,
                        "issue": "low_success_rate",
                        "value": stats.success_rate,
                        "threshold": 95,
                        "message": f"Success rate ({stats.success_rate:.1f}%) is below 95%",
                    }
                )

            # Check if throughput is below 1000 pps
            if stats.throughput_pps < 1000 and stats.total_executions >= 100:
                report["performance_issues"].append(
                    {
                        "attack": attack_name,
                        "issue": "low_throughput",
                        "value": stats.throughput_pps,
                        "threshold": 1000,
                        "message": f"Throughput ({stats.throughput_pps:.0f} pps) is below 1000 pps target",
                    }
                )

        return report

    def export_metrics_json(self, filepath: str) -> None:
        """
        Export all metrics to a JSON file.

        Args:
            filepath: Path to the output JSON file
        """
        data = {
            "metrics": [asdict(m) for m in self._metrics],
            "stats": {name: asdict(stats) for name, stats in self._stats.items()},
            "report": self.get_performance_report(),
        }

        output_path = Path(filepath)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported metrics to {filepath}")

    def export_metrics_csv(self, filepath: str) -> None:
        """
        Export metrics to a CSV file.

        Args:
            filepath: Path to the output CSV file
        """
        import csv

        output_path = Path(filepath)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", newline="") as f:
            if not self._metrics:
                return

            fieldnames = list(asdict(self._metrics[0]).keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            writer.writeheader()
            for metrics in self._metrics:
                writer.writerow(asdict(metrics))

        logger.info(f"Exported metrics to {filepath}")

    def reset(self) -> None:
        """Reset all metrics and statistics."""
        self._metrics.clear()
        self._stats.clear()
        self._start_time = time.time()
        logger.info("Performance monitor reset")

    def print_summary(self) -> None:
        """Print a summary of performance metrics to the console."""
        report = self.get_performance_report()
        summary = report["summary"]

        print("\n" + "=" * 60)
        print("ATTACK PERFORMANCE SUMMARY")
        print("=" * 60)
        print(f"Total Executions: {summary['total_executions']}")
        print(f"Success Rate: {summary['overall_success_rate']:.1f}%")
        print(f"Overall Throughput: {summary['overall_throughput_pps']:.0f} pps")
        print(f"Monitoring Duration: {summary['monitoring_duration_seconds']:.1f}s")
        print(f"Unique Attacks: {summary['unique_attacks']}")

        if report["top_performers"]["fastest_avg"]:
            print("\nTop 5 Fastest Attacks (avg):")
            for i, perf in enumerate(report["top_performers"]["fastest_avg"], 1):
                print(f"  {i}. {perf['attack']}: {perf['avg_time_ms']:.2f}ms")

        if report["performance_issues"]:
            print(f"\nPerformance Issues Found: {len(report['performance_issues'])}")
            for issue in report["performance_issues"][:5]:
                print(f"  - {issue['attack']}: {issue['message']}")

        print("=" * 60 + "\n")
