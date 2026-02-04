"""
Attack metrics collection system.

Collects and aggregates metrics for attack execution including
success rates, execution times, and throughput.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, List
from threading import Lock


@dataclass
class AttackMetrics:
    """Metrics for a specific attack type."""

    attack_name: str
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    error_executions: int = 0
    total_execution_time_ms: float = 0.0
    min_execution_time_ms: float = float("inf")
    max_execution_time_ms: float = 0.0
    total_segments_generated: int = 0
    fallback_count: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_executions == 0:
            return 0.0
        return self.successful_executions / self.total_executions

    @property
    def failure_rate(self) -> float:
        """Calculate failure rate."""
        if self.total_executions == 0:
            return 0.0
        return self.failed_executions / self.total_executions

    @property
    def error_rate(self) -> float:
        """Calculate error rate."""
        if self.total_executions == 0:
            return 0.0
        return self.error_executions / self.total_executions

    @property
    def avg_execution_time_ms(self) -> float:
        """Calculate average execution time."""
        if self.total_executions == 0:
            return 0.0
        return self.total_execution_time_ms / self.total_executions

    @property
    def avg_segments_per_execution(self) -> float:
        """Calculate average segments per execution."""
        if self.total_executions == 0:
            return 0.0
        return self.total_segments_generated / self.total_executions

    @property
    def fallback_rate(self) -> float:
        """Calculate fallback rate."""
        if self.total_executions == 0:
            return 0.0
        return self.fallback_count / self.total_executions

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["success_rate"] = self.success_rate
        data["failure_rate"] = self.failure_rate
        data["error_rate"] = self.error_rate
        data["avg_execution_time_ms"] = self.avg_execution_time_ms
        data["avg_segments_per_execution"] = self.avg_segments_per_execution
        data["fallback_rate"] = self.fallback_rate
        return data


@dataclass
class ThroughputMetrics:
    """Throughput metrics over a time window."""

    window_start: datetime
    window_end: datetime
    total_packets: int = 0
    total_bytes: int = 0

    @property
    def duration_seconds(self) -> float:
        """Calculate window duration in seconds."""
        return (self.window_end - self.window_start).total_seconds()

    @property
    def packets_per_second(self) -> float:
        """Calculate packets per second."""
        if self.duration_seconds == 0:
            return 0.0
        return self.total_packets / self.duration_seconds

    @property
    def bytes_per_second(self) -> float:
        """Calculate bytes per second."""
        if self.duration_seconds == 0:
            return 0.0
        return self.total_bytes / self.duration_seconds

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "duration_seconds": self.duration_seconds,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
        }


@dataclass
class MetricsSnapshot:
    """Snapshot of all metrics at a point in time."""

    timestamp: datetime
    attack_metrics: Dict[str, AttackMetrics]
    throughput_metrics: ThroughputMetrics
    global_stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "attack_metrics": {
                name: metrics.to_dict() for name, metrics in self.attack_metrics.items()
            },
            "throughput_metrics": self.throughput_metrics.to_dict(),
            "global_stats": self.global_stats,
        }


class AttackMetricsCollector:
    """
    Collector for attack execution metrics.

    Features:
    - Per-attack metrics tracking
    - Success/failure rate calculation
    - Execution time statistics
    - Throughput measurement
    - Fallback frequency tracking
    - Thread-safe operations
    """

    def __init__(self, throughput_window_seconds: int = 60):
        """
        Initialize metrics collector.

        Args:
            throughput_window_seconds: Time window for throughput calculation
        """
        self._metrics: Dict[str, AttackMetrics] = {}
        self._lock = Lock()
        self._throughput_window = timedelta(seconds=throughput_window_seconds)
        self._throughput_start = datetime.now()
        self._throughput_packets = 0
        self._throughput_bytes = 0

    def record_execution(
        self,
        attack_name: str,
        success: bool,
        execution_time_ms: float,
        segments_generated: int,
        payload_size: int,
        is_fallback: bool = False,
        is_error: bool = False,
    ):
        """
        Record an attack execution.

        Args:
            attack_name: Name of the attack
            success: Whether execution was successful
            execution_time_ms: Execution time in milliseconds
            segments_generated: Number of segments generated
            payload_size: Size of payload in bytes
            is_fallback: Whether this was a fallback execution
            is_error: Whether this was an error
        """
        with self._lock:
            # Get or create metrics for this attack
            if attack_name not in self._metrics:
                self._metrics[attack_name] = AttackMetrics(attack_name=attack_name)

            metrics = self._metrics[attack_name]

            # Update counters
            metrics.total_executions += 1

            if is_error:
                metrics.error_executions += 1
            elif success:
                metrics.successful_executions += 1
            else:
                metrics.failed_executions += 1

            if is_fallback:
                metrics.fallback_count += 1

            # Update timing statistics
            metrics.total_execution_time_ms += execution_time_ms
            metrics.min_execution_time_ms = min(metrics.min_execution_time_ms, execution_time_ms)
            metrics.max_execution_time_ms = max(metrics.max_execution_time_ms, execution_time_ms)

            # Update segment count
            metrics.total_segments_generated += segments_generated

            # Update throughput metrics
            self._throughput_packets += segments_generated
            self._throughput_bytes += payload_size

    def get_attack_metrics(self, attack_name: str) -> Optional[AttackMetrics]:
        """
        Get metrics for a specific attack.

        Args:
            attack_name: Name of the attack

        Returns:
            Attack metrics or None if not found
        """
        with self._lock:
            return self._metrics.get(attack_name)

    def get_all_metrics(self) -> Dict[str, AttackMetrics]:
        """
        Get metrics for all attacks.

        Returns:
            Dictionary of attack metrics
        """
        with self._lock:
            return dict(self._metrics)

    def get_throughput_metrics(self) -> ThroughputMetrics:
        """
        Get current throughput metrics.

        Returns:
            Throughput metrics for current window
        """
        with self._lock:
            now = datetime.now()

            # Reset window if needed
            if now - self._throughput_start > self._throughput_window:
                self._throughput_start = now
                packets = self._throughput_packets
                bytes_count = self._throughput_bytes
                self._throughput_packets = 0
                self._throughput_bytes = 0
            else:
                packets = self._throughput_packets
                bytes_count = self._throughput_bytes

            return ThroughputMetrics(
                window_start=self._throughput_start,
                window_end=now,
                total_packets=packets,
                total_bytes=bytes_count,
            )

    def get_snapshot(self) -> MetricsSnapshot:
        """
        Get a snapshot of all current metrics.

        Returns:
            Metrics snapshot
        """
        with self._lock:
            # Calculate global statistics
            total_executions = sum(m.total_executions for m in self._metrics.values())
            total_successful = sum(m.successful_executions for m in self._metrics.values())
            total_failed = sum(m.failed_executions for m in self._metrics.values())
            total_errors = sum(m.error_executions for m in self._metrics.values())
            total_fallbacks = sum(m.fallback_count for m in self._metrics.values())

            global_stats = {
                "total_executions": total_executions,
                "total_successful": total_successful,
                "total_failed": total_failed,
                "total_errors": total_errors,
                "total_fallbacks": total_fallbacks,
                "global_success_rate": (
                    total_successful / total_executions if total_executions > 0 else 0.0
                ),
                "global_fallback_rate": (
                    total_fallbacks / total_executions if total_executions > 0 else 0.0
                ),
                "unique_attacks": len(self._metrics),
            }

            # Get throughput metrics WITHOUT calling get_throughput_metrics (avoid deadlock)
            now = datetime.now()
            if now - self._throughput_start > self._throughput_window:
                self._throughput_start = now
                packets = self._throughput_packets
                bytes_count = self._throughput_bytes
                self._throughput_packets = 0
                self._throughput_bytes = 0
            else:
                packets = self._throughput_packets
                bytes_count = self._throughput_bytes

            throughput = ThroughputMetrics(
                window_start=self._throughput_start,
                window_end=now,
                total_packets=packets,
                total_bytes=bytes_count,
            )

            return MetricsSnapshot(
                timestamp=datetime.now(),
                attack_metrics=dict(self._metrics),
                throughput_metrics=throughput,
                global_stats=global_stats,
            )

    def get_top_attacks(
        self, by: str = "executions", limit: int = 10
    ) -> List[tuple[str, AttackMetrics]]:
        """
        Get top attacks by a specific metric.

        Args:
            by: Metric to sort by ('executions', 'success_rate', 'avg_time')
            limit: Maximum number of results

        Returns:
            List of (attack_name, metrics) tuples
        """
        with self._lock:
            if by == "executions":
                sorted_attacks = sorted(
                    self._metrics.items(), key=lambda x: x[1].total_executions, reverse=True
                )
            elif by == "success_rate":
                sorted_attacks = sorted(
                    self._metrics.items(), key=lambda x: x[1].success_rate, reverse=True
                )
            elif by == "avg_time":
                sorted_attacks = sorted(
                    self._metrics.items(), key=lambda x: x[1].avg_execution_time_ms
                )
            else:
                sorted_attacks = list(self._metrics.items())

            return sorted_attacks[:limit]

    def reset_metrics(self, attack_name: Optional[str] = None):
        """
        Reset metrics for a specific attack or all attacks.

        Args:
            attack_name: Name of attack to reset, or None for all
        """
        with self._lock:
            if attack_name:
                if attack_name in self._metrics:
                    self._metrics[attack_name] = AttackMetrics(attack_name=attack_name)
            else:
                self._metrics.clear()
                self._throughput_packets = 0
                self._throughput_bytes = 0
                self._throughput_start = datetime.now()
