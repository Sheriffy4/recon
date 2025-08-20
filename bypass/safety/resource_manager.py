# recon/core/bypass/safety/resource_manager.py

"""
Resource management for safe attack execution.
Monitors and limits resource usage during attack execution.
"""

import time
import threading
import psutil
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

from .exceptions import ResourceLimitExceededError

LOG = logging.getLogger("ResourceManager")


@dataclass
class ResourceLimits:
    """Resource limits for attack execution."""

    # Time limits
    max_execution_time_seconds: float = 60.0
    max_total_time_seconds: float = 300.0

    # Memory limits (in MB)
    max_memory_mb: float = 100.0
    max_total_memory_mb: float = 500.0

    # CPU limits
    max_cpu_percent: float = 50.0
    max_cpu_time_seconds: float = 30.0

    # Network limits
    max_packets_per_second: int = 1000
    max_bytes_per_second: int = 1024 * 1024  # 1MB/s
    max_total_packets: int = 10000
    max_total_bytes: int = 10 * 1024 * 1024  # 10MB

    # Concurrency limits
    max_concurrent_attacks: int = 5
    max_attacks_per_minute: int = 100

    # System stability limits
    min_free_memory_mb: float = 100.0
    max_system_cpu_percent: float = 80.0

    def validate(self) -> List[str]:
        """Validate resource limits configuration."""
        errors = []

        if self.max_execution_time_seconds <= 0:
            errors.append("max_execution_time_seconds must be positive")

        if self.max_memory_mb <= 0:
            errors.append("max_memory_mb must be positive")

        if self.max_cpu_percent <= 0 or self.max_cpu_percent > 100:
            errors.append("max_cpu_percent must be between 0 and 100")

        if self.max_concurrent_attacks <= 0:
            errors.append("max_concurrent_attacks must be positive")

        return errors


@dataclass
class ResourceUsage:
    """Current resource usage tracking."""

    # Time tracking
    start_time: datetime = field(default_factory=datetime.now)
    execution_time_seconds: float = 0.0

    # Memory tracking
    memory_mb: float = 0.0
    peak_memory_mb: float = 0.0

    # CPU tracking
    cpu_percent: float = 0.0
    cpu_time_seconds: float = 0.0

    # Network tracking
    packets_sent: int = 0
    bytes_sent: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    # System tracking
    system_memory_mb: float = 0.0
    system_cpu_percent: float = 0.0

    def update_execution_time(self) -> None:
        """Update execution time from start time."""
        self.execution_time_seconds = (datetime.now() - self.start_time).total_seconds()

    def update_rates(self) -> None:
        """Update rate calculations."""
        if self.execution_time_seconds > 0:
            self.packets_per_second = self.packets_sent / self.execution_time_seconds
            self.bytes_per_second = self.bytes_sent / self.execution_time_seconds


class ResourceMonitor:
    """Monitors resource usage for a single attack execution."""

    def __init__(self, attack_id: str, limits: ResourceLimits):
        self.attack_id = attack_id
        self.limits = limits
        self.usage = ResourceUsage()
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._process = psutil.Process()
        self._initial_cpu_times = self._process.cpu_times()

    def start_monitoring(self) -> None:
        """Start resource monitoring."""
        if self._monitoring:
            return

        self._monitoring = True
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name=f"ResourceMonitor-{self.attack_id}",
            daemon=True,
        )
        self._monitor_thread.start()
        LOG.debug(f"Started resource monitoring for attack {self.attack_id}")

    def stop_monitoring(self) -> None:
        """Stop resource monitoring."""
        if not self._monitoring:
            return

        self._monitoring = False
        self._stop_event.set()

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=1.0)

        LOG.debug(f"Stopped resource monitoring for attack {self.attack_id}")

    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        try:
            while not self._stop_event.is_set():
                self._update_usage()
                self._check_limits()
                time.sleep(0.1)  # Monitor every 100ms
        except Exception as e:
            LOG.error(f"Resource monitoring error for {self.attack_id}: {e}")

    def _update_usage(self) -> None:
        """Update current resource usage."""
        try:
            # Update execution time
            self.usage.update_execution_time()

            # Update memory usage
            memory_info = self._process.memory_info()
            self.usage.memory_mb = memory_info.rss / (1024 * 1024)
            self.usage.peak_memory_mb = max(
                self.usage.peak_memory_mb, self.usage.memory_mb
            )

            # Update CPU usage
            self.usage.cpu_percent = self._process.cpu_percent()
            current_cpu_times = self._process.cpu_times()
            self.usage.cpu_time_seconds = (
                current_cpu_times.user - self._initial_cpu_times.user
            ) + (current_cpu_times.system - self._initial_cpu_times.system)

            # Update system usage
            system_memory = psutil.virtual_memory()
            self.usage.system_memory_mb = system_memory.available / (1024 * 1024)
            self.usage.system_cpu_percent = psutil.cpu_percent()

            # Update rates
            self.usage.update_rates()

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            LOG.warning(f"Failed to update resource usage for {self.attack_id}: {e}")

    def _check_limits(self) -> None:
        """Check if any resource limits are exceeded."""
        # Check execution time
        if self.usage.execution_time_seconds > self.limits.max_execution_time_seconds:
            raise ResourceLimitExceededError(
                f"Execution time limit exceeded: {self.usage.execution_time_seconds:.2f}s > {self.limits.max_execution_time_seconds}s",
                "execution_time",
                self.limits.max_execution_time_seconds,
                self.usage.execution_time_seconds,
                self.attack_id,
            )

        # Check memory usage
        if self.usage.memory_mb > self.limits.max_memory_mb:
            raise ResourceLimitExceededError(
                f"Memory limit exceeded: {self.usage.memory_mb:.2f}MB > {self.limits.max_memory_mb}MB",
                "memory",
                self.limits.max_memory_mb,
                self.usage.memory_mb,
                self.attack_id,
            )

        # Check CPU usage
        if self.usage.cpu_percent > self.limits.max_cpu_percent:
            raise ResourceLimitExceededError(
                f"CPU limit exceeded: {self.usage.cpu_percent:.2f}% > {self.limits.max_cpu_percent}%",
                "cpu_percent",
                self.limits.max_cpu_percent,
                self.usage.cpu_percent,
                self.attack_id,
            )

        # Check system stability
        if self.usage.system_memory_mb < self.limits.min_free_memory_mb:
            raise ResourceLimitExceededError(
                f"System memory too low: {self.usage.system_memory_mb:.2f}MB < {self.limits.min_free_memory_mb}MB",
                "system_memory",
                self.limits.min_free_memory_mb,
                self.usage.system_memory_mb,
                self.attack_id,
            )

        if self.usage.system_cpu_percent > self.limits.max_system_cpu_percent:
            raise ResourceLimitExceededError(
                f"System CPU too high: {self.usage.system_cpu_percent:.2f}% > {self.limits.max_system_cpu_percent}%",
                "system_cpu",
                self.limits.max_system_cpu_percent,
                self.usage.system_cpu_percent,
                self.attack_id,
            )

    def record_network_activity(self, packets: int, bytes_sent: int) -> None:
        """Record network activity for rate limiting."""
        self.usage.packets_sent += packets
        self.usage.bytes_sent += bytes_sent
        self.usage.update_rates()

        # Check network limits
        if self.usage.packets_per_second > self.limits.max_packets_per_second:
            raise ResourceLimitExceededError(
                f"Packet rate limit exceeded: {self.usage.packets_per_second:.2f} pps > {self.limits.max_packets_per_second} pps",
                "packet_rate",
                self.limits.max_packets_per_second,
                self.usage.packets_per_second,
                self.attack_id,
            )

        if self.usage.bytes_per_second > self.limits.max_bytes_per_second:
            raise ResourceLimitExceededError(
                f"Bandwidth limit exceeded: {self.usage.bytes_per_second:.2f} Bps > {self.limits.max_bytes_per_second} Bps",
                "bandwidth",
                self.limits.max_bytes_per_second,
                self.usage.bytes_per_second,
                self.attack_id,
            )

    def get_usage_summary(self) -> Dict[str, Any]:
        """Get current usage summary."""
        return {
            "attack_id": self.attack_id,
            "execution_time_seconds": self.usage.execution_time_seconds,
            "memory_mb": self.usage.memory_mb,
            "peak_memory_mb": self.usage.peak_memory_mb,
            "cpu_percent": self.usage.cpu_percent,
            "cpu_time_seconds": self.usage.cpu_time_seconds,
            "packets_sent": self.usage.packets_sent,
            "bytes_sent": self.usage.bytes_sent,
            "packets_per_second": self.usage.packets_per_second,
            "bytes_per_second": self.usage.bytes_per_second,
            "system_memory_mb": self.usage.system_memory_mb,
            "system_cpu_percent": self.usage.system_cpu_percent,
        }


class ResourceManager:
    """Manages resource limits and monitoring for attack execution."""

    def __init__(self, default_limits: Optional[ResourceLimits] = None):
        self.default_limits = default_limits or ResourceLimits()
        self._active_monitors: Dict[str, ResourceMonitor] = {}
        self._attack_history: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        self._rate_limiter = self._create_rate_limiter()

        # Validate default limits
        errors = self.default_limits.validate()
        if errors:
            raise ValueError(f"Invalid default limits: {', '.join(errors)}")

    def _create_rate_limiter(self) -> Dict[str, List[datetime]]:
        """Create rate limiter tracking."""
        return {"attacks_per_minute": []}

    def create_monitor(
        self, attack_id: str, limits: Optional[ResourceLimits] = None
    ) -> ResourceMonitor:
        """Create a resource monitor for an attack."""
        with self._lock:
            # Check concurrent attack limit
            if len(self._active_monitors) >= self.default_limits.max_concurrent_attacks:
                raise ResourceLimitExceededError(
                    f"Too many concurrent attacks: {len(self._active_monitors)} >= {self.default_limits.max_concurrent_attacks}",
                    "concurrent_attacks",
                    self.default_limits.max_concurrent_attacks,
                    len(self._active_monitors),
                    attack_id,
                )

            # Check rate limit
            self._check_rate_limits(attack_id)

            # Create monitor
            monitor_limits = limits or self.default_limits
            monitor = ResourceMonitor(attack_id, monitor_limits)
            self._active_monitors[attack_id] = monitor

            # Record attack start
            self._rate_limiter["attacks_per_minute"].append(datetime.now())
            self._cleanup_rate_limiter()

            LOG.info(f"Created resource monitor for attack {attack_id}")
            return monitor

    def _check_rate_limits(self, attack_id: str) -> None:
        """Check if rate limits allow new attack."""
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)

        # Count attacks in last minute
        recent_attacks = [
            t for t in self._rate_limiter["attacks_per_minute"] if t > minute_ago
        ]

        if len(recent_attacks) >= self.default_limits.max_attacks_per_minute:
            raise ResourceLimitExceededError(
                f"Attack rate limit exceeded: {len(recent_attacks)} attacks/minute >= {self.default_limits.max_attacks_per_minute}",
                "attack_rate",
                self.default_limits.max_attacks_per_minute,
                len(recent_attacks),
                attack_id,
            )

    def _cleanup_rate_limiter(self) -> None:
        """Clean up old rate limiter entries."""
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)

        self._rate_limiter["attacks_per_minute"] = [
            t for t in self._rate_limiter["attacks_per_minute"] if t > minute_ago
        ]

    def remove_monitor(self, attack_id: str) -> Optional[Dict[str, Any]]:
        """Remove and return final usage summary for an attack."""
        with self._lock:
            monitor = self._active_monitors.pop(attack_id, None)
            if not monitor:
                return None

            monitor.stop_monitoring()
            usage_summary = monitor.get_usage_summary()
            self._attack_history.append(usage_summary)

            # Keep only last 1000 attack records
            if len(self._attack_history) > 1000:
                self._attack_history = self._attack_history[-1000:]

            LOG.info(f"Removed resource monitor for attack {attack_id}")
            return usage_summary

    def get_active_monitors(self) -> Dict[str, ResourceMonitor]:
        """Get all active resource monitors."""
        with self._lock:
            return self._active_monitors.copy()

    def get_system_status(self) -> Dict[str, Any]:
        """Get current system resource status."""
        try:
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=0.1)

            return {
                "active_attacks": len(self._active_monitors),
                "max_concurrent_attacks": self.default_limits.max_concurrent_attacks,
                "system_memory": {
                    "total_mb": memory.total / (1024 * 1024),
                    "available_mb": memory.available / (1024 * 1024),
                    "used_percent": memory.percent,
                },
                "system_cpu_percent": cpu_percent,
                "rate_limits": {
                    "attacks_last_minute": len(
                        [
                            t
                            for t in self._rate_limiter["attacks_per_minute"]
                            if t > datetime.now() - timedelta(minutes=1)
                        ]
                    ),
                    "max_attacks_per_minute": self.default_limits.max_attacks_per_minute,
                },
            }
        except Exception as e:
            LOG.error(f"Failed to get system status: {e}")
            return {"error": str(e)}

    def get_attack_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent attack execution history."""
        with self._lock:
            return self._attack_history[-limit:] if self._attack_history else []

    def emergency_stop_all(self) -> int:
        """Emergency stop all active monitors."""
        with self._lock:
            count = len(self._active_monitors)
            for monitor in self._active_monitors.values():
                try:
                    monitor.stop_monitoring()
                except Exception as e:
                    LOG.error(f"Error stopping monitor {monitor.attack_id}: {e}")

            self._active_monitors.clear()
            LOG.warning(f"Emergency stopped {count} active monitors")
            return count

    def update_default_limits(self, new_limits: ResourceLimits) -> None:
        """Update default resource limits."""
        errors = new_limits.validate()
        if errors:
            raise ValueError(f"Invalid limits: {', '.join(errors)}")

        with self._lock:
            self.default_limits = new_limits
            LOG.info("Updated default resource limits")

    def get_usage_statistics(self) -> Dict[str, Any]:
        """Get usage statistics from attack history."""
        with self._lock:
            if not self._attack_history:
                return {"total_attacks": 0}

            # Calculate statistics
            total_attacks = len(self._attack_history)
            avg_execution_time = (
                sum(h["execution_time_seconds"] for h in self._attack_history)
                / total_attacks
            )
            avg_memory = (
                sum(h["peak_memory_mb"] for h in self._attack_history) / total_attacks
            )
            avg_cpu_time = (
                sum(h["cpu_time_seconds"] for h in self._attack_history) / total_attacks
            )

            max_memory = max(h["peak_memory_mb"] for h in self._attack_history)
            max_execution_time = max(
                h["execution_time_seconds"] for h in self._attack_history
            )

            return {
                "total_attacks": total_attacks,
                "averages": {
                    "execution_time_seconds": avg_execution_time,
                    "memory_mb": avg_memory,
                    "cpu_time_seconds": avg_cpu_time,
                },
                "maximums": {
                    "memory_mb": max_memory,
                    "execution_time_seconds": max_execution_time,
                },
            }
