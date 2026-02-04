"""
Resource Management for runtime packet filtering.

This module provides resource monitoring and management including:
- Memory usage limits and monitoring
- CPU usage tracking and throttling
- Automatic cleanup of old cache entries
- Graceful degradation under resource pressure
"""

import time
import threading
import logging
import psutil
import os
from typing import Dict, Any, Optional, Callable, List
from dataclasses import dataclass
from enum import Enum


logger = logging.getLogger(__name__)


class ResourceState(Enum):
    """Resource usage states for graceful degradation."""

    NORMAL = "normal"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class ResourceLimits:
    """Configuration for resource limits."""

    # Memory limits (in MB)
    memory_warning_mb: float = 200.0
    memory_critical_mb: float = 400.0
    memory_emergency_mb: float = 500.0

    # CPU limits (percentage)
    cpu_warning_percent: float = 70.0
    cpu_critical_percent: float = 85.0
    cpu_emergency_percent: float = 95.0

    # Cache limits
    max_cache_entries: int = 1000
    cache_cleanup_threshold: float = 0.8  # Cleanup when 80% full

    # Monitoring intervals (seconds)
    monitoring_interval: float = 5.0
    cleanup_interval: float = 30.0


class ResourceManager:
    """
    Manages system resources for packet filtering operations.

    This class provides:
    - Real-time resource monitoring
    - Automatic cache cleanup
    - Graceful degradation under pressure
    - Resource usage alerts and throttling
    """

    def __init__(self, limits: Optional[ResourceLimits] = None):
        """
        Initialize Resource Manager.

        Args:
            limits: Resource limits configuration

        Requirements: 6.4
        """
        self.limits = limits or ResourceLimits()
        self.current_state = ResourceState.NORMAL

        # Process monitoring
        self._process = psutil.Process(os.getpid())
        self._monitoring_active = False
        self._monitoring_thread = None

        # Resource statistics
        self._memory_samples = []
        self._cpu_samples = []
        self._max_samples = 100

        # Callbacks for resource events
        self._state_change_callbacks: List[Callable[[ResourceState, ResourceState], None]] = []
        self._cleanup_callbacks: List[Callable[[], None]] = []

        # Throttling state
        self._throttle_active = False
        self._throttle_start_time = None

        # Thread safety
        self._lock = threading.RLock()

        logger.info(
            f"ResourceManager initialized with limits: memory={self.limits.memory_emergency_mb}MB, cpu={self.limits.cpu_emergency_percent}%"
        )

    def start_monitoring(self) -> None:
        """
        Start background resource monitoring.

        Requirements: 6.4
        """
        with self._lock:
            if self._monitoring_active:
                return

            self._monitoring_active = True
            self._monitoring_thread = threading.Thread(
                target=self._monitoring_loop, daemon=True, name="ResourceMonitor"
            )
            self._monitoring_thread.start()

        logger.info("Resource monitoring started")

    def stop_monitoring(self) -> None:
        """Stop background resource monitoring."""
        with self._lock:
            self._monitoring_active = False

        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self._monitoring_thread.join(timeout=1.0)

        logger.info("Resource monitoring stopped")

    def _monitoring_loop(self) -> None:
        """Background monitoring loop."""
        last_cleanup = time.time()

        while self._monitoring_active:
            try:
                # Sample current resource usage
                memory_mb = self._sample_memory()
                cpu_percent = self._sample_cpu()

                # Update resource state
                new_state = self._calculate_resource_state(memory_mb, cpu_percent)
                if new_state != self.current_state:
                    self._change_resource_state(new_state)

                # Perform periodic cleanup
                current_time = time.time()
                if (current_time - last_cleanup) >= self.limits.cleanup_interval:
                    self._perform_cleanup()
                    last_cleanup = current_time

                # Sleep until next monitoring cycle
                time.sleep(self.limits.monitoring_interval)

            except Exception as e:
                logger.error(f"Error in resource monitoring loop: {e}")
                time.sleep(self.limits.monitoring_interval)

    def _sample_memory(self) -> float:
        """
        Sample current memory usage.

        Returns:
            Memory usage in MB
        """
        try:
            memory_info = self._process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)

            with self._lock:
                self._memory_samples.append(memory_mb)
                if len(self._memory_samples) > self._max_samples:
                    self._memory_samples.pop(0)

            return memory_mb

        except Exception as e:
            logger.warning(f"Error sampling memory: {e}")
            return 0.0

    def _sample_cpu(self) -> float:
        """
        Sample current CPU usage.

        Returns:
            CPU usage percentage
        """
        try:
            # Get CPU usage over a short interval
            cpu_percent = self._process.cpu_percent(interval=0.1)

            with self._lock:
                self._cpu_samples.append(cpu_percent)
                if len(self._cpu_samples) > self._max_samples:
                    self._cpu_samples.pop(0)

            return cpu_percent

        except Exception as e:
            logger.warning(f"Error sampling CPU: {e}")
            return 0.0

    def _calculate_resource_state(self, memory_mb: float, cpu_percent: float) -> ResourceState:
        """
        Calculate current resource state based on usage.

        Args:
            memory_mb: Current memory usage in MB
            cpu_percent: Current CPU usage percentage

        Returns:
            Current resource state
        """
        # Check emergency conditions first
        if (
            memory_mb >= self.limits.memory_emergency_mb
            or cpu_percent >= self.limits.cpu_emergency_percent
        ):
            return ResourceState.EMERGENCY

        # Check critical conditions
        if (
            memory_mb >= self.limits.memory_critical_mb
            or cpu_percent >= self.limits.cpu_critical_percent
        ):
            return ResourceState.CRITICAL

        # Check warning conditions
        if (
            memory_mb >= self.limits.memory_warning_mb
            or cpu_percent >= self.limits.cpu_warning_percent
        ):
            return ResourceState.WARNING

        return ResourceState.NORMAL

    def _change_resource_state(self, new_state: ResourceState) -> None:
        """
        Change resource state and trigger appropriate actions.

        Args:
            new_state: New resource state
        """
        old_state = self.current_state
        self.current_state = new_state

        logger.info(f"Resource state changed: {old_state.value} -> {new_state.value}")

        # Trigger state-specific actions
        if new_state == ResourceState.EMERGENCY:
            self._handle_emergency_state()
        elif new_state == ResourceState.CRITICAL:
            self._handle_critical_state()
        elif new_state == ResourceState.WARNING:
            self._handle_warning_state()
        else:
            self._handle_normal_state()

        # Notify callbacks
        for callback in self._state_change_callbacks:
            try:
                callback(old_state, new_state)
            except Exception as e:
                logger.error(f"Error in state change callback: {e}")

    def _handle_emergency_state(self) -> None:
        """Handle emergency resource state."""
        logger.warning("EMERGENCY: Severe resource pressure detected")

        # Aggressive cleanup
        self._perform_aggressive_cleanup()

        # Enable throttling
        self._enable_throttling()

        # Force garbage collection
        import gc

        gc.collect()

    def _handle_critical_state(self) -> None:
        """Handle critical resource state."""
        logger.warning("CRITICAL: High resource usage detected")

        # Perform cleanup
        self._perform_cleanup()

        # Enable throttling if not already active
        if not self._throttle_active:
            self._enable_throttling()

    def _handle_warning_state(self) -> None:
        """Handle warning resource state."""
        logger.info("WARNING: Elevated resource usage detected")

        # Perform light cleanup
        self._perform_cleanup()

    def _handle_normal_state(self) -> None:
        """Handle normal resource state."""
        # Disable throttling if active
        if self._throttle_active:
            self._disable_throttling()

    def _perform_cleanup(self) -> None:
        """Perform standard resource cleanup."""
        logger.debug("Performing resource cleanup")

        # Trigger cleanup callbacks
        for callback in self._cleanup_callbacks:
            try:
                callback()
            except Exception as e:
                logger.error(f"Error in cleanup callback: {e}")

    def _perform_aggressive_cleanup(self) -> None:
        """Perform aggressive resource cleanup."""
        logger.warning("Performing aggressive resource cleanup")

        # Clear all samples to free memory
        with self._lock:
            self._memory_samples.clear()
            self._cpu_samples.clear()

        # Trigger cleanup callbacks
        self._perform_cleanup()

    def _enable_throttling(self) -> None:
        """Enable processing throttling."""
        if not self._throttle_active:
            self._throttle_active = True
            self._throttle_start_time = time.time()
            logger.warning("Processing throttling enabled")

    def _disable_throttling(self) -> None:
        """Disable processing throttling."""
        if self._throttle_active:
            self._throttle_active = False
            throttle_duration = time.time() - (self._throttle_start_time or 0)
            logger.info(f"Processing throttling disabled after {throttle_duration:.1f}s")

    def should_throttle_processing(self) -> bool:
        """
        Check if processing should be throttled.

        Returns:
            True if processing should be throttled

        Requirements: 6.4
        """
        return self._throttle_active

    def get_throttle_delay(self) -> float:
        """
        Get recommended delay for throttling.

        Returns:
            Delay in seconds (0.0 if no throttling)
        """
        if not self._throttle_active:
            return 0.0

        # Increase delay based on resource state
        if self.current_state == ResourceState.EMERGENCY:
            return 0.1  # 100ms delay
        elif self.current_state == ResourceState.CRITICAL:
            return 0.05  # 50ms delay
        else:
            return 0.01  # 10ms delay

    def check_memory_limit(self, current_usage_mb: float) -> bool:
        """
        Check if memory usage is within limits.

        Args:
            current_usage_mb: Current memory usage in MB

        Returns:
            True if within limits, False if exceeded

        Requirements: 6.4
        """
        return current_usage_mb < self.limits.memory_emergency_mb

    def get_cache_size_limit(self) -> int:
        """
        Get recommended cache size limit based on resource state.

        Returns:
            Maximum recommended cache entries

        Requirements: 6.4
        """
        base_limit = self.limits.max_cache_entries

        if self.current_state == ResourceState.EMERGENCY:
            return int(base_limit * 0.1)  # 10% of normal
        elif self.current_state == ResourceState.CRITICAL:
            return int(base_limit * 0.3)  # 30% of normal
        elif self.current_state == ResourceState.WARNING:
            return int(base_limit * 0.7)  # 70% of normal
        else:
            return base_limit

    def add_state_change_callback(
        self, callback: Callable[[ResourceState, ResourceState], None]
    ) -> None:
        """
        Add callback for resource state changes.

        Args:
            callback: Function to call when state changes
        """
        self._state_change_callbacks.append(callback)

    def add_cleanup_callback(self, callback: Callable[[], None]) -> None:
        """
        Add callback for resource cleanup events.

        Args:
            callback: Function to call during cleanup
        """
        self._cleanup_callbacks.append(callback)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get resource usage statistics.

        Returns:
            Dictionary with resource statistics

        Requirements: 6.4
        """
        with self._lock:
            memory_stats = self._calculate_memory_stats()
            cpu_stats = self._calculate_cpu_stats()

        return {
            "current_state": self.current_state.value,
            "throttling_active": self._throttle_active,
            "memory": memory_stats,
            "cpu": cpu_stats,
            "limits": {
                "memory_warning_mb": self.limits.memory_warning_mb,
                "memory_critical_mb": self.limits.memory_critical_mb,
                "memory_emergency_mb": self.limits.memory_emergency_mb,
                "cpu_warning_percent": self.limits.cpu_warning_percent,
                "cpu_critical_percent": self.limits.cpu_critical_percent,
                "cpu_emergency_percent": self.limits.cpu_emergency_percent,
                "max_cache_entries": self.limits.max_cache_entries,
            },
            "recommended_cache_limit": self.get_cache_size_limit(),
        }

    def _calculate_memory_stats(self) -> Dict[str, float]:
        """Calculate memory usage statistics."""
        if not self._memory_samples:
            return {"current_mb": 0.0, "avg_mb": 0.0, "max_mb": 0.0, "min_mb": 0.0}

        return {
            "current_mb": self._memory_samples[-1] if self._memory_samples else 0.0,
            "avg_mb": sum(self._memory_samples) / len(self._memory_samples),
            "max_mb": max(self._memory_samples),
            "min_mb": min(self._memory_samples),
        }

    def _calculate_cpu_stats(self) -> Dict[str, float]:
        """Calculate CPU usage statistics."""
        if not self._cpu_samples:
            return {
                "current_percent": 0.0,
                "avg_percent": 0.0,
                "max_percent": 0.0,
                "min_percent": 0.0,
            }

        return {
            "current_percent": self._cpu_samples[-1] if self._cpu_samples else 0.0,
            "avg_percent": sum(self._cpu_samples) / len(self._cpu_samples),
            "max_percent": max(self._cpu_samples),
            "min_percent": min(self._cpu_samples),
        }

    def __enter__(self):
        """Context manager entry."""
        self.start_monitoring()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop_monitoring()


# Global resource manager instance
_global_resource_manager: Optional[ResourceManager] = None


def get_global_resource_manager() -> ResourceManager:
    """
    Get or create global resource manager instance.

    Returns:
        Global ResourceManager instance
    """
    global _global_resource_manager
    if _global_resource_manager is None:
        _global_resource_manager = ResourceManager()
    return _global_resource_manager


def configure_global_resource_manager(limits: ResourceLimits) -> ResourceManager:
    """
    Configure global resource manager with custom limits.

    Args:
        limits: Resource limits configuration

    Returns:
        Configured global ResourceManager instance
    """
    global _global_resource_manager
    if _global_resource_manager is not None:
        _global_resource_manager.stop_monitoring()

    _global_resource_manager = ResourceManager(limits)
    return _global_resource_manager
