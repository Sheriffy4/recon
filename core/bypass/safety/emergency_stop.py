# recon/core/bypass/safety/emergency_stop.py

"""
Emergency stop mechanisms for problematic attacks.
Provides immediate termination and recovery capabilities.
"""

import time
import logging
import threading
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


LOG = logging.getLogger("EmergencyStopManager")


class StopReason(Enum):
    """Reasons for emergency stop."""

    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SANDBOX_VIOLATION = "sandbox_violation"
    SYSTEM_INSTABILITY = "system_instability"
    USER_REQUEST = "user_request"
    TIMEOUT = "timeout"
    CRITICAL_ERROR = "critical_error"
    ATTACK_MALFUNCTION = "attack_malfunction"
    SECURITY_THREAT = "security_threat"


class StopPriority(Enum):
    """Priority levels for emergency stops."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    IMMEDIATE = 5


@dataclass
class EmergencyStopEvent:
    """Record of an emergency stop event."""

    attack_id: str
    reason: StopReason
    priority: StopPriority
    description: str
    timestamp: datetime = field(default_factory=datetime.now)
    context: Dict[str, Any] = field(default_factory=dict)
    stopped_by: str = "system"
    recovery_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/storage."""
        return {
            "attack_id": self.attack_id,
            "reason": self.reason.value,
            "priority": self.priority.value,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context,
            "stopped_by": self.stopped_by,
            "recovery_actions": self.recovery_actions,
        }


@dataclass
class StopCondition:
    """Condition that triggers emergency stop."""

    name: str
    check_function: Callable[[], bool]
    reason: StopReason
    priority: StopPriority
    description: str
    enabled: bool = True
    check_interval_seconds: float = 1.0
    consecutive_failures_required: int = 1

    # Internal state
    consecutive_failures: int = 0
    last_check: Optional[datetime] = None
    last_triggered: Optional[datetime] = None


class AttackStopController:
    """Controls emergency stopping for a single attack."""

    def __init__(self, attack_id: str):
        self.attack_id = attack_id
        self._stop_requested = False
        self._stop_reason: Optional[StopReason] = None
        self._stop_description: Optional[str] = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._callbacks: List[Callable[[EmergencyStopEvent], None]] = []

    def request_stop(
        self,
        reason: StopReason,
        description: str,
        priority: StopPriority = StopPriority.HIGH,
    ) -> None:
        """Request emergency stop for this attack."""
        with self._lock:
            if self._stop_requested:
                LOG.debug(f"Stop already requested for attack {self.attack_id}")
                return

            self._stop_requested = True
            self._stop_reason = reason
            self._stop_description = description
            self._stop_event.set()

            # Create stop event
            stop_event = EmergencyStopEvent(
                attack_id=self.attack_id,
                reason=reason,
                priority=priority,
                description=description,
            )

            # Notify callbacks
            for callback in self._callbacks:
                try:
                    callback(stop_event)
                except Exception as e:
                    LOG.error(f"Stop callback failed for {self.attack_id}: {e}")

            LOG.warning(f"Emergency stop requested for attack {self.attack_id}: {description}")

    def is_stop_requested(self) -> bool:
        """Check if stop has been requested."""
        with self._lock:
            return self._stop_requested

    def wait_for_stop(self, timeout: Optional[float] = None) -> bool:
        """Wait for stop signal."""
        return self._stop_event.wait(timeout)

    def get_stop_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the stop request."""
        with self._lock:
            if not self._stop_requested:
                return None

            return {
                "attack_id": self.attack_id,
                "reason": self._stop_reason.value if self._stop_reason else None,
                "description": self._stop_description,
                "requested": True,
            }

    def add_callback(self, callback: Callable[[EmergencyStopEvent], None]) -> None:
        """Add callback for stop events."""
        self._callbacks.append(callback)

    def reset(self) -> None:
        """Reset stop state (for testing/recovery)."""
        with self._lock:
            self._stop_requested = False
            self._stop_reason = None
            self._stop_description = None
            self._stop_event.clear()


class EmergencyStopManager:
    """Manages emergency stop mechanisms for all attacks."""

    def __init__(self):
        self._controllers: Dict[str, AttackStopController] = {}
        self._stop_conditions: List[StopCondition] = []
        self._stop_history: List[EmergencyStopEvent] = []
        self._global_callbacks: List[Callable[[EmergencyStopEvent], None]] = []
        self._monitoring_thread: Optional[threading.Thread] = None
        self._monitoring_active = False
        self._lock = threading.RLock()

        # Initialize default stop conditions
        self._initialize_default_conditions()

        # Start monitoring
        self.start_monitoring()

    def _initialize_default_conditions(self) -> None:
        """Initialize default emergency stop conditions."""

        # System memory condition
        def check_system_memory() -> bool:
            try:
                import psutil

                memory = psutil.virtual_memory()
                return memory.available < 100 * 1024 * 1024  # Less than 100MB available
            except Exception:
                return False

        self.add_stop_condition(
            StopCondition(
                name="system_memory_low",
                check_function=check_system_memory,
                reason=StopReason.RESOURCE_EXHAUSTION,
                priority=StopPriority.HIGH,
                description="System memory critically low",
                check_interval_seconds=5.0,
                consecutive_failures_required=2,
            )
        )

        # System CPU condition
        def check_system_cpu() -> bool:
            try:
                import psutil

                cpu_percent = psutil.cpu_percent(interval=1.0)
                return cpu_percent > 95.0  # CPU usage over 95%
            except Exception:
                return False

        self.add_stop_condition(
            StopCondition(
                name="system_cpu_high",
                check_function=check_system_cpu,
                reason=StopReason.SYSTEM_INSTABILITY,
                priority=StopPriority.MEDIUM,
                description="System CPU usage critically high",
                check_interval_seconds=10.0,
                consecutive_failures_required=3,
            )
        )

        # Disk space condition
        def check_disk_space() -> bool:
            try:
                import psutil

                disk_usage = psutil.disk_usage("/")
                free_percent = (disk_usage.free / disk_usage.total) * 100
                return free_percent < 5.0  # Less than 5% free space
            except Exception:
                return False

        self.add_stop_condition(
            StopCondition(
                name="disk_space_low",
                check_function=check_disk_space,
                reason=StopReason.RESOURCE_EXHAUSTION,
                priority=StopPriority.MEDIUM,
                description="Disk space critically low",
                check_interval_seconds=30.0,
                consecutive_failures_required=2,
            )
        )

    def create_controller(self, attack_id: str) -> AttackStopController:
        """Create emergency stop controller for an attack."""
        with self._lock:
            if attack_id in self._controllers:
                return self._controllers[attack_id]

            controller = AttackStopController(attack_id)

            # Add global callbacks to controller
            for callback in self._global_callbacks:
                controller.add_callback(callback)

            self._controllers[attack_id] = controller
            LOG.debug(f"Created emergency stop controller for attack {attack_id}")
            return controller

    def remove_controller(self, attack_id: str) -> Optional[AttackStopController]:
        """Remove emergency stop controller."""
        with self._lock:
            controller = self._controllers.pop(attack_id, None)
            if controller:
                LOG.debug(f"Removed emergency stop controller for attack {attack_id}")
            return controller

    def get_controller(self, attack_id: str) -> Optional[AttackStopController]:
        """Get emergency stop controller for an attack."""
        with self._lock:
            return self._controllers.get(attack_id)

    def request_stop(
        self,
        attack_id: str,
        reason: StopReason,
        description: str,
        priority: StopPriority = StopPriority.HIGH,
    ) -> bool:
        """Request emergency stop for a specific attack."""
        with self._lock:
            controller = self._controllers.get(attack_id)
            if not controller:
                LOG.warning(f"No controller found for attack {attack_id}")
                return False

            controller.request_stop(reason, description, priority)

            # Record in history
            stop_event = EmergencyStopEvent(
                attack_id=attack_id,
                reason=reason,
                priority=priority,
                description=description,
                stopped_by="manual",
            )
            self._stop_history.append(stop_event)

            # Keep only last 1000 events
            if len(self._stop_history) > 1000:
                self._stop_history = self._stop_history[-1000:]

            return True

    def request_stop_all(
        self,
        reason: StopReason,
        description: str,
        priority: StopPriority = StopPriority.CRITICAL,
    ) -> int:
        """Request emergency stop for all active attacks."""
        with self._lock:
            count = 0
            for attack_id, controller in self._controllers.items():
                try:
                    controller.request_stop(reason, f"Global stop: {description}", priority)
                    count += 1
                except Exception as e:
                    LOG.error(f"Failed to stop attack {attack_id}: {e}")

            if count > 0:
                # Record global stop event
                stop_event = EmergencyStopEvent(
                    attack_id="ALL",
                    reason=reason,
                    priority=priority,
                    description=f"Global stop: {description}",
                    stopped_by="system",
                    context={"affected_attacks": count},
                )
                self._stop_history.append(stop_event)

                LOG.critical(
                    f"Emergency stop requested for all {count} active attacks: {description}"
                )

            return count

    def add_stop_condition(self, condition: StopCondition) -> None:
        """Add a condition that can trigger emergency stops."""
        with self._lock:
            self._stop_conditions.append(condition)
            LOG.info(f"Added emergency stop condition: {condition.name}")

    def remove_stop_condition(self, condition_name: str) -> bool:
        """Remove a stop condition by name."""
        with self._lock:
            for i, condition in enumerate(self._stop_conditions):
                if condition.name == condition_name:
                    del self._stop_conditions[i]
                    LOG.info(f"Removed emergency stop condition: {condition_name}")
                    return True
            return False

    def enable_condition(self, condition_name: str) -> bool:
        """Enable a stop condition."""
        with self._lock:
            for condition in self._stop_conditions:
                if condition.name == condition_name:
                    condition.enabled = True
                    LOG.info(f"Enabled emergency stop condition: {condition_name}")
                    return True
            return False

    def disable_condition(self, condition_name: str) -> bool:
        """Disable a stop condition."""
        with self._lock:
            for condition in self._stop_conditions:
                if condition.name == condition_name:
                    condition.enabled = False
                    LOG.info(f"Disabled emergency stop condition: {condition_name}")
                    return True
            return False

    def start_monitoring(self) -> None:
        """Start monitoring stop conditions."""
        with self._lock:
            if self._monitoring_active:
                return

            self._monitoring_active = True
            self._monitoring_thread = threading.Thread(
                target=self._monitoring_loop, name="EmergencyStopMonitor", daemon=True
            )
            self._monitoring_thread.start()
            LOG.info("Started emergency stop monitoring")

    def stop_monitoring(self) -> None:
        """Stop monitoring stop conditions."""
        with self._lock:
            if not self._monitoring_active:
                return

            self._monitoring_active = False

            if self._monitoring_thread and self._monitoring_thread.is_alive():
                self._monitoring_thread.join(timeout=5.0)

            LOG.info("Stopped emergency stop monitoring")

    def _monitoring_loop(self) -> None:
        """Main monitoring loop for stop conditions."""
        try:
            while self._monitoring_active:
                current_time = datetime.now()

                for condition in self._stop_conditions:
                    if not condition.enabled:
                        continue

                    # Check if it's time to evaluate this condition
                    if (
                        condition.last_check
                        and (current_time - condition.last_check).total_seconds()
                        < condition.check_interval_seconds
                    ):
                        continue

                    condition.last_check = current_time

                    try:
                        # Evaluate condition
                        should_stop = condition.check_function()

                        if should_stop:
                            condition.consecutive_failures += 1

                            # Check if we've reached the threshold
                            if (
                                condition.consecutive_failures
                                >= condition.consecutive_failures_required
                            ):
                                # Trigger emergency stop
                                self._trigger_condition_stop(condition)
                                condition.last_triggered = current_time
                                condition.consecutive_failures = 0  # Reset counter
                        else:
                            condition.consecutive_failures = 0  # Reset on success

                    except Exception as e:
                        LOG.error(f"Error evaluating stop condition {condition.name}: {e}")

                time.sleep(1.0)  # Check every second

        except Exception as e:
            LOG.error(f"Emergency stop monitoring loop failed: {e}")

    def _trigger_condition_stop(self, condition: StopCondition) -> None:
        """Trigger emergency stop based on condition."""
        LOG.critical(
            f"Emergency stop condition triggered: {condition.name} - {condition.description}"
        )

        # Stop all attacks based on priority
        if condition.priority in [StopPriority.CRITICAL, StopPriority.IMMEDIATE]:
            self.request_stop_all(condition.reason, condition.description, condition.priority)
        else:
            # For lower priority conditions, just log and let individual attacks handle it
            LOG.warning(
                f"Stop condition {condition.name} triggered but not stopping attacks (priority: {condition.priority.name})"
            )

    def add_global_callback(self, callback: Callable[[EmergencyStopEvent], None]) -> None:
        """Add global callback for all stop events."""
        with self._lock:
            self._global_callbacks.append(callback)

            # Add to existing controllers
            for controller in self._controllers.values():
                controller.add_callback(callback)

    def get_active_controllers(self) -> Dict[str, AttackStopController]:
        """Get all active stop controllers."""
        with self._lock:
            return self._controllers.copy()

    def get_stop_conditions(self) -> List[StopCondition]:
        """Get all stop conditions."""
        with self._lock:
            return self._stop_conditions.copy()

    def get_stop_history(self, limit: int = 100) -> List[EmergencyStopEvent]:
        """Get recent stop events."""
        with self._lock:
            return self._stop_history[-limit:] if self._stop_history else []

    def get_status(self) -> Dict[str, Any]:
        """Get emergency stop manager status."""
        with self._lock:
            active_stops = sum(1 for c in self._controllers.values() if c.is_stop_requested())
            enabled_conditions = sum(1 for c in self._stop_conditions if c.enabled)

            return {
                "monitoring_active": self._monitoring_active,
                "active_controllers": len(self._controllers),
                "active_stops": active_stops,
                "total_conditions": len(self._stop_conditions),
                "enabled_conditions": enabled_conditions,
                "total_stop_events": len(self._stop_history),
            }

    def force_stop_attack(self, attack_id: str) -> bool:
        """Force immediate stop of an attack (for testing/debugging)."""
        return self.request_stop(
            attack_id,
            StopReason.USER_REQUEST,
            "Force stop requested",
            StopPriority.IMMEDIATE,
        )

    def clear_history(self) -> int:
        """Clear stop event history."""
        with self._lock:
            count = len(self._stop_history)
            self._stop_history.clear()
            LOG.info(f"Cleared {count} stop events from history")
            return count

    def shutdown(self) -> None:
        """Shutdown emergency stop manager."""
        LOG.info("Shutting down emergency stop manager")

        # Stop monitoring
        self.stop_monitoring()

        # Stop all active attacks
        self.request_stop_all(StopReason.USER_REQUEST, "System shutdown", StopPriority.IMMEDIATE)

        # Clear controllers
        with self._lock:
            self._controllers.clear()
            self._global_callbacks.clear()

        LOG.info("Emergency stop manager shutdown complete")
