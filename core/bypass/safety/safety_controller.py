"""
Main safety controller for the modernized bypass engine.
Orchestrates all safety mechanisms including resource management, sandboxing, and emergency stops.
"""

import time
import logging
import threading
import asyncio
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from contextlib import asynccontextmanager, contextmanager
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.safety.resource_manager import (
    ResourceManager,
    ResourceLimits,
    ResourceMonitor,
)
from core.bypass.safety.attack_sandbox import (
    AttackSandbox,
    SandboxConstraints,
    SandboxMonitor,
)
from core.bypass.safety.emergency_stop import (
    EmergencyStopManager,
    StopReason,
    StopPriority,
)
from core.bypass.safety.safety_validator import (
    SafetyValidator,
    ValidationLevel,
    ValidationReport,
)
from core.bypass.safety.exceptions import (
    ResourceLimitExceededError,
    AttackTimeoutError,
    SandboxViolationError,
    EmergencyStopError,
    AttackValidationError,
)

LOG = logging.getLogger("SafetyController")


@dataclass
class SafetyConfiguration:
    """Configuration for safety controller."""

    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    enable_resource_monitoring: bool = True
    sandbox_constraints: SandboxConstraints = field(
        default_factory=lambda: SandboxConstraints().get_default_constraints()
    )
    enable_sandboxing: bool = True
    validation_level: ValidationLevel = ValidationLevel.STANDARD
    enable_pre_validation: bool = True
    enable_post_validation: bool = True
    fail_on_validation_errors: bool = True
    enable_emergency_stops: bool = True
    auto_stop_on_violations: bool = True
    default_attack_timeout: float = 60.0
    max_attack_timeout: float = 300.0
    log_all_executions: bool = True
    store_execution_history: bool = True
    max_history_entries: int = 1000

    def validate(self) -> List[str]:
        """Validate configuration."""
        errors = []
        if self.default_attack_timeout <= 0:
            errors.append("default_attack_timeout must be positive")
        if self.max_attack_timeout < self.default_attack_timeout:
            errors.append("max_attack_timeout must be >= default_attack_timeout")
        if self.max_history_entries <= 0:
            errors.append("max_history_entries must be positive")
        resource_errors = self.resource_limits.validate()
        errors.extend([f"resource_limits.{err}" for err in resource_errors])
        return errors


@dataclass
class ExecutionRecord:
    """Record of attack execution."""

    attack_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    resource_monitor: bool = False
    sandbox_monitor: bool = False
    emergency_stop: bool = False
    pre_validation: Optional[ValidationReport] = None
    post_validation: Optional[ValidationReport] = None
    result: Optional[AttackResult] = None
    success: bool = False
    error_message: Optional[str] = None
    resource_violations: int = 0
    sandbox_violations: int = 0
    emergency_stops: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/logging."""
        return {
            "attack_id": self.attack_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "safety_components": {
                "resource_monitor": self.resource_monitor,
                "sandbox_monitor": self.sandbox_monitor,
                "emergency_stop": self.emergency_stop,
            },
            "validation": {
                "pre_validation_score": (
                    self.pre_validation.safety_score if self.pre_validation else None
                ),
                "post_validation_score": (
                    self.post_validation.safety_score if self.post_validation else None
                ),
            },
            "result": {
                "success": self.success,
                "status": self.result.status.value if self.result else None,
                "error_message": self.error_message,
            },
            "safety_events": {
                "resource_violations": self.resource_violations,
                "sandbox_violations": self.sandbox_violations,
                "emergency_stops": self.emergency_stops,
            },
        }


class SafetyController:
    """
    Main safety controller for attack execution.
    Orchestrates resource management, sandboxing, validation, and emergency stops.
    """

    def __init__(self, config: Optional[SafetyConfiguration] = None):
        self.config = config or SafetyConfiguration()
        config_errors = self.config.validate()
        if config_errors:
            raise ValueError(
                f"Invalid safety configuration: {', '.join(config_errors)}"
            )
        self.resource_manager = (
            ResourceManager(self.config.resource_limits)
            if self.config.enable_resource_monitoring
            else None
        )
        self.sandbox = (
            AttackSandbox(self.config.sandbox_constraints)
            if self.config.enable_sandboxing
            else None
        )
        self.emergency_stop_manager = (
            EmergencyStopManager() if self.config.enable_emergency_stops else None
        )
        self.validator = SafetyValidator(self.config.validation_level)
        self._active_executions: Dict[str, ExecutionRecord] = {}
        self._execution_history: List[ExecutionRecord] = []
        self._lock = threading.RLock()
        self._stats = {
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "safety_violations": 0,
            "emergency_stops": 0,
        }
        self._setup_callbacks()
        LOG.info("SafetyController initialized with configuration")

    def _setup_callbacks(self) -> None:
        """Setup callbacks between safety components."""
        if (
            self.sandbox
            and self.emergency_stop_manager
            and self.config.auto_stop_on_violations
        ):

            def on_sandbox_violation(violation):
                if violation.severity == "critical":
                    self.emergency_stop_manager.request_stop(
                        violation.attack_id,
                        StopReason.SANDBOX_VIOLATION,
                        f"Critical sandbox violation: {violation.description}",
                        StopPriority.HIGH,
                    )

            self.sandbox.add_violation_callback(on_sandbox_violation)
        if self.emergency_stop_manager:

            def on_emergency_stop(stop_event):
                LOG.critical(
                    f"Emergency stop triggered: {stop_event.attack_id} - {stop_event.description}"
                )
                self._stats["emergency_stops"] += 1

            self.emergency_stop_manager.add_global_callback(on_emergency_stop)

    @contextmanager
    def execute_attack_sync(
        self,
        attack: BaseAttack,
        context: AttackContext,
        timeout: Optional[float] = None,
    ):
        """
        Execute attack with full safety monitoring (synchronous version).

        Args:
            attack: Attack instance to execute
            context: Attack execution context
            timeout: Execution timeout (uses default if None)

        Yields:
            ExecutionRecord for tracking execution progress

        Raises:
            SafetyError: If safety validation fails
            AttackTimeoutError: If execution times out
            ResourceLimitExceededError: If resource limits exceeded
            SandboxViolationError: If sandbox violations occur
            EmergencyStopError: If emergency stop triggered
        """
        attack_id = getattr(attack, "id", f"attack_{id(attack)}")
        execution_timeout = min(
            timeout or self.config.default_attack_timeout,
            self.config.max_attack_timeout,
        )
        record = ExecutionRecord(attack_id=attack_id, start_time=datetime.now())
        with self._lock:
            self._active_executions[attack_id] = record
        resource_monitor: Optional[ResourceMonitor] = None
        sandbox_monitor: Optional[SandboxMonitor] = None
        emergency_controller = None
        try:
            if self.config.enable_pre_validation:
                LOG.debug(f"Running pre-execution validation for {attack_id}")
                pre_validation = self.validator.validate_pre_execution(attack, context)
                record.pre_validation = pre_validation
                if (
                    not pre_validation.is_safe_to_execute()
                    and self.config.fail_on_validation_errors
                ):
                    critical_issues = pre_validation.get_critical_issues()
                    raise AttackValidationError(
                        f"Pre-execution validation failed: {'; '.join(critical_issues)}",
                        critical_issues,
                        attack_id,
                    )
            if self.resource_manager:
                resource_monitor = self.resource_manager.create_monitor(attack_id)
                resource_monitor.start_monitoring()
                record.resource_monitor = True
                LOG.debug(f"Started resource monitoring for {attack_id}")
            if self.sandbox:
                sandbox_monitor = self.sandbox.create_monitor(attack_id)
                sandbox_monitor.start_monitoring()
                record.sandbox_monitor = True
                LOG.debug(f"Started sandbox monitoring for {attack_id}")
            if self.emergency_stop_manager:
                emergency_controller = self.emergency_stop_manager.create_controller(
                    attack_id
                )
                record.emergency_stop = True
                LOG.debug(f"Created emergency stop controller for {attack_id}")
            start_time = time.time()
            result = None
            try:
                if emergency_controller and emergency_controller.is_stop_requested():
                    stop_info = emergency_controller.get_stop_info()
                    raise EmergencyStopError(
                        f"Emergency stop requested before execution: {stop_info['description']}",
                        stop_info["reason"],
                        attack_id,
                    )
                LOG.info(
                    f"Executing attack {attack_id} with timeout {execution_timeout}s"
                )
                result_container = [None]
                exception_container = [None]

                def execute_with_monitoring():
                    try:
                        if resource_monitor:
                            resource_monitor.record_network_activity(
                                1, len(context.payload)
                            )
                        if sandbox_monitor:
                            sandbox_monitor.record_network_operation(
                                "execute", context.dst_ip, context.dst_port
                            )
                        attack_result = attack.execute(context)
                        result_container[0] = attack_result
                    except Exception as e:
                        exception_container[0] = e

                execution_thread = threading.Thread(
                    target=execute_with_monitoring, daemon=True
                )
                execution_thread.start()
                execution_thread.join(timeout=execution_timeout)
                if execution_thread.is_alive():
                    if emergency_controller:
                        emergency_controller.request_stop(
                            StopReason.TIMEOUT,
                            f"Attack execution timed out after {execution_timeout}s",
                            StopPriority.HIGH,
                        )
                    raise AttackTimeoutError(
                        f"Attack execution timed out after {execution_timeout}s",
                        execution_timeout,
                        attack_id,
                    )
                if exception_container[0]:
                    raise exception_container[0]
                result = result_container[0]
                if emergency_controller and emergency_controller.is_stop_requested():
                    stop_info = emergency_controller.get_stop_info()
                    raise EmergencyStopError(
                        f"Emergency stop triggered during execution: {stop_info['description']}",
                        stop_info["reason"],
                        attack_id,
                    )
            except Exception as e:
                execution_time = time.time() - start_time
                record.duration_seconds = execution_time
                record.error_message = str(e)
                record.success = False
                LOG.error(
                    f"Attack {attack_id} execution failed after {execution_time:.2f}s: {e}"
                )
                raise
            execution_time = time.time() - start_time
            record.duration_seconds = execution_time
            record.result = result
            record.success = (
                isinstance(result, AttackResult)
                and result.status == AttackStatus.SUCCESS
            )
            LOG.info(
                f"Attack {attack_id} execution completed in {execution_time:.2f}s: {(result.status if result else 'No result')}"
            )
            if self.config.enable_post_validation and result:
                LOG.debug(f"Running post-execution validation for {attack_id}")
                post_validation = self.validator.validate_post_execution(
                    attack, context, result
                )
                record.post_validation = post_validation
                if (
                    not post_validation.is_safe_to_execute()
                    and self.config.fail_on_validation_errors
                ):
                    critical_issues = post_validation.get_critical_issues()
                    raise AttackValidationError(
                        f"Post-execution validation failed: {'; '.join(critical_issues)}",
                        critical_issues,
                        attack_id,
                    )
            if sandbox_monitor and result:
                self.sandbox.validate_attack_result(result, sandbox_monitor)
            yield record
        except Exception as e:
            self._stats["failed_executions"] += 1
            if isinstance(e, (SandboxViolationError, ResourceLimitExceededError)):
                self._stats["safety_violations"] += 1
            LOG.error(f"Safe attack execution failed for {attack_id}: {e}")
            raise
        finally:
            try:
                if resource_monitor:
                    usage_summary = self.resource_manager.remove_monitor(attack_id)
                    if usage_summary:
                        record.resource_violations = 0
                if sandbox_monitor:
                    violations = self.sandbox.remove_monitor(attack_id)
                    if violations:
                        record.sandbox_violations = len(violations)
                        LOG.warning(
                            f"Attack {attack_id} had {len(violations)} sandbox violations"
                        )
                if emergency_controller:
                    self.emergency_stop_manager.remove_controller(attack_id)
            except Exception as cleanup_error:
                LOG.error(
                    f"Error during safety cleanup for {attack_id}: {cleanup_error}"
                )
            record.end_time = datetime.now()
            if record.duration_seconds == 0.0:
                record.duration_seconds = (
                    record.end_time - record.start_time
                ).total_seconds()
            with self._lock:
                self._active_executions.pop(attack_id, None)
                self._execution_history.append(record)
                if len(self._execution_history) > self.config.max_history_entries:
                    self._execution_history = self._execution_history[
                        -self.config.max_history_entries :
                    ]
                self._stats["total_executions"] += 1
                if record.success:
                    self._stats["successful_executions"] += 1
            if self.config.log_all_executions:
                LOG.info(f"Attack execution completed: {record.to_dict()}")

    @asynccontextmanager
    async def execute_attack_async(
        self,
        attack: BaseAttack,
        context: AttackContext,
        timeout: Optional[float] = None,
    ):
        """
        Execute attack with full safety monitoring (asynchronous version).

        Args:
            attack: Attack instance to execute
            context: Attack execution context
            timeout: Execution timeout (uses default if None)

        Yields:
            ExecutionRecord for tracking execution progress
        """
        loop = asyncio.get_event_loop()

        def sync_execution():
            with self.execute_attack_sync(attack, context, timeout) as record:
                return record

        try:
            record = await loop.run_in_executor(None, sync_execution)
            yield record
        except Exception as e:
            LOG.error(f"Async attack execution failed: {e}")
            raise

    def validate_attack_safety(
        self, attack: BaseAttack, context: AttackContext
    ) -> ValidationReport:
        """
        Validate attack safety without executing it.

        Args:
            attack: Attack to validate
            context: Attack context

        Returns:
            Validation report
        """
        return self.validator.validate_pre_execution(attack, context)

    def emergency_stop_attack(
        self, attack_id: str, reason: str = "Manual stop"
    ) -> bool:
        """
        Trigger emergency stop for a specific attack.

        Args:
            attack_id: ID of attack to stop
            reason: Reason for stop

        Returns:
            True if stop was triggered, False if attack not found
        """
        if not self.emergency_stop_manager:
            LOG.warning("Emergency stop manager not enabled")
            return False
        return self.emergency_stop_manager.request_stop(
            attack_id, StopReason.USER_REQUEST, reason, StopPriority.HIGH
        )

    def emergency_stop_all(self, reason: str = "Manual stop all") -> int:
        """
        Trigger emergency stop for all active attacks.

        Args:
            reason: Reason for stop

        Returns:
            Number of attacks stopped
        """
        if not self.emergency_stop_manager:
            LOG.warning("Emergency stop manager not enabled")
            return 0
        return self.emergency_stop_manager.request_stop_all(
            StopReason.USER_REQUEST, reason, StopPriority.CRITICAL
        )

    def get_active_executions(self) -> Dict[str, ExecutionRecord]:
        """Get all currently active attack executions."""
        with self._lock:
            return self._active_executions.copy()

    def get_execution_history(self, limit: int = 100) -> List[ExecutionRecord]:
        """Get recent execution history."""
        with self._lock:
            return self._execution_history[-limit:] if self._execution_history else []

    def get_safety_status(self) -> Dict[str, Any]:
        """Get comprehensive safety status."""
        status = {
            "configuration": {
                "resource_monitoring": self.config.enable_resource_monitoring,
                "sandboxing": self.config.enable_sandboxing,
                "emergency_stops": self.config.enable_emergency_stops,
                "validation_level": self.config.validation_level.value,
                "pre_validation": self.config.enable_pre_validation,
                "post_validation": self.config.enable_post_validation,
            },
            "statistics": self._stats.copy(),
            "active_executions": len(self._active_executions),
            "components": {},
        }
        if self.resource_manager:
            status["components"][
                "resource_manager"
            ] = self.resource_manager.get_system_status()
        if self.sandbox:
            status["components"]["sandbox"] = self.sandbox.get_violation_summary()
        if self.emergency_stop_manager:
            status["components"][
                "emergency_stop"
            ] = self.emergency_stop_manager.get_status()
        if self.validator:
            status["components"]["validator"] = self.validator.get_statistics()
        return status

    def update_configuration(self, new_config: SafetyConfiguration) -> None:
        """
        Update safety configuration.

        Args:
            new_config: New configuration to apply

        Raises:
            ValueError: If configuration is invalid
        """
        config_errors = new_config.validate()
        if config_errors:
            raise ValueError(
                f"Invalid safety configuration: {', '.join(config_errors)}"
            )
        with self._lock:
            old_config = self.config
            self.config = new_config
            if (
                self.resource_manager
                and old_config.resource_limits != new_config.resource_limits
            ):
                self.resource_manager.update_default_limits(new_config.resource_limits)
            if (
                self.validator
                and old_config.validation_level != new_config.validation_level
            ):
                self.validator.set_validation_level(new_config.validation_level)
            LOG.info("Safety configuration updated")

    def get_statistics(self) -> Dict[str, Any]:
        """Get detailed safety statistics."""
        with self._lock:
            stats = self._stats.copy()
            if self._execution_history:
                successful = sum((1 for r in self._execution_history if r.success))
                avg_duration = sum(
                    (r.duration_seconds for r in self._execution_history)
                ) / len(self._execution_history)
                total_violations = sum(
                    (
                        r.resource_violations + r.sandbox_violations
                        for r in self._execution_history
                    )
                )
                stats.update(
                    {
                        "history_success_rate": successful
                        / len(self._execution_history),
                        "average_execution_time": avg_duration,
                        "total_safety_violations": total_violations,
                    }
                )
            return stats

    def clear_history(self) -> int:
        """Clear execution history."""
        with self._lock:
            count = len(self._execution_history)
            self._execution_history.clear()
            LOG.info(f"Cleared {count} execution records from history")
            return count

    def shutdown(self) -> None:
        """Shutdown safety controller and all components."""
        LOG.info("Shutting down safety controller")
        active_count = self.emergency_stop_all("System shutdown")
        if active_count > 0:
            LOG.info(f"Stopped {active_count} active executions for shutdown")
        if self.emergency_stop_manager:
            self.emergency_stop_manager.shutdown()
        if self.resource_manager:
            self.resource_manager.emergency_stop_all()
        if self.sandbox:
            self.sandbox.emergency_stop_all()
        LOG.info("Safety controller shutdown complete")
