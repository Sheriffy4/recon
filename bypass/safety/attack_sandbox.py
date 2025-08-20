# recon/core/bypass/safety/attack_sandbox.py

"""
Attack sandboxing system for safe execution.
Provides isolation and validation for attack execution.
"""

import time
import logging
import tempfile
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable, Set
from dataclasses import dataclass, field
from contextlib import contextmanager

from ..attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from .exceptions import SandboxViolationError, AttackValidationError

LOG = logging.getLogger("AttackSandbox")


@dataclass
class SandboxConstraints:
    """Constraints for attack execution sandbox."""

    # File system constraints
    allowed_read_paths: Set[str] = field(default_factory=set)
    allowed_write_paths: Set[str] = field(default_factory=set)
    forbidden_paths: Set[str] = field(default_factory=set)
    max_file_operations: int = 100

    # Network constraints
    allowed_destinations: Set[str] = field(
        default_factory=set
    )  # IP addresses or domains
    forbidden_destinations: Set[str] = field(default_factory=set)
    allowed_ports: Set[int] = field(default_factory=lambda: {80, 443, 53})
    forbidden_ports: Set[int] = field(default_factory=set)
    max_network_operations: int = 1000

    # System constraints
    allow_system_calls: bool = False
    allow_subprocess: bool = False
    allow_threading: bool = True
    max_threads: int = 5

    # Resource constraints (handled by ResourceManager)
    validate_memory_access: bool = True
    validate_cpu_usage: bool = True

    # Validation constraints
    validate_input_parameters: bool = True
    validate_output_format: bool = True
    require_deterministic: bool = False

    def get_default_constraints(self) -> "SandboxConstraints":
        """Get default sandbox constraints for attacks."""
        return SandboxConstraints(
            # Allow reading from common system paths
            allowed_read_paths={
                str(Path.cwd()),  # Current working directory
                "/etc/hosts",
                "/etc/resolv.conf",
                str(Path.home() / ".recon"),  # User config directory
            },
            # Allow writing to temp and cache directories
            allowed_write_paths={
                tempfile.gettempdir(),
                str(Path.cwd() / "cache"),
                str(Path.cwd() / "logs"),
            },
            # Forbid critical system paths
            forbidden_paths={
                "/etc/passwd",
                "/etc/shadow",
                "/boot",
                "/sys",
                "/proc/sys",
                "C:\\Windows\\System32",
                "C:\\Windows\\SysWOW64",
            },
            # Network constraints for DPI bypass
            allowed_ports={53, 80, 443, 853, 8080, 8443},
            forbidden_ports={22, 23, 25, 135, 139, 445},  # Common service ports
            max_network_operations=1000,
            max_file_operations=50,
            allow_threading=True,
            max_threads=3,
            validate_input_parameters=True,
            validate_output_format=True,
        )


@dataclass
class SandboxViolation:
    """Record of a sandbox constraint violation."""

    violation_type: str
    description: str
    attack_id: str
    timestamp: float = field(default_factory=time.time)
    context: Dict[str, Any] = field(default_factory=dict)
    severity: str = "medium"  # low, medium, high, critical

    def to_dict(self) -> Dict[str, Any]:
        """Convert violation to dictionary."""
        return {
            "violation_type": self.violation_type,
            "description": self.description,
            "attack_id": self.attack_id,
            "timestamp": self.timestamp,
            "context": self.context,
            "severity": self.severity,
        }


class SandboxMonitor:
    """Monitors attack execution for sandbox violations."""

    def __init__(self, attack_id: str, constraints: SandboxConstraints):
        self.attack_id = attack_id
        self.constraints = constraints
        self.violations: List[SandboxViolation] = []
        self._monitoring = False
        self._counters = {
            "file_operations": 0,
            "network_operations": 0,
            "threads_created": 0,
            "system_calls": 0,
        }
        self._lock = threading.RLock()

    def start_monitoring(self) -> None:
        """Start sandbox monitoring."""
        with self._lock:
            if self._monitoring:
                return
            self._monitoring = True
            LOG.debug(f"Started sandbox monitoring for attack {self.attack_id}")

    def stop_monitoring(self) -> None:
        """Stop sandbox monitoring."""
        with self._lock:
            self._monitoring = False
            LOG.debug(f"Stopped sandbox monitoring for attack {self.attack_id}")

    def record_file_operation(self, operation: str, path: str) -> None:
        """Record a file system operation."""
        with self._lock:
            if not self._monitoring:
                return

            self._counters["file_operations"] += 1

            # Check operation count limit
            if self._counters["file_operations"] > self.constraints.max_file_operations:
                violation = SandboxViolation(
                    violation_type="file_operations_limit",
                    description=f"Too many file operations: {self._counters['file_operations']} > {self.constraints.max_file_operations}",
                    attack_id=self.attack_id,
                    context={
                        "operation": operation,
                        "path": path,
                        "count": self._counters["file_operations"],
                    },
                    severity="high",
                )
                self.violations.append(violation)
                raise SandboxViolationError(
                    violation.description, violation.violation_type, self.attack_id
                )

            # Check path constraints
            path_obj = Path(path).resolve()
            path_str = str(path_obj)

            # Check forbidden paths
            for forbidden in self.constraints.forbidden_paths:
                if path_str.startswith(forbidden):
                    violation = SandboxViolation(
                        violation_type="forbidden_path_access",
                        description=f"Access to forbidden path: {path_str}",
                        attack_id=self.attack_id,
                        context={
                            "operation": operation,
                            "path": path_str,
                            "forbidden_path": forbidden,
                        },
                        severity="critical",
                    )
                    self.violations.append(violation)
                    raise SandboxViolationError(
                        violation.description, violation.violation_type, self.attack_id
                    )

            # Check allowed paths for write operations
            if operation in ["write", "create", "delete", "modify"]:
                allowed = False
                for allowed_path in self.constraints.allowed_write_paths:
                    if path_str.startswith(allowed_path):
                        allowed = True
                        break

                if not allowed:
                    violation = SandboxViolation(
                        violation_type="unauthorized_write",
                        description=f"Write operation to unauthorized path: {path_str}",
                        attack_id=self.attack_id,
                        context={"operation": operation, "path": path_str},
                        severity="high",
                    )
                    self.violations.append(violation)
                    raise SandboxViolationError(
                        violation.description, violation.violation_type, self.attack_id
                    )

    def record_network_operation(
        self, operation: str, destination: str, port: int
    ) -> None:
        """Record a network operation."""
        with self._lock:
            if not self._monitoring:
                return

            self._counters["network_operations"] += 1

            # Check operation count limit
            if (
                self._counters["network_operations"]
                > self.constraints.max_network_operations
            ):
                violation = SandboxViolation(
                    violation_type="network_operations_limit",
                    description=f"Too many network operations: {self._counters['network_operations']} > {self.constraints.max_network_operations}",
                    attack_id=self.attack_id,
                    context={
                        "operation": operation,
                        "destination": destination,
                        "port": port,
                        "count": self._counters["network_operations"],
                    },
                    severity="high",
                )
                self.violations.append(violation)
                raise SandboxViolationError(
                    violation.description, violation.violation_type, self.attack_id
                )

            # Check forbidden destinations
            if destination in self.constraints.forbidden_destinations:
                violation = SandboxViolation(
                    violation_type="forbidden_destination",
                    description=f"Connection to forbidden destination: {destination}",
                    attack_id=self.attack_id,
                    context={
                        "operation": operation,
                        "destination": destination,
                        "port": port,
                    },
                    severity="critical",
                )
                self.violations.append(violation)
                raise SandboxViolationError(
                    violation.description, violation.violation_type, self.attack_id
                )

            # Check forbidden ports
            if port in self.constraints.forbidden_ports:
                violation = SandboxViolation(
                    violation_type="forbidden_port",
                    description=f"Connection to forbidden port: {port}",
                    attack_id=self.attack_id,
                    context={
                        "operation": operation,
                        "destination": destination,
                        "port": port,
                    },
                    severity="high",
                )
                self.violations.append(violation)
                raise SandboxViolationError(
                    violation.description, violation.violation_type, self.attack_id
                )

            # Check allowed ports (if specified)
            if (
                self.constraints.allowed_ports
                and port not in self.constraints.allowed_ports
            ):
                violation = SandboxViolation(
                    violation_type="unauthorized_port",
                    description=f"Connection to unauthorized port: {port}",
                    attack_id=self.attack_id,
                    context={
                        "operation": operation,
                        "destination": destination,
                        "port": port,
                    },
                    severity="medium",
                )
                self.violations.append(violation)
                # Don't raise exception for unauthorized ports, just log
                LOG.warning(
                    f"Attack {self.attack_id} connected to unauthorized port {port}"
                )

    def record_thread_creation(self) -> None:
        """Record thread creation."""
        with self._lock:
            if not self._monitoring:
                return

            if not self.constraints.allow_threading:
                violation = SandboxViolation(
                    violation_type="threading_forbidden",
                    description="Thread creation is forbidden",
                    attack_id=self.attack_id,
                    severity="high",
                )
                self.violations.append(violation)
                raise SandboxViolationError(
                    violation.description, violation.violation_type, self.attack_id
                )

            self._counters["threads_created"] += 1

            if self._counters["threads_created"] > self.constraints.max_threads:
                violation = SandboxViolation(
                    violation_type="thread_limit_exceeded",
                    description=f"Too many threads created: {self._counters['threads_created']} > {self.constraints.max_threads}",
                    attack_id=self.attack_id,
                    context={"count": self._counters["threads_created"]},
                    severity="high",
                )
                self.violations.append(violation)
                raise SandboxViolationError(
                    violation.description, violation.violation_type, self.attack_id
                )

    def record_system_call(self, call_name: str) -> None:
        """Record system call."""
        with self._lock:
            if not self._monitoring:
                return

            if not self.constraints.allow_system_calls:
                violation = SandboxViolation(
                    violation_type="system_call_forbidden",
                    description=f"System call forbidden: {call_name}",
                    attack_id=self.attack_id,
                    context={"call_name": call_name},
                    severity="critical",
                )
                self.violations.append(violation)
                raise SandboxViolationError(
                    violation.description, violation.violation_type, self.attack_id
                )

            self._counters["system_calls"] += 1

    def get_violations(self) -> List[SandboxViolation]:
        """Get all recorded violations."""
        with self._lock:
            return self.violations.copy()

    def get_counters(self) -> Dict[str, int]:
        """Get operation counters."""
        with self._lock:
            return self._counters.copy()

    def has_critical_violations(self) -> bool:
        """Check if there are any critical violations."""
        with self._lock:
            return any(v.severity == "critical" for v in self.violations)


class AttackSandbox:
    """Provides sandboxed execution environment for attacks."""

    def __init__(self, default_constraints: Optional[SandboxConstraints] = None):
        self.default_constraints = (
            default_constraints or SandboxConstraints().get_default_constraints()
        )
        self._active_monitors: Dict[str, SandboxMonitor] = {}
        self._violation_callbacks: List[Callable[[SandboxViolation], None]] = []
        self._lock = threading.RLock()

    def create_monitor(
        self, attack_id: str, constraints: Optional[SandboxConstraints] = None
    ) -> SandboxMonitor:
        """Create a sandbox monitor for an attack."""
        with self._lock:
            monitor_constraints = constraints or self.default_constraints
            monitor = SandboxMonitor(attack_id, monitor_constraints)
            self._active_monitors[attack_id] = monitor
            LOG.info(f"Created sandbox monitor for attack {attack_id}")
            return monitor

    def remove_monitor(self, attack_id: str) -> Optional[List[SandboxViolation]]:
        """Remove sandbox monitor and return violations."""
        with self._lock:
            monitor = self._active_monitors.pop(attack_id, None)
            if not monitor:
                return None

            monitor.stop_monitoring()
            violations = monitor.get_violations()

            # Notify callbacks of violations
            for violation in violations:
                for callback in self._violation_callbacks:
                    try:
                        callback(violation)
                    except Exception as e:
                        LOG.error(f"Violation callback failed: {e}")

            LOG.info(
                f"Removed sandbox monitor for attack {attack_id}, {len(violations)} violations"
            )
            return violations

    def add_violation_callback(
        self, callback: Callable[[SandboxViolation], None]
    ) -> None:
        """Add callback for sandbox violations."""
        self._violation_callbacks.append(callback)

    @contextmanager
    def execute_attack(
        self,
        attack: BaseAttack,
        context: AttackContext,
        constraints: Optional[SandboxConstraints] = None,
    ):
        """Execute attack in sandboxed environment."""
        attack_id = getattr(attack, "id", f"attack_{id(attack)}")
        monitor = self.create_monitor(attack_id, constraints)

        try:
            monitor.start_monitoring()

            # Validate attack before execution
            self._validate_attack_safety(attack, context, monitor)

            # Execute attack with monitoring
            yield monitor

        finally:
            violations = self.remove_monitor(attack_id)

            # Check for critical violations
            if violations and any(v.severity == "critical" for v in violations):
                critical_violations = [
                    v for v in violations if v.severity == "critical"
                ]
                raise SandboxViolationError(
                    f"Critical sandbox violations detected: {len(critical_violations)} violations",
                    "critical_violations",
                    attack_id,
                )

    def _validate_attack_safety(
        self, attack: BaseAttack, context: AttackContext, monitor: SandboxMonitor
    ) -> None:
        """Validate attack safety before execution."""
        validation_errors = []

        # Validate attack parameters
        if monitor.constraints.validate_input_parameters:
            param_errors = self._validate_attack_parameters(attack, context)
            validation_errors.extend(param_errors)

        # Validate target destination
        if context.dst_ip:
            try:
                import ipaddress

                ip = ipaddress.ip_address(context.dst_ip)

                # Check for localhost/private addresses in production
                if ip.is_loopback or ip.is_private:
                    LOG.warning(
                        f"Attack targeting private/loopback address: {context.dst_ip}"
                    )

                # Check forbidden destinations
                if context.dst_ip in monitor.constraints.forbidden_destinations:
                    validation_errors.append(f"Target IP {context.dst_ip} is forbidden")

            except ValueError:
                # Not a valid IP address, might be a domain
                if context.dst_ip in monitor.constraints.forbidden_destinations:
                    validation_errors.append(
                        f"Target destination {context.dst_ip} is forbidden"
                    )

        # Validate target port
        if context.dst_port:
            if context.dst_port in monitor.constraints.forbidden_ports:
                validation_errors.append(f"Target port {context.dst_port} is forbidden")

            if (
                monitor.constraints.allowed_ports
                and context.dst_port not in monitor.constraints.allowed_ports
            ):
                validation_errors.append(
                    f"Target port {context.dst_port} is not in allowed ports"
                )

        # Validate payload size
        if context.payload and len(context.payload) > 64 * 1024:  # 64KB limit
            validation_errors.append(
                f"Payload too large: {len(context.payload)} bytes > 64KB"
            )

        if validation_errors:
            raise AttackValidationError(
                f"Attack validation failed: {'; '.join(validation_errors)}",
                validation_errors,
                getattr(attack, "id", "unknown"),
            )

    def _validate_attack_parameters(
        self, attack: BaseAttack, context: AttackContext
    ) -> List[str]:
        """Validate attack parameters for safety."""
        errors = []

        # Check for dangerous parameter values
        if hasattr(attack, "params") and attack.params:
            for key, value in attack.params.items():
                # Check for potentially dangerous values
                if isinstance(value, str):
                    dangerous_patterns = [
                        "../",
                        "..\\",  # Path traversal
                        "/etc/",
                        "C:\\Windows\\",  # System paths
                        "rm -rf",
                        "del /f",  # Dangerous commands
                        "DROP TABLE",
                        "DELETE FROM",  # SQL injection
                    ]

                    for pattern in dangerous_patterns:
                        if pattern in value:
                            errors.append(
                                f"Dangerous pattern '{pattern}' in parameter '{key}'"
                            )

                # Check for excessively large values
                if isinstance(value, (int, float)) and value > 1000000:
                    errors.append(
                        f"Parameter '{key}' has excessively large value: {value}"
                    )

        # Check context parameters
        if context.params:
            for key, value in context.params.items():
                if isinstance(value, str) and len(value) > 10000:
                    errors.append(
                        f"Context parameter '{key}' is too large: {len(value)} characters"
                    )

        return errors

    def validate_attack_result(
        self, result: AttackResult, monitor: SandboxMonitor
    ) -> None:
        """Validate attack result format and content."""
        if not monitor.constraints.validate_output_format:
            return

        validation_errors = []

        # Validate result structure
        if not isinstance(result, AttackResult):
            validation_errors.append(f"Invalid result type: {type(result)}")
            return

        # Validate status
        if not isinstance(result.status, AttackStatus):
            validation_errors.append(f"Invalid status type: {type(result.status)}")

        # Validate metadata
        if result.metadata and not isinstance(result.metadata, dict):
            validation_errors.append(f"Invalid metadata type: {type(result.metadata)}")

        # Check for suspicious metadata
        if result.metadata:
            for key, value in result.metadata.items():
                if isinstance(value, str) and len(value) > 100000:
                    validation_errors.append(
                        f"Metadata '{key}' is suspiciously large: {len(value)} characters"
                    )

        # Validate segments if present
        if hasattr(result, "segments") and result.segments:
            for i, segment in enumerate(result.segments):
                if not isinstance(segment, tuple) or len(segment) != 3:
                    validation_errors.append(f"Invalid segment {i} format")
                else:
                    payload_data, seq_offset, options = segment
                    if not isinstance(payload_data, bytes):
                        validation_errors.append(
                            f"Segment {i} payload_data must be bytes"
                        )
                    if len(payload_data) > 64 * 1024:  # 64KB limit per segment
                        validation_errors.append(
                            f"Segment {i} payload too large: {len(payload_data)} bytes"
                        )

        if validation_errors:
            raise AttackValidationError(
                f"Attack result validation failed: {'; '.join(validation_errors)}",
                validation_errors,
                monitor.attack_id,
            )

    def get_active_monitors(self) -> Dict[str, SandboxMonitor]:
        """Get all active sandbox monitors."""
        with self._lock:
            return self._active_monitors.copy()

    def get_violation_summary(self) -> Dict[str, Any]:
        """Get summary of all violations across active monitors."""
        with self._lock:
            total_violations = 0
            violations_by_type = {}
            violations_by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}

            for monitor in self._active_monitors.values():
                violations = monitor.get_violations()
                total_violations += len(violations)

                for violation in violations:
                    violations_by_type[violation.violation_type] = (
                        violations_by_type.get(violation.violation_type, 0) + 1
                    )
                    violations_by_severity[violation.severity] += 1

            return {
                "total_violations": total_violations,
                "active_monitors": len(self._active_monitors),
                "violations_by_type": violations_by_type,
                "violations_by_severity": violations_by_severity,
            }

    def emergency_stop_all(self) -> int:
        """Emergency stop all active monitors."""
        with self._lock:
            count = len(self._active_monitors)
            for monitor in self._active_monitors.values():
                try:
                    monitor.stop_monitoring()
                except Exception as e:
                    LOG.error(
                        f"Error stopping sandbox monitor {monitor.attack_id}: {e}"
                    )

            self._active_monitors.clear()
            LOG.warning(f"Emergency stopped {count} sandbox monitors")
            return count
