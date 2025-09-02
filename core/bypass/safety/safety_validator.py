"""
Safety validation system for attack execution.
Validates attacks before and after execution for safety compliance.
"""

import logging
import threading
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult
from core.bypass.attacks.attack_definition import AttackStability, AttackComplexity

LOG = logging.getLogger("SafetyValidator")


class ValidationLevel(Enum):
    """Levels of safety validation."""

    MINIMAL = "minimal"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"


class ValidationResult(Enum):
    """Results of safety validation."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    ERROR = "error"


@dataclass
class ValidationCheck:
    """Individual validation check."""

    name: str
    description: str
    check_function: Callable[
        [BaseAttack, AttackContext, Optional[AttackResult]],
        Tuple[ValidationResult, str],
    ]
    level: ValidationLevel
    category: str
    enabled: bool = True
    weight: float = 1.0

    def execute(
        self,
        attack: BaseAttack,
        context: AttackContext,
        result: Optional[AttackResult] = None,
    ) -> Tuple[ValidationResult, str]:
        """Execute this validation check."""
        try:
            return self.check_function(attack, context, result)
        except Exception as e:
            LOG.error(f"Validation check {self.name} failed with error: {e}")
            return (ValidationResult.ERROR, f"Check execution failed: {str(e)}")


@dataclass
class ValidationReport:
    """Report of safety validation results."""

    attack_id: str
    validation_level: ValidationLevel
    timestamp: datetime = field(default_factory=datetime.now)
    checks_passed: int = 0
    checks_warned: int = 0
    checks_failed: int = 0
    checks_errored: int = 0
    check_results: List[Tuple[str, ValidationResult, str]] = field(default_factory=list)
    overall_result: ValidationResult = ValidationResult.PASS
    safety_score: float = 1.0
    recommendations: List[str] = field(default_factory=list)

    def add_check_result(
        self,
        check_name: str,
        result: ValidationResult,
        message: str,
        weight: float = 1.0,
    ) -> None:
        """Add a check result to the report."""
        self.check_results.append((check_name, result, message))
        if result == ValidationResult.PASS:
            self.checks_passed += 1
        elif result == ValidationResult.WARN:
            self.checks_warned += 1
        elif result == ValidationResult.FAIL:
            self.checks_failed += 1
        elif result == ValidationResult.ERROR:
            self.checks_errored += 1
        if result == ValidationResult.FAIL or result == ValidationResult.ERROR:
            if self.overall_result in [ValidationResult.PASS, ValidationResult.WARN]:
                self.overall_result = result
        elif (
            result == ValidationResult.WARN
            and self.overall_result == ValidationResult.PASS
        ):
            self.overall_result = ValidationResult.WARN
        self._calculate_safety_score()

    def _calculate_safety_score(self) -> None:
        """Calculate overall safety score."""
        if not self.check_results:
            self.safety_score = 1.0
            return
        total_weight = len(self.check_results)
        score = 0.0
        for _, result, _ in self.check_results:
            if result == ValidationResult.PASS:
                score += 1.0
            elif result == ValidationResult.WARN:
                score += 0.7
            elif result == ValidationResult.FAIL:
                score += 0.0
            elif result == ValidationResult.ERROR:
                score += 0.0
        self.safety_score = score / total_weight if total_weight > 0 else 1.0

    def is_safe_to_execute(self) -> bool:
        """Check if attack is safe to execute based on validation."""
        return (
            self.overall_result in [ValidationResult.PASS, ValidationResult.WARN]
            and self.checks_failed == 0
            and (self.checks_errored == 0)
        )

    def get_critical_issues(self) -> List[str]:
        """Get list of critical issues that prevent execution."""
        critical_issues = []
        for check_name, result, message in self.check_results:
            if result in [ValidationResult.FAIL, ValidationResult.ERROR]:
                critical_issues.append(f"{check_name}: {message}")
        return critical_issues

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "attack_id": self.attack_id,
            "validation_level": self.validation_level.value,
            "timestamp": self.timestamp.isoformat(),
            "summary": {
                "checks_passed": self.checks_passed,
                "checks_warned": self.checks_warned,
                "checks_failed": self.checks_failed,
                "checks_errored": self.checks_errored,
                "overall_result": self.overall_result.value,
                "safety_score": self.safety_score,
                "safe_to_execute": self.is_safe_to_execute(),
            },
            "check_results": [
                {"name": name, "result": result.value, "message": message}
                for name, result, message in self.check_results
            ],
            "recommendations": self.recommendations,
            "critical_issues": self.get_critical_issues(),
        }


class SafetyValidator:
    """Validates attacks for safety before and after execution."""

    def __init__(self, validation_level: ValidationLevel = ValidationLevel.STANDARD):
        self.validation_level = validation_level
        self._checks: List[ValidationCheck] = []
        self._validation_history: List[ValidationReport] = []
        self._lock = threading.RLock()
        self._initialize_default_checks()

    def _initialize_default_checks(self) -> None:
        """Initialize default safety validation checks."""

        def check_attack_structure(
            attack: BaseAttack, context: AttackContext, result: Optional[AttackResult]
        ) -> Tuple[ValidationResult, str]:
            if not hasattr(attack, "execute"):
                return (ValidationResult.FAIL, "Attack missing execute method")
            if not isinstance(context, AttackContext):
                return (ValidationResult.FAIL, "Invalid attack context type")
            return (ValidationResult.PASS, "Attack structure valid")

        self.add_check(
            ValidationCheck(
                name="attack_structure",
                description="Validate basic attack structure",
                check_function=check_attack_structure,
                level=ValidationLevel.MINIMAL,
                category="structure",
            )
        )

        def check_context_safety(
            attack: BaseAttack, context: AttackContext, result: Optional[AttackResult]
        ) -> Tuple[ValidationResult, str]:
            issues = []
            if not context.dst_ip:
                issues.append("Missing destination IP")
            elif context.dst_ip in ["127.0.0.1", "localhost"]:
                return (
                    ValidationResult.WARN,
                    "Targeting localhost - ensure this is intentional",
                )
            if not context.dst_port:
                issues.append("Missing destination port")
            elif context.dst_port < 1 or context.dst_port > 65535:
                issues.append("Invalid port number")
            if context.payload and len(context.payload) > 64 * 1024:
                issues.append("Payload too large (>64KB)")
            if context.params:
                for key, value in context.params.items():
                    if isinstance(value, str) and any(
                        (
                            dangerous in value.lower()
                            for dangerous in ["rm -rf", "del /f", "format c:"]
                        )
                    ):
                        issues.append(f"Dangerous command in parameter {key}")
            if issues:
                return (ValidationResult.FAIL, "; ".join(issues))
            return (ValidationResult.PASS, "Context validation passed")

        self.add_check(
            ValidationCheck(
                name="context_safety",
                description="Validate attack context for safety",
                check_function=check_context_safety,
                level=ValidationLevel.MINIMAL,
                category="context",
            )
        )

        def check_attack_definition(
            attack: BaseAttack, context: AttackContext, result: Optional[AttackResult]
        ) -> Tuple[ValidationResult, str]:
            attack_id = getattr(attack, "id", "unknown")
            if (
                hasattr(attack, "stability")
                and attack.stability == AttackStability.EXPERIMENTAL
            ):
                return (
                    ValidationResult.WARN,
                    "Attack marked as experimental - use with caution",
                )
            if (
                hasattr(attack, "complexity")
                and attack.complexity == AttackComplexity.EXPERIMENTAL
            ):
                return (ValidationResult.WARN, "Attack has experimental complexity")
            return (ValidationResult.PASS, "Attack definition validation passed")

        self.add_check(
            ValidationCheck(
                name="attack_definition",
                description="Validate attack definition properties",
                check_function=check_attack_definition,
                level=ValidationLevel.STANDARD,
                category="definition",
            )
        )

        def check_resource_prediction(
            attack: BaseAttack, context: AttackContext, result: Optional[AttackResult]
        ) -> Tuple[ValidationResult, str]:
            warnings = []
            if context.payload:
                payload_size = len(context.payload)
                if payload_size > 10 * 1024:
                    warnings.append(
                        f"Large payload may use significant memory: {payload_size} bytes"
                    )
            if context.params:
                if context.params.get("iterations", 1) > 1000:
                    warnings.append(
                        "High iteration count may consume significant resources"
                    )
                if context.params.get("delay", 0) > 10:
                    warnings.append("Long delay may cause timeout issues")
            if warnings:
                return (ValidationResult.WARN, "; ".join(warnings))
            return (ValidationResult.PASS, "Resource prediction passed")

        self.add_check(
            ValidationCheck(
                name="resource_prediction",
                description="Predict resource usage for attack",
                check_function=check_resource_prediction,
                level=ValidationLevel.STANDARD,
                category="resources",
            )
        )

        def check_network_safety(
            attack: BaseAttack, context: AttackContext, result: Optional[AttackResult]
        ) -> Tuple[ValidationResult, str]:
            issues = []
            if context.dst_ip:
                try:
                    import ipaddress

                    ip = ipaddress.ip_address(context.dst_ip)
                    if ip.is_multicast:
                        issues.append("Targeting multicast address")
                    elif ip.is_reserved:
                        issues.append("Targeting reserved IP address")
                except ValueError:
                    pass
            dangerous_ports = {22, 23, 25, 135, 139, 445, 1433, 3389}
            if context.dst_port in dangerous_ports:
                return (
                    ValidationResult.WARN,
                    f"Targeting potentially sensitive port {context.dst_port}",
                )
            if context.protocol and context.protocol.lower() not in ["tcp", "udp"]:
                return (ValidationResult.WARN, f"Unusual protocol: {context.protocol}")
            if issues:
                return (ValidationResult.FAIL, "; ".join(issues))
            return (ValidationResult.PASS, "Network safety validation passed")

        self.add_check(
            ValidationCheck(
                name="network_safety",
                description="Validate network safety aspects",
                check_function=check_network_safety,
                level=ValidationLevel.STANDARD,
                category="network",
            )
        )

        def check_result_safety(
            attack: BaseAttack, context: AttackContext, result: Optional[AttackResult]
        ) -> Tuple[ValidationResult, str]:
            if result is None:
                return (ValidationResult.PASS, "No result to validate (pre-execution)")
            issues = []
            if not isinstance(result, AttackResult):
                issues.append("Invalid result type")
            if result.metadata:
                for key, value in result.metadata.items():
                    if isinstance(value, str) and len(value) > 100000:
                        issues.append(f"Suspiciously large metadata field: {key}")
                    if key.lower() in ["password", "secret", "key"] and isinstance(
                        value, str
                    ):
                        issues.append(f"Potentially sensitive data in metadata: {key}")
            if hasattr(result, "segments") and result.segments:
                total_payload_size = sum(
                    (
                        len(segment[0])
                        for segment in result.segments
                        if isinstance(segment, tuple) and len(segment) >= 1
                    )
                )
                if total_payload_size > 1024 * 1024:
                    issues.append(
                        f"Very large total payload in segments: {total_payload_size} bytes"
                    )
            if issues:
                return (ValidationResult.FAIL, "; ".join(issues))
            return (ValidationResult.PASS, "Result safety validation passed")

        self.add_check(
            ValidationCheck(
                name="result_safety",
                description="Validate attack result for safety",
                check_function=check_result_safety,
                level=ValidationLevel.STANDARD,
                category="result",
            )
        )

        def check_deterministic_behavior(
            attack: BaseAttack, context: AttackContext, result: Optional[AttackResult]
        ) -> Tuple[ValidationResult, str]:
            if context.params:
                for key, value in context.params.items():
                    if "random" in key.lower() or "rand" in key.lower():
                        return (
                            ValidationResult.WARN,
                            "Attack uses random parameters - behavior may not be deterministic",
                        )
            return (ValidationResult.PASS, "Deterministic behavior check passed")

        self.add_check(
            ValidationCheck(
                name="deterministic_behavior",
                description="Check for deterministic attack behavior",
                check_function=check_deterministic_behavior,
                level=ValidationLevel.STRICT,
                category="behavior",
            )
        )

        def check_side_effects(
            attack: BaseAttack, context: AttackContext, result: Optional[AttackResult]
        ) -> Tuple[ValidationResult, str]:
            warnings = []
            if (
                hasattr(attack, "modifies_global_state")
                and attack.modifies_global_state
            ):
                warnings.append("Attack may modify global state")
            if context.params and any(
                (
                    "file" in str(key).lower() or "path" in str(key).lower()
                    for key in context.params.keys()
                )
            ):
                warnings.append("Attack may access file system")
            if context.params and any(
                (
                    "config" in str(key).lower() or "setting" in str(key).lower()
                    for key in context.params.keys()
                )
            ):
                warnings.append("Attack may modify network configuration")
            if warnings:
                return (ValidationResult.WARN, "; ".join(warnings))
            return (ValidationResult.PASS, "Side effects check passed")

        self.add_check(
            ValidationCheck(
                name="side_effects",
                description="Check for potential side effects",
                check_function=check_side_effects,
                level=ValidationLevel.PARANOID,
                category="side_effects",
            )
        )

    def add_check(self, check: ValidationCheck) -> None:
        """Add a validation check."""
        with self._lock:
            self._checks.append(check)
            LOG.debug(f"Added validation check: {check.name}")

    def remove_check(self, check_name: str) -> bool:
        """Remove a validation check by name."""
        with self._lock:
            for i, check in enumerate(self._checks):
                if check.name == check_name:
                    del self._checks[i]
                    LOG.debug(f"Removed validation check: {check_name}")
                    return True
            return False

    def enable_check(self, check_name: str) -> bool:
        """Enable a validation check."""
        with self._lock:
            for check in self._checks:
                if check.name == check_name:
                    check.enabled = True
                    LOG.debug(f"Enabled validation check: {check_name}")
                    return True
            return False

    def disable_check(self, check_name: str) -> bool:
        """Disable a validation check."""
        with self._lock:
            for check in self._checks:
                if check.name == check_name:
                    check.enabled = False
                    LOG.debug(f"Disabled validation check: {check_name}")
                    return True
            return False

    def validate_pre_execution(
        self, attack: BaseAttack, context: AttackContext
    ) -> ValidationReport:
        """Validate attack before execution."""
        attack_id = getattr(attack, "id", f"attack_{id(attack)}")
        report = ValidationReport(
            attack_id=attack_id, validation_level=self.validation_level
        )
        with self._lock:
            applicable_checks = [
                check
                for check in self._checks
                if check.enabled and self._is_check_applicable(check)
            ]
            for check in applicable_checks:
                result, message = check.execute(attack, context, None)
                report.add_check_result(check.name, result, message, check.weight)
        self._add_recommendations(report)
        self._validation_history.append(report)
        if len(self._validation_history) > 1000:
            self._validation_history = self._validation_history[-1000:]
        LOG.info(
            f"Pre-execution validation for {attack_id}: {report.overall_result.value} (score: {report.safety_score:.2f})"
        )
        return report

    def validate_post_execution(
        self, attack: BaseAttack, context: AttackContext, result: AttackResult
    ) -> ValidationReport:
        """Validate attack after execution."""
        attack_id = getattr(attack, "id", f"attack_{id(attack)}")
        report = ValidationReport(
            attack_id=attack_id, validation_level=self.validation_level
        )
        with self._lock:
            applicable_checks = [
                check
                for check in self._checks
                if check.enabled and self._is_check_applicable(check)
            ]
            for check in applicable_checks:
                check_result, message = check.execute(attack, context, result)
                report.add_check_result(check.name, check_result, message, check.weight)
        self._add_recommendations(report)
        self._validation_history.append(report)
        if len(self._validation_history) > 1000:
            self._validation_history = self._validation_history[-1000:]
        LOG.info(
            f"Post-execution validation for {attack_id}: {report.overall_result.value} (score: {report.safety_score:.2f})"
        )
        return report

    def _is_check_applicable(self, check: ValidationCheck) -> bool:
        """Check if a validation check is applicable for current validation level."""
        level_order = [
            ValidationLevel.MINIMAL,
            ValidationLevel.STANDARD,
            ValidationLevel.STRICT,
            ValidationLevel.PARANOID,
        ]
        current_level_index = level_order.index(self.validation_level)
        check_level_index = level_order.index(check.level)
        return check_level_index <= current_level_index

    def _add_recommendations(self, report: ValidationReport) -> None:
        """Add recommendations based on validation results."""
        if report.checks_failed > 0:
            report.recommendations.append(
                "Address all failed validation checks before executing attack"
            )
        if report.checks_warned > 0:
            report.recommendations.append(
                "Review warnings and consider if attack execution is appropriate"
            )
        if report.safety_score < 0.8:
            report.recommendations.append(
                "Consider using a safer attack or adjusting parameters"
            )
        if report.overall_result == ValidationResult.ERROR:
            report.recommendations.append("Fix validation errors and retry validation")
        for check_name, result, message in report.check_results:
            if result == ValidationResult.WARN:
                if "experimental" in message.lower():
                    report.recommendations.append(
                        "Monitor attack execution closely due to experimental nature"
                    )
                elif "resource" in message.lower():
                    report.recommendations.append(
                        "Monitor system resources during attack execution"
                    )
                elif "port" in message.lower():
                    report.recommendations.append(
                        "Verify target port is appropriate for your use case"
                    )

    def get_validation_checks(self) -> List[ValidationCheck]:
        """Get all validation checks."""
        with self._lock:
            return self._checks.copy()

    def get_validation_history(self, limit: int = 100) -> List[ValidationReport]:
        """Get recent validation history."""
        with self._lock:
            return self._validation_history[-limit:] if self._validation_history else []

    def get_statistics(self) -> Dict[str, Any]:
        """Get validation statistics."""
        with self._lock:
            if not self._validation_history:
                return {"total_validations": 0}
            total_validations = len(self._validation_history)
            passed = sum(
                (
                    1
                    for r in self._validation_history
                    if r.overall_result == ValidationResult.PASS
                )
            )
            warned = sum(
                (
                    1
                    for r in self._validation_history
                    if r.overall_result == ValidationResult.WARN
                )
            )
            failed = sum(
                (
                    1
                    for r in self._validation_history
                    if r.overall_result == ValidationResult.FAIL
                )
            )
            errored = sum(
                (
                    1
                    for r in self._validation_history
                    if r.overall_result == ValidationResult.ERROR
                )
            )
            avg_safety_score = (
                sum((r.safety_score for r in self._validation_history))
                / total_validations
            )
            return {
                "total_validations": total_validations,
                "results": {
                    "passed": passed,
                    "warned": warned,
                    "failed": failed,
                    "errored": errored,
                },
                "average_safety_score": avg_safety_score,
                "validation_level": self.validation_level.value,
                "total_checks": len(self._checks),
                "enabled_checks": sum((1 for c in self._checks if c.enabled)),
            }

    def set_validation_level(self, level: ValidationLevel) -> None:
        """Set validation level."""
        with self._lock:
            self.validation_level = level
            LOG.info(f"Set validation level to {level.value}")

    def clear_history(self) -> int:
        """Clear validation history."""
        with self._lock:
            count = len(self._validation_history)
            self._validation_history.clear()
            LOG.info(f"Cleared {count} validation reports from history")
            return count
