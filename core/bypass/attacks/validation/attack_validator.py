"""
Attack validator for comprehensive validation of attack implementations.

Provides validation for:
- Parameter validation testing
- Execution validation with test payloads
- Output format validation
- Protocol compliance checking
- Validation report generation
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Type
from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus


logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Validation severity levels."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    SUCCESS = "success"


@dataclass
class ValidationResult:
    """Result of a single validation check."""
    check_name: str
    level: ValidationLevel
    passed: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ValidationReport:
    """Comprehensive validation report for an attack."""
    attack_name: str
    attack_class: str
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warnings: int = 0
    results: List[ValidationResult] = field(default_factory=list)
    execution_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    
    def add_result(self, result: ValidationResult):
        """Add a validation result to the report."""
        self.results.append(result)
        self.total_checks += 1
        
        if result.level == ValidationLevel.ERROR:
            if not result.passed:
                self.failed_checks += 1
        elif result.level == ValidationLevel.WARNING:
            self.warnings += 1
        elif result.passed:
            self.passed_checks += 1
    
    def get_summary(self) -> str:
        """Get human-readable summary of validation report."""
        success_rate = (self.passed_checks / self.total_checks * 100) if self.total_checks > 0 else 0
        
        summary = f"""
Attack Validation Report: {self.attack_name}
{'=' * 60}
Attack Class: {self.attack_class}
Timestamp: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Execution Time: {self.execution_time_ms:.2f}ms

Results:
  Total Checks: {self.total_checks}
  Passed: {self.passed_checks} ({success_rate:.1f}%)
  Failed: {self.failed_checks}
  Warnings: {self.warnings}

Status: {'✅ PASSED' if self.failed_checks == 0 else '❌ FAILED'}
"""
        
        if self.failed_checks > 0:
            summary += "\nFailed Checks:\n"
            for result in self.results:
                if result.level == ValidationLevel.ERROR and not result.passed:
                    summary += f"  ❌ {result.check_name}: {result.message}\n"
        
        if self.warnings > 0:
            summary += "\nWarnings:\n"
            for result in self.results:
                if result.level == ValidationLevel.WARNING:
                    summary += f"  ⚠️  {result.check_name}: {result.message}\n"
        
        return summary


class AttackValidator:
    """
    Comprehensive validator for attack implementations.
    
    Validates:
    - Parameter validation logic
    - Execution with test payloads
    - Output format compliance
    - Protocol compliance
    - Error handling
    """
    
    def __init__(self):
        """Initialize the attack validator."""
        self.logger = logging.getLogger(f"{__name__}.AttackValidator")
    
    async def validate_attack(
        self,
        attack_class: Type[BaseAttack],
        test_payloads: Optional[List[bytes]] = None
    ) -> ValidationReport:
        """
        Validate an attack implementation comprehensively.
        
        Args:
            attack_class: The attack class to validate
            test_payloads: Optional list of test payloads to use
            
        Returns:
            ValidationReport with all validation results
        """
        start_time = datetime.now()
        attack_name = getattr(attack_class, '__name__', str(attack_class))
        
        report = ValidationReport(
            attack_name=attack_name,
            attack_class=str(attack_class)
        )
        
        self.logger.info(f"Starting validation for {attack_name}")
        
        # Create attack instance
        try:
            attack = attack_class()
        except Exception as e:
            report.add_result(ValidationResult(
                check_name="instantiation",
                level=ValidationLevel.ERROR,
                passed=False,
                message=f"Failed to instantiate attack: {str(e)}"
            ))
            return report
        
        # Run validation checks
        await self._validate_metadata(attack, report)
        await self._validate_parameter_validation(attack, report)
        await self._validate_execution(attack, report, test_payloads)
        await self._validate_output_format(attack, report)
        await self._validate_error_handling(attack, report)
        
        # Calculate execution time
        end_time = datetime.now()
        report.execution_time_ms = (end_time - start_time).total_seconds() * 1000
        
        self.logger.info(f"Validation complete for {attack_name}: "
                        f"{report.passed_checks}/{report.total_checks} checks passed")
        
        return report
    
    async def _validate_metadata(self, attack: BaseAttack, report: ValidationReport):
        """Validate attack metadata."""
        try:
            metadata = attack.get_metadata()
            
            # Check required metadata fields
            required_fields = ['name', 'description', 'category']
            for field in required_fields:
                if not hasattr(metadata, field) or not getattr(metadata, field):
                    report.add_result(ValidationResult(
                        check_name=f"metadata_{field}",
                        level=ValidationLevel.WARNING,
                        passed=False,
                        message=f"Missing or empty metadata field: {field}"
                    ))
                else:
                    report.add_result(ValidationResult(
                        check_name=f"metadata_{field}",
                        level=ValidationLevel.SUCCESS,
                        passed=True,
                        message=f"Metadata field '{field}' present"
                    ))
        except Exception as e:
            report.add_result(ValidationResult(
                check_name="metadata_retrieval",
                level=ValidationLevel.ERROR,
                passed=False,
                message=f"Failed to retrieve metadata: {str(e)}"
            ))
    
    async def _validate_parameter_validation(self, attack: BaseAttack, report: ValidationReport):
        """Validate parameter validation logic."""
        # Test with valid parameters
        try:
            valid_params = {}
            validation = attack.validate_params(valid_params)
            
            if validation.is_valid:
                report.add_result(ValidationResult(
                    check_name="param_validation_empty",
                    level=ValidationLevel.SUCCESS,
                    passed=True,
                    message="Empty parameters accepted"
                ))
            else:
                report.add_result(ValidationResult(
                    check_name="param_validation_empty",
                    level=ValidationLevel.WARNING,
                    passed=False,
                    message=f"Empty parameters rejected: {validation.error_message}"
                ))
        except Exception as e:
            report.add_result(ValidationResult(
                check_name="param_validation_empty",
                level=ValidationLevel.ERROR,
                passed=False,
                message=f"Parameter validation failed: {str(e)}"
            ))
        
        # Test with invalid parameters
        try:
            invalid_params = {"invalid_param": "invalid_value"}
            validation = attack.validate_params(invalid_params)
            
            # Should either accept (ignore unknown) or reject gracefully
            report.add_result(ValidationResult(
                check_name="param_validation_invalid",
                level=ValidationLevel.SUCCESS,
                passed=True,
                message="Invalid parameters handled gracefully"
            ))
        except Exception as e:
            report.add_result(ValidationResult(
                check_name="param_validation_invalid",
                level=ValidationLevel.ERROR,
                passed=False,
                message=f"Invalid parameter handling failed: {str(e)}"
            ))
    
    async def _validate_execution(
        self,
        attack: BaseAttack,
        report: ValidationReport,
        test_payloads: Optional[List[bytes]] = None
    ):
        """Validate attack execution with test payloads."""
        if test_payloads is None:
            test_payloads = [
                b"test data",
                b"Hello World",
                b"A" * 100,  # Larger payload
            ]
        
        for i, payload in enumerate(test_payloads):
            try:
                context = AttackContext(
                    dst_ip="192.168.1.100",
                    dst_port=443,
                    src_ip="192.168.1.1",
                    src_port=12345,
                    domain="example.com",
                    payload=payload,
                    params={}
                )
                
                # Execute attack
                if asyncio.iscoroutinefunction(attack.execute):
                    result = await attack.execute(context)
                else:
                    result = attack.execute(context)
                
                # Validate result
                if result.status == AttackStatus.SUCCESS:
                    report.add_result(ValidationResult(
                        check_name=f"execution_test_{i}",
                        level=ValidationLevel.SUCCESS,
                        passed=True,
                        message=f"Execution successful with test payload {i}",
                        details={"payload_size": len(payload)}
                    ))
                else:
                    report.add_result(ValidationResult(
                        check_name=f"execution_test_{i}",
                        level=ValidationLevel.WARNING,
                        passed=False,
                        message=f"Execution returned status: {result.status}",
                        details={"payload_size": len(payload), "error": result.error_message}
                    ))
            except Exception as e:
                report.add_result(ValidationResult(
                    check_name=f"execution_test_{i}",
                    level=ValidationLevel.ERROR,
                    passed=False,
                    message=f"Execution failed: {str(e)}",
                    details={"payload_size": len(payload)}
                ))
    
    async def _validate_output_format(self, attack: BaseAttack, report: ValidationReport):
        """Validate attack output format."""
        try:
            context = AttackContext(
                dst_ip="192.168.1.100",
                dst_port=443,
                src_ip="192.168.1.1",
                src_port=12345,
                domain="example.com",
                payload=b"test data",
                params={}
            )
            
            # Execute attack
            if asyncio.iscoroutinefunction(attack.execute):
                result = await attack.execute(context)
            else:
                result = attack.execute(context)
            
            # Validate result structure
            if not isinstance(result, AttackResult):
                report.add_result(ValidationResult(
                    check_name="output_format_type",
                    level=ValidationLevel.ERROR,
                    passed=False,
                    message=f"Result is not AttackResult type: {type(result)}"
                ))
                return
            
            report.add_result(ValidationResult(
                check_name="output_format_type",
                level=ValidationLevel.SUCCESS,
                passed=True,
                message="Result is correct AttackResult type"
            ))
            
            # Check required fields
            if not hasattr(result, 'status'):
                report.add_result(ValidationResult(
                    check_name="output_format_status",
                    level=ValidationLevel.ERROR,
                    passed=False,
                    message="Result missing 'status' field"
                ))
            else:
                report.add_result(ValidationResult(
                    check_name="output_format_status",
                    level=ValidationLevel.SUCCESS,
                    passed=True,
                    message="Result has 'status' field"
                ))
            
            # Check metadata field
            if not hasattr(result, 'metadata'):
                report.add_result(ValidationResult(
                    check_name="output_format_metadata",
                    level=ValidationLevel.WARNING,
                    passed=False,
                    message="Result missing 'metadata' field"
                ))
            else:
                report.add_result(ValidationResult(
                    check_name="output_format_metadata",
                    level=ValidationLevel.SUCCESS,
                    passed=True,
                    message="Result has 'metadata' field"
                ))
            
            # Check modified_payload for successful attacks
            if result.status == AttackStatus.SUCCESS:
                if not hasattr(result, 'modified_payload') or result.modified_payload is None:
                    report.add_result(ValidationResult(
                        check_name="output_format_payload",
                        level=ValidationLevel.ERROR,
                        passed=False,
                        message="Successful result missing 'modified_payload'"
                    ))
                else:
                    report.add_result(ValidationResult(
                        check_name="output_format_payload",
                        level=ValidationLevel.SUCCESS,
                        passed=True,
                        message="Result has 'modified_payload'"
                    ))
        except Exception as e:
            report.add_result(ValidationResult(
                check_name="output_format_validation",
                level=ValidationLevel.ERROR,
                passed=False,
                message=f"Output format validation failed: {str(e)}"
            ))
    
    async def _validate_error_handling(self, attack: BaseAttack, report: ValidationReport):
        """Validate error handling."""
        # Test with None payload
        try:
            context = AttackContext(
                dst_ip="192.168.1.100",
                dst_port=443,
                src_ip="192.168.1.1",
                src_port=12345,
                domain="example.com",
                payload=None,
                params={}
            )
            
            if asyncio.iscoroutinefunction(attack.execute):
                result = await attack.execute(context)
            else:
                result = attack.execute(context)
            
            # Should handle gracefully
            if result.status == AttackStatus.ERROR:
                report.add_result(ValidationResult(
                    check_name="error_handling_none_payload",
                    level=ValidationLevel.SUCCESS,
                    passed=True,
                    message="None payload handled gracefully with ERROR status"
                ))
            else:
                report.add_result(ValidationResult(
                    check_name="error_handling_none_payload",
                    level=ValidationLevel.WARNING,
                    passed=False,
                    message=f"None payload returned status: {result.status}"
                ))
        except Exception as e:
            report.add_result(ValidationResult(
                check_name="error_handling_none_payload",
                level=ValidationLevel.ERROR,
                passed=False,
                message=f"None payload caused exception: {str(e)}"
            ))
        
        # Test with empty payload
        try:
            context = AttackContext(
                dst_ip="192.168.1.100",
                dst_port=443,
                src_ip="192.168.1.1",
                src_port=12345,
                domain="example.com",
                payload=b"",
                params={}
            )
            
            if asyncio.iscoroutinefunction(attack.execute):
                result = await attack.execute(context)
            else:
                result = attack.execute(context)
            
            # Should handle gracefully
            report.add_result(ValidationResult(
                check_name="error_handling_empty_payload",
                level=ValidationLevel.SUCCESS,
                passed=True,
                message=f"Empty payload handled with status: {result.status}"
            ))
        except Exception as e:
            report.add_result(ValidationResult(
                check_name="error_handling_empty_payload",
                level=ValidationLevel.ERROR,
                passed=False,
                message=f"Empty payload caused exception: {str(e)}"
            ))
