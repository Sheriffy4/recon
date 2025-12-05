"""
Strategy Validator for PCAP vs Log Verification

This module validates that strategy application logs match actual PCAP data.
It compares expected operations (from logs) with actual operations (from PCAP).

Requirements: 1.3, 1.4, 1.5
"""

import logging
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from enum import Enum

from core.pcap.unified_analyzer import UnifiedPCAPAnalyzer, PCAPAnalysisResult

LOG = logging.getLogger(__name__)


class ValidationStatus(Enum):
    """
    Status of strategy validation.
    
    Requirements: 1.3
    """
    VALID = "valid"  # Strategy applied correctly
    INVALID = "invalid"  # Strategy not applied or applied incorrectly
    PARTIAL = "partial"  # Some operations applied, some missing
    UNKNOWN = "unknown"  # Cannot determine (e.g., PCAP file missing)


@dataclass
class ValidationResult:
    """
    Result of strategy validation.
    
    Requirements: 1.3, 1.5
    """
    status: ValidationStatus
    strategy_name: str
    expected_operations: List[str] = field(default_factory=list)
    actual_operations: List[str] = field(default_factory=list)
    missing_operations: List[str] = field(default_factory=list)
    unexpected_operations: List[str] = field(default_factory=list)
    operation_details: Dict[str, Dict] = field(default_factory=dict)
    message: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "status": self.status.value,
            "strategy_name": self.strategy_name,
            "expected_operations": self.expected_operations,
            "actual_operations": self.actual_operations,
            "missing_operations": self.missing_operations,
            "unexpected_operations": self.unexpected_operations,
            "operation_details": self.operation_details,
            "message": self.message
        }


class StrategyValidator:
    """
    Validates strategy application by comparing logs with PCAP analysis.
    
    Requirements: 1.3, 1.4, 1.5
    """
    
    def __init__(self):
        """Initialize the validator."""
        self.logger = LOG
        self.analyzer = UnifiedPCAPAnalyzer()
        self.validation_results: List[ValidationResult] = []
        self.logger.info("StrategyValidator initialized")
    
    def validate_strategy(
        self, 
        strategy_log: Optional[Dict], 
        pcap_file: Path, 
        domain: str,
        strategy_name: Optional[str] = None
    ) -> ValidationResult:
        """
        Validate strategy by comparing log with PCAP.
        
        Args:
            strategy_log: Dictionary containing strategy operations from log (optional)
            pcap_file: Path to PCAP file
            domain: Domain name being tested
            strategy_name: Name of strategy being tested (optional, extracted from log if not provided)
            
        Returns:
            ValidationResult with validation status and details
            
        Requirements: 1.3, 1.4
        """
        # Use provided strategy_name or extract from log
        if not strategy_name:
            strategy_name = strategy_log.get("strategy_name", "unknown") if strategy_log else "unknown"
        
        self.logger.info(
            f"Validating strategy '{strategy_name}' for domain {domain}"
        )
        
        # Check if PCAP file exists
        if not pcap_file.exists():
            result = ValidationResult(
                status=ValidationStatus.UNKNOWN,
                strategy_name=strategy_name,
                message=f"PCAP file not found: {pcap_file}"
            )
            self.validation_results.append(result)
            self.logger.warning(result.message)
            return result
        
        try:
            # Analyze PCAP
            self.logger.info(f"📊 Analyzing PCAP file: {pcap_file}")
            pcap_result = self.analyzer.analyze(pcap_file, domain)
            
            # Check for analysis errors
            if pcap_result.analysis_errors:
                result = ValidationResult(
                    status=ValidationStatus.UNKNOWN,
                    strategy_name=strategy_name,
                    message=f"PCAP analysis errors: {', '.join(pcap_result.analysis_errors)}"
                )
                self.validation_results.append(result)
                self.logger.warning(result.message)
                return result
            
            # If no strategy log, run PCAP-only analysis
            if not strategy_log:
                self.logger.info("No strategy log provided, running PCAP-only analysis")
                result = self._pcap_only_analysis(strategy_name, pcap_result, domain)
                self.validation_results.append(result)
                return result
            
            # Extract expected operations from log
            expected_ops = self._extract_expected_operations(strategy_log)
            
            # Extract actual operations from PCAP
            actual_ops = self._extract_actual_operations(pcap_result)
            
            # Compare operations
            result = self._compare_operations(
                strategy_name,
                expected_ops,
                actual_ops,
                pcap_result
            )
            
            self.validation_results.append(result)
            self.logger.info(
                f"Validation complete: status={result.status.value}, "
                f"expected={len(result.expected_operations)}, "
                f"actual={len(result.actual_operations)}, "
                f"missing={len(result.missing_operations)}"
            )
            
            return result
        
        except Exception as e:
            self.logger.error(f"Validation error: {e}", exc_info=True)
            result = ValidationResult(
                status=ValidationStatus.UNKNOWN,
                strategy_name=strategy_name,
                message=f"Validation error: {str(e)}"
            )
            self.validation_results.append(result)
            return result
    
    def _pcap_only_analysis(
        self,
        strategy_name: str,
        pcap_result: PCAPAnalysisResult,
        domain: str
    ) -> ValidationResult:
        """
        Perform PCAP-only analysis without operation log.
        
        This method analyzes PCAP to detect what strategies were applied,
        without comparing to expected operations.
        
        Args:
            strategy_name: Name of strategy
            pcap_result: PCAP analysis result
            domain: Domain name
            
        Returns:
            ValidationResult with detected operations
        """
        # Extract actual operations from PCAP
        actual_ops = self._extract_actual_operations(pcap_result)
        
        # Build operation details
        operation_details = {
            "clienthello_count": len(pcap_result.clienthello_packets),
            "split_detected": pcap_result.split_info.detected if pcap_result.split_info else False,
            "fake_packet_count": len(pcap_result.fake_packets),
            "disorder_detected": pcap_result.disorder_detected,
            "fooling_modes": pcap_result.fooling_modes,
            "total_packets": pcap_result.total_packets,
            "rst_packets": len(pcap_result.rst_packets) if hasattr(pcap_result, 'rst_packets') else 0
        }
        
        # Log detected operations
        self.logger.info(f"📊 PCAP Analysis Results for {domain}:")
        self.logger.info(f"   Total packets: {operation_details['total_packets']}")
        self.logger.info(f"   ClientHello packets: {operation_details['clienthello_count']}")
        
        if actual_ops:
            self.logger.info(f"   Detected operations: {', '.join(actual_ops)}")
        else:
            self.logger.info(f"   No DPI bypass operations detected")
        
        if operation_details['split_detected']:
            split_info = pcap_result.split_info
            self.logger.info(f"   Split: position={split_info.position}, fragments={split_info.fragment_count}")
        
        if operation_details['fake_packet_count'] > 0:
            self.logger.info(f"   Fake packets: {operation_details['fake_packet_count']}")
        
        if operation_details['disorder_detected']:
            self.logger.info(f"   Disorder: detected")
        
        # Determine status based on detected operations
        if actual_ops:
            status = ValidationStatus.PARTIAL  # Operations detected but no log to compare
            message = f"PCAP-only analysis: detected {len(actual_ops)} operation(s)"
        else:
            status = ValidationStatus.UNKNOWN  # No operations detected
            message = "PCAP-only analysis: no DPI bypass operations detected"
        
        return ValidationResult(
            status=status,
            strategy_name=strategy_name,
            expected_operations=[],  # No expected operations without log
            actual_operations=actual_ops,
            missing_operations=[],
            unexpected_operations=[],
            operation_details=operation_details,
            message=message
        )
    
    def _extract_expected_operations(self, strategy_log: Dict) -> List[str]:
        """
        Extract expected operations from strategy log.
        
        Args:
            strategy_log: Strategy log dictionary
            
        Returns:
            List of expected operation descriptions
            
        Requirements: 1.4
        """
        expected = []
        
        # Extract operations from log
        operations = strategy_log.get("operations", [])
        
        for op in operations:
            op_type = op.get("type", "unknown")
            params = op.get("params", {})
            
            if op_type == "split":
                position = params.get("position", 0)
                count = params.get("count", 0)
                expected.append(f"split:position={position},count={count}")
            
            elif op_type == "fake":
                ttl = params.get("ttl", 0)
                count = params.get("count", 0)
                expected.append(f"fake:ttl={ttl},count={count}")
            
            elif op_type == "disorder":
                expected.append("disorder")
            
            elif op_type == "fooling":
                mode = params.get("mode", "unknown")
                expected.append(f"fooling:{mode}")
            
            else:
                expected.append(f"{op_type}")
        
        self.logger.debug(f"Expected operations: {expected}")
        return expected
    
    def _extract_actual_operations(self, pcap_result: PCAPAnalysisResult) -> List[str]:
        """
        Extract actual operations from PCAP analysis.
        
        Args:
            pcap_result: PCAP analysis result
            
        Returns:
            List of actual operation descriptions
            
        Requirements: 1.4
        """
        actual = []
        
        # Check for split
        if pcap_result.split_info and pcap_result.split_info.detected:
            split_info = pcap_result.split_info
            actual.append(
                f"split:position={split_info.position},"
                f"count={split_info.fragment_count}"
            )
        
        # Check for fake packets
        if pcap_result.fake_packets:
            # Group by TTL
            ttl_counts = {}
            for fake in pcap_result.fake_packets:
                ttl_counts[fake.ttl] = ttl_counts.get(fake.ttl, 0) + 1
            
            for ttl, count in ttl_counts.items():
                actual.append(f"fake:ttl={ttl},count={count}")
        
        # Check for disorder
        if pcap_result.disorder_detected:
            actual.append("disorder")
        
        # Check for fooling modes
        for mode in pcap_result.fooling_modes:
            actual.append(f"fooling:{mode}")
        
        self.logger.debug(f"Actual operations: {actual}")
        return actual
    
    def _compare_operations(
        self,
        strategy_name: str,
        expected: List[str],
        actual: List[str],
        pcap_result: PCAPAnalysisResult
    ) -> ValidationResult:
        """
        Compare expected and actual operations.
        
        Args:
            strategy_name: Name of strategy
            expected: Expected operations
            actual: Actual operations
            pcap_result: PCAP analysis result
            
        Returns:
            ValidationResult
            
        Requirements: 1.4, 1.5
        """
        # Find missing operations (expected but not found)
        missing = []
        for exp_op in expected:
            if not self._operation_matches(exp_op, actual):
                missing.append(exp_op)
        
        # Find unexpected operations (found but not expected)
        unexpected = []
        for act_op in actual:
            if not self._operation_matches(act_op, expected):
                unexpected.append(act_op)
        
        # Build operation details
        operation_details = {
            "clienthello_count": len(pcap_result.clienthello_packets),
            "split_detected": pcap_result.split_info.detected if pcap_result.split_info else False,
            "fake_packet_count": len(pcap_result.fake_packets),
            "disorder_detected": pcap_result.disorder_detected,
            "fooling_modes": pcap_result.fooling_modes
        }
        
        # Determine status
        if not missing and not unexpected:
            status = ValidationStatus.VALID
            message = "All operations validated successfully"
        elif missing and not actual:
            status = ValidationStatus.INVALID
            message = f"No operations detected in PCAP. Missing: {', '.join(missing)}"
        elif missing:
            status = ValidationStatus.PARTIAL
            message = f"Some operations missing: {', '.join(missing)}"
        elif unexpected:
            status = ValidationStatus.PARTIAL
            message = f"Unexpected operations found: {', '.join(unexpected)}"
        else:
            status = ValidationStatus.VALID
            message = "Operations validated"
        
        return ValidationResult(
            status=status,
            strategy_name=strategy_name,
            expected_operations=expected,
            actual_operations=actual,
            missing_operations=missing,
            unexpected_operations=unexpected,
            operation_details=operation_details,
            message=message
        )
    
    def _operation_matches(self, operation: str, operation_list: List[str]) -> bool:
        """
        Check if operation matches any in the list.
        
        Handles fuzzy matching for operations with parameters.
        
        Args:
            operation: Operation to match
            operation_list: List of operations to search
            
        Returns:
            True if match found
        """
        # Extract operation type
        op_type = operation.split(":")[0]
        
        for op in operation_list:
            # Check if types match
            if op.split(":")[0] == op_type:
                # For simple operations (disorder), type match is enough
                if ":" not in operation and ":" not in op:
                    return True
                
                # For parameterized operations, check parameters
                if ":" in operation and ":" in op:
                    # Parse parameters
                    exp_params = self._parse_operation_params(operation)
                    act_params = self._parse_operation_params(op)
                    
                    # Check if parameters match (with tolerance)
                    if self._params_match(exp_params, act_params):
                        return True
        
        return False
    
    def _parse_operation_params(self, operation: str) -> Dict:
        """
        Parse operation parameters.
        
        Args:
            operation: Operation string (e.g., "split:position=5,count=6")
            
        Returns:
            Dictionary of parameters
        """
        params = {}
        
        if ":" not in operation:
            return params
        
        param_str = operation.split(":", 1)[1]
        
        for param in param_str.split(","):
            if "=" in param:
                key, value = param.split("=", 1)
                try:
                    params[key.strip()] = int(value.strip())
                except ValueError:
                    params[key.strip()] = value.strip()
        
        return params
    
    def _params_match(self, expected: Dict, actual: Dict) -> bool:
        """
        Check if parameters match with tolerance.
        
        Args:
            expected: Expected parameters
            actual: Actual parameters
            
        Returns:
            True if parameters match
        """
        # Check all expected parameters are present
        for key, exp_value in expected.items():
            if key not in actual:
                return False
            
            act_value = actual[key]
            
            # For numeric values, allow small tolerance
            if isinstance(exp_value, (int, float)) and isinstance(act_value, (int, float)):
                # Allow ±1 tolerance for positions and counts
                if abs(exp_value - act_value) > 1:
                    return False
            else:
                # Exact match for non-numeric
                if exp_value != act_value:
                    return False
        
        return True
    
    def generate_report(self) -> str:
        """
        Generate validation report for all validations.
        
        Returns:
            Formatted report string
            
        Requirements: 1.5
        """
        if not self.validation_results:
            return "No validation results available."
        
        report_lines = [
            "=" * 80,
            "STRATEGY VALIDATION REPORT",
            "=" * 80,
            ""
        ]
        
        # Summary
        total = len(self.validation_results)
        valid = sum(1 for r in self.validation_results if r.status == ValidationStatus.VALID)
        invalid = sum(1 for r in self.validation_results if r.status == ValidationStatus.INVALID)
        partial = sum(1 for r in self.validation_results if r.status == ValidationStatus.PARTIAL)
        unknown = sum(1 for r in self.validation_results if r.status == ValidationStatus.UNKNOWN)
        
        report_lines.extend([
            f"Total Validations: {total}",
            f"  ✓ VALID:   {valid}",
            f"  ✗ INVALID: {invalid}",
            f"  ~ PARTIAL: {partial}",
            f"  ? UNKNOWN: {unknown}",
            ""
        ])
        
        # Detailed results
        report_lines.append("DETAILED RESULTS:")
        report_lines.append("-" * 80)
        
        for idx, result in enumerate(self.validation_results, 1):
            status_symbol = {
                ValidationStatus.VALID: "✓",
                ValidationStatus.INVALID: "✗",
                ValidationStatus.PARTIAL: "~",
                ValidationStatus.UNKNOWN: "?"
            }.get(result.status, "?")
            
            report_lines.extend([
                "",
                f"{idx}. [{status_symbol}] {result.strategy_name} - {result.status.value.upper()}",
                f"   Message: {result.message}"
            ])
            
            if result.expected_operations:
                report_lines.append(f"   Expected: {', '.join(result.expected_operations)}")
            
            if result.actual_operations:
                report_lines.append(f"   Actual:   {', '.join(result.actual_operations)}")
            
            if result.missing_operations:
                report_lines.append(f"   Missing:  {', '.join(result.missing_operations)}")
            
            if result.unexpected_operations:
                report_lines.append(f"   Unexpected: {', '.join(result.unexpected_operations)}")
            
            if result.operation_details:
                report_lines.append("   Details:")
                for key, value in result.operation_details.items():
                    report_lines.append(f"     - {key}: {value}")
        
        report_lines.extend([
            "",
            "=" * 80
        ])
        
        report = "\n".join(report_lines)
        self.logger.info("Generated validation report")
        return report
    
    def clear_results(self):
        """Clear all validation results."""
        self.validation_results.clear()
        self.logger.info("Cleared validation results")
    
    def save_results(self, output_file: Path):
        """
        Save validation results to JSON file.
        
        Args:
            output_file: Path to output file
        """
        try:
            results_data = {
                "total": len(self.validation_results),
                "summary": {
                    "valid": sum(1 for r in self.validation_results if r.status == ValidationStatus.VALID),
                    "invalid": sum(1 for r in self.validation_results if r.status == ValidationStatus.INVALID),
                    "partial": sum(1 for r in self.validation_results if r.status == ValidationStatus.PARTIAL),
                    "unknown": sum(1 for r in self.validation_results if r.status == ValidationStatus.UNKNOWN)
                },
                "results": [r.to_dict() for r in self.validation_results]
            }
            
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Saved validation results to {output_file}")
        
        except Exception as e:
            self.logger.error(f"Error saving results: {e}", exc_info=True)
