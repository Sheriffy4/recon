#!/usr/bin/env python3
"""
Migration Validation Tool

Automated tool for validating attack migrations and ensuring backward compatibility.
Provides comprehensive testing and reporting for migration quality assurance.
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
import importlib.util

from core.bypass.attacks.base import BaseAttack, AttackContext, AttackStatus
from core.bypass.attacks.compatibility.backward_compatibility_manager import (
    BackwardCompatibilityManager,
    CompatibilityReport,
    CompatibilityMode
)
from core.bypass.attacks.compatibility.migration_utilities import (
    AttackMigrationUtility,
    MigrationTemplate
)


@dataclass
class ValidationResult:
    """Result of migration validation."""
    attack_name: str
    validation_passed: bool
    compatibility_score: float  # 0.0 to 1.0
    performance_score: float    # 0.0 to 1.0
    functionality_score: float  # 0.0 to 1.0
    issues: List[str]
    recommendations: List[str]
    test_results: Dict[str, Any]
    performance_metrics: Dict[str, float]


class MigrationValidationTool:
    """
    Comprehensive tool for validating attack migrations.
    
    Features:
    - Automated compatibility testing
    - Performance benchmarking
    - Functionality validation
    - Regression testing
    - Report generation
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir or Path("migration_reports")
        self.output_dir.mkdir(exist_ok=True)
        
        self.compatibility_manager = BackwardCompatibilityManager()
        self.migration_utility = AttackMigrationUtility()
        
        # Test contexts for validation
        self.test_contexts = self._create_test_contexts()
    
    def _create_test_contexts(self) -> List[AttackContext]:
        """Create comprehensive test contexts for validation."""
        return [
            # HTTP GET request
            AttackContext(
                dst_ip="192.168.1.1",
                dst_port=80,
                payload=b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                connection_id="http_get_test"
            ),
            
            # HTTP POST with auth
            AttackContext(
                dst_ip="10.0.0.1",
                dst_port=443,
                payload=b"POST /api/login HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer token123\r\nContent-Type: application/json\r\n\r\n{\"username\":\"admin\",\"password\":\"secret\"}",
                connection_id="http_post_auth_test"
            ),
            
            # Large payload
            AttackContext(
                dst_ip="203.0.113.10",
                dst_port=8080,
                payload=b"PUT /upload HTTP/1.1\r\nHost: upload.example.com\r\nContent-Length: 2048\r\n\r\n" + b"X" * 2000,
                connection_id="large_payload_test"
            ),
            
            # Small payload
            AttackContext(
                dst_ip="198.51.100.1",
                dst_port=22,
                payload=b"SSH-2.0-OpenSSH_8.0",
                connection_id="small_payload_test"
            ),
            
            # Binary data
            AttackContext(
                dst_ip="172.16.0.1",
                dst_port=3306,
                payload=bytes(range(256)),  # All byte values
                connection_id="binary_data_test"
            )
        ]
    
    def validate_single_attack(self, attack_class: type, 
                             reference_attack_class: Optional[type] = None) -> ValidationResult:
        """
        Validate a single migrated attack.
        
        Args:
            attack_class: Migrated attack class to validate
            reference_attack_class: Optional legacy attack for comparison
            
        Returns:
            ValidationResult with comprehensive validation data
        """
        attack_name = attack_class.__name__
        self.logger.info(f"Validating attack: {attack_name}")
        
        issues = []
        recommendations = []
        test_results = {}
        performance_metrics = {}
        
        try:
            # Create attack instance
            attack = attack_class()
            
            # 1. Compatibility Testing
            compatibility_score, compatibility_issues = self._test_compatibility(attack)
            issues.extend(compatibility_issues)
            test_results['compatibility'] = compatibility_score
            
            # 2. Functionality Testing
            functionality_score, functionality_issues = self._test_functionality(attack)
            issues.extend(functionality_issues)
            test_results['functionality'] = functionality_score
            
            # 3. Performance Testing
            performance_score, perf_metrics = self._test_performance(attack)
            performance_metrics.update(perf_metrics)
            test_results['performance'] = performance_score
            
            # 4. Interface Compliance Testing
            interface_score, interface_issues = self._test_interface_compliance(attack)
            issues.extend(interface_issues)
            test_results['interface'] = interface_score
            
            # 5. Regression Testing (if reference provided)
            if reference_attack_class:
                regression_score, regression_issues = self._test_regression(attack, reference_attack_class)
                issues.extend(regression_issues)
                test_results['regression'] = regression_score
            else:
                test_results['regression'] = 1.0  # No regression test
            
            # Calculate overall scores
            overall_compatibility = compatibility_score
            overall_performance = performance_score
            overall_functionality = (functionality_score + interface_score + test_results['regression']) / 3
            
            # Generate recommendations
            recommendations = self._generate_recommendations(test_results, issues)
            
            # Determine if validation passed
            validation_passed = (
                compatibility_score >= 0.8 and
                performance_score >= 0.7 and
                functionality_score >= 0.8 and
                interface_score >= 0.9
            )
            
            return ValidationResult(
                attack_name=attack_name,
                validation_passed=validation_passed,
                compatibility_score=overall_compatibility,
                performance_score=overall_performance,
                functionality_score=overall_functionality,
                issues=issues,
                recommendations=recommendations,
                test_results=test_results,
                performance_metrics=performance_metrics
            )
            
        except Exception as e:
            self.logger.error(f"Validation failed for {attack_name}: {e}")
            return ValidationResult(
                attack_name=attack_name,
                validation_passed=False,
                compatibility_score=0.0,
                performance_score=0.0,
                functionality_score=0.0,
                issues=[f"Validation error: {str(e)}"],
                recommendations=["Fix critical errors before proceeding"],
                test_results={},
                performance_metrics={}
            )
    
    def _test_compatibility(self, attack: BaseAttack) -> Tuple[float, List[str]]:
        """Test attack compatibility with segment system."""
        issues = []
        
        try:
            # Check compatibility report
            report = self.compatibility_manager.check_attack_compatibility(attack)
            
            # Score based on compatibility features
            score = 0.0
            
            if report.has_segments_support:
                score += 0.6
            else:
                issues.append("Attack does not support segments architecture")
            
            if report.has_legacy_support:
                score += 0.2
            
            if not report.migration_required:
                score += 0.2
            else:
                issues.append("Attack requires migration")
            
            # Test execution with compatibility manager
            try:
                test_context = self.test_contexts[0]
                result = self.compatibility_manager.execute_with_fallback(attack, test_context)
                
                if result.status == AttackStatus.SUCCESS:
                    score = max(score, 0.8)  # Successful execution is good
                else:
                    issues.append(f"Compatibility execution failed: {result.error_message}")
                    score = min(score, 0.5)
                    
            except Exception as e:
                issues.append(f"Compatibility execution error: {str(e)}")
                score = min(score, 0.3)
            
            return min(1.0, score), issues
            
        except Exception as e:
            issues.append(f"Compatibility test error: {str(e)}")
            return 0.0, issues
    
    def _test_functionality(self, attack: BaseAttack) -> Tuple[float, List[str]]:
        """Test attack functionality across different contexts."""
        issues = []
        successful_tests = 0
        total_tests = len(self.test_contexts)
        
        for i, context in enumerate(self.test_contexts):
            try:
                result = attack.execute(context)
                
                if result.status == AttackStatus.SUCCESS:
                    successful_tests += 1
                    
                    # Check segments
                    if not hasattr(result, '_segments') or not result._segments:
                        issues.append(f"Test {i+1}: No segments generated")
                    else:
                        # Validate segment format
                        for j, segment in enumerate(result._segments):
                            if not isinstance(segment, tuple) or len(segment) != 3:
                                issues.append(f"Test {i+1}, Segment {j+1}: Invalid format")
                            else:
                                payload, offset, options = segment
                                if not isinstance(payload, bytes):
                                    issues.append(f"Test {i+1}, Segment {j+1}: Payload not bytes")
                                if not isinstance(offset, int) or offset < 0:
                                    issues.append(f"Test {i+1}, Segment {j+1}: Invalid offset")
                                if not isinstance(options, dict):
                                    issues.append(f"Test {i+1}, Segment {j+1}: Options not dict")
                else:
                    issues.append(f"Test {i+1}: Execution failed - {result.error_message}")
                    
            except Exception as e:
                issues.append(f"Test {i+1}: Exception - {str(e)}")
        
        functionality_score = successful_tests / total_tests if total_tests > 0 else 0.0
        return functionality_score, issues
    
    def _test_performance(self, attack: BaseAttack) -> Tuple[float, Dict[str, float]]:
        """Test attack performance."""
        metrics = {}
        
        try:
            # Test with medium-sized payload
            test_context = self.test_contexts[2]  # Large payload context
            
            # Warmup
            for _ in range(5):
                attack.execute(test_context)
            
            # Measure performance
            times = []
            for _ in range(20):
                start_time = time.time()
                result = attack.execute(test_context)
                execution_time = time.time() - start_time
                times.append(execution_time)
                
                if result.status != AttackStatus.SUCCESS:
                    break
            
            if times:
                avg_time = sum(times) / len(times)
                min_time = min(times)
                max_time = max(times)
                
                metrics['avg_execution_time'] = avg_time
                metrics['min_execution_time'] = min_time
                metrics['max_execution_time'] = max_time
                metrics['execution_consistency'] = 1.0 - (max_time - min_time) / avg_time if avg_time > 0 else 0.0
                
                # Score based on performance
                if avg_time < 0.01:  # < 10ms
                    performance_score = 1.0
                elif avg_time < 0.05:  # < 50ms
                    performance_score = 0.8
                elif avg_time < 0.1:   # < 100ms
                    performance_score = 0.6
                else:
                    performance_score = 0.4
                
                # Adjust for consistency
                performance_score *= metrics['execution_consistency']
                
            else:
                performance_score = 0.0
                metrics['error'] = 'No successful executions'
            
            return performance_score, metrics
            
        except Exception as e:
            return 0.0, {'error': str(e)}
    
    def _test_interface_compliance(self, attack: BaseAttack) -> Tuple[float, List[str]]:
        """Test interface compliance."""
        issues = []
        score = 0.0
        
        required_methods = [
            'execute', 'validate_context', 'estimate_effectiveness',
            'get_required_capabilities', 'get_attack_info'
        ]
        
        # Check method presence
        methods_present = 0
        for method_name in required_methods:
            if hasattr(attack, method_name) and callable(getattr(attack, method_name)):
                methods_present += 1
            else:
                issues.append(f"Missing required method: {method_name}")
        
        score += (methods_present / len(required_methods)) * 0.6
        
        # Test method functionality
        try:
            test_context = self.test_contexts[0]
            
            # Test validate_context
            if hasattr(attack, 'validate_context'):
                is_valid, error = attack.validate_context(test_context)
                if isinstance(is_valid, bool):
                    score += 0.1
                else:
                    issues.append("validate_context should return bool")
            
            # Test estimate_effectiveness
            if hasattr(attack, 'estimate_effectiveness'):
                effectiveness = attack.estimate_effectiveness(test_context)
                if isinstance(effectiveness, (int, float)) and 0.0 <= effectiveness <= 1.0:
                    score += 0.1
                else:
                    issues.append("estimate_effectiveness should return float between 0.0 and 1.0")
            
            # Test get_required_capabilities
            if hasattr(attack, 'get_required_capabilities'):
                capabilities = attack.get_required_capabilities()
                if isinstance(capabilities, list):
                    score += 0.1
                else:
                    issues.append("get_required_capabilities should return list")
            
            # Test get_attack_info
            if hasattr(attack, 'get_attack_info'):
                info = attack.get_attack_info()
                if isinstance(info, dict):
                    score += 0.1
                    required_keys = ['name', 'type', 'description']
                    for key in required_keys:
                        if key not in info:
                            issues.append(f"get_attack_info missing key: {key}")
                else:
                    issues.append("get_attack_info should return dict")
            
        except Exception as e:
            issues.append(f"Interface testing error: {str(e)}")
        
        return min(1.0, score), issues
    
    def _test_regression(self, migrated_attack: BaseAttack, 
                        reference_attack: type) -> Tuple[float, List[str]]:
        """Test for regression compared to reference attack."""
        issues = []
        
        try:
            reference = reference_attack()
            
            # Compare effectiveness
            effectiveness_scores = []
            for context in self.test_contexts[:3]:  # Test subset
                try:
                    migrated_eff = migrated_attack.estimate_effectiveness(context)
                    reference_eff = reference.estimate_effectiveness(context) if hasattr(reference, 'estimate_effectiveness') else 0.5
                    
                    effectiveness_scores.append(migrated_eff / reference_eff if reference_eff > 0 else 1.0)
                    
                except Exception:
                    effectiveness_scores.append(0.5)  # Neutral score on error
            
            avg_effectiveness_ratio = sum(effectiveness_scores) / len(effectiveness_scores)
            
            if avg_effectiveness_ratio < 0.8:
                issues.append(f"Effectiveness regression: {avg_effectiveness_ratio:.2f} of reference")
            
            # Compare execution success
            migrated_successes = 0
            reference_successes = 0
            
            for context in self.test_contexts[:3]:
                try:
                    migrated_result = migrated_attack.execute(context)
                    if migrated_result.status == AttackStatus.SUCCESS:
                        migrated_successes += 1
                except Exception:
                    pass
                
                try:
                    reference_result = reference.execute(context)
                    if reference_result.status == AttackStatus.SUCCESS:
                        reference_successes += 1
                except Exception:
                    pass
            
            success_ratio = migrated_successes / reference_successes if reference_successes > 0 else 1.0
            
            if success_ratio < 1.0:
                issues.append(f"Success rate regression: {success_ratio:.2f} of reference")
            
            # Overall regression score
            regression_score = min(avg_effectiveness_ratio, success_ratio)
            return min(1.0, regression_score), issues
            
        except Exception as e:
            issues.append(f"Regression test error: {str(e)}")
            return 0.5, issues
    
    def _generate_recommendations(self, test_results: Dict[str, Any], 
                                issues: List[str]) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []
        
        # Compatibility recommendations
        if test_results.get('compatibility', 0) < 0.8:
            recommendations.append("Improve segments architecture support")
            recommendations.append("Ensure proper AttackResult format with _segments")
        
        # Performance recommendations
        if test_results.get('performance', 0) < 0.7:
            recommendations.append("Optimize execution performance")
            recommendations.append("Consider reducing segment count or payload processing")
        
        # Functionality recommendations
        if test_results.get('functionality', 0) < 0.8:
            recommendations.append("Fix functionality issues across different payload types")
            recommendations.append("Improve error handling and validation")
        
        # Interface recommendations
        if test_results.get('interface', 0) < 0.9:
            recommendations.append("Implement all required interface methods")
            recommendations.append("Ensure method return types match specifications")
        
        # Regression recommendations
        if test_results.get('regression', 1.0) < 0.8:
            recommendations.append("Address regression issues compared to reference implementation")
            recommendations.append("Ensure migrated attack maintains or improves effectiveness")
        
        # Issue-specific recommendations
        if any("segments" in issue.lower() for issue in issues):
            recommendations.append("Review segment generation logic")
        
        if any("performance" in issue.lower() for issue in issues):
            recommendations.append("Profile and optimize performance bottlenecks")
        
        return list(set(recommendations))  # Remove duplicates
    
    def validate_multiple_attacks(self, attack_classes: List[type], 
                                reference_classes: Optional[List[type]] = None) -> List[ValidationResult]:
        """Validate multiple attacks."""
        results = []
        
        for i, attack_class in enumerate(attack_classes):
            reference_class = reference_classes[i] if reference_classes and i < len(reference_classes) else None
            result = self.validate_single_attack(attack_class, reference_class)
            results.append(result)
        
        return results
    
    def generate_report(self, results: List[ValidationResult], 
                       output_file: Optional[Path] = None) -> Dict[str, Any]:
        """Generate comprehensive validation report."""
        if not output_file:
            timestamp = int(time.time())
            output_file = self.output_dir / f"migration_validation_report_{timestamp}.json"
        
        # Calculate summary statistics
        total_attacks = len(results)
        passed_attacks = sum(1 for r in results if r.validation_passed)
        
        avg_compatibility = sum(r.compatibility_score for r in results) / total_attacks if total_attacks > 0 else 0
        avg_performance = sum(r.performance_score for r in results) / total_attacks if total_attacks > 0 else 0
        avg_functionality = sum(r.functionality_score for r in results) / total_attacks if total_attacks > 0 else 0
        
        # Collect all issues and recommendations
        all_issues = []
        all_recommendations = []
        for result in results:
            all_issues.extend(result.issues)
            all_recommendations.extend(result.recommendations)
        
        # Generate report
        report = {
            "summary": {
                "total_attacks": total_attacks,
                "passed_attacks": passed_attacks,
                "pass_rate": passed_attacks / total_attacks if total_attacks > 0 else 0,
                "average_compatibility_score": avg_compatibility,
                "average_performance_score": avg_performance,
                "average_functionality_score": avg_functionality
            },
            "results": [asdict(result) for result in results],
            "common_issues": list(set(all_issues)),
            "common_recommendations": list(set(all_recommendations)),
            "generated_at": time.time()
        }
        
        # Save report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Validation report saved to: {output_file}")
        return report
    
    def print_summary(self, results: List[ValidationResult]):
        """Print validation summary to console."""
        print("\n" + "=" * 60)
        print("MIGRATION VALIDATION SUMMARY")
        print("=" * 60)
        
        total = len(results)
        passed = sum(1 for r in results if r.validation_passed)
        
        print(f"Total attacks validated: {total}")
        print(f"Passed validation: {passed}")
        print(f"Pass rate: {passed/total*100:.1f}%" if total > 0 else "Pass rate: N/A")
        
        if results:
            avg_compat = sum(r.compatibility_score for r in results) / total
            avg_perf = sum(r.performance_score for r in results) / total
            avg_func = sum(r.functionality_score for r in results) / total
            
            print(f"\nAverage Scores:")
            print(f"  Compatibility: {avg_compat:.2f}")
            print(f"  Performance:   {avg_perf:.2f}")
            print(f"  Functionality: {avg_func:.2f}")
        
        print("\nIndividual Results:")
        for result in results:
            status = "✓ PASS" if result.validation_passed else "✗ FAIL"
            print(f"  {result.attack_name}: {status} (C:{result.compatibility_score:.2f} P:{result.performance_score:.2f} F:{result.functionality_score:.2f})")
        
        # Show common issues
        all_issues = []
        for result in results:
            all_issues.extend(result.issues)
        
        if all_issues:
            print(f"\nCommon Issues ({len(set(all_issues))} unique):")
            for issue in sorted(set(all_issues)):
                print(f"  - {issue}")


def load_attack_class_from_file(file_path: Path, class_name: str) -> Optional[type]:
    """Load attack class from Python file."""
    try:
        spec = importlib.util.spec_from_file_location("attack_module", file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        if hasattr(module, class_name):
            return getattr(module, class_name)
        else:
            print(f"Class {class_name} not found in {file_path}")
            return None
            
    except Exception as e:
        print(f"Error loading {class_name} from {file_path}: {e}")
        return None


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(description="Migration Validation Tool")
    parser.add_argument("--attack-file", type=Path, help="Python file containing attack class")
    parser.add_argument("--attack-class", type=str, help="Attack class name to validate")
    parser.add_argument("--reference-file", type=Path, help="Python file containing reference attack class")
    parser.add_argument("--reference-class", type=str, help="Reference attack class name")
    parser.add_argument("--output-dir", type=Path, default=Path("migration_reports"), help="Output directory for reports")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Create validation tool
    tool = MigrationValidationTool(args.output_dir)
    
    if args.attack_file and args.attack_class:
        # Validate single attack
        attack_class = load_attack_class_from_file(args.attack_file, args.attack_class)
        if not attack_class:
            sys.exit(1)
        
        reference_class = None
        if args.reference_file and args.reference_class:
            reference_class = load_attack_class_from_file(args.reference_file, args.reference_class)
        
        print(f"Validating {args.attack_class}...")
        result = tool.validate_single_attack(attack_class, reference_class)
        
        # Generate and save report
        report = tool.generate_report([result])
        tool.print_summary([result])
        
        if result.validation_passed:
            print(f"\n✓ {args.attack_class} passed validation!")
            sys.exit(0)
        else:
            print(f"\n✗ {args.attack_class} failed validation.")
            print("Issues:")
            for issue in result.issues:
                print(f"  - {issue}")
            print("Recommendations:")
            for rec in result.recommendations:
                print(f"  - {rec}")
            sys.exit(1)
    
    else:
        print("Usage: python migration_validation_tool.py --attack-file <file> --attack-class <class>")
        print("Example: python migration_validation_tool.py --attack-file my_attack.py --attack-class MyAttack")
        sys.exit(1)


if __name__ == "__main__":
    main()