#!/usr/bin/env python3
"""
Fingerprint Accuracy Validator - Task 19 Implementation
Validates fingerprint accuracy against known DPI systems and provides comprehensive testing.

Requirements: 1.1, 1.2, 1.3, 1.4, 6.1, 6.2, 6.3, 6.4
"""

import asyncio
import logging
import time
import json
import statistics
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from enhanced_dpi_detector_task19 import EnhancedDPIDetector, ModernDPIType

LOG = logging.getLogger("fingerprint_accuracy_validator_task19")


@dataclass
class ValidationTestCase:
    """Test case for fingerprint validation"""
    test_id: str
    domain: str
    expected_dpi_type: str
    expected_confidence_min: float
    expected_strategies: List[str]
    network_simulation_data: Dict[str, Any]
    description: str


@dataclass
class AccuracyTestResult:
    """Result of accuracy testing"""
    test_id: str
    domain: str
    expected_dpi_type: str
    detected_dpi_type: Optional[str]
    expected_confidence: float
    actual_confidence: float
    confidence_accurate: bool
    dpi_type_accurate: bool
    strategy_recommendations: List[str]
    strategy_accuracy: float
    false_positive: bool
    false_negative: bool
    test_duration: float
    error_details: Optional[str]
    timestamp: datetime


@dataclass
class ValidationSummary:
    """Summary of validation results"""
    total_tests: int
    accurate_detections: int
    inaccurate_detections: int
    false_positives: int
    false_negatives: int
    average_confidence_accuracy: float
    average_strategy_accuracy: float
    overall_accuracy: float
    performance_metrics: Dict[str, float]


class FingerprintAccuracyValidator:
    """
    Validates fingerprint accuracy against known DPI systems.
    
    Features:
    - Tests against comprehensive DPI system database
    - Validates detection accuracy and confidence scores
    - Tests strategy recommendation quality
    - Measures false positive/negative rates
    - Performance benchmarking
    - Regression testing capabilities
    """
    
    def __init__(self):
        self.enhanced_detector = EnhancedDPIDetector()
        self.test_cases = self._load_validation_test_cases()
        self.test_results: List[AccuracyTestResult] = []
        self.validation_history: List[ValidationSummary] = []
        
    def _load_validation_test_cases(self) -> List[ValidationTestCase]:
        """Load comprehensive validation test cases"""
        
        test_cases = []
        
        # Roskomnadzor TSPU test cases
        test_cases.extend([
            ValidationTestCase(
                test_id="tspu_001",
                domain="blocked-site.ru",
                expected_dpi_type="roskomnadzor_tspu",
                expected_confidence_min=0.70,
                expected_strategies=[
                    "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                    "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq"
                ],
                network_simulation_data={
                    "rst_ttl": 62,
                    "rst_from_target": False,
                    "tls_fingerprint_blocking": True,
                    "encrypted_sni_blocking": True,
                    "timing_correlation_detection": True,
                    "statistical_anomaly_detection": True,
                    "processing_latency_ms": 25.0
                },
                description="Roskomnadzor TSPU with typical RST injection pattern"
            ),
            ValidationTestCase(
                test_id="tspu_002",
                domain="social-media.com",
                expected_dpi_type="roskomnadzor_tspu",
                expected_confidence_min=0.65,
                expected_strategies=[
                    "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum",
                    "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-fooling=badseq"
                ],
                network_simulation_data={
                    "rst_ttl": 64,
                    "rst_from_target": False,
                    "tls_fingerprint_blocking": True,
                    "encrypted_sni_blocking": True,
                    "statistical_anomaly_detection": True,
                    "processing_latency_ms": 15.0
                },
                description="Roskomnadzor TSPU with encrypted SNI blocking"
            )
        ])
        
        # Sandvine test cases
        test_cases.extend([
            ValidationTestCase(
                test_id="sandvine_001",
                domain="streaming-service.com",
                expected_dpi_type="sandvine",
                expected_confidence_min=0.75,
                expected_strategies=[
                    "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-fooling=badsum",
                    "--dpi-desync=disorder --dpi-desync-split-pos=midsld"
                ],
                network_simulation_data={
                    "rst_ttl": 128,
                    "tcp_options": [2, 4, 8],
                    "application_layer_inspection": True,
                    "protocol_anomaly_detection": True,
                    "traffic_flow_analysis": True,
                    "rate_limiting_sophistication": 4,
                    "threat_intelligence_integration": True
                },
                description="Sandvine with application layer inspection"
            )
        ])
        
        # Great Firewall test cases
        test_cases.extend([
            ValidationTestCase(
                test_id="gfw_001",
                domain="foreign-news.org",
                expected_dpi_type="gfw",
                expected_confidence_min=0.70,
                expected_strategies=[
                    "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq",
                    "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10"
                ],
                network_simulation_data={
                    "rst_from_target": False,
                    "icmp_ttl_exceeded": True,
                    "ja3_fingerprint_detected": True,
                    "certificate_transparency_monitoring": True,
                    "machine_learning_classification": True,
                    "geo_blocking_patterns": True
                },
                description="Great Firewall with ML classification"
            )
        ])
        
        # Cloudflare Security test cases
        test_cases.extend([
            ValidationTestCase(
                test_id="cloudflare_001",
                domain="protected-site.com",
                expected_dpi_type="cloudflare_security",
                expected_confidence_min=0.80,
                expected_strategies=[
                    "--dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fooling=badsum",
                    "--dpi-desync=multisplit --dpi-desync-split-count=3"
                ],
                network_simulation_data={
                    "cdn_edge_detection": True,
                    "load_balancer_fingerprinting": True,
                    "http2_frame_analysis": True,
                    "quic_connection_id_tracking": True,
                    "rate_limiting_sophistication": 4,
                    "processing_latency_ms": 5.0,
                    "machine_learning_classification": True
                },
                description="Cloudflare edge security with advanced features"
            )
        ])
        
        # AWS WAF test cases
        test_cases.extend([
            ValidationTestCase(
                test_id="aws_waf_001",
                domain="cloud-app.amazonaws.com",
                expected_dpi_type="aws_waf",
                expected_confidence_min=0.75,
                expected_strategies=[
                    "--dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fooling=badsum",
                    "--dpi-desync=disorder --dpi-desync-split-pos=midsld"
                ],
                network_simulation_data={
                    "application_layer_inspection": True,
                    "machine_learning_classification": True,
                    "geo_blocking_patterns": True,
                    "rate_limiting_sophistication": 3,
                    "threat_intelligence_integration": True,
                    "statistical_anomaly_detection": True,
                    "processing_latency_ms": 15.0
                },
                description="AWS WAF with ML-powered protection"
            )
        ])
        
        # ML-based DPI test cases
        test_cases.extend([
            ValidationTestCase(
                test_id="ml_dpi_001",
                domain="ai-protected.com",
                expected_dpi_type="ml_based_dpi",
                expected_confidence_min=0.65,
                expected_strategies=[
                    "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=random --dpi-desync-fooling=badseq",
                    "--dpi-desync=disorder --dpi-desync-split-pos=random --dpi-desync-fooling=md5sig"
                ],
                network_simulation_data={
                    "machine_learning_classification": True,
                    "statistical_anomaly_detection": True,
                    "timing_correlation_detection": True,
                    "processing_latency_ms": 45.0
                },
                description="ML-based DPI with advanced AI classification"
            )
        ])
        
        # Unknown/New pattern test cases
        test_cases.extend([
            ValidationTestCase(
                test_id="unknown_001",
                domain="mystery-dpi.test",
                expected_dpi_type="unknown",
                expected_confidence_min=0.0,
                expected_strategies=[
                    "--dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fooling=badsum"
                ],
                network_simulation_data={
                    "novel_detection_method": True,
                    "unknown_fingerprint_pattern": True,
                    "experimental_blocking": True
                },
                description="Unknown DPI system for new pattern detection testing"
            )
        ])
        
        return test_cases
    
    async def run_comprehensive_validation(self) -> ValidationSummary:
        """Run comprehensive fingerprint accuracy validation"""
        
        LOG.info(f"Starting comprehensive fingerprint validation with {len(self.test_cases)} test cases")
        
        start_time = time.time()
        self.test_results.clear()
        
        # Run all test cases
        for test_case in self.test_cases:
            LOG.info(f"Running test case: {test_case.test_id} - {test_case.description}")
            
            result = await self._run_single_test_case(test_case)
            self.test_results.append(result)
            
            # Log immediate result
            if result.dpi_type_accurate:
                LOG.info(f"  ✓ DPI type correctly detected: {result.detected_dpi_type}")
            else:
                LOG.warning(f"  ✗ DPI type mismatch: expected {result.expected_dpi_type}, got {result.detected_dpi_type}")
            
            if result.confidence_accurate:
                LOG.info(f"  ✓ Confidence acceptable: {result.actual_confidence:.2f}")
            else:
                LOG.warning(f"  ✗ Low confidence: {result.actual_confidence:.2f} < {result.expected_confidence:.2f}")
        
        total_time = time.time() - start_time
        
        # Generate validation summary
        summary = self._generate_validation_summary(total_time)
        self.validation_history.append(summary)
        
        # Save detailed results
        await self._save_validation_results(summary)
        
        LOG.info(f"Validation completed in {total_time:.2f}s")
        LOG.info(f"Overall accuracy: {summary.overall_accuracy:.2%}")
        
        return summary
    
    async def _run_single_test_case(self, test_case: ValidationTestCase) -> AccuracyTestResult:
        """Run a single validation test case"""
        
        start_time = time.time()
        
        try:
            # Run fingerprinting with test data
            signature = self.enhanced_detector.detect_dpi_system(test_case.network_simulation_data)
            
            test_duration = time.time() - start_time
            
            if signature:
                # Evaluate detection accuracy
                detected_dpi_type = signature.dpi_type.value
                actual_confidence = signature.confidence
                
                # Get strategy recommendations from detection rules
                strategy_recommendations = self._get_strategy_recommendations(signature.dpi_type)
                
                # Check DPI type accuracy
                dpi_type_accurate = self._is_dpi_type_accurate(
                    test_case.expected_dpi_type,
                    detected_dpi_type
                )
                
                # Check confidence accuracy
                confidence_accurate = actual_confidence >= test_case.expected_confidence_min
                
                # Evaluate strategy recommendations
                strategy_accuracy = self._evaluate_strategy_accuracy(
                    test_case.expected_strategies,
                    strategy_recommendations
                )
                
                # Determine false positive/negative
                false_positive = (
                    test_case.expected_dpi_type == "unknown" and
                    detected_dpi_type != "unknown"
                )
                false_negative = (
                    test_case.expected_dpi_type != "unknown" and
                    detected_dpi_type == "unknown"
                )
                
                return AccuracyTestResult(
                    test_id=test_case.test_id,
                    domain=test_case.domain,
                    expected_dpi_type=test_case.expected_dpi_type,
                    detected_dpi_type=detected_dpi_type,
                    expected_confidence=test_case.expected_confidence_min,
                    actual_confidence=actual_confidence,
                    confidence_accurate=confidence_accurate,
                    dpi_type_accurate=dpi_type_accurate,
                    strategy_recommendations=strategy_recommendations,
                    strategy_accuracy=strategy_accuracy,
                    false_positive=false_positive,
                    false_negative=false_negative,
                    test_duration=test_duration,
                    error_details=None,
                    timestamp=datetime.now()
                )
            
            else:
                # Fingerprinting failed
                return AccuracyTestResult(
                    test_id=test_case.test_id,
                    domain=test_case.domain,
                    expected_dpi_type=test_case.expected_dpi_type,
                    detected_dpi_type=None,
                    expected_confidence=test_case.expected_confidence_min,
                    actual_confidence=0.0,
                    confidence_accurate=False,
                    dpi_type_accurate=False,
                    strategy_recommendations=[],
                    strategy_accuracy=0.0,
                    false_positive=False,
                    false_negative=test_case.expected_dpi_type != "unknown",
                    test_duration=test_duration,
                    error_details="Fingerprinting returned no result",
                    timestamp=datetime.now()
                )
        
        except Exception as e:
            test_duration = time.time() - start_time
            
            LOG.error(f"Test case {test_case.test_id} failed: {e}")
            
            return AccuracyTestResult(
                test_id=test_case.test_id,
                domain=test_case.domain,
                expected_dpi_type=test_case.expected_dpi_type,
                detected_dpi_type=None,
                expected_confidence=test_case.expected_confidence_min,
                actual_confidence=0.0,
                confidence_accurate=False,
                dpi_type_accurate=False,
                strategy_recommendations=[],
                strategy_accuracy=0.0,
                false_positive=False,
                false_negative=test_case.expected_dpi_type != "unknown",
                test_duration=test_duration,
                error_details=str(e),
                timestamp=datetime.now()
            )
    
    def _get_strategy_recommendations(self, dpi_type: ModernDPIType) -> List[str]:
        """Get strategy recommendations for detected DPI type"""
        
        # Find the detection rule for this DPI type
        for rule in self.enhanced_detector.detection_rules:
            if rule.dpi_type == dpi_type:
                return rule.strategy_recommendations
        
        # Fallback strategies
        return ["--dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fooling=badsum"]
    
    def _is_dpi_type_accurate(self, expected: str, detected: Optional[str]) -> bool:
        """Check if detected DPI type is accurate"""
        
        if detected is None:
            return expected == "unknown"
        
        # Exact match
        if expected == detected:
            return True
        
        # Fuzzy matching for similar types
        expected_lower = expected.lower()
        detected_lower = detected.lower()
        
        # Check for partial matches
        if "roskomnadzor" in expected_lower and "roskomnadzor" in detected_lower:
            return True
        if "sandvine" in expected_lower and "sandvine" in detected_lower:
            return True
        if "gfw" in expected_lower and ("gfw" in detected_lower or "firewall" in detected_lower):
            return True
        if "cloudflare" in expected_lower and "cloudflare" in detected_lower:
            return True
        if "aws" in expected_lower and "aws" in detected_lower:
            return True
        if "ml_based" in expected_lower and ("ml_based" in detected_lower or "machine_learning" in detected_lower):
            return True
        
        return False
    
    def _evaluate_strategy_accuracy(self, expected_strategies: List[str], recommended_strategies: List[str]) -> float:
        """Evaluate accuracy of strategy recommendations"""
        
        if not expected_strategies or not recommended_strategies:
            return 0.0
        
        # Count matching strategies (fuzzy matching)
        matches = 0
        
        for expected in expected_strategies:
            for recommended in recommended_strategies:
                if self._strategies_similar(expected, recommended):
                    matches += 1
                    break
        
        # Calculate accuracy as percentage of expected strategies found
        accuracy = matches / len(expected_strategies)
        return accuracy
    
    def _strategies_similar(self, strategy1: str, strategy2: str) -> bool:
        """Check if two strategies are similar"""
        
        # Extract key components
        components1 = self._extract_strategy_components(strategy1)
        components2 = self._extract_strategy_components(strategy2)
        
        # Check if main attack types match
        if components1.get("desync_type") == components2.get("desync_type"):
            return True
        
        # Check for compatible attack types
        compatible_attacks = {
            "fake": ["fake", "fakeddisorder"],
            "multisplit": ["multisplit", "disorder"],
            "disorder": ["disorder", "multidisorder"]
        }
        
        attack1 = components1.get("desync_type", "")
        attack2 = components2.get("desync_type", "")
        
        for base_attack, compatible in compatible_attacks.items():
            if attack1 in compatible and attack2 in compatible:
                return True
        
        return False
    
    def _extract_strategy_components(self, strategy: str) -> Dict[str, str]:
        """Extract components from strategy string"""
        
        components = {}
        
        # Extract desync type
        if "--dpi-desync=" in strategy:
            start = strategy.find("--dpi-desync=") + len("--dpi-desync=")
            end = strategy.find(" ", start)
            if end == -1:
                end = len(strategy)
            desync_part = strategy[start:end]
            
            # Handle comma-separated attacks
            if "," in desync_part:
                components["desync_type"] = desync_part.split(",")[0]
            else:
                components["desync_type"] = desync_part
        
        # Extract TTL
        if "--dpi-desync-ttl=" in strategy:
            start = strategy.find("--dpi-desync-ttl=") + len("--dpi-desync-ttl=")
            end = strategy.find(" ", start)
            if end == -1:
                end = len(strategy)
            components["ttl"] = strategy[start:end]
        
        # Extract fooling
        if "--dpi-desync-fooling=" in strategy:
            start = strategy.find("--dpi-desync-fooling=") + len("--dpi-desync-fooling=")
            end = strategy.find(" ", start)
            if end == -1:
                end = len(strategy)
            components["fooling"] = strategy[start:end]
        
        return components
    
    def _generate_validation_summary(self, total_time: float) -> ValidationSummary:
        """Generate validation summary from test results"""
        
        total_tests = len(self.test_results)
        accurate_detections = sum(1 for r in self.test_results if r.dpi_type_accurate)
        inaccurate_detections = total_tests - accurate_detections
        false_positives = sum(1 for r in self.test_results if r.false_positive)
        false_negatives = sum(1 for r in self.test_results if r.false_negative)
        
        # Calculate average accuracies
        confidence_accuracies = [r.actual_confidence for r in self.test_results if r.confidence_accurate]
        average_confidence_accuracy = statistics.mean(confidence_accuracies) if confidence_accuracies else 0.0
        
        strategy_accuracies = [r.strategy_accuracy for r in self.test_results]
        average_strategy_accuracy = statistics.mean(strategy_accuracies) if strategy_accuracies else 0.0
        
        # Overall accuracy
        overall_accuracy = accurate_detections / total_tests if total_tests > 0 else 0.0
        
        # Performance metrics
        test_durations = [r.test_duration for r in self.test_results]
        performance_metrics = {
            "total_test_time": total_time,
            "average_test_duration": statistics.mean(test_durations) if test_durations else 0.0,
            "fastest_test": min(test_durations) if test_durations else 0.0,
            "slowest_test": max(test_durations) if test_durations else 0.0
        }
        
        return ValidationSummary(
            total_tests=total_tests,
            accurate_detections=accurate_detections,
            inaccurate_detections=inaccurate_detections,
            false_positives=false_positives,
            false_negatives=false_negatives,
            average_confidence_accuracy=average_confidence_accuracy,
            average_strategy_accuracy=average_strategy_accuracy,
            overall_accuracy=overall_accuracy,
            performance_metrics=performance_metrics
        )
    
    async def _save_validation_results(self, summary: ValidationSummary) -> None:
        """Save validation results to file"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save summary
        summary_filename = f"fingerprint_validation_summary_{timestamp}.json"
        with open(summary_filename, 'w') as f:
            json.dump(asdict(summary), f, indent=2, default=str)
        
        # Save detailed results
        results_filename = f"fingerprint_validation_results_{timestamp}.json"
        detailed_results = {
            "validation_summary": asdict(summary),
            "test_results": [asdict(result) for result in self.test_results],
            "test_cases": [asdict(case) for case in self.test_cases]
        }
        
        with open(results_filename, 'w') as f:
            json.dump(detailed_results, f, indent=2, default=str)
        
        LOG.info(f"Validation results saved to {results_filename}")
        LOG.info(f"Validation summary saved to {summary_filename}")
    
    def get_problematic_test_cases(self) -> List[AccuracyTestResult]:
        """Get test cases that had accuracy issues"""
        
        problematic = []
        
        for result in self.test_results:
            if (not result.dpi_type_accurate or 
                not result.confidence_accurate or 
                result.strategy_accuracy < 0.5 or
                result.false_positive or 
                result.false_negative):
                problematic.append(result)
        
        return problematic
    
    def generate_improvement_recommendations(self) -> List[str]:
        """Generate recommendations for improving accuracy"""
        
        recommendations = []
        
        # Analyze results
        total_tests = len(self.test_results)
        if total_tests == 0:
            return ["No test results available for analysis"]
        
        accurate_detections = sum(1 for r in self.test_results if r.dpi_type_accurate)
        accuracy_rate = accurate_detections / total_tests
        
        if accuracy_rate < 0.8:
            recommendations.append("Improve DPI type detection accuracy by refining detection rules")
        
        confidence_issues = sum(1 for r in self.test_results if not r.confidence_accurate)
        if confidence_issues > total_tests * 0.3:
            recommendations.append("Adjust confidence thresholds or improve signature extraction")
        
        strategy_issues = sum(1 for r in self.test_results if r.strategy_accuracy < 0.5)
        if strategy_issues > total_tests * 0.2:
            recommendations.append("Update strategy recommendations based on latest DPI bypass techniques")
        
        false_positives = sum(1 for r in self.test_results if r.false_positive)
        if false_positives > 2:
            recommendations.append("Reduce false positive rate by tightening detection criteria")
        
        false_negatives = sum(1 for r in self.test_results if r.false_negative)
        if false_negatives > 2:
            recommendations.append("Reduce false negative rate by adding more detection markers")
        
        return recommendations


# Main execution function
async def main():
    """Main execution function for fingerprint accuracy validation"""
    
    LOG.info("=== FINGERPRINT ACCURACY VALIDATION - TASK 19 ===")
    
    # Initialize validator
    validator = FingerprintAccuracyValidator()
    
    try:
        # Run comprehensive validation
        summary = await validator.run_comprehensive_validation()
        
        # Print summary
        LOG.info("\n=== VALIDATION SUMMARY ===")
        LOG.info(f"Total tests: {summary.total_tests}")
        LOG.info(f"Accurate detections: {summary.accurate_detections}")
        LOG.info(f"Inaccurate detections: {summary.inaccurate_detections}")
        LOG.info(f"False positives: {summary.false_positives}")
        LOG.info(f"False negatives: {summary.false_negatives}")
        LOG.info(f"Overall accuracy: {summary.overall_accuracy:.2%}")
        LOG.info(f"Average confidence accuracy: {summary.average_confidence_accuracy:.2%}")
        LOG.info(f"Average strategy accuracy: {summary.average_strategy_accuracy:.2%}")
        
        # Print performance metrics
        LOG.info("\n=== PERFORMANCE METRICS ===")
        perf = summary.performance_metrics
        LOG.info(f"Total test time: {perf['total_test_time']:.2f}s")
        LOG.info(f"Average test duration: {perf['average_test_duration']:.3f}s")
        LOG.info(f"Fastest test: {perf['fastest_test']:.3f}s")
        LOG.info(f"Slowest test: {perf['slowest_test']:.3f}s")
        
        # Get problematic cases
        problematic_cases = validator.get_problematic_test_cases()
        if problematic_cases:
            LOG.info(f"\n=== PROBLEMATIC TEST CASES ({len(problematic_cases)}) ===")
            for case in problematic_cases:
                LOG.info(f"  {case.test_id}: Expected {case.expected_dpi_type}, got {case.detected_dpi_type}")
                LOG.info(f"    Confidence: {case.actual_confidence:.2f} (expected >= {case.expected_confidence:.2f})")
                LOG.info(f"    Strategy accuracy: {case.strategy_accuracy:.2%}")
        
        # Generate recommendations
        recommendations = validator.generate_improvement_recommendations()
        if recommendations:
            LOG.info(f"\n=== IMPROVEMENT RECOMMENDATIONS ===")
            for i, rec in enumerate(recommendations, 1):
                LOG.info(f"{i}. {rec}")
        
        LOG.info("\n=== FINGERPRINT ACCURACY VALIDATION COMPLETED ===")
        
        return summary
        
    except Exception as e:
        LOG.error(f"Fingerprint accuracy validation failed: {e}")
        import traceback
        LOG.error(traceback.format_exc())
        return None


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    asyncio.run(main())