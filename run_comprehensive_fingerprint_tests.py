#!/usr/bin/env python3
"""
Comprehensive Fingerprint Testing Runner - Task 19 Implementation
Runs all fingerprint testing and improvement components together.

Requirements: 1.1, 1.2, 1.3, 1.4, 6.1, 6.2, 6.3, 6.4
"""

import asyncio
import logging
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Import fingerprint testing components
try:
    from core.fingerprint.comprehensive_fingerprint_tester import ComprehensiveFingerprintTester
    from core.fingerprint.enhanced_dpi_detector import EnhancedDPIDetector
    from core.fingerprint.fingerprint_accuracy_validator import FingerprintAccuracyValidator
    from core.integration.fingerprint_integration import FingerprintIntegrator
    FINGERPRINT_COMPONENTS_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Fingerprint components not available: {e}")
    FINGERPRINT_COMPONENTS_AVAILABLE = False

LOG = logging.getLogger("comprehensive_fingerprint_test_runner")


class ComprehensiveFingerprintTestRunner:
    """
    Comprehensive test runner for all fingerprint testing and improvement tasks.
    
    Coordinates:
    - Basic fingerprint functionality testing
    - DPI analysis accuracy testing
    - Strategy recommendation validation
    - New DPI pattern discovery
    - Performance optimization testing
    - Enhanced DPI detection with modern markers
    - Accuracy validation against known systems
    """
    
    def __init__(self):
        self.fingerprint_integrator = None
        self.comprehensive_tester = None
        self.enhanced_detector = None
        self.accuracy_validator = None
        self.test_results = {}
        self.start_time = None
        
        if FINGERPRINT_COMPONENTS_AVAILABLE:
            self._initialize_components()
    
    def _initialize_components(self):
        """Initialize all fingerprint testing components"""
        try:
            # Initialize fingerprint integrator
            self.fingerprint_integrator = FingerprintIntegrator(enable_fingerprinting=True)
            LOG.info("Fingerprint integrator initialized")
            
            # Initialize comprehensive tester
            self.comprehensive_tester = ComprehensiveFingerprintTester(debug=True)
            LOG.info("Comprehensive fingerprint tester initialized")
            
            # Initialize enhanced DPI detector
            self.enhanced_detector = EnhancedDPIDetector()
            LOG.info("Enhanced DPI detector initialized")
            
            # Initialize accuracy validator
            self.accuracy_validator = FingerprintAccuracyValidator(
                fingerprint_integrator=self.fingerprint_integrator
            )
            LOG.info("Fingerprint accuracy validator initialized")
            
        except Exception as e:
            LOG.error(f"Failed to initialize fingerprint components: {e}")
            raise
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all comprehensive fingerprint tests"""
        
        if not FINGERPRINT_COMPONENTS_AVAILABLE:
            LOG.error("Fingerprint components not available - cannot run tests")
            return {"error": "Fingerprint components not available"}
        
        LOG.info("=== STARTING COMPREHENSIVE FINGERPRINT TESTING ===")
        self.start_time = time.time()
        
        # Test domains for comprehensive testing
        test_domains = [
            # Social media and communication
            "x.com",
            "twitter.com", 
            "facebook.com",
            "instagram.com",
            "tiktok.com",
            "discord.com",
            "telegram.org",
            "whatsapp.com",
            
            # Video and streaming
            "youtube.com",
            "twitch.tv",
            "netflix.com",
            "hulu.com",
            
            # News and information
            "bbc.com",
            "cnn.com",
            "reuters.com",
            "wikipedia.org",
            
            # Technology and development
            "github.com",
            "stackoverflow.com",
            "reddit.com",
            "medium.com",
            
            # Cloud and CDN services
            "cloudflare.com",
            "amazonaws.com",
            "azure.microsoft.com",
            "googleapis.com",
            
            # Potentially blocked or restricted
            "blocked-site.test",
            "restricted-content.test",
            "censored-news.test"
        ]
        
        try:
            # Phase 1: Comprehensive fingerprint functionality testing
            LOG.info("\n=== PHASE 1: COMPREHENSIVE FINGERPRINT TESTING ===")
            comprehensive_results = await self._run_comprehensive_testing(test_domains)
            
            # Phase 2: Enhanced DPI detection testing
            LOG.info("\n=== PHASE 2: ENHANCED DPI DETECTION TESTING ===")
            enhanced_detection_results = await self._run_enhanced_detection_testing(test_domains)
            
            # Phase 3: Accuracy validation testing
            LOG.info("\n=== PHASE 3: ACCURACY VALIDATION TESTING ===")
            accuracy_validation_results = await self._run_accuracy_validation()
            
            # Phase 4: Integration testing
            LOG.info("\n=== PHASE 4: INTEGRATION TESTING ===")
            integration_results = await self._run_integration_testing(test_domains)
            
            # Phase 5: Performance benchmarking
            LOG.info("\n=== PHASE 5: PERFORMANCE BENCHMARKING ===")
            performance_results = await self._run_performance_benchmarking(test_domains)
            
            # Phase 6: Generate comprehensive report
            LOG.info("\n=== PHASE 6: GENERATING COMPREHENSIVE REPORT ===")
            final_report = await self._generate_comprehensive_report({
                "comprehensive_testing": comprehensive_results,
                "enhanced_detection": enhanced_detection_results,
                "accuracy_validation": accuracy_validation_results,
                "integration_testing": integration_results,
                "performance_benchmarking": performance_results
            })
            
            total_time = time.time() - self.start_time
            final_report["total_execution_time"] = total_time
            
            LOG.info(f"\n=== COMPREHENSIVE FINGERPRINT TESTING COMPLETED IN {total_time:.2f}s ===")
            
            return final_report
            
        except Exception as e:
            LOG.error(f"Comprehensive fingerprint testing failed: {e}")
            import traceback
            LOG.error(traceback.format_exc())
            return {"error": str(e), "traceback": traceback.format_exc()}
    
    async def _run_comprehensive_testing(self, domains: List[str]) -> Dict[str, Any]:
        """Run comprehensive fingerprint testing"""
        
        LOG.info(f"Running comprehensive fingerprint testing on {len(domains)} domains")
        
        if self.comprehensive_tester:
            try:
                results = await self.comprehensive_tester.run_comprehensive_testing(domains)
                
                LOG.info("Comprehensive testing results:")
                LOG.info(f"  - Successful fingerprints: {results['test_summary']['successful_fingerprints']}")
                LOG.info(f"  - Failed fingerprints: {results['test_summary']['failed_fingerprints']}")
                LOG.info(f"  - New patterns found: {results['test_summary']['new_patterns_found']}")
                LOG.info(f"  - Accuracy improvements: {results['test_summary']['accuracy_improvements']}")
                
                return results
                
            except Exception as e:
                LOG.error(f"Comprehensive testing failed: {e}")
                return {"error": str(e)}
        
        return {"error": "Comprehensive tester not available"}
    
    async def _run_enhanced_detection_testing(self, domains: List[str]) -> Dict[str, Any]:
        """Run enhanced DPI detection testing"""
        
        LOG.info(f"Running enhanced DPI detection testing on {len(domains)} domains")
        
        if self.enhanced_detector:
            try:
                results = {
                    "domains_tested": len(domains),
                    "detections": [],
                    "new_patterns": [],
                    "statistics": {}
                }
                
                # Test enhanced detection on sample network data
                for i, domain in enumerate(domains[:10]):  # Test first 10 domains
                    # Simulate network data for testing
                    network_data = self._generate_test_network_data(domain, i)
                    
                    signature = self.enhanced_detector.detect_dpi_system(network_data)
                    
                    if signature:
                        detection_result = {
                            "domain": domain,
                            "dpi_type": signature.dpi_type.value,
                            "confidence": signature.confidence,
                            "signature_id": signature.signature_id,
                            "modern_markers_detected": self._count_modern_markers(signature)
                        }
                        results["detections"].append(detection_result)
                        
                        LOG.info(f"  - {domain}: {signature.dpi_type.value} (confidence: {signature.confidence:.2f})")
                
                # Get statistics
                results["statistics"] = self.enhanced_detector.get_detection_statistics()
                
                # Export new patterns
                results["new_patterns"] = self.enhanced_detector.export_new_patterns()
                
                LOG.info(f"Enhanced detection completed: {len(results['detections'])} detections")
                
                return results
                
            except Exception as e:
                LOG.error(f"Enhanced detection testing failed: {e}")
                return {"error": str(e)}
        
        return {"error": "Enhanced detector not available"}
    
    async def _run_accuracy_validation(self) -> Dict[str, Any]:
        """Run accuracy validation testing"""
        
        LOG.info("Running fingerprint accuracy validation")
        
        if self.accuracy_validator:
            try:
                summary = await self.accuracy_validator.run_comprehensive_validation()
                
                LOG.info("Accuracy validation results:")
                LOG.info(f"  - Overall accuracy: {summary.overall_accuracy:.2%}")
                LOG.info(f"  - Accurate detections: {summary.accurate_detections}/{summary.total_tests}")
                LOG.info(f"  - False positives: {summary.false_positives}")
                LOG.info(f"  - False negatives: {summary.false_negatives}")
                LOG.info(f"  - Strategy accuracy: {summary.average_strategy_accuracy:.2%}")
                
                # Get problematic test cases
                problematic_cases = self.accuracy_validator.get_problematic_test_cases()
                
                return {
                    "validation_summary": {
                        "total_tests": summary.total_tests,
                        "accurate_detections": summary.accurate_detections,
                        "inaccurate_detections": summary.inaccurate_detections,
                        "false_positives": summary.false_positives,
                        "false_negatives": summary.false_negatives,
                        "overall_accuracy": summary.overall_accuracy,
                        "average_confidence_accuracy": summary.average_confidence_accuracy,
                        "average_strategy_accuracy": summary.average_strategy_accuracy
                    },
                    "performance_metrics": summary.performance_metrics,
                    "problematic_cases_count": len(problematic_cases),
                    "problematic_cases": [
                        {
                            "test_id": case.test_id,
                            "expected_dpi": case.expected_dpi_type,
                            "detected_dpi": case.detected_dpi_type,
                            "confidence": case.actual_confidence,
                            "strategy_accuracy": case.strategy_accuracy
                        }
                        for case in problematic_cases[:5]  # Show first 5
                    ]
                }
                
            except Exception as e:
                LOG.error(f"Accuracy validation failed: {e}")
                return {"error": str(e)}
        
        return {"error": "Accuracy validator not available"}
    
    async def _run_integration_testing(self, domains: List[str]) -> Dict[str, Any]:
        """Run integration testing between components"""
        
        LOG.info("Running integration testing")
        
        results = {
            "integration_tests": [],
            "component_compatibility": {},
            "data_flow_validation": {}
        }
        
        try:
            # Test integration between fingerprint integrator and enhanced detector
            if self.fingerprint_integrator and self.enhanced_detector:
                for domain in domains[:5]:  # Test first 5 domains
                    # Get fingerprint from integrator
                    fingerprint_result = await self.fingerprint_integrator.fingerprint_target(
                        domain=domain,
                        target_ip="1.2.3.4"
                    )
                    
                    if fingerprint_result:
                        # Convert to network data for enhanced detector
                        network_data = {
                            "dpi_type_detected": fingerprint_result.dpi_type,
                            "confidence": fingerprint_result.confidence,
                            "fingerprint_data": fingerprint_result.fingerprint_data
                        }
                        
                        # Test enhanced detection
                        enhanced_signature = self.enhanced_detector.detect_dpi_system(network_data)
                        
                        integration_test = {
                            "domain": domain,
                            "integrator_result": {
                                "dpi_type": fingerprint_result.dpi_type,
                                "confidence": fingerprint_result.confidence
                            },
                            "enhanced_detector_result": {
                                "dpi_type": enhanced_signature.dpi_type.value if enhanced_signature else None,
                                "confidence": enhanced_signature.confidence if enhanced_signature else 0.0
                            },
                            "results_consistent": self._check_result_consistency(
                                fingerprint_result, enhanced_signature
                            )
                        }
                        
                        results["integration_tests"].append(integration_test)
            
            # Test component compatibility
            results["component_compatibility"] = {
                "fingerprint_integrator_available": self.fingerprint_integrator is not None,
                "comprehensive_tester_available": self.comprehensive_tester is not None,
                "enhanced_detector_available": self.enhanced_detector is not None,
                "accuracy_validator_available": self.accuracy_validator is not None
            }
            
            # Validate data flow
            consistent_results = sum(
                1 for test in results["integration_tests"] 
                if test["results_consistent"]
            )
            
            results["data_flow_validation"] = {
                "total_integration_tests": len(results["integration_tests"]),
                "consistent_results": consistent_results,
                "consistency_rate": consistent_results / len(results["integration_tests"]) if results["integration_tests"] else 0.0
            }
            
            LOG.info(f"Integration testing completed: {consistent_results}/{len(results['integration_tests'])} consistent results")
            
        except Exception as e:
            LOG.error(f"Integration testing failed: {e}")
            results["error"] = str(e)
        
        return results
    
    async def _run_performance_benchmarking(self, domains: List[str]) -> Dict[str, Any]:
        """Run performance benchmarking"""
        
        LOG.info("Running performance benchmarking")
        
        results = {
            "fingerprint_performance": {},
            "detection_performance": {},
            "validation_performance": {},
            "memory_usage": {},
            "scalability_analysis": {}
        }
        
        try:
            # Benchmark fingerprint integrator
            if self.fingerprint_integrator:
                fingerprint_times = []
                
                for domain in domains[:10]:
                    start_time = time.time()
                    await self.fingerprint_integrator.fingerprint_target(domain, "1.2.3.4")
                    fingerprint_times.append(time.time() - start_time)
                
                results["fingerprint_performance"] = {
                    "average_time": sum(fingerprint_times) / len(fingerprint_times),
                    "fastest_time": min(fingerprint_times),
                    "slowest_time": max(fingerprint_times),
                    "total_time": sum(fingerprint_times)
                }
            
            # Benchmark enhanced detector
            if self.enhanced_detector:
                detection_times = []
                
                for i in range(10):
                    network_data = self._generate_test_network_data(f"test-domain-{i}.com", i)
                    start_time = time.time()
                    self.enhanced_detector.detect_dpi_system(network_data)
                    detection_times.append(time.time() - start_time)
                
                results["detection_performance"] = {
                    "average_time": sum(detection_times) / len(detection_times),
                    "fastest_time": min(detection_times),
                    "slowest_time": max(detection_times),
                    "total_time": sum(detection_times)
                }
            
            # Memory usage analysis (simplified)
            results["memory_usage"] = {
                "estimated_fingerprint_cache_size": len(getattr(self.fingerprint_integrator, 'cache', {})) if self.fingerprint_integrator else 0,
                "estimated_signature_cache_size": len(getattr(self.enhanced_detector, 'signature_cache', {})) if self.enhanced_detector else 0
            }
            
            # Scalability analysis
            results["scalability_analysis"] = {
                "domains_tested": len(domains),
                "estimated_max_concurrent_fingerprints": 50,  # Conservative estimate
                "recommended_cache_size": 1000,
                "performance_degradation_threshold": 100  # domains
            }
            
            LOG.info("Performance benchmarking completed")
            
        except Exception as e:
            LOG.error(f"Performance benchmarking failed: {e}")
            results["error"] = str(e)
        
        return results
    
    async def _generate_comprehensive_report(self, all_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        
        LOG.info("Generating comprehensive test report")
        
        report = {
            "test_execution_summary": {
                "start_time": self.start_time,
                "end_time": time.time(),
                "total_duration": time.time() - self.start_time,
                "timestamp": datetime.now().isoformat()
            },
            "component_results": all_results,
            "overall_assessment": {},
            "recommendations": [],
            "improvements_implemented": [],
            "issues_identified": [],
            "next_steps": []
        }
        
        try:
            # Overall assessment
            assessment = self._assess_overall_performance(all_results)
            report["overall_assessment"] = assessment
            
            # Generate recommendations
            recommendations = self._generate_recommendations(all_results)
            report["recommendations"] = recommendations
            
            # Identify improvements
            improvements = self._identify_improvements(all_results)
            report["improvements_implemented"] = improvements
            
            # Identify issues
            issues = self._identify_issues(all_results)
            report["issues_identified"] = issues
            
            # Generate next steps
            next_steps = self._generate_next_steps(all_results)
            report["next_steps"] = next_steps
            
            # Save report
            await self._save_comprehensive_report(report)
            
            LOG.info("Comprehensive test report generated successfully")
            
        except Exception as e:
            LOG.error(f"Failed to generate comprehensive report: {e}")
            report["report_generation_error"] = str(e)
        
        return report
    
    def _generate_test_network_data(self, domain: str, index: int) -> Dict[str, Any]:
        """Generate test network data for domain"""
        
        # Simulate different DPI systems based on index
        dpi_patterns = [
            # Roskomnadzor TSPU
            {
                "rst_ttl": 62,
                "rst_from_target": False,
                "stateful_inspection": True,
                "tls_fingerprint_analysis": True,
                "timing_analysis": True
            },
            # Sandvine
            {
                "rst_ttl": 128,
                "checksum_validation": True,
                "application_layer_inspection": True,
                "rate_limiting": True
            },
            # Great Firewall
            {
                "supports_ip_frag": False,
                "ja3_fingerprint_detected": True,
                "machine_learning_classification": True,
                "geo_blocking_patterns": True
            },
            # Cloudflare
            {
                "cdn_edge_detection": True,
                "load_balancer_fingerprinting": True,
                "http2_frame_analysis": True,
                "processing_latency_ms": 5.0
            },
            # Unknown/Generic
            {
                "unknown_pattern": True,
                "experimental_blocking": True
            }
        ]
        
        pattern = dpi_patterns[index % len(dpi_patterns)]
        pattern["domain"] = domain
        pattern["test_index"] = index
        
        return pattern
    
    def _count_modern_markers(self, signature) -> int:
        """Count modern DPI markers in signature"""
        
        modern_markers = [
            signature.tls_fingerprint_blocking,
            signature.ja3_fingerprint_detected,
            signature.http2_frame_analysis,
            signature.quic_connection_id_tracking,
            signature.machine_learning_classification,
            signature.cdn_edge_detection,
            signature.application_layer_inspection,
            signature.obfuscation_detection
        ]
        
        return sum(1 for marker in modern_markers if marker)
    
    def _check_result_consistency(self, fingerprint_result, enhanced_signature) -> bool:
        """Check consistency between fingerprint integrator and enhanced detector results"""
        
        if not fingerprint_result or not enhanced_signature:
            return False
        
        # Check if DPI types are compatible
        integrator_type = fingerprint_result.dpi_type.lower()
        detector_type = enhanced_signature.dpi_type.value.lower()
        
        # Exact match
        if integrator_type == detector_type:
            return True
        
        # Fuzzy matching
        if "unknown" in integrator_type and "unknown" in detector_type:
            return True
        
        # Check for partial matches
        compatible_types = [
            ("roskomnadzor", "tspu"),
            ("sandvine", "commercial"),
            ("gfw", "firewall"),
            ("cloudflare", "cdn"),
            ("aws", "cloud")
        ]
        
        for type1, type2 in compatible_types:
            if (type1 in integrator_type and type2 in detector_type) or \
               (type2 in integrator_type and type1 in detector_type):
                return True
        
        return False
    
    def _assess_overall_performance(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall performance across all tests"""
        
        assessment = {
            "overall_score": 0.0,
            "component_scores": {},
            "strengths": [],
            "weaknesses": [],
            "critical_issues": []
        }
        
        scores = []
        
        # Assess comprehensive testing
        if "comprehensive_testing" in results and "test_summary" in results["comprehensive_testing"]:
            summary = results["comprehensive_testing"]["test_summary"]
            total = summary.get("successful_fingerprints", 0) + summary.get("failed_fingerprints", 0)
            if total > 0:
                success_rate = summary.get("successful_fingerprints", 0) / total
                assessment["component_scores"]["comprehensive_testing"] = success_rate
                scores.append(success_rate)
                
                if success_rate > 0.8:
                    assessment["strengths"].append("High fingerprint success rate")
                elif success_rate < 0.5:
                    assessment["weaknesses"].append("Low fingerprint success rate")
        
        # Assess accuracy validation
        if "accuracy_validation" in results and "validation_summary" in results["accuracy_validation"]:
            summary = results["accuracy_validation"]["validation_summary"]
            accuracy = summary.get("overall_accuracy", 0.0)
            assessment["component_scores"]["accuracy_validation"] = accuracy
            scores.append(accuracy)
            
            if accuracy > 0.85:
                assessment["strengths"].append("High detection accuracy")
            elif accuracy < 0.7:
                assessment["weaknesses"].append("Low detection accuracy")
                assessment["critical_issues"].append("Detection accuracy below acceptable threshold")
        
        # Assess integration testing
        if "integration_testing" in results and "data_flow_validation" in results["integration_testing"]:
            validation = results["integration_testing"]["data_flow_validation"]
            consistency = validation.get("consistency_rate", 0.0)
            assessment["component_scores"]["integration_testing"] = consistency
            scores.append(consistency)
            
            if consistency > 0.9:
                assessment["strengths"].append("Excellent component integration")
            elif consistency < 0.7:
                assessment["weaknesses"].append("Poor component integration")
        
        # Calculate overall score
        if scores:
            assessment["overall_score"] = sum(scores) / len(scores)
        
        return assessment
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on test results"""
        
        recommendations = []
        
        # Check comprehensive testing results
        if "comprehensive_testing" in results:
            summary = results["comprehensive_testing"].get("test_summary", {})
            failed = summary.get("failed_fingerprints", 0)
            total = summary.get("successful_fingerprints", 0) + failed
            
            if total > 0 and failed / total > 0.3:
                recommendations.append("Improve fingerprint reliability - high failure rate detected")
            
            if summary.get("new_patterns_found", 0) > 0:
                recommendations.append("Integrate newly discovered DPI patterns into detection algorithms")
        
        # Check accuracy validation results
        if "accuracy_validation" in results:
            summary = results["accuracy_validation"].get("validation_summary", {})
            accuracy = summary.get("overall_accuracy", 0.0)
            
            if accuracy < 0.8:
                recommendations.append("Improve DPI detection accuracy through algorithm enhancement")
            
            if summary.get("false_positives", 0) > 2:
                recommendations.append("Reduce false positive rate in DPI detection")
            
            if summary.get("false_negatives", 0) > 2:
                recommendations.append("Reduce false negative rate in DPI detection")
        
        # Check performance results
        if "performance_benchmarking" in results:
            perf = results["performance_benchmarking"]
            
            if "fingerprint_performance" in perf:
                avg_time = perf["fingerprint_performance"].get("average_time", 0.0)
                if avg_time > 2.0:
                    recommendations.append("Optimize fingerprint analysis speed - currently too slow")
        
        return recommendations
    
    def _identify_improvements(self, results: Dict[str, Any]) -> List[str]:
        """Identify improvements implemented during testing"""
        
        improvements = []
        
        # Check for new patterns discovered
        if "comprehensive_testing" in results:
            new_patterns = results["comprehensive_testing"].get("test_summary", {}).get("new_patterns_found", 0)
            if new_patterns > 0:
                improvements.append(f"Discovered {new_patterns} new DPI patterns")
        
        # Check for enhanced detection capabilities
        if "enhanced_detection" in results:
            detections = results["enhanced_detection"].get("detections", [])
            modern_detections = sum(1 for d in detections if d.get("modern_markers_detected", 0) > 3)
            if modern_detections > 0:
                improvements.append(f"Enhanced detection with modern markers for {modern_detections} systems")
        
        # Check for accuracy improvements
        if "accuracy_validation" in results:
            accuracy = results["accuracy_validation"].get("validation_summary", {}).get("overall_accuracy", 0.0)
            if accuracy > 0.85:
                improvements.append("Achieved high detection accuracy (>85%)")
        
        return improvements
    
    def _identify_issues(self, results: Dict[str, Any]) -> List[str]:
        """Identify issues found during testing"""
        
        issues = []
        
        # Check for errors in results
        for component, result in results.items():
            if isinstance(result, dict) and "error" in result:
                issues.append(f"{component}: {result['error']}")
        
        # Check for performance issues
        if "performance_benchmarking" in results:
            perf = results["performance_benchmarking"]
            if "fingerprint_performance" in perf:
                avg_time = perf["fingerprint_performance"].get("average_time", 0.0)
                if avg_time > 3.0:
                    issues.append(f"Slow fingerprint analysis: {avg_time:.2f}s average")
        
        # Check for accuracy issues
        if "accuracy_validation" in results:
            summary = results["accuracy_validation"].get("validation_summary", {})
            accuracy = summary.get("overall_accuracy", 0.0)
            if accuracy < 0.7:
                issues.append(f"Low detection accuracy: {accuracy:.1%}")
        
        return issues
    
    def _generate_next_steps(self, results: Dict[str, Any]) -> List[str]:
        """Generate next steps based on test results"""
        
        next_steps = []
        
        # Always include basic next steps
        next_steps.extend([
            "Integrate improved fingerprint algorithms into production system",
            "Update DPI signature database with newly discovered patterns",
            "Implement enhanced strategy recommendation engine",
            "Set up continuous fingerprint accuracy monitoring"
        ])
        
        # Add specific next steps based on results
        if "comprehensive_testing" in results:
            new_patterns = results["comprehensive_testing"].get("test_summary", {}).get("new_patterns_found", 0)
            if new_patterns > 0:
                next_steps.append("Validate and classify newly discovered DPI patterns")
        
        if "accuracy_validation" in results:
            problematic = results["accuracy_validation"].get("problematic_cases_count", 0)
            if problematic > 0:
                next_steps.append("Address problematic test cases to improve accuracy")
        
        return next_steps
    
    async def _save_comprehensive_report(self, report: Dict[str, Any]) -> None:
        """Save comprehensive test report"""
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"comprehensive_fingerprint_test_report_{timestamp}.json"
            filepath = Path("recon") / "reports" / filename
            
            # Ensure reports directory exists
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            LOG.info(f"Comprehensive test report saved to {filepath}")
            
        except Exception as e:
            LOG.error(f"Failed to save comprehensive report: {e}")


async def main():
    """Main function for running comprehensive fingerprint tests"""
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    LOG.info("Starting comprehensive fingerprint testing and improvement")
    
    try:
        runner = ComprehensiveFingerprintTestRunner()
        results = await runner.run_all_tests()
        
        if "error" not in results:
            LOG.info("=== COMPREHENSIVE FINGERPRINT TESTING SUMMARY ===")
            
            # Display overall assessment
            if "overall_assessment" in results:
                assessment = results["overall_assessment"]
                LOG.info(f"Overall Score: {assessment.get('overall_score', 0.0):.2f}")
                
                if assessment.get("strengths"):
                    LOG.info("Strengths:")
                    for strength in assessment["strengths"]:
                        LOG.info(f"  + {strength}")
                
                if assessment.get("weaknesses"):
                    LOG.info("Weaknesses:")
                    for weakness in assessment["weaknesses"]:
                        LOG.info(f"  - {weakness}")
            
            # Display key metrics
            if "component_results" in results:
                components = results["component_results"]
                
                if "comprehensive_testing" in components:
                    summary = components["comprehensive_testing"].get("test_summary", {})
                    LOG.info(f"Fingerprint Success Rate: {summary.get('successful_fingerprints', 0)}/{summary.get('successful_fingerprints', 0) + summary.get('failed_fingerprints', 0)}")
                
                if "accuracy_validation" in components:
                    summary = components["accuracy_validation"].get("validation_summary", {})
                    LOG.info(f"Detection Accuracy: {summary.get('overall_accuracy', 0.0):.1%}")
            
            # Display recommendations
            if results.get("recommendations"):
                LOG.info("Key Recommendations:")
                for rec in results["recommendations"][:3]:
                    LOG.info(f"  • {rec}")
            
            LOG.info(f"Total Execution Time: {results.get('total_execution_time', 0.0):.2f}s")
            LOG.info("Comprehensive fingerprint testing completed successfully!")
        
        else:
            LOG.error(f"Comprehensive fingerprint testing failed: {results['error']}")
    
    except Exception as e:
        LOG.error(f"Failed to run comprehensive fingerprint tests: {e}")
        import traceback
        LOG.error(traceback.format_exc())


if __name__ == "__main__":
    asyncio.run(main())