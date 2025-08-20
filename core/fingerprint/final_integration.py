#!/usr/bin/env python3
"""
Final Integration Testing and Optimization - Task 20 Implementation
End-to-end system validation, performance optimization, and production readiness.
"""

import asyncio
import time
import statistics
import json
import sys
import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

try:
    from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType
    from core.fingerprint.config import AdvancedFingerprintingConfig, get_config_manager
    from core.fingerprint.diagnostics import get_diagnostic_system
    from ml.zapret_strategy_generator import ZapretStrategyGenerator
    from core.hybrid_engine import HybridEngine
except ImportError:
    from recon.core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter
    from recon.core.fingerprint.advanced_models import DPIFingerprint, DPIType
    from recon.core.fingerprint.config import AdvancedFingerprintingConfig, get_config_manager
    from recon.core.fingerprint.diagnostics import get_diagnostic_system
    from recon.ml.zapret_strategy_generator import ZapretStrategyGenerator
    from recon.core.hybrid_engine import HybridEngine


@dataclass
class ValidationResult:
    """Validation test result."""
    test_name: str
    success: bool
    duration: float
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class PerformanceResult:
    """Performance test result."""
    test_name: str
    duration: float
    throughput: float
    success_rate: float
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntegrationReport:
    """Final integration test report."""
    timestamp: float = field(default_factory=time.time)
    validation_results: List[ValidationResult] = field(default_factory=list)
    performance_results: List[PerformanceResult] = field(default_factory=list)
    system_health: Dict[str, Any] = field(default_factory=dict)
    optimization_recommendations: List[str] = field(default_factory=list)
    production_readiness: Dict[str, bool] = field(default_factory=dict)


class FinalIntegrationTester:
    """Final integration testing and optimization system."""
    
    def __init__(self):
        """Initialize final integration tester."""
        self.config = get_config_manager().get_config()
        self.diagnostic_system = get_diagnostic_system()
        self.test_targets = [
            "integration-test-1.com",
            "integration-test-2.com", 
            "integration-test-3.com"
        ]
    
    async def run_complete_validation(self) -> IntegrationReport:
        """Run complete system validation."""
        print("🚀 Starting Final Integration Testing and Validation")
        print("=" * 60)
        
        report = IntegrationReport()
        
        # Run validation tests
        validation_tests = [
            self._test_fingerprinting_workflow,
            self._test_strategy_integration,
            self._test_cache_integration,
            self._test_ml_classification,
            self._test_monitoring_integration,
            self._test_configuration_system,
            self._test_backward_compatibility
        ]
        
        for test in validation_tests:
            try:
                result = await test()
                report.validation_results.append(result)
                status = "✅ PASS" if result.success else "❌ FAIL"
                print(f"{status} {result.test_name} ({result.duration:.3f}s)")
                if result.error:
                    print(f"    Error: {result.error}")
            except Exception as e:
                result = ValidationResult(
                    test_name=test.__name__,
                    success=False,
                    duration=0.0,
                    error=str(e)
                )
                report.validation_results.append(result)
                print(f"❌ FAIL {test.__name__} - Exception: {str(e)}")
        
        # Run performance tests
        performance_tests = [
            self._test_fingerprinting_performance,
            self._test_strategy_generation_performance,
            self._test_concurrent_operations_performance
        ]
        
        for test in performance_tests:
            try:
                result = await test()
                report.performance_results.append(result)
                print(f"📊 {result.test_name}: {result.throughput:.2f} ops/sec, "
                      f"{result.success_rate:.1%} success rate")
            except Exception as e:
                print(f"❌ Performance test {test.__name__} failed: {str(e)}")
        
        # Check system health
        report.system_health = self._check_system_health()
        
        # Generate optimization recommendations
        report.optimization_recommendations = self._generate_optimization_recommendations(report)
        
        # Assess production readiness
        report.production_readiness = self._assess_production_readiness(report)
        
        return report
    
    async def _test_fingerprinting_workflow(self) -> ValidationResult:
        """Test complete fingerprinting workflow."""
        start_time = time.time()
        
        try:
            fingerprinter = AdvancedFingerprinter(config=self.config)
            
            # Mock analyzer responses for testing
            from unittest.mock import patch, AsyncMock
            
            with patch('core.fingerprint.tcp_analyzer.TCPAnalyzer.analyze_tcp_behavior') as mock_tcp, \
                 patch('core.fingerprint.http_analyzer.HTTPAnalyzer.analyze_http_behavior') as mock_http, \
                 patch('core.fingerprint.dns_analyzer.DNSAnalyzer.analyze_dns_behavior') as mock_dns:
                
                mock_tcp.return_value = {'rst_injection_detected': True}
                mock_http.return_value = {'http_header_filtering': True}
                mock_dns.return_value = {'dns_hijacking_detected': False}
                
                fingerprint = await fingerprinter.fingerprint_target(self.test_targets[0])
                
                duration = time.time() - start_time
                
                # Validate fingerprint
                if not isinstance(fingerprint, DPIFingerprint):
                    return ValidationResult(
                        test_name="Fingerprinting Workflow",
                        success=False,
                        duration=duration,
                        error="Invalid fingerprint type returned"
                    )
                
                if fingerprint.target != self.test_targets[0]:
                    return ValidationResult(
                        test_name="Fingerprinting Workflow", 
                        success=False,
                        duration=duration,
                        error="Fingerprint target mismatch"
                    )
                
                return ValidationResult(
                    test_name="Fingerprinting Workflow",
                    success=True,
                    duration=duration,
                    details={
                        'target': fingerprint.target,
                        'dpi_type': fingerprint.dpi_type.value,
                        'confidence': fingerprint.confidence
                    }
                )
        
        except Exception as e:
            return ValidationResult(
                test_name="Fingerprinting Workflow",
                success=False,
                duration=time.time() - start_time,
                error=str(e)
            )
    
    async def _test_strategy_integration(self) -> ValidationResult:
        """Test strategy generation integration."""
        start_time = time.time()
        
        try:
            # Create test fingerprint
            fingerprint = DPIFingerprint(
                target="strategy-test.com",
                dpi_type=DPIType.ROSKOMNADZOR_TSPU,
                confidence=0.85,
                rst_injection_detected=True
            )
            
            # Test strategy generation
            generator = ZapretStrategyGenerator()
            strategies = generator.generate_strategies(fingerprint=fingerprint, count=10)
            
            duration = time.time() - start_time
            
            # Validate strategies
            if len(strategies) != 10:
                return ValidationResult(
                    test_name="Strategy Integration",
                    success=False,
                    duration=duration,
                    error=f"Expected 10 strategies, got {len(strategies)}"
                )
            
            if not all('--dpi-desync' in s for s in strategies):
                return ValidationResult(
                    test_name="Strategy Integration",
                    success=False,
                    duration=duration,
                    error="Invalid strategy format"
                )
            
            return ValidationResult(
                test_name="Strategy Integration",
                success=True,
                duration=duration,
                details={
                    'strategies_generated': len(strategies),
                    'sample_strategy': strategies[0][:50] + "..."
                }
            )
        
        except Exception as e:
            return ValidationResult(
                test_name="Strategy Integration",
                success=False,
                duration=time.time() - start_time,
                error=str(e)
            )
    
    async def _test_cache_integration(self) -> ValidationResult:
        """Test cache system integration."""
        start_time = time.time()
        
        try:
            from core.fingerprint.cache import FingerprintCache
            
            cache = FingerprintCache(cache_dir=self.config.cache.cache_dir)
            
            # Test cache operations
            test_fingerprint = DPIFingerprint(
                target="cache-test.com",
                dpi_type=DPIType.COMMERCIAL_DPI,
                confidence=0.9
            )
            
            # Store fingerprint
            cache.store("cache-test", test_fingerprint)
            
            # Retrieve fingerprint
            retrieved = cache.get("cache-test")
            
            duration = time.time() - start_time
            
            if not retrieved:
                return ValidationResult(
                    test_name="Cache Integration",
                    success=False,
                    duration=duration,
                    error="Failed to retrieve cached fingerprint"
                )
            
            if retrieved.target != test_fingerprint.target:
                return ValidationResult(
                    test_name="Cache Integration",
                    success=False,
                    duration=duration,
                    error="Cached fingerprint data mismatch"
                )
            
            return ValidationResult(
                test_name="Cache Integration",
                success=True,
                duration=duration,
                details={
                    'cache_store_success': True,
                    'cache_retrieve_success': True,
                    'data_integrity': True
                }
            )
        
        except Exception as e:
            return ValidationResult(
                test_name="Cache Integration",
                success=False,
                duration=time.time() - start_time,
                error=str(e)
            )
    
    async def _test_ml_classification(self) -> ValidationResult:
        """Test ML classification system."""
        start_time = time.time()
        
        try:
            from core.fingerprint.ml_classifier import MLClassifier
            
            classifier = MLClassifier()
            
            # Test classification
            test_metrics = {
                'rst_injection_detected': True,
                'http_header_filtering': True,
                'dns_hijacking_detected': False,
                'content_inspection_depth': 1500
            }
            
            prediction = classifier.classify_dpi(test_metrics)
            
            duration = time.time() - start_time
            
            if not prediction:
                return ValidationResult(
                    test_name="ML Classification",
                    success=False,
                    duration=duration,
                    error="ML classification returned no result"
                )
            
            if 'dpi_type' not in prediction:
                return ValidationResult(
                    test_name="ML Classification",
                    success=False,
                    duration=duration,
                    error="ML classification missing dpi_type"
                )
            
            return ValidationResult(
                test_name="ML Classification",
                success=True,
                duration=duration,
                details={
                    'prediction': prediction,
                    'has_confidence': 'confidence' in prediction
                }
            )
        
        except Exception as e:
            return ValidationResult(
                test_name="ML Classification",
                success=False,
                duration=time.time() - start_time,
                error=str(e)
            )
    
    async def _test_monitoring_integration(self) -> ValidationResult:
        """Test monitoring and diagnostics integration."""
        start_time = time.time()
        
        try:
            # Test diagnostic system
            diagnostic_system = get_diagnostic_system()
            
            # Record test metrics
            diagnostic_system.record_fingerprinting_operation(
                target="monitoring-test.com",
                success=True,
                duration=1.0,
                fingerprint=DPIFingerprint(
                    target="monitoring-test.com",
                    dpi_type=DPIType.COMMERCIAL_DPI,
                    confidence=0.8
                )
            )
            
            # Generate diagnostic report
            report = diagnostic_system.generate_diagnostic_report()
            
            duration = time.time() - start_time
            
            if not report:
                return ValidationResult(
                    test_name="Monitoring Integration",
                    success=False,
                    duration=duration,
                    error="Failed to generate diagnostic report"
                )
            
            if not report.fingerprinting_stats:
                return ValidationResult(
                    test_name="Monitoring Integration",
                    success=False,
                    duration=duration,
                    error="Diagnostic report missing fingerprinting stats"
                )
            
            return ValidationResult(
                test_name="Monitoring Integration",
                success=True,
                duration=duration,
                details={
                    'report_generated': True,
                    'stats_available': bool(report.fingerprinting_stats),
                    'health_checks': len(report.health_checks)
                }
            )
        
        except Exception as e:
            return ValidationResult(
                test_name="Monitoring Integration",
                success=False,
                duration=time.time() - start_time,
                error=str(e)
            )
    
    async def _test_configuration_system(self) -> ValidationResult:
        """Test configuration system."""
        start_time = time.time()
        
        try:
            config_manager = get_config_manager()
            config = config_manager.get_config()
            
            # Test configuration validation
            errors = config.validate()
            
            # Test analyzer management
            original_tcp_state = config.is_analyzer_enabled("tcp")
            config.disable_analyzer("tcp")
            disabled_state = config.is_analyzer_enabled("tcp")
            config.enable_analyzer("tcp")
            enabled_state = config.is_analyzer_enabled("tcp")
            
            # Test feature flags
            original_ml_state = config.is_feature_enabled("ml_classification")
            config.disable_feature("ml_classification")
            disabled_ml_state = config.is_feature_enabled("ml_classification")
            config.enable_feature("ml_classification")
            enabled_ml_state = config.is_feature_enabled("ml_classification")
            
            duration = time.time() - start_time
            
            if errors:
                return ValidationResult(
                    test_name="Configuration System",
                    success=False,
                    duration=duration,
                    error=f"Configuration validation failed: {errors}"
                )
            
            if disabled_state or not enabled_state:
                return ValidationResult(
                    test_name="Configuration System",
                    success=False,
                    duration=duration,
                    error="Analyzer enable/disable not working"
                )
            
            if disabled_ml_state or not enabled_ml_state:
                return ValidationResult(
                    test_name="Configuration System",
                    success=False,
                    duration=duration,
                    error="Feature flag enable/disable not working"
                )
            
            return ValidationResult(
                test_name="Configuration System",
                success=True,
                duration=duration,
                details={
                    'validation_passed': len(errors) == 0,
                    'analyzer_management': True,
                    'feature_flags': True
                }
            )
        
        except Exception as e:
            return ValidationResult(
                test_name="Configuration System",
                success=False,
                duration=time.time() - start_time,
                error=str(e)
            )
    
    async def _test_backward_compatibility(self) -> ValidationResult:
        """Test backward compatibility layer."""
        start_time = time.time()
        
        try:
            from core.fingerprint.compatibility import BackwardCompatibilityLayer
            
            compat_layer = BackwardCompatibilityLayer()
            wrapper = compat_layer.create_compatibility_wrapper()
            
            # Test legacy interface
            legacy_fp = wrapper.get_simple_fingerprint("compat-test.com")
            is_blocked = wrapper.is_blocked("compat-test.com")
            blocking_type = wrapper.get_blocking_type("compat-test.com")
            
            duration = time.time() - start_time
            
            if not isinstance(legacy_fp, dict):
                return ValidationResult(
                    test_name="Backward Compatibility",
                    success=False,
                    duration=duration,
                    error="Legacy fingerprint not in dict format"
                )
            
            if 'dpi_type' not in legacy_fp:
                return ValidationResult(
                    test_name="Backward Compatibility",
                    success=False,
                    duration=duration,
                    error="Legacy fingerprint missing dpi_type"
                )
            
            if not isinstance(is_blocked, bool):
                return ValidationResult(
                    test_name="Backward Compatibility",
                    success=False,
                    duration=duration,
                    error="is_blocked not returning boolean"
                )
            
            return ValidationResult(
                test_name="Backward Compatibility",
                success=True,
                duration=duration,
                details={
                    'legacy_interface': True,
                    'dict_format': True,
                    'boolean_methods': True
                }
            )
        
        except Exception as e:
            return ValidationResult(
                test_name="Backward Compatibility",
                success=False,
                duration=time.time() - start_time,
                error=str(e)
            )    
    
    async def _test_fingerprinting_performance(self) -> PerformanceResult:
        """Test fingerprinting performance."""
        from unittest.mock import patch
        
        with patch('core.fingerprint.tcp_analyzer.TCPAnalyzer.analyze_tcp_behavior') as mock_tcp, \
             patch('core.fingerprint.http_analyzer.HTTPAnalyzer.analyze_http_behavior') as mock_http, \
             patch('core.fingerprint.dns_analyzer.DNSAnalyzer.analyze_dns_behavior') as mock_dns:
            
            # Mock fast responses
            async def fast_mock(*args, **kwargs):
                await asyncio.sleep(0.01)  # 10ms delay
                return {'test_metric': True}
            
            mock_tcp.side_effect = fast_mock
            mock_http.side_effect = fast_mock
            mock_dns.side_effect = fast_mock
            
            fingerprinter = AdvancedFingerprinter(config=self.config)
            
            # Test batch fingerprinting
            start_time = time.time()
            tasks = []
            
            for i, target in enumerate(self.test_targets):
                task = fingerprinter.fingerprint_target(f"{target}-{i}")
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            duration = time.time() - start_time
            
            successful_results = [r for r in results if isinstance(r, DPIFingerprint)]
            success_rate = len(successful_results) / len(results)
            throughput = len(successful_results) / duration
            
            return PerformanceResult(
                test_name="Fingerprinting Performance",
                duration=duration,
                throughput=throughput,
                success_rate=success_rate,
                details={
                    'total_operations': len(results),
                    'successful_operations': len(successful_results),
                    'average_time_per_operation': duration / len(results)
                }
            )
    
    async def _test_strategy_generation_performance(self) -> PerformanceResult:
        """Test strategy generation performance."""
        generator = ZapretStrategyGenerator()
        
        # Create test fingerprint
        fingerprint = DPIFingerprint(
            target="perf-test.com",
            dpi_type=DPIType.ROSKOMNADZOR_DPI,
            confidence=0.9
        )
        
        # Test multiple strategy generations
        start_time = time.time()
        operations = 50
        
        for i in range(operations):
            strategies = generator.generate_strategies(fingerprint=fingerprint, count=20)
            if len(strategies) != 20:
                raise Exception(f"Expected 20 strategies, got {len(strategies)}")
        
        duration = time.time() - start_time
        throughput = operations / duration
        
        return PerformanceResult(
            test_name="Strategy Generation Performance",
            duration=duration,
            throughput=throughput,
            success_rate=1.0,
            details={
                'operations': operations,
                'strategies_per_operation': 20,
                'total_strategies_generated': operations * 20
            }
        )
    
    async def _test_concurrent_operations_performance(self) -> PerformanceResult:
        """Test concurrent operations performance."""
        from unittest.mock import patch
        
        with patch('core.fingerprint.tcp_analyzer.TCPAnalyzer.analyze_tcp_behavior') as mock_tcp, \
             patch('core.fingerprint.http_analyzer.HTTPAnalyzer.analyze_http_behavior') as mock_http, \
             patch('core.fingerprint.dns_analyzer.DNSAnalyzer.analyze_dns_behavior') as mock_dns:
            
            # Mock responses with slight delay
            async def concurrent_mock(*args, **kwargs):
                await asyncio.sleep(0.05)  # 50ms delay
                return {'concurrent_test': True}
            
            mock_tcp.side_effect = concurrent_mock
            mock_http.side_effect = concurrent_mock
            mock_dns.side_effect = concurrent_mock
            
            fingerprinter = AdvancedFingerprinter(config=self.config)
            
            # Test high concurrency
            start_time = time.time()
            tasks = []
            
            for i in range(20):  # 20 concurrent operations
                task = fingerprinter.fingerprint_target(f"concurrent-test-{i}.com")
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            duration = time.time() - start_time
            
            successful_results = [r for r in results if isinstance(r, DPIFingerprint)]
            success_rate = len(successful_results) / len(results)
            throughput = len(successful_results) / duration
            
            return PerformanceResult(
                test_name="Concurrent Operations Performance",
                duration=duration,
                throughput=throughput,
                success_rate=success_rate,
                details={
                    'concurrent_operations': len(results),
                    'successful_operations': len(successful_results),
                    'concurrency_level': 20
                }
            )
    
    def _check_system_health(self) -> Dict[str, Any]:
        """Check overall system health."""
        diagnostic_system = get_diagnostic_system()
        health_results = diagnostic_system.health_checker.run_all_checks()
        
        health_summary = {
            'overall_status': 'healthy',
            'component_count': len(health_results),
            'healthy_components': 0,
            'warning_components': 0,
            'critical_components': 0,
            'components': {}
        }
        
        for result in health_results:
            health_summary['components'][result.component] = {
                'status': result.status,
                'message': result.message
            }
            
            if result.status == 'healthy':
                health_summary['healthy_components'] += 1
            elif result.status == 'warning':
                health_summary['warning_components'] += 1
            elif result.status == 'critical':
                health_summary['critical_components'] += 1
        
        # Determine overall status
        if health_summary['critical_components'] > 0:
            health_summary['overall_status'] = 'critical'
        elif health_summary['warning_components'] > 0:
            health_summary['overall_status'] = 'warning'
        
        return health_summary
    
    def _generate_optimization_recommendations(self, report: IntegrationReport) -> List[str]:
        """Generate optimization recommendations based on test results."""
        recommendations = []
        
        # Analyze validation results
        failed_validations = [r for r in report.validation_results if not r.success]
        if failed_validations:
            recommendations.append(
                f"Fix {len(failed_validations)} failed validation tests before production deployment"
            )
        
        # Analyze performance results
        for perf_result in report.performance_results:
            if perf_result.success_rate < 0.95:
                recommendations.append(
                    f"Improve {perf_result.test_name} success rate (currently {perf_result.success_rate:.1%})"
                )
            
            if perf_result.throughput < 1.0:
                recommendations.append(
                    f"Optimize {perf_result.test_name} throughput (currently {perf_result.throughput:.2f} ops/sec)"
                )
        
        # Analyze system health
        if report.system_health.get('critical_components', 0) > 0:
            recommendations.append("Address critical system health issues before production")
        
        if report.system_health.get('warning_components', 0) > 0:
            recommendations.append("Review and resolve system health warnings")
        
        # Configuration recommendations
        config = self.config
        if config.performance.max_concurrent_fingerprints < 10:
            recommendations.append("Consider increasing max_concurrent_fingerprints for better throughput")
        
        if not config.cache.enabled:
            recommendations.append("Enable caching for improved performance")
        
        if not config.ml.enabled:
            recommendations.append("Enable ML classification for better accuracy")
        
        # General recommendations
        if not recommendations:
            recommendations.append("System is well-optimized and ready for production")
        
        return recommendations
    
    def _assess_production_readiness(self, report: IntegrationReport) -> Dict[str, bool]:
        """Assess production readiness based on test results."""
        readiness = {
            'core_functionality': True,
            'performance_acceptable': True,
            'system_health_good': True,
            'integration_working': True,
            'monitoring_operational': True,
            'configuration_valid': True,
            'backward_compatibility': True,
            'overall_ready': True
        }
        
        # Check validation results
        failed_validations = [r for r in report.validation_results if not r.success]
        if failed_validations:
            readiness['core_functionality'] = False
            
            # Check specific components
            for result in failed_validations:
                if 'Strategy' in result.test_name:
                    readiness['integration_working'] = False
                elif 'Configuration' in result.test_name:
                    readiness['configuration_valid'] = False
                elif 'Monitoring' in result.test_name:
                    readiness['monitoring_operational'] = False
                elif 'Compatibility' in result.test_name:
                    readiness['backward_compatibility'] = False
        
        # Check performance results
        for perf_result in report.performance_results:
            if perf_result.success_rate < 0.9 or perf_result.throughput < 0.5:
                readiness['performance_acceptable'] = False
        
        # Check system health
        if report.system_health.get('critical_components', 0) > 0:
            readiness['system_health_good'] = False
        
        # Overall readiness
        readiness['overall_ready'] = all(readiness.values())
        
        return readiness
    
    def export_report(self, report: IntegrationReport, file_path: str):
        """Export integration report to file."""
        report_data = {
            'timestamp': report.timestamp,
            'validation_results': [
                {
                    'test_name': r.test_name,
                    'success': r.success,
                    'duration': r.duration,
                    'details': r.details,
                    'error': r.error
                }
                for r in report.validation_results
            ],
            'performance_results': [
                {
                    'test_name': r.test_name,
                    'duration': r.duration,
                    'throughput': r.throughput,
                    'success_rate': r.success_rate,
                    'details': r.details
                }
                for r in report.performance_results
            ],
            'system_health': report.system_health,
            'optimization_recommendations': report.optimization_recommendations,
            'production_readiness': report.production_readiness
        }
        
        with open(file_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)


async def run_final_integration_tests():
    """Run final integration tests and generate report."""
    tester = FinalIntegrationTester()
    report = await tester.run_complete_validation()
    
    print("\n" + "=" * 60)
    print("FINAL INTEGRATION TEST RESULTS")
    print("=" * 60)
    
    # Summary
    total_validations = len(report.validation_results)
    passed_validations = len([r for r in report.validation_results if r.success])
    
    print(f"Validation Tests: {passed_validations}/{total_validations} passed")
    print(f"Performance Tests: {len(report.performance_results)} completed")
    print(f"System Health: {report.system_health.get('overall_status', 'unknown')}")
    print(f"Production Ready: {'✅ YES' if report.production_readiness.get('overall_ready', False) else '❌ NO'}")
    
    # Recommendations
    if report.optimization_recommendations:
        print(f"\n📋 Optimization Recommendations:")
        for i, rec in enumerate(report.optimization_recommendations, 1):
            print(f"  {i}. {rec}")
    
    # Production readiness details
    print(f"\n🚀 Production Readiness Assessment:")
    for component, ready in report.production_readiness.items():
        if component != 'overall_ready':
            status = "✅" if ready else "❌"
            print(f"  {status} {component.replace('_', ' ').title()}")
    
    return report


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Final Integration Testing and Optimization')
    parser.add_argument('--export', help='Export report to file')
    parser.add_argument('--quick', action='store_true', help='Run quick validation only')
    
    args = parser.parse_args()
    
    async def main():
        if args.quick:
            print("Running quick validation...")
            # Run subset of tests for quick validation
        
        report = await run_final_integration_tests()
        
        if args.export:
            tester = FinalIntegrationTester()
            tester.export_report(report, args.export)
            print(f"\n📄 Report exported to: {args.export}")
        
        # Exit with appropriate code
        if report.production_readiness.get('overall_ready', False):
            print(f"\n🎉 System is ready for production deployment!")
            sys.exit(0)
        else:
            print(f"\n⚠️  System needs attention before production deployment")
            sys.exit(1)
    
    asyncio.run(main())