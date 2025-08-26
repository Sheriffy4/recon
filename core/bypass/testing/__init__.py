"""
Enhanced Testing Framework for Bypass Engine.

This module provides comprehensive testing capabilities including:
- Attack functionality testing
- Stability testing over time
- Performance benchmarking
- Regression testing
- Integration testing
- Automated test execution

Main Components:
- ComprehensiveTestSuite: Main testing orchestrator
- TestRunner: CLI and automated test execution
- Integration tests: End-to-end workflow testing
- Test models: Data structures for test results

Usage:
    # Quick test of all attacks
    from core.bypass.testing import run_quick_test_suite
    report = await run_quick_test_suite()

    # Comprehensive testing
    from core.bypass.testing import ComprehensiveTestSuite
    from core.bypass.attacks.modern_registry import ModernAttackRegistry

    registry = ModernAttackRegistry()
    suite = ComprehensiveTestSuite(registry)
    report = await suite.run_comprehensive_tests()

    # CLI usage
    python -m core.bypass.testing.test_runner quick --verbose
"""
from core.bypass.testing.test_models import TestCase, TestResult, TestStatus, TestSeverity, ValidationMethod, BenchmarkResult, StabilityResult, TestSuite, TestReport
from core.bypass.testing.attack_test_suite import ComprehensiveTestSuite, TestExecutor, StabilityTester, PerformanceBenchmarker, RegressionTester, run_attack_test, run_quick_test_suite
try:
    from core.bypass.testing.integration_tests import WorkflowIntegrationTester, ComponentIntegrationTester, run_integration_tests, run_component_integration_tests, run_full_integration_suite
    _integration_available = True
except ImportError:

    def run_integration_tests():
        raise ImportError(f'Integration tests not available: {e}')

    def run_component_integration_tests():
        raise ImportError(f'Component integration tests not available: {e}')

    def run_full_integration_suite():
        raise ImportError(f'Full integration suite not available: {e}')
    WorkflowIntegrationTester = None
    ComponentIntegrationTester = None
    _integration_available = False
from core.bypass.testing.test_runner import TestRunner, TestConfiguration
__all__ = ['TestCase', 'TestResult', 'TestStatus', 'TestSeverity', 'ValidationMethod', 'BenchmarkResult', 'StabilityResult', 'TestSuite', 'TestReport', 'ComprehensiveTestSuite', 'TestExecutor', 'StabilityTester', 'PerformanceBenchmarker', 'RegressionTester', 'WorkflowIntegrationTester', 'ComponentIntegrationTester', 'TestRunner', 'TestConfiguration', 'run_attack_test', 'run_quick_test_suite', 'run_integration_tests', 'run_component_integration_tests', 'run_full_integration_suite']
__version__ = '1.0.0'
__author__ = 'Bypass Engine Team'
__description__ = 'Enhanced Testing Framework for DPI Bypass Engine'