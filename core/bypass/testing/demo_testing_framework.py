"""
Demo script for the enhanced testing framework.
Shows how to use the comprehensive testing suite.
"""

import asyncio
import logging

from .attack_test_suite import ComprehensiveTestSuite
from .integration_tests import run_integration_tests
from .test_runner import TestRunner, TestConfiguration
from ..attacks.modern_registry import ModernAttackRegistry

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
LOG = logging.getLogger("TestingFrameworkDemo")


async def demo_basic_testing():
    """Demonstrate basic attack testing."""
    LOG.info("=== Demo: Basic Attack Testing ===")

    # Initialize registry
    registry = ModernAttackRegistry()

    # Get available attacks
    attack_ids = registry.list_attacks(enabled_only=True)
    LOG.info(f"Found {len(attack_ids)} enabled attacks")

    if not attack_ids:
        LOG.warning("No attacks available for testing")
        return

    # Test first few attacks
    test_attacks = attack_ids[:3]
    LOG.info(f"Testing attacks: {test_attacks}")

    # Create test suite
    suite = ComprehensiveTestSuite(registry)

    # Run quick tests
    report = await suite.run_quick_tests(test_attacks)

    # Print results
    LOG.info(f"Test Results: {report.passed_tests}/{report.total_tests} passed")
    LOG.info(f"Success Rate: {report.success_rate:.1%}")

    return report


async def demo_comprehensive_testing():
    """Demonstrate comprehensive testing with all features."""
    LOG.info("=== Demo: Comprehensive Testing ===")

    # Initialize components
    registry = ModernAttackRegistry()
    suite = ComprehensiveTestSuite(registry)

    # Get a few attacks for demo
    attack_ids = registry.list_attacks(enabled_only=True)[:2]  # Test only 2 for demo

    if not attack_ids:
        LOG.warning("No attacks available for testing")
        return

    LOG.info(f"Running comprehensive tests on: {attack_ids}")

    # Run comprehensive tests with reduced parameters for demo
    report = await suite.run_comprehensive_tests(
        attack_ids=attack_ids,
        include_stability=True,
        include_benchmarks=True,
        include_regression=False,  # Skip regression for demo
        stability_duration_minutes=1,  # Short duration for demo
        benchmark_iterations=10,  # Few iterations for demo
    )

    # Print detailed results
    LOG.info("Comprehensive Test Results:")
    LOG.info(f"  Basic Tests: {report.passed_tests}/{report.total_tests} passed")
    LOG.info(f"  Stability Tests: {len(report.stability_results)} completed")
    LOG.info(f"  Benchmarks: {len(report.benchmark_results)} completed")

    # Show stability results
    for stability in report.stability_results:
        LOG.info(f"  {stability.attack_id}: {stability.stability_score:.1%} stable")

    # Show benchmark results
    for benchmark in report.benchmark_results:
        LOG.info(
            f"  {benchmark.attack_id}: {benchmark.average_time:.3f}s avg, {benchmark.success_rate:.1%} success"
        )

    return report


async def demo_integration_testing():
    """Demonstrate integration testing."""
    LOG.info("=== Demo: Integration Testing ===")

    try:
        # Run integration tests
        report = await run_integration_tests()

        LOG.info(
            f"Integration Test Results: {report.passed_tests}/{report.total_tests} passed"
        )

        # Show individual test results
        for result in report.test_results:
            status = "✓" if result.success else "✗"
            LOG.info(f"  {status} {result.test_case_id}: {result.duration:.2f}s")
            if result.error_message:
                LOG.info(f"    Error: {result.error_message}")

        return report

    except Exception as e:
        LOG.error(f"Integration testing failed: {e}")
        return None


async def demo_test_runner():
    """Demonstrate the test runner with configuration."""
    LOG.info("=== Demo: Test Runner ===")

    # Create test configuration
    config = TestConfiguration()

    # Modify config for demo
    config.config["test_settings"]["max_parallel_tests"] = 2
    config.config["stability_settings"]["duration_minutes"] = 1
    config.config["benchmark_settings"]["iterations"] = 5

    # Create test runner
    runner = TestRunner(config)

    # Run quick tests
    LOG.info("Running quick tests via test runner...")
    report = await runner.run_tests("quick")

    LOG.info(f"Test Runner Results: {report.passed_tests}/{report.total_tests} passed")

    # Generate text report
    text_report = runner.generate_report(report, "text")
    LOG.info("Generated text report:")
    print(text_report[:500] + "..." if len(text_report) > 500 else text_report)

    return report


async def demo_category_testing():
    """Demonstrate category-specific testing."""
    LOG.info("=== Demo: Category Testing ===")

    registry = ModernAttackRegistry()
    suite = ComprehensiveTestSuite(registry)

    # Get available categories
    categories = registry.get_categories()
    LOG.info(f"Available categories: {[c.value for c in categories]}")

    if not categories:
        LOG.warning("No categories available")
        return

    # Test first category
    test_category = categories[0]
    LOG.info(f"Testing category: {test_category.value}")

    try:
        report = await suite.run_category_tests(test_category)
        LOG.info(
            f"Category Test Results: {report.passed_tests}/{report.total_tests} passed"
        )
        return report
    except Exception as e:
        LOG.error(f"Category testing failed: {e}")
        return None


async def demo_performance_monitoring():
    """Demonstrate performance monitoring during tests."""
    LOG.info("=== Demo: Performance Monitoring ===")

    registry = ModernAttackRegistry()
    suite = ComprehensiveTestSuite(registry)

    # Add performance monitoring callback
    def performance_callback(result):
        if result.performance_metrics:
            LOG.info(
                f"Performance - {result.test_case_id}: "
                f"{result.duration:.3f}s, "
                f"Memory: {result.performance_metrics.get('memory_usage_mb', 0):.1f}MB"
            )

    suite.add_test_callback(performance_callback)

    # Run tests with monitoring
    attack_ids = registry.list_attacks(enabled_only=True)[:2]
    if attack_ids:
        report = await suite.run_quick_tests(attack_ids)
        LOG.info(
            f"Performance Monitoring Results: {report.passed_tests}/{report.total_tests} passed"
        )
        return report
    else:
        LOG.warning("No attacks available for performance monitoring")
        return None


async def demo_error_handling():
    """Demonstrate error handling in tests."""
    LOG.info("=== Demo: Error Handling ===")

    registry = ModernAttackRegistry()
    suite = ComprehensiveTestSuite(registry)

    # Try to test non-existent attack
    try:
        from .test_models import TestCase, ValidationMethod

        # Create a test case for non-existent attack
        fake_test_case = TestCase(
            id="fake_test",
            name="Fake Test",
            description="Test for non-existent attack",
            attack_id="non_existent_attack",
            test_domain="example.com",
            expected_result=True,
            validation_methods=[ValidationMethod.HTTP_RESPONSE],
        )

        result = await suite.test_executor.execute_test(fake_test_case, registry)

        LOG.info(f"Error Handling Test: Status={result.status.value}")
        if result.error_message:
            LOG.info(f"Error Message: {result.error_message}")

        return result

    except Exception as e:
        LOG.error(f"Error handling demo failed: {e}")
        return None


async def run_all_demos():
    """Run all demonstration functions."""
    LOG.info("Starting Enhanced Testing Framework Demonstration")
    LOG.info("=" * 60)

    demos = [
        ("Basic Testing", demo_basic_testing),
        ("Comprehensive Testing", demo_comprehensive_testing),
        ("Integration Testing", demo_integration_testing),
        ("Test Runner", demo_test_runner),
        ("Category Testing", demo_category_testing),
        ("Performance Monitoring", demo_performance_monitoring),
        ("Error Handling", demo_error_handling),
    ]

    results = {}

    for demo_name, demo_func in demos:
        try:
            LOG.info(f"\n{'='*20} {demo_name} {'='*20}")
            result = await demo_func()
            results[demo_name] = result
            LOG.info(f"✓ {demo_name} completed successfully")
        except Exception as e:
            LOG.error(f"✗ {demo_name} failed: {e}")
            results[demo_name] = None

    # Summary
    LOG.info(f"\n{'='*60}")
    LOG.info("DEMONSTRATION SUMMARY")
    LOG.info(f"{'='*60}")

    successful_demos = sum(1 for result in results.values() if result is not None)
    total_demos = len(demos)

    LOG.info(f"Completed: {successful_demos}/{total_demos} demonstrations")

    for demo_name, result in results.items():
        status = "✓" if result is not None else "✗"
        LOG.info(f"  {status} {demo_name}")

    LOG.info("\nEnhanced Testing Framework demonstration completed!")
    return results


if __name__ == "__main__":
    asyncio.run(run_all_demos())
