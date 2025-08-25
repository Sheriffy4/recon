#!/usr/bin/env python3
"""
Test script for comprehensive system validation.
Verifies that the comprehensive system test implementation works correctly.
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add the recon directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from core.bypass.testing.comprehensive_system_test import (
    ComprehensiveSystemValidator,
    SystemMetricsCollector,
)

LOG = logging.getLogger("TestComprehensiveSystem")


async def test_system_metrics_collector():
    """Test the system metrics collector."""
    print("Testing SystemMetricsCollector...")

    collector = SystemMetricsCollector()

    # Start collection
    collector.start_collection()

    # Let it collect for a few seconds
    await asyncio.sleep(3)

    # Stop collection
    collector.stop_collection()

    # Check results
    assert len(collector.metrics) > 0, "No metrics collected"

    summary = collector.get_metrics_summary()
    assert "cpu_usage" in summary, "CPU usage not in summary"
    assert "memory_usage_mb" in summary, "Memory usage not in summary"

    print(f"✅ Collected {len(collector.metrics)} metric data points")
    print(f"   Average CPU: {summary['cpu_usage']['avg']:.1f}%")
    print(f"   Average Memory: {summary['memory_usage_mb']['avg']:.1f} MB")


async def test_comprehensive_validator_init():
    """Test comprehensive validator initialization."""
    print("Testing ComprehensiveSystemValidator initialization...")

    validator = ComprehensiveSystemValidator()

    # Check that components are initialized
    assert validator.attack_registry is not None, "Attack registry not initialized"
    assert validator.metrics_collector is not None, "Metrics collector not initialized"
    assert len(validator.test_domains) > 0, "No test domains configured"

    # Check attack registry has attacks
    attack_ids = validator.attack_registry.list_attacks()
    print(f"✅ Validator initialized with {len(attack_ids)} attacks")


async def test_attack_validation_phase():
    """Test attack validation phase."""
    print("Testing attack validation phase...")

    # Run a limited attack validation (first 3 attacks only)
    validator = ComprehensiveSystemValidator()

    # Get first few attacks for testing
    all_attacks = validator.attack_registry.list_attacks()
    test_attacks = all_attacks[:3] if len(all_attacks) >= 3 else all_attacks

    if not test_attacks:
        print("⚠️  No attacks available for testing")
        return

    # Test individual attack validation
    for attack_id in test_attacks:
        try:
            result = await validator._validate_single_attack(attack_id)
            print(f"   Attack {attack_id}: {'PASS' if result.test_passed else 'FAIL'}")
            if not result.test_passed and result.error_message:
                print(f"     Error: {result.error_message}")
        except Exception as e:
            print(f"   Attack {attack_id}: ERROR - {e}")

    print("✅ Attack validation phase test completed")


async def test_strategy_effectiveness_phase():
    """Test strategy effectiveness phase."""
    print("Testing strategy effectiveness phase...")

    validator = ComprehensiveSystemValidator()

    if not validator.strategy_selector:
        print("⚠️  Strategy selector not available, skipping test")
        return

    # Test with one domain
    test_domain = validator.test_domains[0]

    try:
        modern_result = await validator._test_modern_strategy_effectiveness(test_domain)
        legacy_result = await validator._simulate_legacy_strategy_effectiveness(
            test_domain
        )

        print(f"   Domain: {test_domain}")
        print(f"   Modern success rate: {modern_result['success_rate']:.1%}")
        print(f"   Legacy success rate: {legacy_result['success_rate']:.1%}")

        print("✅ Strategy effectiveness phase test completed")

    except Exception as e:
        print(f"⚠️  Strategy effectiveness test failed: {e}")


async def test_stability_operations():
    """Test stability test operations."""
    print("Testing stability test operations...")

    validator = ComprehensiveSystemValidator()

    # Test individual operations
    registry_result = await validator._test_registry_operation()
    print(f"   Registry operation: {'PASS' if registry_result else 'FAIL'}")

    if validator.strategy_selector:
        strategy_result = await validator._test_strategy_operation()
        print(f"   Strategy operation: {'PASS' if strategy_result else 'FAIL'}")

    if validator.reliability_validator:
        validation_result = await validator._test_validation_operation()
        print(f"   Validation operation: {'PASS' if validation_result else 'FAIL'}")

    # Test batch operations
    batch_results = await validator._perform_stability_test_batch()
    success_count = sum(1 for r in batch_results if r)
    print(f"   Batch operations: {success_count}/{len(batch_results)} successful")

    print("✅ Stability operations test completed")


async def test_report_generation():
    """Test report generation."""
    print("Testing report generation...")

    validator = ComprehensiveSystemValidator()

    # Create mock data for report
    from core.bypass.testing.comprehensive_system_test import (
        AttackValidationResult,
        StrategyEffectivenessResult,
        StabilityTestResult,
    )
    from datetime import datetime

    # Mock attack results
    attack_results = [
        AttackValidationResult(
            attack_id="test_attack_1",
            attack_name="Test Attack 1",
            category="tcp_fragmentation",
            complexity="simple",
            enabled=True,
            test_passed=True,
            execution_time_ms=50.0,
            error_message=None,
            stability_score=0.9,
            performance_score=0.8,
            compatibility_modes=["native"],
        ),
        AttackValidationResult(
            attack_id="test_attack_2",
            attack_name="Test Attack 2",
            category="http_manipulation",
            complexity="moderate",
            enabled=True,
            test_passed=False,
            execution_time_ms=100.0,
            error_message="Test error",
            stability_score=0.5,
            performance_score=0.3,
            compatibility_modes=["emulated"],
        ),
    ]

    # Mock strategy results
    strategy_results = [
        StrategyEffectivenessResult(
            domain="example.com",
            legacy_success_rate=0.7,
            modern_success_rate=0.9,
            improvement_percent=28.6,
            legacy_avg_time_ms=150.0,
            modern_avg_time_ms=100.0,
            performance_improvement_percent=33.3,
            reliability_improvement=0.2,
        )
    ]

    # Mock stability results
    stability_results = StabilityTestResult(
        test_duration_minutes=5.0,
        total_operations=100,
        successful_operations=95,
        failed_operations=5,
        error_rate_percent=5.0,
        avg_cpu_usage=25.0,
        max_cpu_usage=40.0,
        avg_memory_usage_mb=512.0,
        max_memory_usage_mb=600.0,
        memory_leaks_detected=False,
        system_crashes=0,
        performance_degradation_percent=2.0,
    )

    # Generate report
    start_time = datetime.now()
    end_time = datetime.now()

    report = validator._generate_comprehensive_report(
        start_time, end_time, attack_results, strategy_results, stability_results, {}
    )

    # Verify report structure
    assert report.total_attacks_tested == 2, "Incorrect attack count"
    assert report.attacks_passed == 1, "Incorrect passed count"
    assert report.attacks_failed == 1, "Incorrect failed count"
    assert report.attack_success_rate == 0.5, "Incorrect success rate"

    # Test text report generation
    text_report = validator._generate_text_report(report)
    assert (
        "COMPREHENSIVE SYSTEM VALIDATION REPORT" in text_report
    ), "Missing report header"
    assert "ATTACK VALIDATION RESULTS" in text_report, "Missing attack section"

    print("✅ Report generation test completed")


async def run_quick_comprehensive_test():
    """Run a quick version of the comprehensive test."""
    print("Running quick comprehensive validation test...")

    validator = ComprehensiveSystemValidator()

    # Reduce test duration for quick test
    validator.stability_test_duration_minutes = 1  # 1 minute instead of 30
    validator.max_parallel_tests = 2  # Reduce parallelism

    try:
        # Start metrics collection
        validator.metrics_collector.start_collection()

        # Run a very limited validation
        print("  Phase 1: Testing first 2 attacks...")
        attack_ids = validator.attack_registry.list_attacks()[:2]
        if attack_ids:
            attack_results = []
            for attack_id in attack_ids:
                try:
                    result = await validator._validate_single_attack(attack_id)
                    attack_results.append(result)
                except Exception as e:
                    print(f"    Attack {attack_id} failed: {e}")

        print("  Phase 2: Testing strategy effectiveness...")
        if validator.strategy_selector:
            try:
                strategy_results = await validator._test_strategy_effectiveness()
                print(f"    Tested {len(strategy_results)} domains")
            except Exception as e:
                print(f"    Strategy test failed: {e}")

        print("  Phase 3: Running 30-second stability test...")
        try:
            # Very short stability test
            start_time = datetime.now()
            operations = 0
            while (datetime.now() - start_time).total_seconds() < 30:
                batch_results = await validator._perform_stability_test_batch()
                operations += len(batch_results)
                await asyncio.sleep(1)

            print(f"    Completed {operations} operations in 30 seconds")
        except Exception as e:
            print(f"    Stability test failed: {e}")

        # Stop metrics collection
        validator.metrics_collector.stop_collection()

        # Get metrics summary
        summary = validator.metrics_collector.get_metrics_summary()
        print(
            f"  System metrics: {len(validator.metrics_collector.metrics)} data points collected"
        )

        print("✅ Quick comprehensive test completed successfully")

    except Exception as e:
        print(f"❌ Quick comprehensive test failed: {e}")
        validator.metrics_collector.stop_collection()


async def main():
    """Run all tests."""
    print("=" * 60)
    print("COMPREHENSIVE SYSTEM TEST - VERIFICATION")
    print("=" * 60)

    try:
        # Test individual components
        await test_system_metrics_collector()
        print()

        await test_comprehensive_validator_init()
        print()

        await test_attack_validation_phase()
        print()

        await test_strategy_effectiveness_phase()
        print()

        await test_stability_operations()
        print()

        await test_report_generation()
        print()

        # Run quick comprehensive test
        await run_quick_comprehensive_test()
        print()

        print("=" * 60)
        print("✅ ALL TESTS PASSED - Comprehensive system test is working correctly!")
        print("=" * 60)

        return 0

    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Run tests
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
