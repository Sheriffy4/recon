#!/usr/bin/env python3
"""
Final Integration Testing - Task 20 Implementation
Quick integration test to validate system readiness.
"""

import asyncio
import time
import sys
import os
from unittest.mock import patch

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType
    from core.fingerprint.config import get_config_manager
    from core.fingerprint.diagnostics import get_diagnostic_system
    from ml.zapret_strategy_generator import ZapretStrategyGenerator
    from core.fingerprint.cache import FingerprintCache
    from core.fingerprint.compatibility import BackwardCompatibilityLayer
except ImportError:
    from recon.core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter
    from recon.core.fingerprint.advanced_models import DPIFingerprint, DPIType
    from recon.core.fingerprint.config import get_config_manager
    from recon.core.fingerprint.diagnostics import get_diagnostic_system
    from recon.ml.zapret_strategy_generator import ZapretStrategyGenerator
    from recon.core.fingerprint.cache import FingerprintCache
    from recon.core.fingerprint.compatibility import BackwardCompatibilityLayer


async def test_complete_system():
    """Test complete system integration."""
    print("🚀 Running Final Integration Tests")
    print("=" * 50)

    results = {"tests_run": 0, "tests_passed": 0, "tests_failed": 0, "errors": []}

    # Test 1: Configuration System
    print("1. Testing Configuration System...")
    try:
        config_manager = get_config_manager()
        config = config_manager.get_config()
        errors = config.validate()

        if not errors:
            print("   ✅ Configuration system working")
            results["tests_passed"] += 1
        else:
            print(f"   ❌ Configuration validation failed: {errors}")
            results["tests_failed"] += 1
            results["errors"].append(f"Configuration: {errors}")
    except Exception as e:
        print(f"   ❌ Configuration system error: {e}")
        results["tests_failed"] += 1
        results["errors"].append(f"Configuration: {e}")

    results["tests_run"] += 1

    # Test 2: Cache System
    print("2. Testing Cache System...")
    try:
        cache = FingerprintCache()
        test_fp = DPIFingerprint(
            target="cache-test.com", dpi_type=DPIType.COMMERCIAL_DPI, confidence=0.8
        )

        cache.store("test-key", test_fp)
        retrieved = cache.get("test-key")

        if retrieved and retrieved.target == test_fp.target:
            print("   ✅ Cache system working")
            results["tests_passed"] += 1
        else:
            print("   ❌ Cache system failed")
            results["tests_failed"] += 1
            results["errors"].append("Cache: Store/retrieve failed")
    except Exception as e:
        print(f"   ❌ Cache system error: {e}")
        results["tests_failed"] += 1
        results["errors"].append(f"Cache: {e}")

    results["tests_run"] += 1

    # Test 3: Strategy Generation
    print("3. Testing Strategy Generation...")
    try:
        generator = ZapretStrategyGenerator()
        test_fp = DPIFingerprint(
            target="strategy-test.com",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.85,
        )

        strategies = generator.generate_strategies(fingerprint=test_fp, count=5)

        if len(strategies) == 5 and all("--dpi-desync" in s for s in strategies):
            print("   ✅ Strategy generation working")
            results["tests_passed"] += 1
        else:
            print("   ❌ Strategy generation failed")
            results["tests_failed"] += 1
            results["errors"].append("Strategy: Invalid output")
    except Exception as e:
        print(f"   ❌ Strategy generation error: {e}")
        results["tests_failed"] += 1
        results["errors"].append(f"Strategy: {e}")

    results["tests_run"] += 1

    # Test 4: Fingerprinting Workflow (with mocks)
    print("4. Testing Fingerprinting Workflow...")
    try:
        with patch(
            "core.fingerprint.tcp_analyzer.TCPAnalyzer.analyze_tcp_behavior"
        ) as mock_tcp, patch(
            "core.fingerprint.http_analyzer.HTTPAnalyzer.analyze_http_behavior"
        ) as mock_http, patch(
            "core.fingerprint.dns_analyzer.DNSAnalyzer.analyze_dns_behavior"
        ) as mock_dns:

            mock_tcp.return_value = {"rst_injection_detected": True}
            mock_http.return_value = {"http_header_filtering": True}
            mock_dns.return_value = {"dns_hijacking_detected": False}

            fingerprinter = AdvancedFingerprinter()
            fingerprint = await fingerprinter.fingerprint_target("workflow-test.com")

            if (
                isinstance(fingerprint, DPIFingerprint)
                and fingerprint.target == "workflow-test.com"
            ):
                print("   ✅ Fingerprinting workflow working")
                results["tests_passed"] += 1
            else:
                print("   ❌ Fingerprinting workflow failed")
                results["tests_failed"] += 1
                results["errors"].append("Fingerprinting: Invalid result")
    except Exception as e:
        print(f"   ❌ Fingerprinting workflow error: {e}")
        results["tests_failed"] += 1
        results["errors"].append(f"Fingerprinting: {e}")

    results["tests_run"] += 1

    # Test 5: Backward Compatibility
    print("5. Testing Backward Compatibility...")
    try:
        compat_layer = BackwardCompatibilityLayer()
        wrapper = compat_layer.create_compatibility_wrapper()

        legacy_fp = wrapper.get_simple_fingerprint("compat-test.com")

        if isinstance(legacy_fp, dict) and "dpi_type" in legacy_fp:
            print("   ✅ Backward compatibility working")
            results["tests_passed"] += 1
        else:
            print("   ❌ Backward compatibility failed")
            results["tests_failed"] += 1
            results["errors"].append("Compatibility: Invalid format")
    except Exception as e:
        print(f"   ❌ Backward compatibility error: {e}")
        results["tests_failed"] += 1
        results["errors"].append(f"Compatibility: {e}")

    results["tests_run"] += 1

    # Test 6: Diagnostics System
    print("6. Testing Diagnostics System...")
    try:
        diagnostic_system = get_diagnostic_system()
        health_results = diagnostic_system.health_checker.run_all_checks()

        if health_results and len(health_results) > 0:
            print("   ✅ Diagnostics system working")
            results["tests_passed"] += 1
        else:
            print("   ❌ Diagnostics system failed")
            results["tests_failed"] += 1
            results["errors"].append("Diagnostics: No health checks")
    except Exception as e:
        print(f"   ❌ Diagnostics system error: {e}")
        results["tests_failed"] += 1
        results["errors"].append(f"Diagnostics: {e}")

    results["tests_run"] += 1

    # Summary
    print("\n" + "=" * 50)
    print("FINAL INTEGRATION TEST RESULTS")
    print("=" * 50)
    print(f"Tests Run: {results['tests_run']}")
    print(f"Tests Passed: {results['tests_passed']}")
    print(f"Tests Failed: {results['tests_failed']}")
    print(f"Success Rate: {results['tests_passed']/results['tests_run']*100:.1f}%")

    if results["errors"]:
        print("\nErrors:")
        for error in results["errors"]:
            print(f"  - {error}")

    # Production readiness assessment
    success_rate = results["tests_passed"] / results["tests_run"]

    if success_rate >= 0.9:
        print("\n🎉 SYSTEM READY FOR PRODUCTION")
        print("   All critical components are working correctly")
        return True
    elif success_rate >= 0.7:
        print("\n⚠️  SYSTEM NEEDS ATTENTION")
        print("   Some components have issues but core functionality works")
        return False
    else:
        print("\n❌ SYSTEM NOT READY FOR PRODUCTION")
        print("   Critical issues need to be resolved")
        return False


async def run_performance_test():
    """Run quick performance test."""
    print("\n📊 Running Performance Test...")

    try:
        with patch(
            "core.fingerprint.tcp_analyzer.TCPAnalyzer.analyze_tcp_behavior"
        ) as mock_tcp, patch(
            "core.fingerprint.http_analyzer.HTTPAnalyzer.analyze_http_behavior"
        ) as mock_http, patch(
            "core.fingerprint.dns_analyzer.DNSAnalyzer.analyze_dns_behavior"
        ) as mock_dns:

            # Mock fast responses
            async def fast_mock(*args, **kwargs):
                await asyncio.sleep(0.01)  # 10ms delay
                return {"test_metric": True}

            mock_tcp.side_effect = fast_mock
            mock_http.side_effect = fast_mock
            mock_dns.side_effect = fast_mock

            fingerprinter = AdvancedFingerprinter()

            # Test 5 concurrent fingerprints
            start_time = time.time()
            tasks = []

            for i in range(5):
                task = fingerprinter.fingerprint_target(f"perf-test-{i}.com")
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)
            duration = time.time() - start_time

            successful = len([r for r in results if isinstance(r, DPIFingerprint)])
            throughput = successful / duration

            print(f"   Duration: {duration:.3f}s")
            print(f"   Successful: {successful}/5")
            print(f"   Throughput: {throughput:.2f} fingerprints/sec")

            if successful >= 4 and throughput >= 1.0:
                print("   ✅ Performance acceptable")
                return True
            else:
                print("   ⚠️  Performance needs optimization")
                return False

    except Exception as e:
        print(f"   ❌ Performance test failed: {e}")
        return False


def check_system_health():
    """Check system health."""
    print("\n🏥 Checking System Health...")

    try:
        diagnostic_system = get_diagnostic_system()
        health_results = diagnostic_system.health_checker.run_all_checks()

        healthy = 0
        warning = 0
        critical = 0

        for result in health_results:
            if result.status == "healthy":
                healthy += 1
                print(f"   ✅ {result.component}: {result.message}")
            elif result.status == "warning":
                warning += 1
                print(f"   ⚠️  {result.component}: {result.message}")
            elif result.status == "critical":
                critical += 1
                print(f"   ❌ {result.component}: {result.message}")

        print(
            f"\n   Summary: {healthy} healthy, {warning} warnings, {critical} critical"
        )

        if critical == 0:
            print("   ✅ System health good")
            return True
        else:
            print("   ❌ System health issues detected")
            return False

    except Exception as e:
        print(f"   ❌ Health check failed: {e}")
        return False


async def main():
    """Main test runner."""
    print("Advanced DPI Fingerprinting System - Final Integration Test")
    print("Task 20: Final integration testing and optimization")
    print("=" * 70)

    # Run integration tests
    integration_success = await test_complete_system()

    # Run performance test
    performance_success = await run_performance_test()

    # Check system health
    health_success = check_system_health()

    # Final assessment
    print("\n" + "=" * 70)
    print("FINAL SYSTEM ASSESSMENT")
    print("=" * 70)

    overall_success = integration_success and performance_success and health_success

    print(f"Integration Tests: {'✅ PASS' if integration_success else '❌ FAIL'}")
    print(f"Performance Tests: {'✅ PASS' if performance_success else '❌ FAIL'}")
    print(f"System Health: {'✅ GOOD' if health_success else '❌ ISSUES'}")

    if overall_success:
        print("\n🎉 SYSTEM IS PRODUCTION READY!")
        print("   All tests passed and system is healthy")
        print("   Ready for deployment")
        return 0
    else:
        print("\n⚠️  SYSTEM NEEDS ATTENTION")
        print("   Some issues detected, review before production")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
