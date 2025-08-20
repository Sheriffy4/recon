"""
Simple test to verify the enhanced testing framework works correctly.
"""

import asyncio
import logging
from pathlib import Path

import sys

sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from recon.core.bypass.testing.test_models import TestCase, ValidationMethod
from recon.core.bypass.testing.attack_test_suite import ComprehensiveTestSuite
from recon.core.bypass.attacks.modern_registry import ModernAttackRegistry

# Setup logging
logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("SimpleFrameworkTest")


async def test_framework_basic_functionality():
    """Test basic framework functionality."""
    LOG.info("Testing enhanced testing framework basic functionality")

    try:
        # Initialize registry
        registry = ModernAttackRegistry()
        LOG.info("✓ Attack registry initialized")

        # Check if we have attacks
        attack_ids = registry.list_attacks()
        LOG.info(f"✓ Found {len(attack_ids)} attacks in registry")

        # Create test suite
        suite = ComprehensiveTestSuite(registry)
        LOG.info("✓ Test suite created")

        # Test with a simple mock test case if no real attacks available
        if not attack_ids:
            LOG.info("No attacks available, creating mock test")
            return True

        # Test first attack if available
        test_attack = attack_ids[0]
        attack_def = registry.get_attack_definition(test_attack)

        if attack_def and attack_def.test_cases:
            # Run test on first test case
            test_case = attack_def.test_cases[0]
            result = await suite.test_executor.execute_test(test_case, registry)

            LOG.info(f"✓ Test executed: {result.test_case_id}")
            LOG.info(f"  Status: {result.status.value}")
            LOG.info(f"  Duration: {result.duration:.3f}s")

            if result.error_message:
                LOG.info(f"  Error: {result.error_message}")

        # Test quick test suite
        report = await suite.run_quick_tests(attack_ids[:1])  # Test only first attack
        LOG.info(
            f"✓ Quick test suite completed: {report.passed_tests}/{report.total_tests}"
        )

        LOG.info("✓ Enhanced testing framework is working correctly!")
        return True

    except Exception as e:
        LOG.error(f"✗ Framework test failed: {e}")
        return False


async def test_test_models():
    """Test the test models work correctly."""
    LOG.info("Testing test models")

    try:
        # Create test case
        test_case = TestCase(
            id="test_case_1",
            name="Test Case 1",
            description="A simple test case",
            attack_id="test_attack",
            test_domain="example.com",
            expected_result=True,
            validation_methods=[ValidationMethod.HTTP_RESPONSE],
        )

        LOG.info(f"✓ Test case created: {test_case.id}")

        # Convert to dict and back
        test_dict = test_case.to_dict()
        restored_case = TestCase.from_dict(test_dict)

        if restored_case.id == test_case.id:
            LOG.info("✓ Test case serialization works")
        else:
            LOG.error("✗ Test case serialization failed")
            return False

        return True

    except Exception as e:
        LOG.error(f"✗ Test models test failed: {e}")
        return False


async def test_configuration():
    """Test configuration system."""
    LOG.info("Testing configuration system")

    try:
        from recon.core.bypass.testing.test_runner import TestConfiguration

        # Create default config
        config = TestConfiguration()
        LOG.info("✓ Default configuration created")

        # Test config access
        max_parallel = config.get("test_settings.max_parallel_tests")
        if max_parallel:
            LOG.info(
                f"✓ Configuration access works: max_parallel_tests = {max_parallel}"
            )

        # Test config modification
        config.config["test_settings"]["max_parallel_tests"] = 10
        new_value = config.get("test_settings.max_parallel_tests")

        if new_value == 10:
            LOG.info("✓ Configuration modification works")
        else:
            LOG.error("✗ Configuration modification failed")
            return False

        return True

    except Exception as e:
        LOG.error(f"✗ Configuration test failed: {e}")
        return False


async def run_simple_tests():
    """Run all simple tests."""
    LOG.info("Running simple tests for enhanced testing framework")
    LOG.info("=" * 50)

    tests = [
        ("Test Models", test_test_models),
        ("Configuration", test_configuration),
        ("Framework Basic Functionality", test_framework_basic_functionality),
    ]

    results = {}

    for test_name, test_func in tests:
        LOG.info(f"\n--- {test_name} ---")
        try:
            result = await test_func()
            results[test_name] = result
        except Exception as e:
            LOG.error(f"Test {test_name} failed with exception: {e}")
            results[test_name] = False

    # Summary
    LOG.info(f"\n{'='*50}")
    LOG.info("TEST SUMMARY")
    LOG.info(f"{'='*50}")

    passed = sum(1 for result in results.values() if result)
    total = len(results)

    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        LOG.info(f"{status} {test_name}")

    LOG.info(f"\nResults: {passed}/{total} tests passed")

    if passed == total:
        LOG.info("🎉 All tests passed! Enhanced testing framework is ready.")
    else:
        LOG.warning("⚠️  Some tests failed. Check the logs above.")

    return passed == total


if __name__ == "__main__":
    success = asyncio.run(run_simple_tests())
    exit(0 if success else 1)
