#!/usr/bin/env python3
"""
Simple test for comprehensive system validation.
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from core.bypass.testing.comprehensive_system_test import (
        ComprehensiveSystemValidator,
        SystemMetricsCollector,
    )

    print("✅ Successfully imported comprehensive system test components")
except ImportError as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)


async def test_basic_functionality():
    """Test basic functionality of comprehensive system validator."""
    print("Testing basic functionality...")

    try:
        # Test metrics collector
        collector = SystemMetricsCollector()
        collector.start_collection()
        await asyncio.sleep(2)
        collector.stop_collection()

        if len(collector.metrics) > 0:
            print(f"✅ Metrics collector working: {len(collector.metrics)} data points")
        else:
            print("⚠️  Metrics collector collected no data")

        # Test validator initialization
        validator = ComprehensiveSystemValidator()
        print(
            f"✅ Validator initialized with {len(validator.test_domains)} test domains"
        )

        # Test attack registry
        attack_ids = validator.attack_registry.list_attacks()
        print(f"✅ Attack registry has {len(attack_ids)} attacks")

        return True

    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False


async def main():
    """Main test function."""
    print("=" * 50)
    print("COMPREHENSIVE SYSTEM TEST - BASIC VERIFICATION")
    print("=" * 50)

    success = await test_basic_functionality()

    if success:
        print("\n✅ Basic verification passed!")
        print("The comprehensive system test implementation is working.")
        return 0
    else:
        print("\n❌ Basic verification failed!")
        return 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
