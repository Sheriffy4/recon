# recon/core/bypass/attacks/dns/simple_dns_test.py

"""
Simple test runner for DNS attacks to verify basic functionality.
This is a lightweight test that can be run quickly to ensure DNS attacks work.
"""

import asyncio
import sys
import time
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

import sys

# Add current directory to path for local imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from dns_tunneling import (
    DoHAttack,
    DoTAttack,
    DNSQueryManipulation,
    DNSCachePoisoningPrevention,
    get_dns_attack_definitions,
)


async def test_doh_attack():
    """Test DoH attack basic functionality."""
    print("🔍 Testing DoH Attack...")

    attack = DoHAttack()
    result = await attack.execute("example.com", {"provider": "cloudflare"})

    if result.success:
        print(f"  ✅ DoH Success: {result.data['resolved_ip']}")
        return True
    else:
        print(f"  ❌ DoH Failed: {result.error}")
        return False


async def test_dot_attack():
    """Test DoT attack basic functionality."""
    print("🔍 Testing DoT Attack...")

    attack = DoTAttack()
    result = await attack.execute("example.com", {"provider": "cloudflare"})

    if result.success:
        print(f"  ✅ DoT Success: {result.data['resolved_ip']}")
        return True
    else:
        print(f"  ❌ DoT Failed: {result.error}")
        return False


async def test_query_manipulation():
    """Test DNS query manipulation."""
    print("🔍 Testing DNS Query Manipulation...")

    attack = DNSQueryManipulation()
    result = await attack.execute("example.com", {"technique": "case_randomization"})

    if result.success:
        print(f"  ✅ Query Manipulation Success: {result.data['resolved_ip']}")
        return True
    else:
        print(f"  ❌ Query Manipulation Failed: {result.error}")
        return False


async def test_cache_prevention():
    """Test DNS cache poisoning prevention."""
    print("🔍 Testing DNS Cache Poisoning Prevention...")

    attack = DNSCachePoisoningPrevention()
    result = await attack.execute(
        "example.com", {"technique": "multiple_server_validation"}
    )

    if result.success:
        print(
            f"  ✅ Cache Prevention Success: Consistent={result.data.get('consistent', 'N/A')}"
        )
        return True
    else:
        print(f"  ❌ Cache Prevention Failed: {result.error}")
        return False


def test_attack_definitions():
    """Test DNS attack definitions."""
    print("🔍 Testing DNS Attack Definitions...")

    try:
        definitions = get_dns_attack_definitions()

        if len(definitions) == 4:
            print(
                f"  ✅ Attack Definitions Success: {len(definitions)} definitions loaded"
            )

            # Check each definition
            for definition in definitions:
                print(f"    - {definition.name} (ID: {definition.id})")

            return True
        else:
            print(f"  ❌ Attack Definitions Failed: Expected 4, got {len(definitions)}")
            return False

    except Exception as e:
        print(f"  ❌ Attack Definitions Failed: {e}")
        return False


async def run_simple_tests():
    """Run all simple DNS tests."""
    print("=" * 60)
    print("DNS ATTACKS SIMPLE TEST RUNNER")
    print("=" * 60)

    tests = [
        ("Attack Definitions", test_attack_definitions),
        ("DoH Attack", test_doh_attack),
        ("DoT Attack", test_dot_attack),
        ("Query Manipulation", test_query_manipulation),
        ("Cache Prevention", test_cache_prevention),
    ]

    results = []
    total_start_time = time.time()

    for test_name, test_func in tests:
        print(f"\n📋 Running {test_name} test...")

        start_time = time.time()

        try:
            if asyncio.iscoroutinefunction(test_func):
                success = await test_func()
            else:
                success = test_func()

            duration = time.time() - start_time
            results.append((test_name, success, duration, None))

        except Exception as e:
            duration = time.time() - start_time
            results.append((test_name, False, duration, str(e)))
            print(f"  ❌ {test_name} Exception: {e}")

    total_duration = time.time() - total_start_time

    # Print summary
    print("\n" + "=" * 60)
    print("TEST RESULTS SUMMARY")
    print("=" * 60)

    successful_tests = sum(1 for _, success, _, _ in results if success)
    total_tests = len(results)

    print("\n📊 Overall Results:")
    print(f"   Total tests: {total_tests}")
    print(f"   Successful: {successful_tests}")
    print(f"   Failed: {total_tests - successful_tests}")
    print(f"   Success rate: {successful_tests/total_tests*100:.1f}%")
    print(f"   Total duration: {total_duration:.3f}s")

    print("\n📋 Individual Test Results:")
    for test_name, success, duration, error in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"   {status} {test_name:<25} ({duration:.3f}s)")
        if error:
            print(f"      Error: {error}")

    if successful_tests == total_tests:
        print("\n🎉 All tests passed! DNS attacks are working correctly.")
        return True
    else:
        print("\n⚠️  Some tests failed. Check the errors above.")
        return False


async def main():
    """Main test function."""
    try:
        success = await run_simple_tests()
        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        sys.exit(1)

    except Exception as e:
        print(f"\n\n❌ Tests failed with error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
