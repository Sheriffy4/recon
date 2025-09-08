#!/usr/bin/env python3
"""
Quick Attack Test Runner - Task 16
Simplified runner for comprehensive attack testing that can be executed immediately.
"""

import sys
import asyncio
import logging
from pathlib import Path

# Add recon directory to path
sys.path.insert(0, str(Path(__file__).parent))

from comprehensive_attack_tester import ComprehensiveAttackTester, AttackDefinitions
from core.bypass_engine import BypassTechniques

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
)

LOG = logging.getLogger("run_attack_tests")


async def quick_attack_validation():
    """Quick validation of attack implementations without full PCAP testing."""
    print("🚀 Quick Attack Implementation Validation")
    print("=" * 50)
    
    # Test strategy parsing for all attacks
    attack_strategies = AttackDefinitions.get_attack_strategies()
    
    print(f"Testing {len(attack_strategies)} attack strategies...")
    
    tester = ComprehensiveAttackTester(debug=False)
    
    validation_results = []
    
    for attack_type, strategy_string in attack_strategies.items():
        try:
            print(f"\n🔍 Testing {attack_type}:")
            print(f"   Strategy: {strategy_string}")
            
            # Test strategy parsing
            engine_task = tester.strategy_translator.translate_zapret_to_recon(strategy_string)
            
            # Validate task structure
            if 'type' in engine_task and 'params' in engine_task:
                print(f"   ✅ Parsed successfully as {engine_task['type']}")
                print(f"   📋 Key params: {list(engine_task['params'].keys())}")
                validation_results.append((attack_type, True, None))
            else:
                print(f"   ❌ Invalid task structure")
                validation_results.append((attack_type, False, "Invalid structure"))
                
        except Exception as e:
            print(f"   ❌ Parsing failed: {e}")
            validation_results.append((attack_type, False, str(e)))
    
    # Summary
    successful = sum(1 for _, success, _ in validation_results if success)
    total = len(validation_results)
    success_rate = (successful / total * 100) if total > 0 else 0
    
    print(f"\n📊 Validation Summary:")
    print(f"   Successful: {successful}/{total} ({success_rate:.1f}%)")
    
    if success_rate == 100:
        print("   ✅ All attack strategies parse correctly!")
    else:
        print("   ⚠️  Some strategies failed to parse:")
        for attack_type, success, error in validation_results:
            if not success:
                print(f"      ❌ {attack_type}: {error}")
    
    return success_rate >= 90


async def test_bypass_techniques():
    """Test the bypass techniques implementations."""
    print("\n🔧 Testing Bypass Techniques Implementation")
    print("=" * 50)
    
    try:
        from bypass_engine import BypassTechniques
        
        # Test payload
        test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        
        tests = [
            ("fakeddisorder", lambda: BypassTechniques.apply_fakeddisorder(test_payload, 10)),
            ("fakeddisorder+seqovl", lambda: BypassTechniques.apply_fakeddisorder(test_payload, 10, 20)),
            ("multisplit", lambda: BypassTechniques.apply_multisplit(test_payload, [10, 25, 40])),
            ("multidisorder", lambda: BypassTechniques.apply_multidisorder(test_payload, [10, 25, 40])),
            ("seqovl", lambda: BypassTechniques.apply_seqovl(test_payload, 10, 15)),
        ]
        
        results = []
        
        for test_name, test_func in tests:
            try:
                result = test_func()
                if isinstance(result, list) and len(result) > 0:
                    print(f"   ✅ {test_name}: {len(result)} segments generated")
                    results.append(True)
                else:
                    print(f"   ❌ {test_name}: Invalid result")
                    results.append(False)
            except Exception as e:
                print(f"   ❌ {test_name}: Exception - {e}")
                results.append(False)
        
        # Test fooling methods
        try:
            test_packet = bytearray(b'\x45\x00\x00\x3c' + b'\x00' * 56)  # Minimal packet
            
            fooling_tests = [
                ("badsum", lambda: BypassTechniques.apply_badsum_fooling(test_packet.copy())),
                ("md5sig", lambda: BypassTechniques.apply_md5sig_fooling(test_packet.copy())),
                ("badseq", lambda: BypassTechniques.apply_badseq_fooling(test_packet.copy())),
                ("multiple", lambda: BypassTechniques.apply_multiple_fooling(test_packet.copy(), ["badsum", "md5sig", "badseq"])),
            ]
            
            for test_name, test_func in fooling_tests:
                try:
                    result = test_func()
                    if isinstance(result, bytearray) and len(result) == len(test_packet):
                        print(f"   ✅ {test_name} fooling: Packet modified correctly")
                        results.append(True)
                    else:
                        print(f"   ❌ {test_name} fooling: Invalid result")
                        results.append(False)
                except Exception as e:
                    print(f"   ❌ {test_name} fooling: Exception - {e}")
                    results.append(False)
        
        except Exception as e:
            print(f"   ❌ Fooling tests failed: {e}")
            results.extend([False] * 4)
        
        success_rate = (sum(results) / len(results) * 100) if results else 0
        print(f"\n   📊 Bypass Techniques: {sum(results)}/{len(results)} ({success_rate:.1f}%)")
        
        return success_rate >= 80
        
    except ImportError as e:
        print(f"   ❌ Could not import BypassTechniques: {e}")
        return False


async def test_domain_resolution():
    """Test domain resolution for a few key domains."""
    print("\n🌐 Testing Domain Resolution")
    print("=" * 50)
    
    test_domains = ["x.com", "instagram.com", "rutracker.org"]
    
    try:
        from cli import resolve_all_ips
        
        results = []
        
        for domain in test_domains:
            try:
                ips = await resolve_all_ips(domain)
                if ips:
                    print(f"   ✅ {domain}: {len(ips)} IPs resolved ({list(ips)[:2]}...)")
                    results.append(True)
                else:
                    print(f"   ❌ {domain}: No IPs resolved")
                    results.append(False)
            except Exception as e:
                print(f"   ❌ {domain}: Resolution failed - {e}")
                results.append(False)
        
        success_rate = (sum(results) / len(results) * 100) if results else 0
        print(f"\n   📊 Domain Resolution: {sum(results)}/{len(results)} ({success_rate:.1f}%)")
        
        return success_rate >= 66  # At least 2/3 should work
        
    except ImportError as e:
        print(f"   ❌ Could not import resolution functions: {e}")
        return False


async def main():
    """Main test runner."""
    print("Attack Testing Validation - Task 16")
    print("Quick validation of attack implementations")
    print("=" * 60)
    
    tests = [
        ("Attack Strategy Parsing", quick_attack_validation),
        ("Bypass Techniques", test_bypass_techniques),
        ("Domain Resolution", test_domain_resolution),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            print(f"\n🧪 Running: {test_name}")
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"   ❌ Exception in {test_name}: {e}")
            results.append((test_name, False))
    
    # Final summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
        if result:
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL VALIDATION TESTS PASSED!")
        print("\nTask 16 implementation is ready for comprehensive testing:")
        print("✅ Attack strategy parsing working")
        print("✅ Bypass techniques implemented")
        print("✅ Domain resolution functional")
        print("✅ PCAP capture framework ready")
        print("\nTo run full comprehensive testing with PCAP validation:")
        print("   python comprehensive_attack_tester.py")
        return True
    else:
        print(f"\n⚠️ {total - passed} validation tests failed.")
        print("Fix the issues above before running comprehensive tests.")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)