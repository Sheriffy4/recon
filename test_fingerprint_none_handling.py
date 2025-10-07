#!/usr/bin/env python3
"""
Test script to verify fingerprint None-handling fix.
This tests that the system gracefully handles None fingerprints without crashing.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.zapret_strategy_generator import ZapretStrategyGenerator


def test_none_fingerprint():
    """Test that generate_strategies handles None fingerprint gracefully."""
    print("Test 1: Generating strategies with None fingerprint...")
    
    generator = ZapretStrategyGenerator()
    
    try:
        strategies = generator.generate_strategies(fingerprint=None, count=10)
        
        if strategies and len(strategies) > 0:
            print(f"✓ SUCCESS: Generated {len(strategies)} strategies with None fingerprint")
            print(f"  Sample strategies:")
            for i, strategy in enumerate(strategies[:3], 1):
                print(f"    {i}. {strategy}")
            return True
        else:
            print("✗ FAIL: No strategies generated")
            return False
            
    except AttributeError as e:
        print(f"✗ FAIL: AttributeError occurred: {e}")
        return False
    except Exception as e:
        print(f"✗ FAIL: Unexpected error: {e}")
        return False


def test_empty_fingerprint_dict():
    """Test that generate_strategies handles empty dict fingerprint."""
    print("\nTest 2: Generating strategies with empty dict fingerprint...")
    
    generator = ZapretStrategyGenerator()
    
    # Create a mock fingerprint object with None raw_metrics
    class MockFingerprint:
        def __init__(self):
            self.raw_metrics = None
            self.confidence = 0.5
            self.fragmentation_handling = 'unknown'
    
    try:
        mock_fp = MockFingerprint()
        strategies = generator.generate_strategies(fingerprint=mock_fp, count=10)
        
        if strategies and len(strategies) > 0:
            print(f"✓ SUCCESS: Generated {len(strategies)} strategies with empty fingerprint")
            return True
        else:
            print("✗ FAIL: No strategies generated")
            return False
            
    except AttributeError as e:
        print(f"✗ FAIL: AttributeError occurred: {e}")
        return False
    except Exception as e:
        print(f"✗ FAIL: Unexpected error: {e}")
        return False


def test_fingerprint_with_missing_attributes():
    """Test that generate_strategies handles fingerprint with missing attributes."""
    print("\nTest 3: Generating strategies with incomplete fingerprint...")
    
    generator = ZapretStrategyGenerator()
    
    # Create a mock fingerprint object with minimal attributes
    class MinimalFingerprint:
        pass
    
    try:
        minimal_fp = MinimalFingerprint()
        strategies = generator.generate_strategies(fingerprint=minimal_fp, count=10)
        
        if strategies and len(strategies) > 0:
            print(f"✓ SUCCESS: Generated {len(strategies)} strategies with minimal fingerprint")
            return True
        else:
            print("✗ FAIL: No strategies generated")
            return False
            
    except AttributeError as e:
        print(f"✗ FAIL: AttributeError occurred: {e}")
        return False
    except Exception as e:
        print(f"✗ FAIL: Unexpected error: {e}")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("Fingerprint None-Handling Test Suite")
    print("=" * 60)
    
    results = []
    
    results.append(("None fingerprint", test_none_fingerprint()))
    results.append(("Empty dict fingerprint", test_empty_fingerprint_dict()))
    results.append(("Missing attributes", test_fingerprint_with_missing_attributes()))
    
    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
