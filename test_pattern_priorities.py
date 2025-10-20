#!/usr/bin/env python3
"""
Test script to verify pattern priorities are working correctly.
"""

import sys
import os

# Add current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from cli import AdaptiveLearningCache
from core.attack_mapping import get_attack_mapping


def test_pattern_priorities():
    """Test that pattern priorities work correctly."""
    
    # Create a test instance
    cache = AdaptiveLearningCache()
    attack_mapping = get_attack_mapping()
    
    # Test cases with expected results
    test_cases = [
        # Most specific patterns should match first
        ("--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3", "fake_fakeddisorder"),
        ("--dpi-desync=tcp,multisplit --dpi-desync-split-count=5", "tcp_multisplit"),
        ("--dpi-desync=tcp,multidisorder --dpi-desync-ttl=4", "tcp_multidisorder"),
        ("--dpi-desync=tcp,seqovl --dpi-desync-split-seqovl=20", "tcp_seqovl"),
        
        # Specific zapret patterns
        ("--dpi-desync=ipfrag2 --dpi-desync-split-pos=8", "ip_fragmentation_advanced"),
        ("--filter-udp=443 --dpi-desync=fake", "force_tcp"),
        ("--dpi-desync=fake --dpi-desync-fooling=badsum", "badsum_race"),
        ("--dpi-desync=fake --dpi-desync-fooling=md5sig", "md5sig_race"),
        ("--dpi-desync=fake --dpi-desync-fooling=badseq", "badseq_fooling"),
        
        # Fake disorder should come before generic disorder
        ("--dpi-desync=fake,disorder --dpi-desync-ttl=3", "fake_disorder"),
        
        # Multi-attacks should come before single variants
        ("--dpi-desync=multisplit --dpi-desync-split-count=5", "multisplit"),
        ("--dpi-desync=multidisorder --dpi-desync-ttl=4", "multidisorder"),
        ("--dpi-desync=seqovl --dpi-desync-split-seqovl=20", "sequence_overlap"),
        
        # Basic patterns (lower priority)
        ("--dpi-desync=split --dpi-desync-split-pos=3", "simple_fragment"),
        ("--dpi-desync=disorder --dpi-desync-ttl=4", "disorder"),
        
        # Edge cases
        ("multisplit with tcp", "tcp_multisplit"),  # Should match tcp_multisplit, not multisplit
        ("fake disorder attack", "fake_disorder"),  # Should match fake_disorder, not disorder
        ("simple split attack", "simple_fragment"),  # Should match simple_fragment
    ]
    
    print("Testing pattern priorities...")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for strategy, expected in test_cases:
        # Test CLI extraction
        try:
            result_cli = cache._extract_strategy_type(strategy)
        except Exception as e:
            result_cli = f"ERROR: {e}"
        
        # Test attack mapping extraction
        try:
            result_mapping = attack_mapping.extract_strategy_type(strategy)
        except Exception as e:
            result_mapping = f"ERROR: {e}"
        
        # Check results
        cli_correct = result_cli == expected
        mapping_correct = result_mapping == expected
        
        status_cli = "✅" if cli_correct else "❌"
        status_mapping = "✅" if mapping_correct else "❌"
        
        print(f"Strategy: {strategy}")
        print(f"  Expected: {expected}")
        print(f"  CLI:      {result_cli} {status_cli}")
        print(f"  Mapping:  {result_mapping} {status_mapping}")
        
        if cli_correct and mapping_correct:
            passed += 1
            print(f"  Result:   PASS")
        else:
            failed += 1
            print(f"  Result:   FAIL")
        
        print()
    
    print("=" * 60)
    print(f"Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All pattern priority tests passed!")
        return True
    else:
        print("❌ Some pattern priority tests failed!")
        return False


def test_priority_order():
    """Test that patterns are processed in the correct priority order."""
    
    cache = AdaptiveLearningCache()
    
    # Test ambiguous cases where order matters
    ambiguous_cases = [
        # Should match more specific pattern, not generic one
        ("fake disorder multisplit", "fake_disorder"),  # Not multisplit
        ("tcp multisplit attack", "tcp_multisplit"),    # Not multisplit
        ("badsum fooling attack", "badsum_race"),       # Not timing_based
        ("split multisplit", "multisplit"),             # Not simple_fragment
    ]
    
    print("Testing priority order for ambiguous cases...")
    print("=" * 60)
    
    for strategy, expected in ambiguous_cases:
        result = cache._extract_strategy_type(strategy)
        status = "✅" if result == expected else "❌"
        
        print(f"Strategy: {strategy}")
        print(f"Expected: {expected}")
        print(f"Got:      {result} {status}")
        print()


if __name__ == "__main__":
    print("Pattern Priority Test Suite")
    print("=" * 60)
    
    success = test_pattern_priorities()
    test_priority_order()
    
    if success:
        print("\n🎉 Pattern priorities are working correctly!")
        sys.exit(0)
    else:
        print("\n❌ Pattern priority issues detected!")
        sys.exit(1)