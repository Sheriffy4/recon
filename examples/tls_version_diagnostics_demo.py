#!/usr/bin/env python3
"""
Demo: TLS Version Diagnostics

This script demonstrates how to use the TLS version checker to diagnose
inconsistencies between TEST and BYPASS modes.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.validation.tls_version_checker import TLSVersionChecker


def demo_version_extraction():
    """Demonstrate TLS version extraction."""
    print("="*80)
    print("DEMO: TLS Version Extraction")
    print("="*80)
    print()
    
    # Create sample ClientHello messages
    tls12_hello = b'\x16\x03\x03\x02\x32' + b'\x00' * 562  # TLS 1.2, 562 bytes
    tls13_hello = b'\x16\x03\x04\x07\x65' + b'\x00' * 1893  # TLS 1.3, 1893 bytes
    
    # Extract versions
    tls12_version = TLSVersionChecker.extract_tls_version(tls12_hello)
    tls13_version = TLSVersionChecker.extract_tls_version(tls13_hello)
    
    print(f"TLS 1.2 ClientHello:")
    print(f"  Version: {tls12_version}")
    print(f"  Size: {len(tls12_hello)} bytes")
    print()
    
    print(f"TLS 1.3 ClientHello:")
    print(f"  Version: {tls13_version}")
    print(f"  Size: {len(tls13_hello)} bytes")
    print()


def demo_consistency_check():
    """Demonstrate consistency checking."""
    print("="*80)
    print("DEMO: Consistency Check")
    print("="*80)
    print()
    
    # Scenario 1: Matching versions
    print("Scenario 1: Matching TLS versions")
    print("-" * 40)
    test_hello = b'\x16\x03\x03\x02\x32' + b'\x00' * 562
    bypass_hello = b'\x16\x03\x03\x02\x32' + b'\x00' * 562
    
    is_consistent, details = TLSVersionChecker.check_consistency(test_hello, bypass_hello)
    
    print(f"TEST:   {details['test_version']} ({details['test_size']} bytes)")
    print(f"BYPASS: {details['bypass_version']} ({details['bypass_size']} bytes)")
    print(f"Result: {'✅ CONSISTENT' if is_consistent else '❌ INCONSISTENT'}")
    print()
    
    # Scenario 2: Mismatched versions (the actual bug)
    print("Scenario 2: Mismatched TLS versions (THE BUG)")
    print("-" * 40)
    test_hello = b'\x16\x03\x03\x02\x32' + b'\x00' * 562  # TLS 1.2
    bypass_hello = b'\x16\x03\x04\x07\x65' + b'\x00' * 1893  # TLS 1.3
    
    is_consistent, details = TLSVersionChecker.check_consistency(test_hello, bypass_hello)
    
    print(f"TEST:   {details['test_version']} ({details['test_size']} bytes)")
    print(f"BYPASS: {details['bypass_version']} ({details['bypass_size']} bytes)")
    print(f"Size difference: {details['size_diff_percent']:.1f}%")
    print(f"Result: {'✅ CONSISTENT' if is_consistent else '❌ INCONSISTENT'}")
    print()
    print("💡 This explains why testing doesn't match production!")
    print("   The different TLS versions cause different ClientHello sizes,")
    print("   which affects TCP segmentation and strategy application.")
    print()


def demo_split_pos_validation():
    """Demonstrate split_pos validation."""
    print("="*80)
    print("DEMO: Split Position Validation")
    print("="*80)
    print()
    
    # Test various split positions
    test_cases = [
        (2, "Very small split_pos (works for both)"),
        (300, "Medium split_pos (works for both)"),
        (561, "Just under TLS 1.2 size (works for both)"),
        (600, "Too large for TLS 1.2 (FAILS)"),
        (1800, "Too large for both (FAILS)"),
    ]
    
    for split_pos, description in test_cases:
        print(f"Testing split_pos={split_pos}: {description}")
        result = TLSVersionChecker.validate_split_pos_for_versions(
            split_pos=split_pos,
            tls12_size=562,
            tls13_size=1893
        )
        print(f"  Result: {'✅ VALID' if result else '❌ INVALID'}")
        print()


def demo_real_world_scenario():
    """Demonstrate real-world scenario from nnmclub.to bug."""
    print("="*80)
    print("DEMO: Real-World Scenario (nnmclub.to)")
    print("="*80)
    print()
    
    print("The nnmclub.to bug was caused by TLS version mismatch:")
    print()
    
    # Simulate the actual bug
    test_hello = b'\x16\x03\x03\x02\x32' + b'\x00' * 562  # TEST: TLS 1.2
    bypass_hello = b'\x16\x03\x04\x07\x65' + b'\x00' * 1893  # BYPASS: TLS 1.3
    
    print("TEST mode (curl):")
    test_version = TLSVersionChecker.extract_tls_version(test_hello)
    print(f"  TLS Version: {test_version}")
    print(f"  ClientHello: {len(test_hello)} bytes")
    print(f"  TCP segments: 1 (fits in single segment)")
    print()
    
    print("BYPASS mode (browser):")
    bypass_version = TLSVersionChecker.extract_tls_version(bypass_hello)
    print(f"  TLS Version: {bypass_version}")
    print(f"  ClientHello: {len(bypass_hello)} bytes")
    print(f"  TCP segments: 2 (1400 + 495 bytes)")
    print()
    
    is_consistent, details = TLSVersionChecker.check_consistency(test_hello, bypass_hello)
    
    print("Analysis:")
    print(f"  Version match: {details['version_match']}")
    print(f"  Size difference: {details['size_diff_percent']:.1f}%")
    print()
    
    if not is_consistent:
        print("❌ ROOT CAUSE IDENTIFIED:")
        print("   TEST mode uses TLS 1.2 (smaller ClientHello)")
        print("   BYPASS mode uses TLS 1.3 (larger ClientHello)")
        print()
        print("💡 SOLUTION:")
        print("   Configure TEST mode to use TLS 1.3 to match BYPASS mode.")
        print("   This will ensure consistent testing results.")
    print()


def main():
    """Run all demos."""
    demo_version_extraction()
    demo_consistency_check()
    demo_split_pos_validation()
    demo_real_world_scenario()
    
    print("="*80)
    print("SUMMARY")
    print("="*80)
    print()
    print("The TLS version diagnostics help identify when TEST and BYPASS modes")
    print("use different TLS versions, which causes:")
    print()
    print("  1. Different ClientHello sizes")
    print("  2. Different TCP segmentation")
    print("  3. Inconsistent strategy application")
    print("  4. Testing that doesn't reflect production behavior")
    print()
    print("Use these diagnostics in PCAP analysis to detect and fix such issues.")
    print()


if __name__ == '__main__':
    main()
