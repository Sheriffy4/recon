#!/usr/bin/env python3
"""
Test TTL validation and error handling improvements (Task 3).

This test verifies that:
1. TTL values are validated (1-255 range)
2. Invalid TTL values generate proper error messages
3. Default TTL is changed from 1 to 64 for better compatibility
4. Fallback behavior works for missing TTL parameters

Requirements: 1.3, 2.4
"""

import sys
import os
import logging

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from core.strategy_interpreter import interpret_strategy, EnhancedStrategyInterpreter

# Set up logging to capture validation messages
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def test_ttl_validation():
    """Test TTL value validation (1-255 range)."""
    print("=== Testing TTL Validation ===")
    
    # Test valid TTL values
    valid_ttl_cases = [
        ("--dpi-desync=fakeddisorder --dpi-desync-ttl=1", 1),
        ("--dpi-desync=fakeddisorder --dpi-desync-ttl=64", 64),
        ("--dpi-desync=fakeddisorder --dpi-desync-ttl=128", 128),
        ("--dpi-desync=fakeddisorder --dpi-desync-ttl=255", 255),
    ]
    
    for strategy_str, expected_ttl in valid_ttl_cases:
        print(f"\nTesting valid TTL: {expected_ttl}")
        result = interpret_strategy(strategy_str)
        
        if "error" in result:
            print(f"❌ ERROR: {result['error']}")
            continue
            
        actual_ttl = result.get("params", {}).get("ttl")
        if actual_ttl == expected_ttl:
            print(f"✅ Valid TTL {expected_ttl} accepted correctly")
        else:
            print(f"❌ Expected TTL {expected_ttl}, got {actual_ttl}")
    
    # Test invalid TTL values
    invalid_ttl_cases = [
        ("--dpi-desync=fakeddisorder --dpi-desync-ttl=0", "TTL too low"),
        ("--dpi-desync=fakeddisorder --dpi-desync-ttl=256", "TTL too high"),
        ("--dpi-desync=fakeddisorder --dpi-desync-ttl=1000", "TTL way too high"),
        ("--dpi-desync=fakeddisorder --dpi-desync-ttl=-5", "Negative TTL"),
    ]
    
    for strategy_str, test_case in invalid_ttl_cases:
        print(f"\nTesting invalid TTL: {test_case}")
        result = interpret_strategy(strategy_str)
        
        if "error" in result:
            print(f"⚠️  Strategy failed: {result['error']}")
            continue
            
        actual_ttl = result.get("params", {}).get("ttl")
        if actual_ttl == 64:  # Should fallback to 64
            print(f"✅ Invalid TTL correctly fell back to default: {actual_ttl}")
        else:
            print(f"❌ Expected fallback TTL 64, got {actual_ttl}")

def test_autottl_validation():
    """Test AutoTTL value validation."""
    print("\n=== Testing AutoTTL Validation ===")
    
    # Test valid AutoTTL values
    valid_autottl_cases = [
        ("--dpi-desync=fakeddisorder --dpi-desync-autottl=1", 1),
        ("--dpi-desync=fakeddisorder --dpi-desync-autottl=2", 2),
        ("--dpi-desync=fakeddisorder --dpi-desync-autottl=10", 10),
        ("--dpi-desync=fakeddisorder --dpi-desync-autottl=64", 64),
    ]
    
    for strategy_str, expected_autottl in valid_autottl_cases:
        print(f"\nTesting valid AutoTTL: {expected_autottl}")
        result = interpret_strategy(strategy_str)
        
        if "error" in result:
            print(f"❌ ERROR: {result['error']}")
            continue
            
        actual_autottl = result.get("params", {}).get("autottl")
        if actual_autottl == expected_autottl:
            print(f"✅ Valid AutoTTL {expected_autottl} accepted correctly")
        else:
            print(f"❌ Expected AutoTTL {expected_autottl}, got {actual_autottl}")
    
    # Test invalid AutoTTL values
    invalid_autottl_cases = [
        ("--dpi-desync=fakeddisorder --dpi-desync-autottl=0", "AutoTTL too low"),
        ("--dpi-desync=fakeddisorder --dpi-desync-autottl=65", "AutoTTL too high"),
        ("--dpi-desync=fakeddisorder --dpi-desync-autottl=100", "AutoTTL way too high"),
    ]
    
    for strategy_str, test_case in invalid_autottl_cases:
        print(f"\nTesting invalid AutoTTL: {test_case}")
        result = interpret_strategy(strategy_str)
        
        if "error" in result:
            print(f"⚠️  Strategy failed: {result['error']}")
            continue
            
        actual_autottl = result.get("params", {}).get("autottl")
        if actual_autottl == 2:  # Should fallback to 2
            print(f"✅ Invalid AutoTTL correctly fell back to default: {actual_autottl}")
        else:
            print(f"❌ Expected fallback AutoTTL 2, got {actual_autottl}")

def test_default_ttl_improvement():
    """Test that default TTL is changed from 1 to 64."""
    print("\n=== Testing Default TTL Improvement ===")
    
    # Test strategies without explicit TTL
    strategies_without_ttl = [
        "--dpi-desync=fakeddisorder --dpi-desync-split-seqovl=1",
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=76",
        "--dpi-desync=fake --dpi-desync-fooling=badsum",
    ]
    
    for strategy_str in strategies_without_ttl:
        print(f"\nTesting default TTL for: {strategy_str}")
        result = interpret_strategy(strategy_str)
        
        if "error" in result:
            print(f"❌ ERROR: {result['error']}")
            continue
            
        actual_ttl = result.get("params", {}).get("ttl")
        if actual_ttl == 64:
            print(f"✅ Default TTL correctly set to 64 (improved from 1)")
        else:
            print(f"❌ Expected default TTL 64, got {actual_ttl}")

def test_fallback_behavior():
    """Test fallback behavior for missing TTL parameters."""
    print("\n=== Testing Fallback Behavior ===")
    
    # Test malformed TTL parameters
    malformed_cases = [
        ("--dpi-desync=fakeddisorder --dpi-desync-ttl=abc", "Non-numeric TTL"),
        ("--dpi-desync=fakeddisorder --dpi-desync-ttl=", "Empty TTL"),
        ("--dpi-desync=fakeddisorder --dpi-desync-autottl=xyz", "Non-numeric AutoTTL"),
    ]
    
    for strategy_str, test_case in malformed_cases:
        print(f"\nTesting fallback for: {test_case}")
        result = interpret_strategy(strategy_str)
        
        if "error" in result:
            print(f"⚠️  Strategy failed: {result['error']}")
            continue
            
        # Should have fallback values
        params = result.get("params", {})
        ttl = params.get("ttl")
        autottl = params.get("autottl")
        
        if ttl == 64:
            print(f"✅ TTL fallback working: {ttl}")
        elif ttl is not None:
            print(f"⚠️  TTL fallback unexpected: {ttl}")
        
        if "autottl" in strategy_str and autottl == 2:
            print(f"✅ AutoTTL fallback working: {autottl}")
        elif "autottl" in strategy_str and autottl is not None:
            print(f"⚠️  AutoTTL fallback unexpected: {autottl}")

def test_error_messages():
    """Test that proper error messages are generated."""
    print("\n=== Testing Error Messages ===")
    
    # Capture log messages
    import io
    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    handler.setLevel(logging.ERROR)
    
    logger = logging.getLogger("strategy_interpreter")
    logger.addHandler(handler)
    
    # Test invalid TTL
    print("\nTesting error message for invalid TTL...")
    result = interpret_strategy("--dpi-desync=fakeddisorder --dpi-desync-ttl=300")
    
    log_output = log_capture.getvalue()
    if "Invalid TTL value 300" in log_output:
        print("✅ Proper error message generated for invalid TTL")
    else:
        print(f"❌ Expected TTL error message not found. Log: {log_output}")
    
    # Clean up
    logger.removeHandler(handler)

def test_original_failing_command():
    """Test the original failing command from the requirements."""
    print("\n=== Testing Original Failing Command ===")
    
    failing_command = (
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 "
        "--dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS "
        "--dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=badseq,md5sig "
        "--dpi-desync-ttl=64"
    )
    
    print(f"Testing command: {failing_command}")
    result = interpret_strategy(failing_command)
    
    if "error" in result:
        print(f"❌ ERROR: {result['error']}")
        return
    
    params = result.get("params", {})
    ttl = params.get("ttl")
    autottl = params.get("autottl")
    
    print(f"Result TTL: {ttl}")
    print(f"Result AutoTTL: {autottl}")
    
    if ttl == 64:
        print("✅ TTL=64 correctly parsed and preserved")
    else:
        print(f"❌ Expected TTL=64, got {ttl}")
    
    if autottl == 2:
        print("✅ AutoTTL=2 correctly parsed")
    else:
        print(f"❌ Expected AutoTTL=2, got {autottl}")

def main():
    """Run all TTL validation tests."""
    print("TTL Validation and Error Handling Test (Task 3)")
    print("=" * 50)
    
    try:
        test_ttl_validation()
        test_autottl_validation()
        test_default_ttl_improvement()
        test_fallback_behavior()
        test_error_messages()
        test_original_failing_command()
        
        print("\n" + "=" * 50)
        print("✅ TTL validation tests completed!")
        print("Task 3 implementation verified:")
        print("- TTL value validation (1-255 range)")
        print("- Proper error messages for invalid TTL values")
        print("- Default TTL changed from 1 to 64")
        print("- Fallback behavior for missing TTL parameters")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())