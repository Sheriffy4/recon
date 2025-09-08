#!/usr/bin/env python3
"""
Debug script to test TTL parameter parsing in strategy interpreter.
This script tests the exact failing command to identify where TTL=64 gets lost.
"""

import sys
import os
import logging

# Add recon directory to path
recon_dir = os.path.dirname(os.path.abspath(__file__))
if recon_dir not in sys.path:
    sys.path.insert(0, recon_dir)

from core.strategy_interpreter import interpret_strategy

# Configure logging to see detailed parsing
logging.basicConfig(level=logging.DEBUG, format='%(name)s - %(levelname)s - %(message)s')

def test_ttl_parsing():
    """Test TTL parameter parsing with the exact failing command."""
    
    # The exact failing command from the requirements
    failing_command = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=badseq,md5sig --dpi-desync-ttl=64"
    
    print("="*80)
    print("TESTING TTL PARAMETER PARSING")
    print("="*80)
    print(f"Input strategy: {failing_command}")
    print()
    
    # Test the interpretation
    result = interpret_strategy(failing_command)
    
    print("="*80)
    print("INTERPRETATION RESULT:")
    print("="*80)
    print(f"Full result: {result}")
    print()
    
    # Check TTL specifically
    if 'params' in result:
        params = result['params']
        ttl_value = params.get('ttl')
        autottl_value = params.get('autottl')
        
        print("TTL ANALYSIS:")
        print(f"  TTL value: {ttl_value}")
        print(f"  AutoTTL value: {autottl_value}")
        
        if ttl_value == 64:
            print("  ✅ TTL=64 correctly parsed!")
        elif ttl_value == 1:
            print("  ❌ TTL=1 (default) - parsing failed!")
        else:
            print(f"  ❓ Unexpected TTL value: {ttl_value}")
            
        if autottl_value == 2:
            print("  ✅ AutoTTL=2 correctly parsed!")
        else:
            print(f"  ❓ AutoTTL value: {autottl_value}")
    else:
        print("❌ No params found in result!")
    
    print()
    return result

def test_simple_ttl_cases():
    """Test simple TTL cases to isolate the issue."""
    
    print("="*80)
    print("TESTING SIMPLE TTL CASES")
    print("="*80)
    
    test_cases = [
        "--dpi-desync=fake --dpi-desync-ttl=64",
        "--dpi-desync=fakeddisorder --dpi-desync-ttl=64",
        "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64",
        "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=1",
        "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=32",
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test_case}")
        result = interpret_strategy(test_case)
        
        if 'params' in result:
            ttl_value = result['params'].get('ttl')
            print(f"  Result TTL: {ttl_value}")
            
            # Extract expected TTL from command
            import re
            ttl_match = re.search(r'--dpi-desync-ttl=(\d+)', test_case)
            if ttl_match:
                expected_ttl = int(ttl_match.group(1))
                if ttl_value == expected_ttl:
                    print(f"  ✅ Correct: {ttl_value}")
                else:
                    print(f"  ❌ Expected {expected_ttl}, got {ttl_value}")
            else:
                print("  ❓ No TTL in command")
        else:
            print("  ❌ No params in result")

if __name__ == "__main__":
    print("TTL Parameter Parsing Debug Script")
    print("This script tests the exact failing command to identify TTL parsing issues.")
    print()
    
    # Test the main failing case
    main_result = test_ttl_parsing()
    
    # Test simple cases
    test_simple_ttl_cases()
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    if 'params' in main_result and main_result['params'].get('ttl') == 64:
        print("✅ TTL parsing appears to be working correctly!")
        print("The issue might be elsewhere in the pipeline.")
    else:
        print("❌ TTL parsing is broken!")
        print("The strategy interpreter is not correctly extracting TTL=64.")
        
    print("\nNext steps:")
    print("1. If TTL parsing is broken, fix the strategy interpreter")
    print("2. If TTL parsing works, check the bypass engine")
    print("3. Add logging throughout the pipeline to track TTL values")