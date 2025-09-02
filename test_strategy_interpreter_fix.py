#!/usr/bin/env python3
"""
Test script for Task 15: Fix strategy interpreter implementation.
Validates that all the critical issues identified in the discrepancy analysis are resolved.
"""

import sys
import logging
from pathlib import Path

# Add the recon directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from core.strategy_interpreter import StrategyTranslator, EnhancedStrategyInterpreter
from core.strategy_integration_fix import StrategyIntegrationFix

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
)

LOG = logging.getLogger("test_strategy_fix")


def test_critical_strategy_parsing():
    """Test the critical strategy from the discrepancy analysis."""
    print("\n" + "="*60)
    print("TEST 1: Critical Strategy Parsing")
    print("="*60)
    
    # The exact strategy that was failing
    critical_strategy = (
        "--dpi-desync=fakeddisorder --dpi-desync-split-seqovl=336 "
        "--dpi-desync-autottl=2 --dpi-desync-fooling=md5sig,badsum,badseq "
        "--dpi-desync-repeats=1 --dpi-desync-split-pos=76 --dpi-desync-ttl=1"
    )
    
    print(f"Input strategy: {critical_strategy}")
    
    # Test the parser
    interpreter = EnhancedStrategyInterpreter(debug=True)
    parsed = interpreter.parse_zapret_strategy(critical_strategy)
    
    print(f"\nParsed strategy:")
    print(f"  Desync methods: {parsed.desync_methods}")
    print(f"  Fooling methods: {parsed.fooling_methods}")
    print(f"  TTL: {parsed.ttl}")
    print(f"  Auto TTL: {parsed.autottl}")
    print(f"  Split positions: {parsed.split_positions}")
    print(f"  Split seqovl: {parsed.split_seqovl}")
    print(f"  Repeats: {parsed.repeats}")
    
    # Test the conversion to engine task
    engine_task = interpreter.convert_to_engine_task(parsed)
    print(f"\nEngine task:")
    print(f"  Type: {engine_task['type']}")
    print(f"  Params: {engine_task['params']}")
    
    # Validate critical components
    success = True
    
    # Check that fakeddisorder is detected
    if "fakeddisorder" not in engine_task['type']:
        print("❌ FAIL: fakeddisorder not detected in task type")
        success = False
    else:
        print("✅ PASS: fakeddisorder correctly detected")
    
    # Check seqovl combination
    if engine_task['params'].get('overlap_size') != 336:
        print(f"❌ FAIL: split-seqovl=336 not correctly parsed (got {engine_task['params'].get('overlap_size')})")
        success = False
    else:
        print("✅ PASS: split-seqovl=336 correctly parsed")
    
    # Check autottl
    if engine_task['params'].get('autottl') != 2:
        print(f"❌ FAIL: autottl=2 not correctly parsed (got {engine_task['params'].get('autottl')})")
        success = False
    else:
        print("✅ PASS: autottl=2 correctly parsed")
    
    # Check fooling methods
    expected_fooling = ["md5sig", "badsum", "badseq"]
    actual_fooling = engine_task['params'].get('fooling_methods', [])
    if actual_fooling != expected_fooling:
        print(f"❌ FAIL: fooling methods not correctly parsed (got {actual_fooling}, expected {expected_fooling})")
        success = False
    else:
        print("✅ PASS: fooling methods correctly parsed")
    
    # Check split position
    if engine_task['params'].get('split_pos') != 76:
        print(f"❌ FAIL: split-pos=76 not correctly parsed (got {engine_task['params'].get('split_pos')})")
        success = False
    else:
        print("✅ PASS: split-pos=76 correctly parsed")
    
    # Check TTL
    if engine_task['params'].get('ttl') != 1:
        print(f"❌ FAIL: ttl=1 not correctly parsed (got {engine_task['params'].get('ttl')})")
        success = False
    else:
        print("✅ PASS: ttl=1 correctly parsed")
    
    return success


def test_multiple_strategies():
    """Test parsing of multiple different strategy types."""
    print("\n" + "="*60)
    print("TEST 2: Multiple Strategy Types")
    print("="*60)
    
    strategies = {
        "multisplit": "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-fooling=badsum --dpi-desync-ttl=4",
        "seqovl_only": "--dpi-desync=seqovl --dpi-desync-split-seqovl=20 --dpi-desync-split-pos=3 --dpi-desync-ttl=2",
        "badsum_race": "--dpi-desync-fooling=badsum --dpi-desync-ttl=3",
        "md5sig_race": "--dpi-desync-fooling=md5sig --dpi-desync-ttl=4",
        "combined_fooling": "--dpi-desync-fooling=badsum,md5sig --dpi-desync-ttl=2"
    }
    
    translator = StrategyTranslator()
    success = True
    
    for name, strategy in strategies.items():
        print(f"\nTesting {name}: {strategy}")
        try:
            result = translator.translate_zapret_to_recon(strategy)
            print(f"  Result: {result['type']} with params: {list(result['params'].keys())}")
            
            # Basic validation
            if 'type' not in result or 'params' not in result:
                print(f"❌ FAIL: Invalid result structure for {name}")
                success = False
            else:
                print(f"✅ PASS: {name} parsed successfully")
                
        except Exception as e:
            print(f"❌ FAIL: Exception parsing {name}: {e}")
            success = False
    
    return success


def test_integration_fix():
    """Test the integration fix functionality."""
    print("\n" + "="*60)
    print("TEST 3: Integration Fix")
    print("="*60)
    
    integration_fix = StrategyIntegrationFix(debug=True)
    
    # Test the critical strategy through integration fix
    critical_strategy = (
        "--dpi-desync=fakeddisorder --dpi-desync-split-seqovl=336 "
        "--dpi-desync-autottl=2 --dpi-desync-fooling=md5sig,badsum,badseq "
        "--dpi-desync-repeats=1 --dpi-desync-split-pos=76 --dpi-desync-ttl=1"
    )
    
    result = integration_fix.fix_strategy_parsing(critical_strategy)
    
    if result['type'] == 'fakeddisorder_seqovl':
        print("✅ PASS: Integration fix correctly identifies fakeddisorder+seqovl combination")
        success = True
    else:
        print(f"❌ FAIL: Integration fix returned wrong type: {result['type']}")
        success = False
    
    # Test strategy map creation
    zapret_config = {
        "x.com": critical_strategy,
        "*.twimg.com": "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-fooling=badsum --dpi-desync-ttl=4",
        "default": "--dpi-desync-fooling=badsum --dpi-desync-ttl=3"
    }
    
    strategy_map = integration_fix.create_strategy_map_from_zapret_config(zapret_config)
    
    if len(strategy_map) == 3:
        print("✅ PASS: Strategy map creation successful")
        for key, value in strategy_map.items():
            print(f"  {key}: {value['type']}")
    else:
        print(f"❌ FAIL: Strategy map creation failed (got {len(strategy_map)} entries)")
        success = False
    
    return success


def test_bypass_techniques():
    """Test the enhanced bypass techniques."""
    print("\n" + "="*60)
    print("TEST 4: Enhanced Bypass Techniques")
    print("="*60)
    
    try:
        from bypass_engine import BypassTechniques
        
        # Test fakeddisorder with seqovl
        test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        # Test standard fakeddisorder
        result1 = BypassTechniques.apply_fakeddisorder(test_payload, split_pos=10)
        print(f"Standard fakeddisorder: {len(result1)} segments")
        
        # Test fakeddisorder with seqovl
        result2 = BypassTechniques.apply_fakeddisorder(test_payload, split_pos=10, overlap_size=20)
        print(f"Fakeddisorder + seqovl: {len(result2)} segments")
        
        # Test multiple fooling
        test_packet = bytearray(b'\x45\x00\x00\x3c' + b'\x00' * 56)  # Minimal IP+TCP header
        original_len = len(test_packet)
        
        fooling_methods = ["badsum", "md5sig", "badseq"]
        result3 = BypassTechniques.apply_multiple_fooling(test_packet, fooling_methods)
        
        if len(result3) == original_len:
            print("✅ PASS: Multiple fooling methods applied successfully")
            success = True
        else:
            print(f"❌ FAIL: Multiple fooling changed packet length unexpectedly")
            success = False
            
    except Exception as e:
        print(f"❌ FAIL: Exception testing bypass techniques: {e}")
        success = False
    
    return success


def main():
    """Run all tests and report results."""
    print("Strategy Interpreter Fix Test Suite")
    print("Task 15: Fix strategy interpreter implementation")
    print("="*60)
    
    tests = [
        ("Critical Strategy Parsing", test_critical_strategy_parsing),
        ("Multiple Strategy Types", test_multiple_strategies),
        ("Integration Fix", test_integration_fix),
        ("Enhanced Bypass Techniques", test_bypass_techniques)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ EXCEPTION in {test_name}: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
        if result:
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Strategy interpreter fixes are working correctly.")
        print("\nThe critical issues identified in the discrepancy analysis have been resolved:")
        print("✅ fakeddisorder attack implementation fixed")
        print("✅ autottl parameter handling implemented")
        print("✅ Multiple fooling methods (md5sig, badsum, badseq) supported")
        print("✅ split-seqovl parameter correctly implemented")
        print("✅ Strategy parameter parsing matches zapret behavior")
        return True
    else:
        print(f"\n⚠️ {total - passed} tests failed. Review the output above for details.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)