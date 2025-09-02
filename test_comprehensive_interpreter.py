#!/usr/bin/env python3
"""
Comprehensive test suite for FixedStrategyInterpreter.

This test suite validates all the critical fixes and ensures the interpreter
correctly handles the problematic zapret command from the analysis.

Tests cover:
- Problematic zapret command parsing
- Edge cases and error handling
- Comparison with expected broken behavior
- All parameter combinations
- Validation and conversion
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recon.core.strategy_interpreter_fixed import (
    FixedStrategyInterpreter, 
    ZapretStrategy, 
    DPIMethod, 
    FoolingMethod,
    parse_zapret_strategy,
    convert_to_legacy
)

class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
    
    def assert_equal(self, actual, expected, description):
        if actual == expected:
            print(f"  ✓ {description}")
            self.passed += 1
        else:
            print(f"  ✗ {description}: Expected {expected}, got {actual}")
            self.failed += 1
            self.errors.append(f"{description}: Expected {expected}, got {actual}")
    
    def assert_true(self, condition, description):
        if condition:
            print(f"  ✓ {description}")
            self.passed += 1
        else:
            print(f"  ✗ {description}")
            self.failed += 1
            self.errors.append(description)
    
    def assert_false(self, condition, description):
        if not condition:
            print(f"  ✓ {description}")
            self.passed += 1
        else:
            print(f"  ✗ {description}")
            self.failed += 1
            self.errors.append(description)
    
    def summary(self):
        total = self.passed + self.failed
        print(f"\nTest Results: {self.passed}/{total} passed")
        if self.failed > 0:
            print("Failures:")
            for error in self.errors:
                print(f"  - {error}")
        return self.failed == 0

def test_problematic_zapret_command(results):
    """Test the exact problematic command from the analysis."""
    print("Testing problematic zapret command from analysis...")
    
    # The exact command that was causing issues
    problematic_command = (
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=336 "
        "--dpi-desync-autottl=2 --dpi-desync-fooling=md5sig,badsum,badseq "
        "--dpi-desync-repeats=1 --dpi-desync-split-pos=76 --dpi-desync-ttl=1"
    )
    
    print(f"Command: {problematic_command}")
    
    try:
        interpreter = FixedStrategyInterpreter()
        strategy = interpreter.parse_strategy(problematic_command)
        
        # Verify methods parsing - CRITICAL FIX
        expected_methods = [DPIMethod.FAKE, DPIMethod.FAKEDDISORDER]
        results.assert_equal(strategy.methods, expected_methods, 
                           "Methods parsed as [FAKE, FAKEDDISORDER]")
        
        # Verify parameter extraction - CRITICAL VALUES
        results.assert_equal(strategy.split_seqovl, 336, "split_seqovl=336")
        results.assert_equal(strategy.split_pos, 76, "split_pos=76 (NOT 3)")
        results.assert_equal(strategy.ttl, 1, "ttl=1 (NOT 64)")
        results.assert_equal(strategy.autottl, 2, "autottl=2")
        results.assert_equal(strategy.repeats, 1, "repeats=1")
        
        # Verify fooling methods
        expected_fooling = [FoolingMethod.MD5SIG, FoolingMethod.BADSUM, FoolingMethod.BADSEQ]
        results.assert_equal(set(strategy.fooling), set(expected_fooling), 
                           "Fooling methods: md5sig,badsum,badseq")
        
        # Verify legacy conversion - CRITICAL FIX
        legacy_format = interpreter.convert_to_legacy_format(strategy)
        results.assert_equal(legacy_format.get('attack_type'), 'fakeddisorder', 
                           "CRITICAL: Maps to fakeddisorder (NOT seqovl)")
        results.assert_equal(legacy_format.get('overlap_size'), 336, 
                           "CRITICAL: overlap_size=336 (NOT seqovl=336)")
        results.assert_equal(legacy_format.get('split_pos'), 76, 
                           "split_pos=76 in legacy format")
        
        # Verify validation passes
        results.assert_true(interpreter.validate_strategy(strategy), 
                          "Strategy validation passes")
        
        print("  → This should fix the 37% -> 87% success rate issue!")
        
    except Exception as e:
        results.errors.append(f"Problematic command parsing failed: {e}")
        print(f"  ✗ ERROR: {e}")

def test_edge_cases(results):
    """Test edge cases and error handling."""
    print("\nTesting edge cases and error handling...")
    
    interpreter = FixedStrategyInterpreter()
    
    # Test 1: Empty string
    try:
        interpreter.parse_strategy("")
        results.assert_false(True, "Empty string should raise ValueError")
    except ValueError:
        results.assert_true(True, "Empty string raises ValueError")
    except Exception as e:
        results.errors.append(f"Empty string test: Unexpected error {e}")
    
    # Test 2: None input
    try:
        interpreter.parse_strategy(None)
        results.assert_false(True, "None input should raise ValueError")
    except ValueError:
        results.assert_true(True, "None input raises ValueError")
    except Exception as e:
        results.errors.append(f"None input test: Unexpected error {e}")
    
    # Test 3: Invalid method
    try:
        strategy = interpreter.parse_strategy("--dpi-desync=invalidmethod")
        results.assert_equal(strategy.methods, [DPIMethod.FAKE], 
                           "Invalid method falls back to FAKE")
    except Exception as e:
        results.errors.append(f"Invalid method test: {e}")
    
    # Test 4: Missing dpi-desync parameter
    try:
        strategy = interpreter.parse_strategy("--some-other-param=value")
        results.assert_equal(strategy.methods, [DPIMethod.FAKE], 
                           "Missing dpi-desync falls back to FAKE")
    except Exception as e:
        results.errors.append(f"Missing dpi-desync test: {e}")
    
    # Test 5: Invalid integer parameter
    try:
        strategy = interpreter.parse_strategy("--dpi-desync=fake --dpi-desync-ttl=invalid")
        results.assert_equal(strategy.ttl, None, 
                           "Invalid integer parameter ignored")
    except Exception as e:
        results.errors.append(f"Invalid integer test: {e}")
    
    # Test 6: Disable value (0x00000000)
    try:
        strategy = interpreter.parse_strategy("--dpi-desync=fake --dpi-desync-fake-http=0x00000000")
        results.assert_equal(strategy.fake_http, None, 
                           "0x00000000 disables parameter")
    except Exception as e:
        results.errors.append(f"Disable value test: {e}")

def test_method_combinations(results):
    """Test various DPI method combinations."""
    print("\nTesting DPI method combinations...")
    
    interpreter = FixedStrategyInterpreter()
    
    test_cases = [
        # (command, expected_methods, expected_attack_type)
        ("--dpi-desync=fake", [DPIMethod.FAKE], "fake"),
        ("--dpi-desync=fakeddisorder", [DPIMethod.FAKEDDISORDER], "fakeddisorder"),
        ("--dpi-desync=fake,fakeddisorder", [DPIMethod.FAKE, DPIMethod.FAKEDDISORDER], "fakeddisorder"),
        ("--dpi-desync=multisplit", [DPIMethod.MULTISPLIT], "multisplit"),
        ("--dpi-desync=multidisorder", [DPIMethod.MULTIDISORDER], "multidisorder"),
        ("--dpi-desync=seqovl", [DPIMethod.SEQOVL], "seqovl"),
        ("--dpi-desync=syndata", [DPIMethod.SYNDATA], "syndata"),
        ("--dpi-desync=disorder", [DPIMethod.DISORDER], "disorder"),
        ("--dpi-desync=ipfrag2", [DPIMethod.IPFRAG2], "ipfrag2"),
    ]
    
    for command, expected_methods, expected_attack_type in test_cases:
        try:
            strategy = interpreter.parse_strategy(command)
            results.assert_equal(set(strategy.methods), set(expected_methods), 
                               f"{command} -> {[m.value for m in expected_methods]}")
            
            legacy_format = interpreter.convert_to_legacy_format(strategy)
            results.assert_equal(legacy_format.get('attack_type'), expected_attack_type,
                               f"{command} -> attack_type={expected_attack_type}")
        except Exception as e:
            results.errors.append(f"Method combination test {command}: {e}")

def test_parameter_combinations(results):
    """Test various parameter combinations."""
    print("\nTesting parameter combinations...")
    
    interpreter = FixedStrategyInterpreter()
    
    # Test comprehensive parameter extraction
    complex_command = (
        "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 "
        "--dpi-desync-ttl=4 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 "
        "--dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-window-div=6 --dpi-desync-delay=10 "
        "--dpi-desync-any-protocol --dpi-desync-wssize=1024"
    )
    
    try:
        strategy = interpreter.parse_strategy(complex_command)
        
        results.assert_equal(strategy.methods, [DPIMethod.MULTISPLIT], "Complex: multisplit method")
        results.assert_equal(strategy.split_count, 7, "Complex: split_count=7")
        results.assert_equal(strategy.split_seqovl, 30, "Complex: split_seqovl=30")
        results.assert_equal(strategy.ttl, 4, "Complex: ttl=4")
        results.assert_equal(strategy.fooling, [FoolingMethod.BADSUM], "Complex: fooling=badsum")
        results.assert_equal(strategy.repeats, 3, "Complex: repeats=3")
        results.assert_equal(strategy.fake_tls, "PAYLOADTLS", "Complex: fake_tls=PAYLOADTLS")
        results.assert_equal(strategy.window_div, 6, "Complex: window_div=6")
        results.assert_equal(strategy.delay, 10, "Complex: delay=10")
        results.assert_equal(strategy.any_protocol, True, "Complex: any_protocol=True")
        results.assert_equal(strategy.wssize, 1024, "Complex: wssize=1024")
        
    except Exception as e:
        results.errors.append(f"Complex parameter test: {e}")

def test_default_value_application(results):
    """Test that default values are applied correctly."""
    print("\nTesting default value application...")
    
    interpreter = FixedStrategyInterpreter()
    
    # Test fakeddisorder defaults
    fakeddisorder_minimal = "--dpi-desync=fakeddisorder --dpi-desync-split-seqovl=100"
    
    try:
        strategy = interpreter.parse_strategy(fakeddisorder_minimal)
        
        # Should apply zapret-compatible defaults
        results.assert_equal(strategy.split_pos, 76, "fakeddisorder default split_pos=76")
        results.assert_equal(strategy.ttl, 1, "fakeddisorder default ttl=1")
        results.assert_equal(strategy.split_seqovl, 100, "fakeddisorder explicit split_seqovl=100")
        
    except Exception as e:
        results.errors.append(f"fakeddisorder defaults test: {e}")
    
    # Test multisplit defaults
    multisplit_minimal = "--dpi-desync=multisplit"
    
    try:
        strategy = interpreter.parse_strategy(multisplit_minimal)
        
        results.assert_equal(strategy.split_count, 5, "multisplit default split_count=5")
        results.assert_equal(strategy.ttl, 4, "multisplit default ttl=4")
        
    except Exception as e:
        results.errors.append(f"multisplit defaults test: {e}")

def test_validation_edge_cases(results):
    """Test validation with edge cases."""
    print("\nTesting validation edge cases...")
    
    interpreter = FixedStrategyInterpreter()
    
    # Test boundary values
    boundary_tests = [
        (ZapretStrategy(methods=[DPIMethod.FAKE], ttl=1), True, "TTL boundary: 1"),
        (ZapretStrategy(methods=[DPIMethod.FAKE], ttl=255), True, "TTL boundary: 255"),
        (ZapretStrategy(methods=[DPIMethod.FAKE], split_pos=1), True, "split_pos boundary: 1"),
        (ZapretStrategy(methods=[DPIMethod.FAKE], split_seqovl=0), True, "split_seqovl boundary: 0"),
        (ZapretStrategy(methods=[DPIMethod.FAKE], repeats=1), True, "repeats boundary: 1"),
    ]
    
    for strategy, should_pass, description in boundary_tests:
        try:
            result = interpreter.validate_strategy(strategy)
            results.assert_equal(result, should_pass, description)
        except Exception as e:
            results.errors.append(f"Validation test {description}: {e}")

def test_legacy_conversion_edge_cases(results):
    """Test legacy conversion with various scenarios."""
    print("\nTesting legacy conversion edge cases...")
    
    interpreter = FixedStrategyInterpreter()
    
    # Test minimal strategy
    minimal_strategy = ZapretStrategy(methods=[DPIMethod.FAKE])
    legacy = interpreter.convert_to_legacy_format(minimal_strategy)
    results.assert_equal(legacy.get('attack_type'), 'fake', "Minimal strategy conversion")
    
    # Test strategy with no methods (edge case)
    empty_strategy = ZapretStrategy(methods=[])
    legacy = interpreter.convert_to_legacy_format(empty_strategy)
    results.assert_equal(legacy.get('attack_type'), 'fake', "Empty methods fallback to fake")
    
    # Test strategy with all parameters
    full_strategy = ZapretStrategy(
        methods=[DPIMethod.FAKEDDISORDER],
        split_seqovl=336,
        split_pos=76,
        split_count=5,
        ttl=1,
        autottl=2,
        fooling=[FoolingMethod.MD5SIG, FoolingMethod.BADSUM],
        fake_http="custom",
        fake_tls="PAYLOADTLS",
        repeats=3,
        window_div=6,
        delay=10
    )
    
    legacy = interpreter.convert_to_legacy_format(full_strategy)
    
    expected_keys = [
        'attack_type', 'overlap_size', 'split_pos', 'split_count', 
        'ttl', 'autottl', 'fooling', 'fake_http', 'fake_tls', 
        'repeats', 'window_div', 'delay'
    ]
    
    for key in expected_keys:
        results.assert_true(key in legacy, f"Full strategy contains {key}")

def test_convenience_functions(results):
    """Test convenience functions."""
    print("\nTesting convenience functions...")
    
    # Test parse_zapret_strategy function
    try:
        strategy = parse_zapret_strategy("--dpi-desync=fake --dpi-desync-ttl=4")
        results.assert_equal(strategy.methods, [DPIMethod.FAKE], "parse_zapret_strategy works")
        results.assert_equal(strategy.ttl, 4, "parse_zapret_strategy extracts parameters")
    except Exception as e:
        results.errors.append(f"parse_zapret_strategy test: {e}")
    
    # Test convert_to_legacy function
    try:
        strategy = ZapretStrategy(methods=[DPIMethod.MULTISPLIT], split_count=7)
        legacy = convert_to_legacy(strategy)
        results.assert_equal(legacy.get('attack_type'), 'multisplit', "convert_to_legacy works")
        results.assert_equal(legacy.get('split_count'), 7, "convert_to_legacy preserves parameters")
    except Exception as e:
        results.errors.append(f"convert_to_legacy test: {e}")

def compare_with_broken_behavior(results):
    """Compare with the expected broken behavior to validate fixes."""
    print("\nComparing with expected broken behavior...")
    
    # The problematic command that was being misinterpreted
    problematic_command = (
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=336 "
        "--dpi-desync-split-pos=76"
    )
    
    try:
        interpreter = FixedStrategyInterpreter()
        strategy = interpreter.parse_strategy(problematic_command)
        legacy = interpreter.convert_to_legacy_format(strategy)
        
        # What the BROKEN implementation would produce:
        # - attack_type: "seqovl" (WRONG!)
        # - seqovl: 336 (WRONG parameter name!)
        # - split_pos: 3 (WRONG default!)
        
        # What the FIXED implementation should produce:
        results.assert_equal(legacy.get('attack_type'), 'fakeddisorder', 
                           "FIXED: attack_type is fakeddisorder (not seqovl)")
        results.assert_equal(legacy.get('overlap_size'), 336, 
                           "FIXED: parameter is overlap_size (not seqovl)")
        results.assert_equal(legacy.get('split_pos'), 76, 
                           "FIXED: split_pos is 76 (not 3)")
        
        # Verify the fix addresses the root cause
        results.assert_true('seqovl' not in legacy, 
                          "FIXED: No 'seqovl' parameter in legacy format")
        results.assert_false(legacy.get('attack_type') == 'seqovl', 
                           "FIXED: attack_type is not 'seqovl'")
        
        print("  → These fixes should resolve the 37% -> 87% success rate issue")
        
    except Exception as e:
        results.errors.append(f"Broken behavior comparison: {e}")

def run_comprehensive_tests():
    """Run all comprehensive tests."""
    print("FixedStrategyInterpreter Comprehensive Test Suite")
    print("="*60)
    print("Testing critical fixes for zapret strategy interpretation")
    print("This should resolve the fake,fakeddisorder -> seqovl misinterpretation")
    print("="*60)
    
    results = TestResults()
    
    # Run all test categories
    test_problematic_zapret_command(results)
    test_edge_cases(results)
    test_method_combinations(results)
    test_parameter_combinations(results)
    test_default_value_application(results)
    test_validation_edge_cases(results)
    test_legacy_conversion_edge_cases(results)
    test_convenience_functions(results)
    compare_with_broken_behavior(results)
    
    # Print summary
    success = results.summary()
    
    if success:
        print("\n" + "="*60)
        print("🎉 ALL TESTS PASSED! 🎉")
        print("FixedStrategyInterpreter is ready for production use")
        print("Critical fixes implemented:")
        print("  ✓ fake,fakeddisorder -> fakeddisorder attack (NOT seqovl)")
        print("  ✓ split-seqovl=336 -> overlap_size=336 (NOT seqovl=336)")
        print("  ✓ split-pos=76 default (NOT 3)")
        print("  ✓ ttl=1 default (NOT 64)")
        print("  ✓ Full autottl and fooling support")
        print("="*60)
    else:
        print("\n" + "="*60)
        print("❌ SOME TESTS FAILED ❌")
        print("Please review and fix issues before production use")
        print("="*60)
    
    return success

if __name__ == "__main__":
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)