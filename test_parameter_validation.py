"""Comprehensive test for parameter validation in StrategyParserV2."""

import sys
import logging
from core.strategy_parser_v2 import StrategyParserV2, ParameterValidator, parse_strategy

# Setup logging
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

def test_required_parameters():
    """Test that required parameters are validated."""
    print("\n" + "="*60)
    print("TEST: Required Parameters Validation")
    print("="*60)
    
    test_cases = [
        # (strategy, should_pass, reason)
        ("split(split_pos=1)", True, "Has required split_pos"),
        ("split()", False, "Missing required split_pos"),
        ("split(ttl=1)", False, "Has ttl but missing split_pos"),
        ("disorder(split_pos=2)", True, "Has required split_pos"),
        ("disorder()", False, "Missing required split_pos"),
        ("multisplit(split_count=5)", True, "Has required split_count"),
        ("multisplit()", False, "Missing required split_count"),
        ("fakeddisorder(split_pos=76)", True, "Has required split_pos"),
        ("fakeddisorder(ttl=1)", False, "Missing required split_pos"),
        ("seqovl(split_pos=5, overlap_size=100)", True, "Has all required params"),
        ("seqovl(split_pos=5)", False, "Missing required overlap_size"),
        ("fake(ttl=1)", True, "Fake has no required params"),
    ]
    
    passed = 0
    failed = 0
    
    for strategy, should_pass, reason in test_cases:
        print(f"\nTesting: {strategy}")
        print(f"  Reason: {reason}")
        print(f"  Expected: {'PASS' if should_pass else 'FAIL'}")
        
        try:
            parsed = parse_strategy(strategy, validate=True)
            if should_pass:
                print(f"  ✓ Correctly passed validation")
                passed += 1
            else:
                print(f"  ✗ Should have failed but passed!")
                failed += 1
        except ValueError as e:
            if not should_pass:
                print(f"  ✓ Correctly rejected")
                print(f"     Error: {str(e).split(chr(10))[0][:70]}...")
                passed += 1
            else:
                print(f"  ✗ Should have passed but failed!")
                print(f"     Error: {e}")
                failed += 1
    
    print(f"\nRequired parameters: {passed} passed, {failed} failed")
    return failed == 0


def test_parameter_types():
    """Test that parameter types are validated."""
    print("\n" + "="*60)
    print("TEST: Parameter Type Validation")
    print("="*60)
    
    # Note: Parser converts types automatically, so we test with parse_strategy
    test_cases = [
        ("fake(ttl=1)", True, "ttl is int"),
        ("fake(ttl=64)", True, "ttl is valid int"),
        ("fake(fooling=['badsum'])", True, "fooling is list"),
        ("fake(fake_sni='example.com')", True, "fake_sni is string"),
        ("fake(enabled=True)", True, "enabled is bool"),
        ("split(split_pos=1)", True, "split_pos is int"),
        ("split(split_pos='midsld')", True, "split_pos can be 'midsld'"),
    ]
    
    passed = 0
    failed = 0
    
    for strategy, should_pass, reason in test_cases:
        print(f"\nTesting: {strategy}")
        print(f"  Reason: {reason}")
        
        try:
            parsed = parse_strategy(strategy, validate=True)
            if should_pass:
                print(f"  ✓ Correctly passed validation")
                print(f"     Params: {parsed.params}")
                passed += 1
            else:
                print(f"  ✗ Should have failed but passed!")
                failed += 1
        except ValueError as e:
            if not should_pass:
                print(f"  ✓ Correctly rejected")
                passed += 1
            else:
                print(f"  ✗ Should have passed but failed!")
                print(f"     Error: {e}")
                failed += 1
    
    print(f"\nParameter types: {passed} passed, {failed} failed")
    return failed == 0


def test_parameter_ranges():
    """Test that parameter value ranges are validated."""
    print("\n" + "="*60)
    print("TEST: Parameter Range Validation")
    print("="*60)
    
    test_cases = [
        # (strategy, should_pass, reason)
        ("fake(ttl=1)", True, "ttl=1 is valid (min)"),
        ("fake(ttl=64)", True, "ttl=64 is valid"),
        ("fake(ttl=255)", True, "ttl=255 is valid (max)"),
        ("fake(ttl=0)", False, "ttl=0 is below min (1)"),
        ("fake(ttl=256)", False, "ttl=256 is above max (255)"),
        ("fake(ttl=300)", False, "ttl=300 is above max (255)"),
        ("split(split_pos=0)", True, "split_pos=0 is valid (min)"),
        ("split(split_pos=1)", True, "split_pos=1 is valid"),
        ("split(split_pos=65535)", True, "split_pos=65535 is valid (max)"),
        ("split(split_pos=-1)", False, "split_pos=-1 is below min (0)"),
        ("multisplit(split_count=1)", True, "split_count=1 is valid (min)"),
        ("multisplit(split_count=50)", True, "split_count=50 is valid"),
        ("multisplit(split_count=100)", True, "split_count=100 is valid (max)"),
        ("multisplit(split_count=0)", False, "split_count=0 is below min (1)"),
        ("multisplit(split_count=101)", False, "split_count=101 is above max (100)"),
        ("fakeddisorder(split_pos=76, overlap_size=0)", True, "overlap_size=0 is valid (min)"),
        ("fakeddisorder(split_pos=76, overlap_size=1000)", True, "overlap_size=1000 is valid"),
    ]
    
    passed = 0
    failed = 0
    
    for strategy, should_pass, reason in test_cases:
        print(f"\nTesting: {strategy}")
        print(f"  Reason: {reason}")
        print(f"  Expected: {'PASS' if should_pass else 'FAIL'}")
        
        try:
            parsed = parse_strategy(strategy, validate=True)
            if should_pass:
                print(f"  ✓ Correctly passed validation")
                passed += 1
            else:
                print(f"  ✗ Should have failed but passed!")
                failed += 1
        except ValueError as e:
            if not should_pass:
                print(f"  ✓ Correctly rejected")
                print(f"     Error: {str(e).split(chr(10))[1][:70]}...")
                passed += 1
            else:
                print(f"  ✗ Should have passed but failed!")
                print(f"     Error: {e}")
                failed += 1
    
    print(f"\nParameter ranges: {passed} passed, {failed} failed")
    return failed == 0


def test_list_values():
    """Test that list parameter values are validated."""
    print("\n" + "="*60)
    print("TEST: List Value Validation")
    print("="*60)
    
    test_cases = [
        ("fake(fooling=['badsum'])", True, "badsum is valid"),
        ("fake(fooling=['md5sig'])", True, "md5sig is valid"),
        ("fake(fooling=['badsum', 'md5sig'])", True, "Multiple valid values"),
        ("fake(fooling=['badseq'])", True, "badseq is valid"),
        ("fake(fooling=['hopbyhop'])", True, "hopbyhop is valid"),
        ("fake(fooling=['datanoack'])", True, "datanoack is valid"),
        ("fake(fooling=['invalid'])", False, "invalid is not allowed"),
        ("fake(fooling=['badsum', 'invalid'])", False, "Contains invalid value"),
    ]
    
    passed = 0
    failed = 0
    
    for strategy, should_pass, reason in test_cases:
        print(f"\nTesting: {strategy}")
        print(f"  Reason: {reason}")
        print(f"  Expected: {'PASS' if should_pass else 'FAIL'}")
        
        try:
            parsed = parse_strategy(strategy, validate=True)
            if should_pass:
                print(f"  ✓ Correctly passed validation")
                passed += 1
            else:
                print(f"  ✗ Should have failed but passed!")
                failed += 1
        except ValueError as e:
            if not should_pass:
                print(f"  ✓ Correctly rejected")
                print(f"     Error: {str(e).split(chr(10))[1][:70]}...")
                passed += 1
            else:
                print(f"  ✗ Should have passed but failed!")
                print(f"     Error: {e}")
                failed += 1
    
    print(f"\nList values: {passed} passed, {failed} failed")
    return failed == 0


def test_error_messages():
    """Test that error messages are clear and helpful."""
    print("\n" + "="*60)
    print("TEST: Error Message Quality")
    print("="*60)
    
    test_cases = [
        ("split()", "Missing required parameter"),
        ("fake(ttl=300)", "above maximum"),
        ("fake(ttl=0)", "below minimum"),
        ("fake(fooling=['invalid'])", "invalid value"),
    ]
    
    passed = 0
    failed = 0
    
    for strategy, expected_msg in test_cases:
        print(f"\nTesting: {strategy}")
        print(f"  Expected message contains: '{expected_msg}'")
        
        try:
            parsed = parse_strategy(strategy, validate=True)
            print(f"  ✗ Should have failed but passed!")
            failed += 1
        except ValueError as e:
            error_str = str(e).lower()
            if expected_msg.lower() in error_str:
                print(f"  ✓ Error message contains expected text")
                print(f"     Full error: {str(e).split(chr(10))[0][:70]}...")
                passed += 1
            else:
                print(f"  ✗ Error message doesn't contain expected text")
                print(f"     Error: {e}")
                failed += 1
    
    print(f"\nError messages: {passed} passed, {failed} failed")
    return failed == 0


def test_validator_info_methods():
    """Test validator info methods."""
    print("\n" + "="*60)
    print("TEST: Validator Info Methods")
    print("="*60)
    
    validator = ParameterValidator()
    passed = 0
    failed = 0
    
    # Test get_attack_info
    print("\nTesting get_attack_info():")
    attack_info = validator.get_attack_info('fake')
    if attack_info and 'required' in attack_info:
        print(f"  ✓ Got info for 'fake' attack")
        print(f"     Required: {attack_info['required']}")
        print(f"     Optional: {attack_info['optional']}")
        passed += 1
    else:
        print(f"  ✗ Failed to get info for 'fake' attack")
        failed += 1
    
    # Test get_parameter_info
    print("\nTesting get_parameter_info():")
    param_info = validator.get_parameter_info('ttl')
    if param_info and 'type' in param_info:
        print(f"  ✓ Got info for 'ttl' parameter")
        print(f"     Type: {param_info['type']}")
        print(f"     Range: {param_info.get('min', 'N/A')} - {param_info.get('max', 'N/A')}")
        print(f"     Description: {param_info.get('description', 'N/A')}")
        passed += 1
    else:
        print(f"  ✗ Failed to get info for 'ttl' parameter")
        failed += 1
    
    print(f"\nValidator info methods: {passed} passed, {failed} failed")
    return failed == 0


def main():
    """Run all validation tests."""
    print("\n" + "="*60)
    print("PARAMETER VALIDATION - COMPREHENSIVE TEST SUITE")
    print("="*60)
    
    results = []
    
    results.append(("Required parameters", test_required_parameters()))
    results.append(("Parameter types", test_parameter_types()))
    results.append(("Parameter ranges", test_parameter_ranges()))
    results.append(("List values", test_list_values()))
    results.append(("Error messages", test_error_messages()))
    results.append(("Validator info methods", test_validator_info_methods()))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {name}")
    
    all_passed = all(passed for _, passed in results)
    
    if all_passed:
        print("\n✓ ALL VALIDATION TESTS PASSED!")
        print("\nParameter validation features:")
        print("  ✓ Required parameters are validated")
        print("  ✓ Parameter types are checked")
        print("  ✓ Parameter values are range-checked")
        print("  ✓ List values are validated against allowed values")
        print("  ✓ Clear error messages are provided")
        print("  ✓ Info methods work correctly")
        return 0
    else:
        print("\n✗ SOME VALIDATION TESTS FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(main())
