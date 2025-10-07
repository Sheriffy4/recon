"""Test StrategyParserV2 implementation."""

import sys
import logging
from core.strategy_parser_v2 import StrategyParserV2, ParameterValidator, parse_strategy

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def test_function_style():
    """Test function-style parsing."""
    print("\n" + "="*60)
    print("TEST: Function-Style Parsing")
    print("="*60)
    
    test_cases = [
        "fake(ttl=1, fooling=['badsum'])",
        "split(split_pos=1)",
        "fakeddisorder(split_pos=76, overlap_size=336, ttl=3)",
        "disorder(split_pos=2)",
        "multisplit(split_count=5, ttl=64)",
        "multidisorder(split_pos=3, ttl=1)",
    ]
    
    parser = StrategyParserV2()
    passed = 0
    failed = 0
    
    for test in test_cases:
        print(f"\nTesting: {test}")
        try:
            parsed = parser.parse(test)
            print(f"  ✓ Attack: {parsed.attack_type}")
            print(f"  ✓ Params: {parsed.params}")
            print(f"  ✓ Syntax: {parsed.syntax_type}")
            passed += 1
        except Exception as e:
            print(f"  ✗ Error: {e}")
            failed += 1
    
    print(f"\nFunction-style: {passed} passed, {failed} failed")
    return failed == 0


def test_zapret_style():
    """Test zapret-style parsing."""
    print("\n" + "="*60)
    print("TEST: Zapret-Style Parsing")
    print("="*60)
    
    test_cases = [
        "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
        "--dpi-desync=split --dpi-desync-split-pos=1",
        "--dpi-desync=fake,disorder --dpi-desync-split-pos=76 --dpi-desync-ttl=3",
        "--dpi-desync=multisplit --dpi-desync-split-count=5",
    ]
    
    parser = StrategyParserV2()
    passed = 0
    failed = 0
    
    for test in test_cases:
        print(f"\nTesting: {test}")
        try:
            parsed = parser.parse(test)
            print(f"  ✓ Attack: {parsed.attack_type}")
            print(f"  ✓ Params: {parsed.params}")
            print(f"  ✓ Syntax: {parsed.syntax_type}")
            passed += 1
        except Exception as e:
            print(f"  ✗ Error: {e}")
            failed += 1
    
    print(f"\nZapret-style: {passed} passed, {failed} failed")
    return failed == 0


def test_parameter_parsing():
    """Test parameter parsing."""
    print("\n" + "="*60)
    print("TEST: Parameter Parsing")
    print("="*60)
    
    test_cases = [
        ("fake(ttl=1)", {'ttl': 1}),
        ("fake(fake_sni='example.com')", {'fake_sni': 'example.com'}),
        ("fake(fooling=['badsum', 'md5sig'])", {'fooling': ['badsum', 'md5sig']}),
        ("fake(enabled=True)", {'enabled': True}),
        ("fake(ttl=1, fooling=['badsum'], fake_sni='test.com')", 
         {'ttl': 1, 'fooling': ['badsum'], 'fake_sni': 'test.com'}),
    ]
    
    parser = StrategyParserV2()
    passed = 0
    failed = 0
    
    for test_str, expected_params in test_cases:
        print(f"\nTesting: {test_str}")
        print(f"Expected params: {expected_params}")
        try:
            parsed = parser.parse(test_str)
            if parsed.params == expected_params:
                print(f"  ✓ Params match: {parsed.params}")
                passed += 1
            else:
                print(f"  ✗ Params mismatch!")
                print(f"    Expected: {expected_params}")
                print(f"    Got: {parsed.params}")
                failed += 1
        except Exception as e:
            print(f"  ✗ Error: {e}")
            failed += 1
    
    print(f"\nParameter parsing: {passed} passed, {failed} failed")
    return failed == 0


def test_validation():
    """Test parameter validation."""
    print("\n" + "="*60)
    print("TEST: Parameter Validation")
    print("="*60)
    
    # Valid cases
    valid_cases = [
        "fake(ttl=1, fooling=['badsum'])",
        "split(split_pos=1)",
        "fakeddisorder(split_pos=76, overlap_size=336, ttl=3)",
    ]
    
    # Invalid cases
    invalid_cases = [
        ("fake(ttl=300)", "TTL out of range"),
        ("split()", "Missing required split_pos"),
        ("fakeddisorder(ttl=1)", "Missing required split_pos"),
    ]
    
    parser = StrategyParserV2()
    validator = ParameterValidator()
    passed = 0
    failed = 0
    
    # Test valid cases
    print("\nValid cases (should pass):")
    for test in valid_cases:
        print(f"\nTesting: {test}")
        try:
            parsed = parser.parse(test)
            validator.validate(parsed)
            print(f"  ✓ Validation passed")
            passed += 1
        except Exception as e:
            print(f"  ✗ Unexpected error: {e}")
            failed += 1
    
    # Test invalid cases
    print("\nInvalid cases (should fail):")
    for test, reason in invalid_cases:
        print(f"\nTesting: {test} ({reason})")
        try:
            parsed = parser.parse(test)
            validator.validate(parsed)
            print(f"  ✗ Should have failed but passed!")
            failed += 1
        except ValueError as e:
            print(f"  ✓ Correctly rejected: {str(e)[:80]}...")
            passed += 1
        except Exception as e:
            print(f"  ✗ Unexpected error: {e}")
            failed += 1
    
    print(f"\nValidation: {passed} passed, {failed} failed")
    return failed == 0


def test_all_attacks():
    """Test all known attack types."""
    print("\n" + "="*60)
    print("TEST: All Attack Types")
    print("="*60)
    
    attacks = [
        "fake(ttl=1)",
        "split(split_pos=1)",
        "disorder(split_pos=2)",
        "disorder2(split_pos=3, ttl=1)",
        "multisplit(split_count=5)",
        "multidisorder(split_pos=4, ttl=2)",
        "fakeddisorder(split_pos=76, overlap_size=336, ttl=3)",
        "seqovl(split_pos=5, overlap_size=100)",
    ]
    
    parser = StrategyParserV2()
    passed = 0
    failed = 0
    
    for attack in attacks:
        print(f"\nTesting: {attack}")
        try:
            parsed = parser.parse(attack)
            print(f"  ✓ Parsed: {parsed.attack_type}")
            passed += 1
        except Exception as e:
            print(f"  ✗ Error: {e}")
            failed += 1
    
    print(f"\nAll attacks: {passed} passed, {failed} failed")
    return failed == 0


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("STRATEGY PARSER V2 - TEST SUITE")
    print("="*60)
    
    results = []
    
    results.append(("Function-style parsing", test_function_style()))
    results.append(("Zapret-style parsing", test_zapret_style()))
    results.append(("Parameter parsing", test_parameter_parsing()))
    results.append(("Validation", test_validation()))
    results.append(("All attack types", test_all_attacks()))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {name}")
    
    all_passed = all(passed for _, passed in results)
    
    if all_passed:
        print("\n✓ ALL TESTS PASSED!")
        return 0
    else:
        print("\n✗ SOME TESTS FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(main())
