"""Test autottl, split_seqovl, and repeats parameter parsing in StrategyParserV2."""

import sys
import logging
from core.strategy_parser_v2 import StrategyParserV2, ParameterValidator, parse_strategy

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')


def test_autottl_parsing():
    """Test autottl parameter parsing."""
    print("\n" + "="*60)
    print("TEST: AutoTTL Parameter Parsing")
    print("="*60)
    
    test_cases = [
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-autottl=2',
            'expected_attack': 'multidisorder',
            'expected_params': {'autottl': 2, 'repeats': 1}
        },
        {
            'strategy': '--dpi-desync=fake --dpi-desync-autottl=1',
            'expected_attack': 'fake',
            'expected_params': {'autottl': 1, 'repeats': 1}
        },
        {
            'strategy': '--dpi-desync=split --dpi-desync-autottl=3 --dpi-desync-split-pos=46',
            'expected_attack': 'split',
            'expected_params': {'autottl': 3, 'split_pos': 46, 'repeats': 1}
        },
        {
            'strategy': '--dpi-desync=fakeddisorder --dpi-desync-autottl=2 --dpi-desync-split-pos=76',
            'expected_attack': 'fakeddisorder',
            'expected_params': {'autottl': 2, 'split_pos': 76, 'repeats': 1}
        },
    ]
    
    parser = StrategyParserV2()
    passed = 0
    failed = 0
    
    for test in test_cases:
        print(f"\nTesting: {test['strategy']}")
        try:
            parsed = parser.parse(test['strategy'])
            
            # Check attack type
            if parsed.attack_type != test['expected_attack']:
                print(f"  ✗ Attack type mismatch!")
                print(f"    Expected: {test['expected_attack']}")
                print(f"    Got: {parsed.attack_type}")
                failed += 1
                continue
            
            # Check params
            if parsed.params != test['expected_params']:
                print(f"  ✗ Params mismatch!")
                print(f"    Expected: {test['expected_params']}")
                print(f"    Got: {parsed.params}")
                failed += 1
                continue
            
            print(f"  ✓ Attack: {parsed.attack_type}")
            print(f"  ✓ Params: {parsed.params}")
            passed += 1
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            failed += 1
    
    print(f"\nAutoTTL parsing: {passed} passed, {failed} failed")
    return failed == 0


def test_autottl_ttl_mutual_exclusivity():
    """Test that autottl and ttl are mutually exclusive."""
    print("\n" + "="*60)
    print("TEST: AutoTTL and TTL Mutual Exclusivity")
    print("="*60)
    
    # These should fail during parsing
    invalid_strategies = [
        '--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-ttl=1',
        '--dpi-desync=fake --dpi-desync-ttl=3 --dpi-desync-autottl=1',
        '--dpi-desync=split --dpi-desync-split-pos=46 --dpi-desync-ttl=4 --dpi-desync-autottl=2',
    ]
    
    parser = StrategyParserV2()
    passed = 0
    failed = 0
    
    for strategy in invalid_strategies:
        print(f"\nTesting: {strategy}")
        try:
            parsed = parser.parse(strategy)
            print(f"  ✗ Should have failed but parsed successfully!")
            print(f"    Params: {parsed.params}")
            failed += 1
        except ValueError as e:
            if 'mutually exclusive' in str(e).lower():
                print(f"  ✓ Correctly rejected: {str(e)[:80]}...")
                passed += 1
            else:
                print(f"  ✗ Wrong error message: {e}")
                failed += 1
        except Exception as e:
            print(f"  ✗ Unexpected error: {e}")
            failed += 1
    
    print(f"\nMutual exclusivity: {passed} passed, {failed} failed")
    return failed == 0


def test_autottl_validation():
    """Test autottl parameter validation."""
    print("\n" + "="*60)
    print("TEST: AutoTTL Parameter Validation")
    print("="*60)
    
    # Valid cases
    valid_cases = [
        '--dpi-desync=multidisorder --dpi-desync-autottl=1 --dpi-desync-split-pos=46',
        '--dpi-desync=fake --dpi-desync-autottl=2',
        '--dpi-desync=split --dpi-desync-autottl=255 --dpi-desync-split-pos=1',
    ]
    
    # Invalid cases (out of range)
    invalid_cases = [
        ('--dpi-desync=fake --dpi-desync-autottl=0', 'AutoTTL below minimum'),
        ('--dpi-desync=fake --dpi-desync-autottl=256', 'AutoTTL above maximum'),
        ('--dpi-desync=fake --dpi-desync-autottl=-1', 'Negative AutoTTL'),
    ]
    
    parser = StrategyParserV2()
    validator = ParameterValidator()
    passed = 0
    failed = 0
    
    # Test valid cases
    print("\nValid cases (should pass):")
    for strategy in valid_cases:
        print(f"\nTesting: {strategy}")
        try:
            parsed = parser.parse(strategy)
            validator.validate(parsed)
            print(f"  ✓ Validation passed")
            print(f"    Params: {parsed.params}")
            passed += 1
        except Exception as e:
            print(f"  ✗ Unexpected error: {e}")
            failed += 1
    
    # Test invalid cases
    print("\nInvalid cases (should fail):")
    for strategy, reason in invalid_cases:
        print(f"\nTesting: {strategy} ({reason})")
        try:
            parsed = parser.parse(strategy)
            validator.validate(parsed)
            print(f"  ✗ Should have failed but passed!")
            failed += 1
        except (ValueError, Exception) as e:
            print(f"  ✓ Correctly rejected: {str(e)[:80]}...")
            passed += 1
    
    print(f"\nAutoTTL validation: {passed} passed, {failed} failed")
    return failed == 0


def test_split_seqovl_parsing():
    """Test split_seqovl parameter parsing."""
    print("\n" + "="*60)
    print("TEST: Split SeqOvl Parameter Parsing")
    print("="*60)
    
    test_cases = [
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1',
            'expected_attack': 'multidisorder',
            'expected_params': {'split_pos': 46, 'split_seqovl': 1, 'overlap_size': 1, 'repeats': 1}
        },
        {
            'strategy': '--dpi-desync=disorder --dpi-desync-split-pos=2 --dpi-desync-split-seqovl=5',
            'expected_attack': 'disorder',
            'expected_params': {'split_pos': 2, 'split_seqovl': 5, 'overlap_size': 5, 'repeats': 1}
        },
        {
            'strategy': '--dpi-desync=fakeddisorder --dpi-desync-split-pos=76 --dpi-desync-split-seqovl=0',
            'expected_attack': 'fakeddisorder',
            'expected_params': {'split_pos': 76, 'split_seqovl': 0, 'overlap_size': 0, 'repeats': 1}
        },
    ]
    
    parser = StrategyParserV2()
    passed = 0
    failed = 0
    
    for test in test_cases:
        print(f"\nTesting: {test['strategy']}")
        try:
            parsed = parser.parse(test['strategy'])
            
            # Check attack type
            if parsed.attack_type != test['expected_attack']:
                print(f"  ✗ Attack type mismatch!")
                print(f"    Expected: {test['expected_attack']}")
                print(f"    Got: {parsed.attack_type}")
                failed += 1
                continue
            
            # Check params
            if parsed.params != test['expected_params']:
                print(f"  ✗ Params mismatch!")
                print(f"    Expected: {test['expected_params']}")
                print(f"    Got: {parsed.params}")
                failed += 1
                continue
            
            # Verify overlap_size is set from split_seqovl
            if 'split_seqovl' in parsed.params:
                if parsed.params.get('overlap_size') != parsed.params['split_seqovl']:
                    print(f"  ✗ overlap_size not mapped from split_seqovl!")
                    failed += 1
                    continue
            
            print(f"  ✓ Attack: {parsed.attack_type}")
            print(f"  ✓ Params: {parsed.params}")
            print(f"  ✓ overlap_size correctly mapped from split_seqovl")
            passed += 1
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            failed += 1
    
    print(f"\nSplit SeqOvl parsing: {passed} passed, {failed} failed")
    return failed == 0


def test_repeats_parsing():
    """Test repeats parameter parsing."""
    print("\n" + "="*60)
    print("TEST: Repeats Parameter Parsing")
    print("="*60)
    
    test_cases = [
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-split-pos=46 --dpi-desync-repeats=2',
            'expected_attack': 'multidisorder',
            'expected_params': {'split_pos': 46, 'repeats': 2}
        },
        {
            'strategy': '--dpi-desync=fake --dpi-desync-repeats=3',
            'expected_attack': 'fake',
            'expected_params': {'repeats': 3}
        },
        {
            'strategy': '--dpi-desync=split --dpi-desync-split-pos=1 --dpi-desync-repeats=1',
            'expected_attack': 'split',
            'expected_params': {'split_pos': 1, 'repeats': 1}
        },
        {
            'strategy': '--dpi-desync=disorder --dpi-desync-split-pos=2',
            'expected_attack': 'disorder',
            'expected_params': {'split_pos': 2, 'repeats': 1}  # Default value
        },
    ]
    
    parser = StrategyParserV2()
    passed = 0
    failed = 0
    
    for test in test_cases:
        print(f"\nTesting: {test['strategy']}")
        try:
            parsed = parser.parse(test['strategy'])
            
            # Check attack type
            if parsed.attack_type != test['expected_attack']:
                print(f"  ✗ Attack type mismatch!")
                print(f"    Expected: {test['expected_attack']}")
                print(f"    Got: {parsed.attack_type}")
                failed += 1
                continue
            
            # Check params
            if parsed.params != test['expected_params']:
                print(f"  ✗ Params mismatch!")
                print(f"    Expected: {test['expected_params']}")
                print(f"    Got: {parsed.params}")
                failed += 1
                continue
            
            # Verify default value
            if 'repeats' not in test['strategy']:
                if parsed.params.get('repeats') != 1:
                    print(f"  ✗ Default repeats value not set to 1!")
                    failed += 1
                    continue
                print(f"  ✓ Default repeats=1 correctly set")
            
            print(f"  ✓ Attack: {parsed.attack_type}")
            print(f"  ✓ Params: {parsed.params}")
            passed += 1
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            failed += 1
    
    print(f"\nRepeats parsing: {passed} passed, {failed} failed")
    return failed == 0


def test_multidisorder_recognition():
    """Test that multidisorder is correctly recognized and not confused with fakeddisorder."""
    print("\n" + "="*60)
    print("TEST: Multidisorder Recognition")
    print("="*60)
    
    test_cases = [
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-split-pos=46',
            'expected_attack': 'multidisorder',
            'description': 'Explicit multidisorder'
        },
        {
            'strategy': '--dpi-desync=fake,disorder --dpi-desync-split-pos=76',
            'expected_attack': 'fakeddisorder',
            'description': 'fake,disorder should be fakeddisorder'
        },
        {
            'strategy': '--dpi-desync=disorder --dpi-desync-split-pos=2',
            'expected_attack': 'disorder',
            'description': 'Plain disorder'
        },
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1 --dpi-desync-repeats=2',
            'expected_attack': 'multidisorder',
            'description': 'Full x.com strategy'
        },
    ]
    
    parser = StrategyParserV2()
    passed = 0
    failed = 0
    
    for test in test_cases:
        print(f"\nTesting: {test['description']}")
        print(f"Strategy: {test['strategy']}")
        try:
            parsed = parser.parse(test['strategy'])
            
            if parsed.attack_type != test['expected_attack']:
                print(f"  ✗ Attack type mismatch!")
                print(f"    Expected: {test['expected_attack']}")
                print(f"    Got: {parsed.attack_type}")
                failed += 1
                continue
            
            print(f"  ✓ Correctly identified as: {parsed.attack_type}")
            print(f"  ✓ Params: {parsed.params}")
            passed += 1
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            failed += 1
    
    print(f"\nMultidisorder recognition: {passed} passed, {failed} failed")
    return failed == 0


def test_x_com_strategy():
    """Test the complete x.com router strategy."""
    print("\n" + "="*60)
    print("TEST: X.com Router Strategy")
    print("="*60)
    
    strategy = (
        '--dpi-desync=multidisorder '
        '--dpi-desync-autottl=2 '
        '--dpi-desync-fooling=badseq '
        '--dpi-desync-repeats=2 '
        '--dpi-desync-split-pos=46 '
        '--dpi-desync-split-seqovl=1'
    )
    
    expected_attack = 'multidisorder'
    expected_params = {
        'autottl': 2,
        'fooling': ['badseq'],
        'repeats': 2,
        'split_pos': 46,
        'split_seqovl': 1,
        'overlap_size': 1
    }
    
    print(f"\nTesting x.com strategy:")
    print(f"  {strategy}")
    
    parser = StrategyParserV2()
    validator = ParameterValidator()
    
    try:
        # Parse
        parsed = parser.parse(strategy)
        
        # Check attack type
        if parsed.attack_type != expected_attack:
            print(f"  ✗ Attack type mismatch!")
            print(f"    Expected: {expected_attack}")
            print(f"    Got: {parsed.attack_type}")
            return False
        
        # Check params
        if parsed.params != expected_params:
            print(f"  ✗ Params mismatch!")
            print(f"    Expected: {expected_params}")
            print(f"    Got: {parsed.params}")
            return False
        
        # Validate
        validator.validate(parsed)
        
        print(f"  ✓ Attack type: {parsed.attack_type}")
        print(f"  ✓ Parameters:")
        for key, value in parsed.params.items():
            print(f"      {key}: {value}")
        print(f"  ✓ Validation passed")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("STRATEGY PARSER - AUTOTTL/SEQOVL/REPEATS TEST SUITE")
    print("="*60)
    
    results = []
    
    results.append(("AutoTTL parsing", test_autottl_parsing()))
    results.append(("AutoTTL/TTL mutual exclusivity", test_autottl_ttl_mutual_exclusivity()))
    results.append(("AutoTTL validation", test_autottl_validation()))
    results.append(("Split SeqOvl parsing", test_split_seqovl_parsing()))
    results.append(("Repeats parsing", test_repeats_parsing()))
    results.append(("Multidisorder recognition", test_multidisorder_recognition()))
    results.append(("X.com router strategy", test_x_com_strategy()))
    
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
