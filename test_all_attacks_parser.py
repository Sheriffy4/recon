"""Test StrategyParserV2 with all registered attacks."""

import sys
import logging
from pathlib import Path

# Setup path
sys.path.insert(0, str(Path(__file__).parent))

from core.strategy_parser_v2 import StrategyParserV2, ParameterValidator
from core.strategy_parser_adapter import StrategyParserAdapter
from core.bypass.attacks.registry import AttackRegistry

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')


def test_all_registered_attacks():
    """Test parser with all attacks from the registry."""
    print("\n" + "="*60)
    print("TEST: All Registered Attacks")
    print("="*60)
    
    # Get all registered attacks
    registry_attacks = AttackRegistry.list_attacks()
    print(f"\nFound {len(registry_attacks)} registered attacks:")
    for attack in sorted(registry_attacks):
        print(f"  - {attack}")
    
    parser = StrategyParserV2()
    adapter = StrategyParserAdapter()
    
    # Define test cases for each attack type
    test_cases = {
        'fake': [
            "fake(ttl=1)",
            "fake(ttl=1, fooling=['badsum'])",
            "fake(ttl=1, fooling=['badsum', 'md5sig'])",
            "fake(ttl=1, fake_sni='example.com')",
            "--dpi-desync=fake --dpi-desync-ttl=1",
            "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
        ],
        'split': [
            "split(split_pos=1)",
            "split(split_pos=2)",
            "split(split_pos=76)",
            "--dpi-desync=split --dpi-desync-split-pos=1",
            "--dpi-desync=split --dpi-desync-split-pos=2",
        ],
        'disorder': [
            "disorder(split_pos=1)",
            "disorder(split_pos=2)",
            "--dpi-desync=disorder --dpi-desync-split-pos=1",
        ],
        'disorder2': [
            "disorder2(split_pos=1, ttl=1)",
            "disorder2(split_pos=2, ttl=2)",
        ],
        'multisplit': [
            "multisplit(split_count=5)",
            "multisplit(split_count=5, ttl=64)",
            "multisplit(split_count=3, overlap_size=100)",
            "--dpi-desync=multisplit --dpi-desync-split-count=5",
        ],
        'multidisorder': [
            "multidisorder(split_pos=1, ttl=1)",
            "multidisorder(split_pos=2, ttl=2)",
        ],
        'fakeddisorder': [
            "fakeddisorder(split_pos=76, overlap_size=336, ttl=3)",
            "fakeddisorder(split_pos=76, ttl=3)",
            "fakeddisorder(split_pos=3, overlap_size=336, ttl=3, fooling=['badsum'])",
            "--dpi-desync=fake,disorder --dpi-desync-split-pos=76 --dpi-desync-ttl=3",
            "--dpi-desync=fake,disorder --dpi-desync-split-pos=76 --dpi-desync-ttl=3 --dpi-desync-split-seqovl=336",
        ],
        'seqovl': [
            "seqovl(split_pos=1, overlap_size=100)",
            "seqovl(split_pos=2, overlap_size=200)",
        ],
    }
    
    passed = 0
    failed = 0
    skipped = 0
    
    for attack_name in sorted(registry_attacks):
        print(f"\n{'='*60}")
        print(f"Testing attack: {attack_name}")
        print('='*60)
        
        if attack_name not in test_cases:
            print(f"  ⚠ No test cases defined for '{attack_name}' - skipping")
            skipped += 1
            continue
        
        attack_passed = 0
        attack_failed = 0
        
        for test_str in test_cases[attack_name]:
            print(f"\n  Testing: {test_str}")
            
            try:
                # Test parsing
                parsed = parser.parse(test_str)
                
                if parsed.attack_type != attack_name:
                    print(f"    ✗ Wrong attack type: expected '{attack_name}', got '{parsed.attack_type}'")
                    attack_failed += 1
                    continue
                
                print(f"    ✓ Parsed: {parsed.attack_type}")
                print(f"      Params: {parsed.params}")
                print(f"      Syntax: {parsed.syntax_type}")
                
                # Test adapter conversion
                engine_task = adapter.interpret_strategy(test_str)
                if engine_task:
                    print(f"    ✓ Adapter: {engine_task['type']}")
                    print(f"      Engine params: {engine_task['params']}")
                else:
                    print(f"    ✗ Adapter failed to convert")
                    attack_failed += 1
                    continue
                
                attack_passed += 1
                
            except Exception as e:
                print(f"    ✗ Error: {e}")
                attack_failed += 1
        
        print(f"\n  {attack_name}: {attack_passed} passed, {attack_failed} failed")
        
        if attack_failed == 0:
            passed += 1
        else:
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print('='*60)
    print(f"Attacks tested: {passed + failed}")
    print(f"  ✓ Passed: {passed}")
    print(f"  ✗ Failed: {failed}")
    print(f"  ⚠ Skipped: {skipped}")
    
    return failed == 0


def test_attack_variations():
    """Test various parameter combinations for each attack."""
    print("\n" + "="*60)
    print("TEST: Attack Parameter Variations")
    print("="*60)
    
    parser = StrategyParserV2()
    validator = ParameterValidator()
    
    # Test parameter variations
    variations = [
        # TTL variations
        ("fake(ttl=1)", True),
        ("fake(ttl=64)", True),
        ("fake(ttl=255)", True),
        ("fake(ttl=0)", False),  # Should fail validation
        ("fake(ttl=256)", False),  # Should fail validation
        
        # Split position variations
        ("split(split_pos=1)", True),
        ("split(split_pos=76)", True),
        ("split(split_pos=0)", True),
        ("split(split_pos=-1)", True),  # Negative positions allowed
        
        # Fooling variations
        ("fake(ttl=1, fooling=['badsum'])", True),
        ("fake(ttl=1, fooling=['badsum', 'md5sig'])", True),
        ("fake(ttl=1, fooling=['badsum', 'md5sig', 'badseq'])", True),
        
        # Complex combinations
        ("fakeddisorder(split_pos=76, overlap_size=336, ttl=3, fooling=['badsum', 'badseq'])", True),
        ("multisplit(split_count=5, ttl=64, overlap_size=100)", True),
    ]
    
    passed = 0
    failed = 0
    
    for test_str, should_pass in variations:
        print(f"\nTesting: {test_str}")
        print(f"  Expected: {'PASS' if should_pass else 'FAIL'}")
        
        try:
            parsed = parser.parse(test_str)
            validator.validate(parsed)
            
            if should_pass:
                print(f"  ✓ Correctly passed validation")
                passed += 1
            else:
                print(f"  ✗ Should have failed validation but passed")
                failed += 1
                
        except ValueError as e:
            if not should_pass:
                print(f"  ✓ Correctly failed validation: {str(e)[:60]}...")
                passed += 1
            else:
                print(f"  ✗ Should have passed but failed: {e}")
                failed += 1
                
        except Exception as e:
            print(f"  ✗ Unexpected error: {e}")
            failed += 1
    
    print(f"\nParameter variations: {passed} passed, {failed} failed")
    return failed == 0


def test_edge_cases():
    """Test edge cases and error handling."""
    print("\n" + "="*60)
    print("TEST: Edge Cases")
    print("="*60)
    
    parser = StrategyParserV2()
    
    edge_cases = [
        # Empty/invalid inputs
        ("", False, "Empty string"),
        ("   ", False, "Whitespace only"),
        ("invalid", False, "No parentheses"),
        ("fake(", False, "Unclosed parentheses"),
        ("fake)", False, "No opening parentheses"),
        
        # Missing parameters
        ("split()", False, "Missing required split_pos"),
        ("fakeddisorder()", False, "Missing required split_pos"),
        
        # Invalid parameter syntax
        ("fake(ttl)", False, "Parameter without value"),
        ("fake(=1)", False, "Value without parameter name"),
        ("fake(ttl=)", False, "Parameter without value"),
        
        # Valid edge cases
        ("fake(ttl=1)", True, "Minimal valid fake"),
        ("split(split_pos=0)", True, "Zero split position"),
        ("fake(ttl=1, fooling=[])", True, "Empty list"),
    ]
    
    passed = 0
    failed = 0
    
    for test_str, should_succeed, description in edge_cases:
        print(f"\nTesting: {description}")
        print(f"  Input: '{test_str}'")
        print(f"  Expected: {'SUCCESS' if should_succeed else 'FAILURE'}")
        
        try:
            parsed = parser.parse(test_str)
            
            if should_succeed:
                print(f"  ✓ Correctly parsed: {parsed.attack_type}")
                passed += 1
            else:
                print(f"  ✗ Should have failed but succeeded")
                failed += 1
                
        except Exception as e:
            if not should_succeed:
                print(f"  ✓ Correctly failed: {str(e)[:60]}...")
                passed += 1
            else:
                print(f"  ✗ Should have succeeded but failed: {e}")
                failed += 1
    
    print(f"\nEdge cases: {passed} passed, {failed} failed")
    return failed == 0


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("COMPREHENSIVE ATTACK PARSER TESTS")
    print("="*60)
    
    results = []
    
    results.append(("All registered attacks", test_all_registered_attacks()))
    results.append(("Parameter variations", test_attack_variations()))
    results.append(("Edge cases", test_edge_cases()))
    
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
