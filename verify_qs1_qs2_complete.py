"""
Verification script for QS-1 and QS-2 completion.

This script demonstrates that:
1. The strategy parser recognizes function-style syntax (QS-1)
2. Simple attacks can be parsed correctly (QS-2)
3. The parser is integrated with the system
4. All validation works correctly
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from core.strategy_parser_v2 import StrategyParserV2, ParameterValidator, parse_strategy
from core.strategy_parser_adapter import StrategyParserAdapter

def print_header(title):
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def print_section(title):
    print("\n" + "-"*70)
    print(f"  {title}")
    print("-"*70)

def verify_qs1():
    """Verify QS-1: Strategy parser recognizes function-style syntax."""
    print_header("QS-1 VERIFICATION: Function-Style Syntax Recognition")
    
    parser = StrategyParserV2()
    
    test_cases = [
        ("fake(ttl=1, fooling=['badsum'])", "Fake attack with TTL and fooling"),
        ("split(split_pos=1)", "Split attack with position"),
        ("fakeddisorder(split_pos=76, ttl=3)", "Fakeddisorder with multiple params"),
    ]
    
    all_passed = True
    
    for strategy, description in test_cases:
        print(f"\n{description}")
        print(f"  Input:  {strategy}")
        
        try:
            parsed = parser.parse(strategy)
            print(f"  Result: [PASS]")
            print(f"    - Attack Type: {parsed.attack_type}")
            print(f"    - Parameters:  {parsed.params}")
            print(f"    - Syntax Type: {parsed.syntax_type}")
        except Exception as e:
            print(f"  Result: [FAIL] {e}")
            all_passed = False
    
    return all_passed

def verify_qs2():
    """Verify QS-2: Parser works with simple attacks."""
    print_header("QS-2 VERIFICATION: Simple Attack Parsing")
    
    parser = StrategyParserV2()
    validator = ParameterValidator()
    
    test_cases = [
        {
            'strategy': 'fake(ttl=1)',
            'description': 'Simple fake attack',
            'expected_type': 'fake',
            'expected_params': {'ttl': 1}
        },
        {
            'strategy': 'split(split_pos=1)',
            'description': 'Simple split attack',
            'expected_type': 'split',
            'expected_params': {'split_pos': 1}
        },
        {
            'strategy': 'fakeddisorder(split_pos=76, ttl=3)',
            'description': 'Complex fakeddisorder attack',
            'expected_type': 'fakeddisorder',
            'expected_params': {'split_pos': 76, 'ttl': 3}
        }
    ]
    
    all_passed = True
    
    for test in test_cases:
        print(f"\n{test['description']}")
        print(f"  Input:  {test['strategy']}")
        
        try:
            # Parse
            parsed = parser.parse(test['strategy'])
            
            # Validate
            validator.validate(parsed)
            
            # Check expectations
            if parsed.attack_type != test['expected_type']:
                print(f"  Result: [FAIL] Wrong attack type")
                all_passed = False
                continue
            
            for key, value in test['expected_params'].items():
                if parsed.params.get(key) != value:
                    print(f"  Result: [FAIL] Wrong parameter: {key}")
                    all_passed = False
                    continue
            
            print(f"  Result: [PASS]")
            print(f"    - Attack Type: {parsed.attack_type}")
            print(f"    - Parameters:  {parsed.params}")
            print(f"    - Validation:  OK")
            
        except Exception as e:
            print(f"  Result: [FAIL] {e}")
            all_passed = False
    
    return all_passed

def verify_integration():
    """Verify integration with system."""
    print_header("INTEGRATION VERIFICATION: System Integration")
    
    adapter = StrategyParserAdapter()
    
    test_cases = [
        ("fake(ttl=1, fooling=['badsum'])", "Function-style syntax"),
        ("--dpi-desync=fake --dpi-desync-ttl=1", "Zapret-style syntax"),
    ]
    
    all_passed = True
    
    for strategy, description in test_cases:
        print(f"\n{description}")
        print(f"  Input:  {strategy}")
        
        try:
            engine_task = adapter.interpret_strategy(strategy)
            
            if engine_task:
                print(f"  Result: [PASS]")
                print(f"    - Type:   {engine_task['type']}")
                print(f"    - Params: {engine_task['params']}")
            else:
                print(f"  Result: [FAIL] Adapter returned None")
                all_passed = False
                
        except Exception as e:
            print(f"  Result: [FAIL] {e}")
            all_passed = False
    
    return all_passed

def verify_all_attacks():
    """Verify all attack types are recognized."""
    print_header("ATTACK TYPES VERIFICATION: All Registered Attacks")
    
    parser = StrategyParserV2()
    
    attacks = [
        ('fake', 'fake(ttl=1)'),
        ('split', 'split(split_pos=1)'),
        ('disorder', 'disorder(split_pos=2)'),
        ('disorder2', 'disorder2(split_pos=3, ttl=1)'),
        ('multisplit', 'multisplit(split_count=5)'),
        ('multidisorder', 'multidisorder(split_pos=4, ttl=2)'),
        ('fakeddisorder', 'fakeddisorder(split_pos=76, overlap_size=336, ttl=3)'),
        ('seqovl', 'seqovl(split_pos=5, overlap_size=100)'),
    ]
    
    all_passed = True
    
    for attack_name, strategy in attacks:
        print(f"\n{attack_name.upper()}")
        print(f"  Strategy: {strategy}")
        
        try:
            parsed = parser.parse(strategy)
            
            if parsed.attack_type == attack_name:
                print(f"  Result: [PASS] Recognized as '{attack_name}'")
            else:
                print(f"  Result: [FAIL] Recognized as '{parsed.attack_type}' instead of '{attack_name}'")
                all_passed = False
                
        except Exception as e:
            print(f"  Result: [FAIL] {e}")
            all_passed = False
    
    return all_passed

def main():
    """Run all verifications."""
    print("\n" + "="*70)
    print("  QS-1 & QS-2 COMPLETION VERIFICATION")
    print("  Attack Validation Suite - Strategy Parser")
    print("="*70)
    
    results = []
    
    # Run verifications
    results.append(("QS-1: Function-Style Syntax", verify_qs1()))
    results.append(("QS-2: Simple Attack Parsing", verify_qs2()))
    results.append(("Integration with System", verify_integration()))
    results.append(("All Attack Types", verify_all_attacks()))
    
    # Summary
    print_header("VERIFICATION SUMMARY")
    
    for name, passed in results:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {name}")
    
    all_passed = all(passed for _, passed in results)
    
    print("\n" + "="*70)
    if all_passed:
        print("  RESULT: ALL VERIFICATIONS PASSED")
        print("  STATUS: QS-1 and QS-2 are COMPLETE")
        print("="*70)
        print("\n  The strategy parser is working correctly and ready for use.")
        print("  The critical blocker has been resolved.")
        print("  Next task: QS-3 (Create simple packet validator)")
        return 0
    else:
        print("  RESULT: SOME VERIFICATIONS FAILED")
        print("="*70)
        return 1

if __name__ == '__main__':
    sys.exit(main())
