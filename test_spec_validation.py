"""
Test script for spec-based attack validation.

Demonstrates loading attack specs and validating attacks using YAML specifications.
"""

import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.attack_spec_loader import get_spec_loader
from core.packet_validator import PacketValidator


def test_spec_loader():
    """Test loading attack specifications."""
    print("=" * 80)
    print("Testing Attack Specification Loader")
    print("=" * 80)
    
    loader = get_spec_loader()
    
    # Test loading individual specs
    attacks = ['fake', 'split', 'disorder', 'fakeddisorder', 'multisplit', 'multidisorder', 'seqovl']
    
    for attack_name in attacks:
        print(f"\n--- Loading spec for: {attack_name} ---")
        spec = loader.load_spec(attack_name)
        
        if spec:
            print(f"[OK] Loaded: {spec.name}")
            print(f"  Description: {spec.description}")
            print(f"  Category: {spec.category}")
            print(f"  Aliases: {', '.join(spec.aliases)}")
            print(f"  Parameters: {len(spec.parameters)}")
            print(f"  Validation rules: {sum(len(rules) for rules in spec.validation_rules.values())}")
            print(f"  Test variations: {len(spec.test_variations)}")
            print(f"  Error cases: {len(spec.error_cases)}")
        else:
            print(f"[FAIL] Failed to load spec for: {attack_name}")
    
    # Test loading all specs
    print(f"\n--- Loading all specs ---")
    all_specs = loader.load_all_specs()
    print(f"[OK] Loaded {len(all_specs)} attack specifications")
    
    return loader


def test_parameter_validation():
    """Test parameter validation against specs."""
    print("\n" + "=" * 80)
    print("Testing Parameter Validation")
    print("=" * 80)
    
    loader = get_spec_loader()
    
    # Test valid parameters
    print("\n--- Testing valid parameters ---")
    valid_params = {
        'fake': {'ttl': 1, 'fooling': ['badsum']},
        'split': {'split_pos': 3},
        'fakeddisorder': {'split_pos': 3, 'ttl': 3, 'fooling': ['badsum']},
    }
    
    for attack_name, params in valid_params.items():
        errors = loader.validate_parameters(attack_name, params)
        if errors:
            print(f"[FAIL] {attack_name}: {errors}")
        else:
            print(f"[OK] {attack_name}: Valid parameters")
    
    # Test invalid parameters
    print("\n--- Testing invalid parameters ---")
    invalid_params = {
        'fake': {'ttl': 0},  # TTL too low
        'split': {},  # Missing required split_pos
        'fakeddisorder': {'split_pos': 3, 'ttl': 300},  # TTL too high
    }
    
    for attack_name, params in invalid_params.items():
        errors = loader.validate_parameters(attack_name, params)
        if errors:
            print(f"[OK] {attack_name}: Correctly detected errors:")
            for error in errors:
                print(f"    - {error}")
        else:
            print(f"[FAIL] {attack_name}: Should have detected errors")


def test_validation_rules():
    """Test validation rules from specs."""
    print("\n" + "=" * 80)
    print("Testing Validation Rules")
    print("=" * 80)
    
    loader = get_spec_loader()
    
    attacks = ['fake', 'split', 'fakeddisorder']
    
    for attack_name in attacks:
        print(f"\n--- Validation rules for: {attack_name} ---")
        
        # Get all rules
        all_rules = loader.get_validation_rules(attack_name)
        print(f"Total rules: {len(all_rules)}")
        
        # Get rules by category
        spec = loader.load_spec(attack_name)
        if spec:
            for category, rules in spec.validation_rules.items():
                print(f"\n  {category}:")
                for rule in rules:
                    severity_icon = "[!]" if rule.severity == "critical" else "[*]" if rule.severity == "warning" else "[i]"
                    print(f"    {severity_icon} {rule.description}")
                    print(f"       Rule: {rule.rule}")


def test_test_variations():
    """Test test variations from specs."""
    print("\n" + "=" * 80)
    print("Testing Test Variations")
    print("=" * 80)
    
    loader = get_spec_loader()
    
    attacks = ['fake', 'split', 'fakeddisorder']
    
    for attack_name in attacks:
        print(f"\n--- Test variations for: {attack_name} ---")
        
        variations = loader.get_test_variations(attack_name)
        print(f"Total variations: {len(variations)}")
        
        for var_name, variation in variations.items():
            print(f"\n  {var_name}:")
            print(f"    Description: {variation.description}")
            print(f"    Parameters: {json.dumps(variation.params, indent=6)}")


def test_error_cases():
    """Test error cases from specs."""
    print("\n" + "=" * 80)
    print("Testing Error Cases")
    print("=" * 80)
    
    loader = get_spec_loader()
    
    attacks = ['fake', 'split', 'fakeddisorder']
    
    for attack_name in attacks:
        print(f"\n--- Error cases for: {attack_name} ---")
        
        error_cases = loader.get_error_cases(attack_name)
        print(f"Total error cases: {len(error_cases)}")
        
        for case_name, error_case in error_cases.items():
            print(f"\n  {case_name}:")
            print(f"    Description: {error_case.description}")
            print(f"    Parameters: {json.dumps(error_case.params, indent=6)}")
            print(f"    Expected error: {error_case.expected_error}")


def test_spec_integration():
    """Test integration with PacketValidator."""
    print("\n" + "=" * 80)
    print("Testing Spec Integration with PacketValidator")
    print("=" * 80)
    
    validator = PacketValidator(debug_mode=True)
    
    if not validator.spec_loader:
        print("[FAIL] Spec loader not available in PacketValidator")
        return
    
    print("[OK] Spec loader integrated with PacketValidator")
    
    # Test parameter validation through validator
    print("\n--- Testing parameter validation through validator ---")
    
    test_cases = [
        ('fake', {'ttl': 1, 'fooling': ['badsum']}, True),
        ('fake', {'ttl': 0}, False),
        ('split', {'split_pos': 3}, True),
        ('split', {}, False),
    ]
    
    for attack_name, params, should_pass in test_cases:
        errors = validator.spec_loader.validate_parameters(attack_name, params)
        passed = len(errors) == 0
        
        if passed == should_pass:
            status = "[OK]"
        else:
            status = "[FAIL]"
        
        print(f"{status} {attack_name} with {params}: {'Valid' if passed else 'Invalid'}")
        if errors:
            for error in errors:
                print(f"    - {error}")


def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("ATTACK SPECIFICATION VALIDATION TEST SUITE")
    print("=" * 80)
    
    try:
        # Test spec loader
        loader = test_spec_loader()
        
        # Test parameter validation
        test_parameter_validation()
        
        # Test validation rules
        test_validation_rules()
        
        # Test test variations
        test_test_variations()
        
        # Test error cases
        test_error_cases()
        
        # Test integration
        test_spec_integration()
        
        print("\n" + "=" * 80)
        print("ALL TESTS COMPLETED")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n[FAIL] Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
