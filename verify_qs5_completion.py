#!/usr/bin/env python3
"""
Verification script for QS-5: Attack Specifications Completion

This script verifies that all 10 attack specifications have been created
and are properly formatted with all required sections.
"""

import os
import yaml
from pathlib import Path

def verify_attack_specs():
    """Verify all 10 attack specifications are complete."""
    
    specs_dir = Path("specs/attacks")
    
    # Top 10 attacks that should have specs
    required_attacks = [
        "fake",
        "split", 
        "disorder",
        "fakeddisorder",
        "multisplit",
        "multidisorder",
        "seqovl",
        "simple_fragment",
        "window_manipulation",
        "tcp_options_modification"
    ]
    
    print("=" * 80)
    print("QS-5: Attack Specifications Verification")
    print("=" * 80)
    print()
    
    # Check each required attack
    results = []
    for attack_name in required_attacks:
        spec_file = specs_dir / f"{attack_name}.yaml"
        
        if not spec_file.exists():
            results.append((attack_name, False, "File not found"))
            continue
        
        try:
            with open(spec_file, 'r') as f:
                spec = yaml.safe_load(f)
            
            # Verify required sections
            required_sections = [
                'name',
                'description',
                'category',
                'parameters',
                'expected_packets',
                'validation_rules',
                'test_variations',
                'error_cases',
                'notes'
            ]
            
            missing_sections = []
            for section in required_sections:
                if section not in spec:
                    missing_sections.append(section)
            
            if missing_sections:
                results.append((attack_name, False, f"Missing sections: {', '.join(missing_sections)}"))
            else:
                # Count details
                param_count = len(spec.get('parameters', []))
                test_var_count = len(spec.get('test_variations', {}))
                error_case_count = len(spec.get('error_cases', {}))
                
                # Count validation rules
                rule_count = 0
                for category in spec.get('validation_rules', {}).values():
                    if isinstance(category, list):
                        rule_count += len(category)
                
                results.append((
                    attack_name, 
                    True, 
                    f"{param_count} params, {test_var_count} tests, {error_case_count} errors, {rule_count} rules"
                ))
        
        except Exception as e:
            results.append((attack_name, False, f"Error: {str(e)}"))
    
    # Print results
    print(f"{'Attack':<25} {'Status':<10} {'Details'}")
    print("-" * 80)
    
    passed = 0
    failed = 0
    
    for attack_name, success, details in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{attack_name:<25} {status:<10} {details}")
        
        if success:
            passed += 1
        else:
            failed += 1
    
    print()
    print("=" * 80)
    print(f"Results: {passed}/{len(required_attacks)} specifications complete")
    print("=" * 80)
    print()
    
    if failed == 0:
        print("✅ SUCCESS: All 10 attack specifications are complete and valid!")
        print()
        print("Next steps:")
        print("  1. Run: python test_spec_validation.py")
        print("  2. Run: python test_all_attacks.py")
        print("  3. Run: python generate_final_integration_report.py")
        return True
    else:
        print(f"❌ FAILURE: {failed} specifications are incomplete or invalid")
        return False

if __name__ == "__main__":
    import sys
    success = verify_attack_specs()
    sys.exit(0 if success else 1)
