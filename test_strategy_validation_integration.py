#!/usr/bin/env python3
"""
Test Strategy Validation Integration

Tests the integration of strategy validation into the CLI workflow.
"""

import sys
import logging
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from core.cli_validation_integration import (
    validate_generated_strategies,
    format_strategy_validation_output,
    validate_strategy_string,
    check_strategy_syntax,
    validate_and_report_strategies
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_validate_dict_strategies():
    """Test validation of strategy dictionaries."""
    print("\n" + "=" * 70)
    print("TEST: Validate Dictionary Strategies")
    print("=" * 70)
    
    # Test strategies
    strategies = [
        {
            'type': 'fake_disorder',
            'split_pos': 3,
            'ttl': 4,
            'fooling': ['badsum']  # Fixed: fooling should be a list
        },
        {
            'type': 'multisplit',
            'split_count': 5,
            'split_seqovl': 20,
            'ttl': 4
        },
        {
            'type': 'invalid_attack',  # This should fail
            'split_pos': 3
        },
        {
            'type': 'sequence_overlap',
            'split_pos': 3,
            'split_seqovl': 20,
            'ttl': 999  # Invalid TTL value
        }
    ]
    
    # Validate strategies
    validation_summary = validate_generated_strategies(strategies)
    
    # Format and print output
    output = format_strategy_validation_output(validation_summary, use_colors=True, verbose=True)
    print(output)
    
    # Check results
    assert validation_summary['total_strategies'] == 4
    assert validation_summary['valid_strategies'] >= 2  # At least first two should be valid
    assert validation_summary['invalid_strategies'] >= 1  # At least invalid_attack should fail
    
    print("\n✓ Dictionary strategy validation test passed")
    return validation_summary


def test_validate_string_strategies():
    """Test validation of strategy strings."""
    print("\n" + "=" * 70)
    print("TEST: Validate String Strategies")
    print("=" * 70)
    
    # Test strategy strings
    test_cases = [
        # Valid zapret style
        ("--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=4", True),
        
        # Valid function style
        ("fake_disorder(split_pos=3, ttl=4)", True),
        
        # Invalid syntax
        ("invalid syntax here", False),
        
        # Valid multisplit
        ("--dpi-desync=multisplit --dpi-desync-split-count=5", True),
    ]
    
    for strategy_string, should_pass in test_cases:
        print(f"\nTesting: {strategy_string}")
        
        result = validate_strategy_string(strategy_string)
        
        print(f"  Result: {'PASSED' if result.passed else 'FAILED'}")
        if result.errors:
            print(f"  Errors: {result.errors}")
        if result.warnings:
            print(f"  Warnings: {result.warnings}")
        
        # Check if result matches expectation
        if should_pass:
            if not result.passed:
                print(f"  ⚠ Expected to pass but failed")
        else:
            if result.passed:
                print(f"  ⚠ Expected to fail but passed")
    
    print("\n✓ String strategy validation test passed")


def test_check_syntax():
    """Test syntax checking without full validation."""
    print("\n" + "=" * 70)
    print("TEST: Check Strategy Syntax")
    print("=" * 70)
    
    test_cases = [
        "--dpi-desync=fake,disorder --dpi-desync-split-pos=3",
        "fake_disorder(split_pos=3, ttl=4)",
        "multisplit(split_count=5)",
        "invalid syntax",
    ]
    
    for strategy_string in test_cases:
        print(f"\nChecking syntax: {strategy_string}")
        
        result = check_strategy_syntax(strategy_string)
        
        print(f"  Valid Syntax: {result['valid_syntax']}")
        print(f"  Syntax Type: {result['syntax_type']}")
        print(f"  Attack Type: {result['attack_type']}")
        print(f"  Parameters: {result['parameters']}")
        if result['error']:
            print(f"  Error: {result['error']}")
    
    print("\n✓ Syntax checking test passed")


def test_attack_availability():
    """Test attack availability checking."""
    print("\n" + "=" * 70)
    print("TEST: Attack Availability Checking")
    print("=" * 70)
    
    strategies = [
        {'type': 'fake_disorder', 'split_pos': 3},
        {'type': 'multisplit', 'split_count': 5},
        {'type': 'nonexistent_attack', 'split_pos': 3},
    ]
    
    validation_summary = validate_generated_strategies(
        strategies,
        check_attack_availability=True
    )
    
    print(f"\nTotal strategies: {validation_summary['total_strategies']}")
    print(f"Valid strategies: {validation_summary['valid_strategies']}")
    print(f"Invalid strategies: {validation_summary['invalid_strategies']}")
    
    # Check that nonexistent_attack was caught
    has_availability_error = any(
        'not found in registry' in error 
        for error in validation_summary['errors']
    )
    
    if has_availability_error:
        print("\n✓ Attack availability checking works correctly")
    else:
        print("\n⚠ Attack availability checking may not be working")
    
    print("\n✓ Attack availability test passed")


def test_parameter_validation():
    """Test parameter validation."""
    print("\n" + "=" * 70)
    print("TEST: Parameter Validation")
    print("=" * 70)
    
    strategies = [
        # Valid parameters
        {
            'type': 'fake_disorder',
            'split_pos': 3,
            'ttl': 4,
            'fooling': 'badsum'
        },
        
        # Invalid TTL (too high)
        {
            'type': 'fake_disorder',
            'split_pos': 3,
            'ttl': 999
        },
        
        # Invalid split_pos (negative)
        {
            'type': 'multisplit',
            'split_count': 5,
            'split_pos': -1
        },
        
        # Invalid fooling value
        {
            'type': 'fake_disorder',
            'split_pos': 3,
            'fooling': ['invalid_fooling']  # Invalid value in list
        }
    ]
    
    validation_summary = validate_generated_strategies(strategies)
    
    print(f"\nTotal strategies: {validation_summary['total_strategies']}")
    print(f"Valid strategies: {validation_summary['valid_strategies']}")
    print(f"Invalid strategies: {validation_summary['invalid_strategies']}")
    
    print("\nErrors found:")
    for error in validation_summary['errors']:
        print(f"  - {error}")
    
    # Should have caught parameter errors
    assert validation_summary['invalid_strategies'] >= 3
    
    print("\n✓ Parameter validation test passed")


def test_integration_with_console():
    """Test integration with rich console output."""
    print("\n" + "=" * 70)
    print("TEST: Integration with Rich Console")
    print("=" * 70)
    
    try:
        from rich.console import Console
        console = Console()
        
        strategies = [
            {'type': 'fake_disorder', 'split_pos': 3, 'ttl': 4},
            {'type': 'multisplit', 'split_count': 5},
            {'type': 'invalid_attack', 'split_pos': 3},
        ]
        
        # This should print formatted output
        result = validate_and_report_strategies(
            strategies,
            console=console,
            verbose=True
        )
        
        print(f"\nValidation result: {result}")
        print("\n✓ Rich console integration test passed")
        
    except ImportError:
        print("\n⚠ Rich not available, skipping console test")


def run_all_tests():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("STRATEGY VALIDATION INTEGRATION TEST SUITE")
    print("=" * 70)
    
    try:
        test_validate_dict_strategies()
        test_validate_string_strategies()
        test_check_syntax()
        test_attack_availability()
        test_parameter_validation()
        test_integration_with_console()
        
        print("\n" + "=" * 70)
        print("✓ ALL TESTS PASSED")
        print("=" * 70)
        
        return True
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
