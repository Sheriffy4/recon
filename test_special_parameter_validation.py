#!/usr/bin/env python3
"""
Test script for special parameter validation in UnifiedStrategyLoader.

This script tests the enhanced validation for special parameters like
'cipher', 'sni', 'midsld' and other parameter validation improvements.
"""

import sys
import logging
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from core.unified_strategy_loader import UnifiedStrategyLoader, StrategyValidationError

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def test_special_position_validation():
    """Test validation of special position values."""
    print("\n=== Testing Special Position Validation ===")
    
    loader = UnifiedStrategyLoader(debug=True)
    
    # Test valid special values
    test_cases = [
        # Valid special values
        {"type": "fakeddisorder", "params": {"split_pos": "cipher"}},
        {"type": "seqovl", "params": {"split_pos": "sni", "overlap_size": 10}},
        {"type": "multisplit", "params": {"positions": ["midsld", 5, "cipher"]}},
        
        # Valid integer positions
        {"type": "disorder", "params": {"split_pos": 10}},
        {"type": "multidisorder", "params": {"positions": [1, 5, 10]}},
        
        # Mixed valid positions
        {"type": "multisplit", "params": {"positions": [1, "cipher", 10, "sni"]}},
    ]
    
    for i, test_case in enumerate(test_cases):
        try:
            strategy = loader.load_strategy(test_case)
            print(f"✅ Test {i+1}: Valid strategy loaded - {test_case['type']} with params {test_case['params']}")
        except Exception as e:
            print(f"❌ Test {i+1}: Unexpected error - {e}")
    
    # Test invalid special values
    invalid_cases = [
        # Invalid special values
        {"type": "fakeddisorder", "params": {"split_pos": "invalid_special"}},
        {"type": "seqovl", "params": {"split_pos": "unknown", "overlap_size": 10}},
        {"type": "multisplit", "params": {"positions": ["cipher", "invalid", 5]}},
        
        # Invalid position types
        {"type": "disorder", "params": {"split_pos": []}},  # Empty list
        {"type": "multidisorder", "params": {"positions": "not_a_list"}},
        
        # Invalid position values
        {"type": "split", "params": {"split_pos": 0}},  # Position must be >= 1
        {"type": "multisplit", "params": {"positions": [-1, 5]}},  # Negative position
    ]
    
    for i, test_case in enumerate(invalid_cases):
        try:
            strategy = loader.load_strategy(test_case)
            print(f"❌ Test {i+1}: Should have failed but didn't - {test_case}")
        except StrategyValidationError as e:
            print(f"✅ Test {i+1}: Correctly caught validation error - {e}")
        except Exception as e:
            print(f"⚠️  Test {i+1}: Unexpected error type - {e}")


def test_parameter_combinations():
    """Test validation of parameter combinations."""
    print("\n=== Testing Parameter Combinations ===")
    
    loader = UnifiedStrategyLoader(debug=True)
    
    # Test seqovl requirements
    test_cases = [
        # Valid seqovl
        {"type": "seqovl", "params": {"split_pos": 5, "overlap_size": 3}},
        
        # Invalid seqovl - missing overlap_size
        {"type": "seqovl", "params": {"split_pos": 5}},
        
        # Invalid seqovl - overlap_size >= split_pos
        {"type": "seqovl", "params": {"split_pos": 5, "overlap_size": 10}},
        
        # Valid multisplit with positions
        {"type": "multisplit", "params": {"positions": [1, 5, 10]}},
        
        # Invalid multisplit - no positions or split_pos
        {"type": "multisplit", "params": {"ttl": 3}},
        
        # Invalid TTL combination
        {"type": "fake", "params": {"ttl": 3, "autottl": 2}},
    ]
    
    expected_results = [True, False, False, True, False, False]
    
    for i, (test_case, should_pass) in enumerate(zip(test_cases, expected_results)):
        try:
            strategy = loader.load_strategy(test_case)
            if should_pass:
                print(f"✅ Test {i+1}: Valid combination passed - {test_case['type']}")
            else:
                print(f"❌ Test {i+1}: Should have failed but didn't - {test_case}")
        except StrategyValidationError as e:
            if not should_pass:
                print(f"✅ Test {i+1}: Correctly caught validation error - {e}")
            else:
                print(f"❌ Test {i+1}: Unexpected validation error - {e}")
        except Exception as e:
            print(f"⚠️  Test {i+1}: Unexpected error - {e}")


def test_fooling_methods_validation():
    """Test validation of fooling methods."""
    print("\n=== Testing Fooling Methods Validation ===")
    
    loader = UnifiedStrategyLoader(debug=True)
    
    test_cases = [
        # Valid fooling methods
        {"type": "fakeddisorder", "params": {"split_pos": 5, "fooling": ["badsum"]}},
        {"type": "fake", "params": {"ttl": 3, "fooling": ["badsum", "badseq"]}},
        
        # Invalid fooling methods
        {"type": "fakeddisorder", "params": {"split_pos": 5, "fooling": ["invalid_method"]}},
        {"type": "fake", "params": {"ttl": 3, "fooling": ["badsum", "unknown"]}},
        
        # Invalid fooling parameter type
        {"type": "fakeddisorder", "params": {"split_pos": 5, "fooling": "not_a_list"}},
    ]
    
    expected_results = [True, True, False, False, False]
    
    for i, (test_case, should_pass) in enumerate(zip(test_cases, expected_results)):
        try:
            strategy = loader.load_strategy(test_case)
            if should_pass:
                print(f"✅ Test {i+1}: Valid fooling methods passed")
            else:
                print(f"❌ Test {i+1}: Should have failed but didn't - {test_case}")
        except StrategyValidationError as e:
            if not should_pass:
                print(f"✅ Test {i+1}: Correctly caught validation error - {e}")
            else:
                print(f"❌ Test {i+1}: Unexpected validation error - {e}")
        except Exception as e:
            print(f"⚠️  Test {i+1}: Unexpected error - {e}")


def test_ttl_validation():
    """Test TTL parameter validation."""
    print("\n=== Testing TTL Validation ===")
    
    loader = UnifiedStrategyLoader(debug=True)
    
    test_cases = [
        # Valid TTL values
        {"type": "fake", "params": {"ttl": 1}},
        {"type": "fake", "params": {"ttl": 255}},
        {"type": "fakeddisorder", "params": {"split_pos": 5, "fake_ttl": 3}},
        
        # Invalid TTL values
        {"type": "fake", "params": {"ttl": 0}},  # Too low
        {"type": "fake", "params": {"ttl": 256}},  # Too high
        {"type": "fake", "params": {"ttl": "invalid"}},  # Not a number
        
        # Valid autottl
        {"type": "fake", "params": {"autottl": 2}},
        {"type": "fake", "params": {"autottl": -5}},
        
        # Invalid autottl
        {"type": "fake", "params": {"autottl": 15}},  # Too high
        {"type": "fake", "params": {"autottl": -15}},  # Too low
    ]
    
    expected_results = [True, True, True, False, False, False, True, True, False, False]
    
    for i, (test_case, should_pass) in enumerate(zip(test_cases, expected_results)):
        try:
            strategy = loader.load_strategy(test_case)
            if should_pass:
                print(f"✅ Test {i+1}: Valid TTL passed")
            else:
                print(f"❌ Test {i+1}: Should have failed but didn't - {test_case}")
        except StrategyValidationError as e:
            if not should_pass:
                print(f"✅ Test {i+1}: Correctly caught validation error - {e}")
            else:
                print(f"❌ Test {i+1}: Unexpected validation error - {e}")
        except Exception as e:
            print(f"⚠️  Test {i+1}: Unexpected error - {e}")


def test_normalization():
    """Test parameter normalization."""
    print("\n=== Testing Parameter Normalization ===")
    
    loader = UnifiedStrategyLoader(debug=True)
    
    # Test special value normalization
    test_case = {"type": "fakeddisorder", "params": {"split_pos": "CIPHER"}}  # Uppercase
    try:
        strategy = loader.load_strategy(test_case)
        if strategy.params["split_pos"] == "cipher":  # Should be normalized to lowercase
            print("✅ Special value normalization works (CIPHER -> cipher)")
        else:
            print(f"❌ Special value not normalized: {strategy.params['split_pos']}")
    except Exception as e:
        print(f"❌ Normalization test failed: {e}")
    
    # Test boolean normalization
    test_case = {"type": "disorder", "params": {"split_pos": 5, "ack_first": "true"}}
    try:
        strategy = loader.load_strategy(test_case)
        if strategy.params["ack_first"] is True:
            print("✅ Boolean normalization works ('true' -> True)")
        else:
            print(f"❌ Boolean not normalized: {strategy.params['ack_first']}")
    except Exception as e:
        print(f"❌ Boolean normalization test failed: {e}")
    
    # Test fooling methods normalization
    test_case = {"type": "fake", "params": {"ttl": 3, "fooling": "badsum,badseq"}}
    try:
        strategy = loader.load_strategy(test_case)
        if isinstance(strategy.params["fooling"], list) and len(strategy.params["fooling"]) == 2:
            print("✅ Fooling methods normalization works (string -> list)")
        else:
            print(f"❌ Fooling methods not normalized: {strategy.params['fooling']}")
    except Exception as e:
        print(f"❌ Fooling methods normalization test failed: {e}")


def main():
    """Run all tests."""
    print("Testing Special Parameter Validation in UnifiedStrategyLoader")
    print("=" * 60)
    
    try:
        test_special_position_validation()
        test_parameter_combinations()
        test_fooling_methods_validation()
        test_ttl_validation()
        test_normalization()
        
        print("\n" + "=" * 60)
        print("✅ All tests completed!")
        
    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())