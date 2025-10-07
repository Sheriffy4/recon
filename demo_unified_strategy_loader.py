#!/usr/bin/env python3
"""
Demo script for UnifiedStrategyLoader

This script demonstrates how to use the UnifiedStrategyLoader to:
1. Load strategies from various formats
2. Create forced overrides for testing mode compatibility
3. Validate strategy parameters
4. Load multiple strategies from files
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.unified_strategy_loader import UnifiedStrategyLoader, NormalizedStrategy
import json
import tempfile

def demo_basic_loading():
    """Demonstrate basic strategy loading from different formats."""
    print("=== Basic Strategy Loading Demo ===")
    
    loader = UnifiedStrategyLoader(debug=True)
    
    # 1. Load Zapret-style strategy
    print("\n1. Loading Zapret-style strategy:")
    zapret_strategy = "--dpi-desync=fakeddisorder --dpi-desync-ttl=3 --dpi-desync-fooling=badseq"
    result = loader.load_strategy(zapret_strategy)
    print(f"   Type: {result.type}")
    print(f"   Params: {result.params}")
    print(f"   Forced: {result.forced}")
    print(f"   No fallbacks: {result.no_fallbacks}")
    
    # 2. Load function-style strategy
    print("\n2. Loading function-style strategy:")
    function_strategy = "multisplit(split_pos=2, ttl=4, fooling='badsum')"
    result = loader.load_strategy(function_strategy)
    print(f"   Type: {result.type}")
    print(f"   Params: {result.params}")
    print(f"   Forced: {result.forced}")
    print(f"   No fallbacks: {result.no_fallbacks}")
    
    # 3. Load dict strategy
    print("\n3. Loading dict strategy:")
    dict_strategy = {
        'type': 'multidisorder',
        'params': {'autottl': 2, 'repeats': 3}
    }
    result = loader.load_strategy(dict_strategy)
    print(f"   Type: {result.type}")
    print(f"   Params: {result.params}")
    print(f"   Forced: {result.forced}")
    print(f"   No fallbacks: {result.no_fallbacks}")

def demo_forced_override():
    """Demonstrate forced override creation."""
    print("\n=== Forced Override Demo ===")
    
    loader = UnifiedStrategyLoader()
    
    # Create a strategy
    strategy = NormalizedStrategy(
        type="fakeddisorder",
        params={'ttl': 3, 'fooling': 'badseq', 'split_pos': 2}
    )
    
    # Create forced override
    override = loader.create_forced_override(strategy)
    print(f"Original strategy: {strategy.to_dict()}")
    print(f"Forced override: {override}")
    
    # Verify critical parameters
    assert override['no_fallbacks'] is True, "CRITICAL: no_fallbacks must be True"
    assert override['forced'] is True, "CRITICAL: forced must be True"
    assert override['override_mode'] is True, "Override mode must be set"
    print("✅ All critical forced override parameters verified!")

def demo_validation():
    """Demonstrate strategy validation."""
    print("\n=== Strategy Validation Demo ===")
    
    loader = UnifiedStrategyLoader()
    
    # Valid strategy
    print("\n1. Validating valid strategy:")
    valid_strategy = NormalizedStrategy(
        type="fakeddisorder",
        params={'ttl': 3, 'fooling': 'badseq'},
        no_fallbacks=True,
        forced=True
    )
    
    try:
        result = loader.validate_strategy(valid_strategy)
        print(f"   ✅ Validation passed: {result}")
    except Exception as e:
        print(f"   ❌ Validation failed: {e}")
    
    # Invalid strategy - bad TTL
    print("\n2. Validating invalid strategy (bad TTL):")
    invalid_strategy = NormalizedStrategy(
        type="fake",
        params={'ttl': 300},  # Invalid TTL > 255
        no_fallbacks=True,
        forced=True
    )
    
    try:
        result = loader.validate_strategy(invalid_strategy)
        print(f"   ❌ Validation should have failed but passed: {result}")
    except Exception as e:
        print(f"   ✅ Validation correctly failed: {e}")

def demo_file_loading():
    """Demonstrate loading strategies from files."""
    print("\n=== File Loading Demo ===")
    
    loader = UnifiedStrategyLoader()
    
    # Create sample strategies file
    strategies_data = {
        "youtube.com": "--dpi-desync=fakeddisorder --dpi-desync-ttl=3 --dpi-desync-fooling=badseq",
        "x.com": "multisplit(split_pos=2, ttl=4)",
        "rutracker.org": {
            "type": "multidisorder",
            "params": {"autottl": 2, "repeats": 3}
        },
        "instagram.com": "--dpi-desync=disorder --dpi-desync-autottl=1"
    }
    
    # Write to temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(strategies_data, f, indent=2)
        temp_path = f.name
    
    try:
        # Load strategies from file
        strategies = loader.load_strategies_from_file(temp_path)
        
        print(f"Loaded {len(strategies)} strategies from file:")
        for domain, strategy in strategies.items():
            print(f"   {domain}:")
            print(f"     Type: {strategy.type}")
            print(f"     Params: {strategy.params}")
            print(f"     Forced: {strategy.forced}")
            print(f"     No fallbacks: {strategy.no_fallbacks}")
            
            # Verify all strategies have forced override
            assert strategy.forced is True, f"Strategy for {domain} must be forced"
            assert strategy.no_fallbacks is True, f"Strategy for {domain} must have no_fallbacks=True"
        
        print("✅ All loaded strategies have forced override enabled!")
        
    finally:
        # Clean up
        os.unlink(temp_path)

def demo_engine_format():
    """Demonstrate conversion to engine format."""
    print("\n=== Engine Format Demo ===")
    
    loader = UnifiedStrategyLoader()
    
    # Load a strategy
    strategy = loader.load_strategy("--dpi-desync=fakeddisorder --dpi-desync-ttl=3 --dpi-desync-fooling=badseq")
    
    # Convert to engine format
    engine_format = strategy.to_engine_format()
    
    print("Original strategy:")
    print(f"   {strategy.to_dict()}")
    print("\nEngine format:")
    print(f"   {engine_format}")
    
    # Verify engine format has critical parameters
    assert engine_format['no_fallbacks'] is True, "Engine format must have no_fallbacks=True"
    assert engine_format['forced'] is True, "Engine format must have forced=True"
    print("✅ Engine format has all critical parameters!")

def main():
    """Run all demos."""
    print("UnifiedStrategyLoader Demo")
    print("=" * 50)
    
    try:
        demo_basic_loading()
        demo_forced_override()
        demo_validation()
        demo_file_loading()
        demo_engine_format()
        
        print("\n" + "=" * 50)
        print("🎉 All demos completed successfully!")
        print("\nKey takeaways:")
        print("1. UnifiedStrategyLoader handles multiple strategy formats")
        print("2. ALL strategies get forced override (no_fallbacks=True, forced=True)")
        print("3. This ensures identical behavior between testing and service modes")
        print("4. Strategy validation prevents invalid configurations")
        print("5. File loading supports mixed strategy formats")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())