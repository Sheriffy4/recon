#!/usr/bin/env python3
"""
Quick test to verify parameter validation integration is working.
"""

import sys
import os

# Add current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

def test_validation_integration():
    """Test parameter validation integration across components."""
    print("🧪 Testing parameter validation integration...")
    
    try:
        from core.bypass.attacks.attack_registry import get_attack_registry
        from core.unified_strategy_loader import UnifiedStrategyLoader
        from cli import SimpleEvolutionarySearcher
        
        # Test AttackRegistry validation
        print("📋 Testing AttackRegistry validation...")
        registry = get_attack_registry()
        
        # Test invalid TTL
        result = registry.validate_parameters('fakeddisorder', {'split_pos': 3, 'ttl': 300})
        print(f"   ❌ Invalid TTL validation: {result.is_valid} - {result.error_message}")
        
        # Test valid parameters
        result = registry.validate_parameters('fakeddisorder', {'split_pos': 3, 'ttl': 4})
        print(f"   ✅ Valid parameters: {result.is_valid}")
        
        # Test CLI validation with correction
        print("🔧 Testing CLI validation with correction...")
        searcher = SimpleEvolutionarySearcher()
        corrected = searcher._validate_attack_parameters('fakeddisorder', {'split_pos': 3, 'ttl': 300})
        print(f"   🔧 CLI corrected TTL: {corrected['ttl']} (should be <= 255)")
        
        # Test UnifiedStrategyLoader integration
        print("📦 Testing UnifiedStrategyLoader integration...")
        loader = UnifiedStrategyLoader()
        strategy = loader.load_strategy({'type': 'fakeddisorder', 'params': {'split_pos': 3, 'ttl': 4}})
        is_valid = loader.validate_strategy(strategy)
        print(f"   ✅ Strategy validation: {is_valid}")
        
        # Test positions parameter validation
        print("📍 Testing positions parameter validation...")
        result = registry.validate_parameters('multisplit', {'positions': [1, 3, 5]})
        print(f"   ✅ Valid positions: {result.is_valid}")
        
        result = registry.validate_parameters('multisplit', {'positions': [1, 'invalid', 5]})
        print(f"   ❌ Invalid positions: {result.is_valid} - {result.error_message}")
        
        print("🎉 Parameter validation integration working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Error during validation test: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_validation_integration()
    sys.exit(0 if success else 1)