#!/usr/bin/env python3
"""
Test imports for Task 24 components
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_strategy_rule_engine():
    """Test strategy rule engine import"""
    try:
        from core.strategy.strategy_rule_engine import StrategyRuleEngine, Rule, RuleCondition
        print("✅ StrategyRuleEngine imports work")
        
        # Test basic functionality
        engine = StrategyRuleEngine()
        print(f"✅ StrategyRuleEngine created with {len(engine.rules)} rules")
        
        return True
    except Exception as e:
        print(f"❌ StrategyRuleEngine import failed: {e}")
        return False

def test_strategy_combinator():
    """Test strategy combinator import"""
    try:
        from core.strategy_combinator import StrategyCombinator
        print("✅ StrategyCombinator imports work")
        
        # Test basic functionality
        combinator = StrategyCombinator()
        print("✅ StrategyCombinator created")
        
        return True
    except Exception as e:
        print(f"❌ StrategyCombinator import failed: {e}")
        return False

def test_intelligent_generator():
    """Test intelligent strategy generator import"""
    try:
        from core.strategy.intelligent_strategy_generator import IntelligentStrategyGenerator
        print("✅ IntelligentStrategyGenerator imports work")
        
        # Test basic functionality
        generator = IntelligentStrategyGenerator()
        print("✅ IntelligentStrategyGenerator created")
        
        return True
    except Exception as e:
        print(f"❌ IntelligentStrategyGenerator import failed: {e}")
        return False

def main():
    """Run all import tests"""
    print("Testing Task 24 component imports...")
    print("=" * 50)
    
    results = []
    
    results.append(test_strategy_rule_engine())
    results.append(test_strategy_combinator())
    results.append(test_intelligent_generator())
    
    print("=" * 50)
    passed = sum(results)
    total = len(results)
    
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All imports working correctly!")
        return 0
    else:
        print("⚠️ Some imports failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())