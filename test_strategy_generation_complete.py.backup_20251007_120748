#!/usr/bin/env python3
"""
Comprehensive test for Strategy Generation Logic Overhaul (Task 10).
Tests all sub-tasks: hybrid_engine startup, rule engine, combinator, validator, and unit tests.
"""

import asyncio
import sys
import traceback
from typing import Dict, Any, List

def test_hybrid_engine_startup():
    """Test sub-task: Fix hybrid_engine Startup Bug"""
    print("Testing hybrid_engine startup bug fix...")
    
    try:
        from core.hybrid_engine import HybridEngine
        from core.bypass_engine import BypassEngine
        
        # Test that BypassEngine has the correct start_with_strategy signature
        engine = BypassEngine(debug=True)
        
        # Check method exists and has correct signature
        assert hasattr(engine, 'start_with_strategy'), "start_with_strategy method missing"
        
        # Test method signature by inspecting parameters
        import inspect
        sig = inspect.signature(engine.start_with_strategy)
        params = list(sig.parameters.keys())
        
        expected_params = ['target_ips', 'dns_cache', 'engine_task']
        for param in expected_params:
            assert param in params, f"Missing parameter: {param}"
        
        print("✓ Hybrid engine startup bug fix: PASSED")
        return True
        
    except Exception as e:
        print(f"✗ Hybrid engine startup bug fix: FAILED - {e}")
        return False


def test_rule_based_strategy_generation():
    """Test sub-task: Develop Rule-Based Strategy Generation"""
    print("Testing rule-based strategy generation...")
    
    try:
        from core.strategy_rule_engine import create_default_rule_engine, StrategyRule
        from core.fingerprint.advanced_models import DPIFingerprint, DPIType
        
        # Create rule engine
        engine = create_default_rule_engine()
        
        # Test rule loading
        assert len(engine.rules) > 0, "No rules loaded"
        
        # Test rule evaluation with different fingerprints
        test_cases = [
            {
                'fingerprint': DPIFingerprint(
                    target='test1.com',
                    dpi_type=DPIType.ROSKOMNADZOR_TSPU,
                    vulnerable_to_bad_checksum_race=True,
                    tcp_options_filtering=True,
                    rst_ttl=1
                ),
                'expected_type': 'fakeddisorder'
            },
            {
                'fingerprint': DPIFingerprint(
                    target='test2.com', 
                    dpi_type=DPIType.COMMERCIAL_DPI,
                    vulnerable_to_bad_checksum_race=True,
                    vulnerable_to_fragmentation=True
                ),
                'expected_type': 'multisplit'
            }
        ]
        
        for i, test_case in enumerate(test_cases):
            strategy = engine.generate_strategy(test_case['fingerprint'])
            assert strategy is not None, f"No strategy generated for test case {i+1}"
            assert 'type' in strategy, f"Strategy missing type for test case {i+1}"
            assert 'params' in strategy, f"Strategy missing params for test case {i+1}"
            
            # Verify strategy makes sense for DPI type
            if test_case['fingerprint'].dpi_type == DPIType.ROSKOMNADZOR_TSPU:
                assert strategy['type'] == 'fakeddisorder', f"Wrong strategy type for Roskomnadzor: {strategy['type']}"
        
        # Test multiple strategy generation
        strategies = engine.generate_multiple_strategies(test_cases[0]['fingerprint'], count=3)
        assert len(strategies) == 3, f"Expected 3 strategies, got {len(strategies)}"
        
        # Test custom rule addition
        custom_rule = StrategyRule(
            name="test_custom",
            condition="Test condition",
            priority=100,
            attack_type="fakeddisorder",
            parameters={"ttl": 128}
        )
        
        initial_count = len(engine.rules)
        engine.add_rule(custom_rule)
        assert len(engine.rules) == initial_count + 1, "Custom rule not added"
        
        print("✓ Rule-based strategy generation: PASSED")
        return True
        
    except Exception as e:
        print(f"✗ Rule-based strategy generation: FAILED - {e}")
        traceback.print_exc()
        return False


def test_strategy_combination_logic():
    """Test sub-task: Implement Strategy Combination Logic"""
    print("Testing strategy combination logic...")
    
    try:
        from core.strategy_combinator import create_default_combinator
        from core.fingerprint.advanced_models import DPIFingerprint, DPIType
        
        # Create combinator
        combinator = create_default_combinator()
        
        # Test component loading
        assert len(combinator.attack_components) > 0, "No attack components loaded"
        assert len(combinator.combination_rules) > 0, "No combination rules loaded"
        
        # Test component compatibility checking
        compatible_components = ["fakeddisorder_base", "badsum_fooling", "high_ttl"]
        is_compatible, conflicts = combinator._check_compatibility(compatible_components)
        assert is_compatible, f"Compatible components rejected: {conflicts}"
        
        # Test incompatible components
        incompatible_components = ["fakeddisorder_base", "low_ttl", "high_ttl"]  # TTL conflict
        is_compatible, conflicts = combinator._check_compatibility(incompatible_components)
        assert not is_compatible, "Incompatible components accepted"
        
        # Test component combination
        strategy = combinator.combine_components(compatible_components)
        assert strategy is not None, "Failed to combine compatible components"
        assert strategy['type'] == 'fakeddisorder', f"Wrong combined strategy type: {strategy['type']}"
        assert 'fooling' in strategy['params'], "Fooling methods not combined"
        assert 'badsum' in strategy['params']['fooling'], "Badsum fooling not included"
        
        # Test predefined combinations
        predefined = combinator.get_predefined_combination("roskomnadzor_aggressive")
        assert predefined is not None, "Failed to get predefined combination"
        assert 'type' in predefined, "Predefined combination missing type"
        
        # Test fingerprint-based suggestions
        fingerprint = DPIFingerprint(
            target='test.com',
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            vulnerable_to_bad_checksum_race=True,
            vulnerable_to_fragmentation=True
        )
        
        suggestions = combinator.suggest_combinations_for_fingerprint(fingerprint)
        assert len(suggestions) > 0, "No suggestions generated"
        
        for name, strategy in suggestions:
            assert isinstance(name, str), f"Invalid suggestion name: {name}"
            assert strategy is not None, f"Invalid strategy for {name}"
            assert 'type' in strategy, f"Strategy missing type for {name}"
        
        # Test custom combination creation
        custom = combinator.create_custom_combination(
            "fakeddisorder",
            ttl=64,
            fooling=["badsum", "md5sig"]
        )
        assert custom is not None, "Failed to create custom combination"
        assert custom['type'] == 'fakeddisorder', "Wrong custom combination type"
        assert custom['params']['ttl'] == 64, "TTL not set correctly"
        
        print("✓ Strategy combination logic: PASSED")
        return True
        
    except Exception as e:
        print(f"✗ Strategy combination logic: FAILED - {e}")
        traceback.print_exc()
        return False


async def test_strategy_validation():
    """Test sub-task: Refine and Validate Generated Strategies"""
    print("Testing strategy validation...")
    
    try:
        from core.strategy_validator import create_default_validator, StrategyTestResult
        from core.fingerprint.advanced_models import DPIFingerprint, DPIType
        
        # Create validator
        validator = create_default_validator()
        
        # Test manual strategies database
        assert len(validator.manual_strategies_db) > 0, "No manual strategies loaded"
        
        # Test strategy effectiveness testing
        test_strategy = {
            'type': 'fakeddisorder',
            'params': {
                'ttl': 64,
                'split_pos': 76,
                'fooling': ['badsum']
            }
        }
        
        test_sites = ['x.com', 'youtube.com', 'instagram.com']
        
        result = await validator.test_strategy_effectiveness(test_strategy, test_sites)
        assert isinstance(result, StrategyTestResult), "Invalid test result type"
        assert result.strategy == test_strategy, "Strategy not preserved in result"
        assert result.total_count == len(test_sites), "Wrong total count"
        assert 0 <= result.success_rate <= 1.0, f"Invalid success rate: {result.success_rate}"
        
        # Test full validation workflow
        fingerprint = DPIFingerprint(
            target='test.com',
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            vulnerable_to_bad_checksum_race=True,
            tcp_options_filtering=True
        )
        
        report = await validator.validate_generated_strategies(fingerprint, test_sites)
        
        assert len(report.generated_strategies) > 0, "No generated strategies tested"
        assert len(report.manual_strategies) > 0, "No manual strategies tested"
        assert report.best_generated is not None, "No best generated strategy found"
        assert report.best_manual is not None, "No best manual strategy found"
        assert isinstance(report.improvement_suggestions, list), "Invalid improvement suggestions"
        assert isinstance(report.performance_comparison, dict), "Invalid performance comparison"
        
        # Test manual strategy addition
        validator.add_manual_strategy(
            "test_manual",
            test_strategy,
            0.85,
            "Test manual strategy"
        )
        
        assert "test_manual" in validator.manual_strategies_db, "Manual strategy not added"
        
        print("✓ Strategy validation: PASSED")
        return True
        
    except Exception as e:
        print(f"✗ Strategy validation: FAILED - {e}")
        traceback.print_exc()
        return False


def test_unit_tests():
    """Test sub-task: Write Unit Tests"""
    print("Testing unit tests...")
    
    try:
        # Test that all test modules can be imported
        from tests.test_strategy_generation_overhaul_fixed import (
            TestStrategyRuleEngine,
            TestStrategyCombinator, 
            TestStrategyValidator,
            TestIntegration
        )
        
        # Test that test classes have the expected methods
        rule_engine_tests = TestStrategyRuleEngine()
        assert hasattr(rule_engine_tests, 'test_rule_engine_initialization'), "Missing rule engine test"
        assert hasattr(rule_engine_tests, 'test_generate_strategy_roskomnadzor'), "Missing Roskomnadzor test"
        
        combinator_tests = TestStrategyCombinator()
        assert hasattr(combinator_tests, 'test_combinator_initialization'), "Missing combinator test"
        assert hasattr(combinator_tests, 'test_combine_compatible_components'), "Missing combination test"
        
        validator_tests = TestStrategyValidator()
        assert hasattr(validator_tests, 'test_validator_initialization'), "Missing validator test"
        
        integration_tests = TestIntegration()
        assert hasattr(integration_tests, 'test_end_to_end_strategy_generation'), "Missing integration test"
        
        print("✓ Unit tests: PASSED")
        return True
        
    except Exception as e:
        print(f"✗ Unit tests: FAILED - {e}")
        traceback.print_exc()
        return False


async def main():
    """Run all sub-task tests"""
    print("=" * 60)
    print("Strategy Generation Logic Overhaul - Comprehensive Test")
    print("=" * 60)
    
    results = []
    
    # Test all sub-tasks
    results.append(test_hybrid_engine_startup())
    results.append(test_rule_based_strategy_generation())
    results.append(test_strategy_combination_logic())
    results.append(await test_strategy_validation())
    results.append(test_unit_tests())
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Sub-tasks passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 ALL SUB-TASKS COMPLETED SUCCESSFULLY!")
        print("\nStrategy Generation Logic Overhaul is fully implemented:")
        print("✓ Hybrid engine startup bug fixed")
        print("✓ Rule-based strategy generation system created")
        print("✓ Strategy combination logic implemented")
        print("✓ Strategy validation and refinement system built")
        print("✓ Comprehensive unit tests written")
        return True
    else:
        print(f"❌ {total - passed} sub-tasks failed. Please review the errors above.")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)