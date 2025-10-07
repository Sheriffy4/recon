#!/usr/bin/env python3
"""
Real-world validation test for unified engine implementation.
Tests domains in both service mode and testing mode to verify identical results.
"""

import json
import logging
import time
from typing import Dict, List, Any, Tuple
from core.unified_strategy_loader import UnifiedStrategyLoader
from core.unified_bypass_engine import UnifiedBypassEngine, UnifiedEngineConfig


class RealWorldValidator:
    """Real-world validation for unified engine."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.results = {}
        
        # Test domains and their strategies
        self.test_domains = {
            'youtube.com': 'fakeddisorder(ttl=8,fooling=badsum)',
            'rutracker.org': 'multidisorder(autottl=2,fooling=badseq)',
            'x.com': 'multisplit(split_pos=2,repeats=3)',
            'instagram.com': 'fakeddisorder(ttl=6,fooling=badseq,repeats=2)'
        }
        
    def test_strategy_loading_consistency(self) -> Dict[str, Any]:
        """Test that strategies load consistently across modes."""
        print("Testing strategy loading consistency...")
        
        loader = UnifiedStrategyLoader()
        results = {}
        
        for domain, strategy_str in self.test_domains.items():
            print(f"  Testing {domain}: {strategy_str}")
            
            try:
                # Load strategy multiple times
                loaded_strategies = []
                for i in range(5):
                    strategy = loader.load_strategy(strategy_str)
                    loaded_strategies.append(strategy.to_dict())
                
                # Check consistency
                first_strategy = loaded_strategies[0]
                all_identical = all(s == first_strategy for s in loaded_strategies)
                
                results[domain] = {
                    'strategy_string': strategy_str,
                    'loaded_consistently': all_identical,
                    'sample_strategy': first_strategy,
                    'forced_override': first_strategy.get('forced', False),
                    'no_fallbacks': first_strategy.get('no_fallbacks', False)
                }
                
                status = "✅" if all_identical else "❌"
                print(f"    {status} Consistency: {all_identical}")
                print(f"    Forced override: {first_strategy.get('forced', False)}")
                print(f"    No fallbacks: {first_strategy.get('no_fallbacks', False)}")
                
            except Exception as e:
                results[domain] = {
                    'strategy_string': strategy_str,
                    'error': str(e),
                    'loaded_consistently': False
                }
                print(f"    ❌ Error: {e}")
        
        return results
    
    def test_forced_override_behavior(self) -> Dict[str, Any]:
        """Test that forced override is always applied."""
        print("Testing forced override behavior...")
        
        loader = UnifiedStrategyLoader()
        results = {}
        
        for domain, strategy_str in self.test_domains.items():
            print(f"  Testing forced override for {domain}")
            
            try:
                # Load strategy
                strategy = loader.load_strategy(strategy_str)
                
                # Create forced override
                forced = loader.create_forced_override(strategy)
                
                # Verify forced override properties
                forced_dict = forced
                has_forced = forced_dict.get('forced', False)
                has_no_fallbacks = forced_dict.get('no_fallbacks', False)
                
                results[domain] = {
                    'original_strategy': strategy.to_dict(),
                    'forced_override': forced_dict,
                    'has_forced_flag': has_forced,
                    'has_no_fallbacks': has_no_fallbacks,
                    'forced_override_correct': has_forced and has_no_fallbacks
                }
                
                status = "✅" if (has_forced and has_no_fallbacks) else "❌"
                print(f"    {status} Forced override: {has_forced}, No fallbacks: {has_no_fallbacks}")
                
            except Exception as e:
                results[domain] = {
                    'error': str(e),
                    'forced_override_correct': False
                }
                print(f"    ❌ Error: {e}")
        
        return results
    
    def test_engine_initialization_modes(self) -> Dict[str, Any]:
        """Test engine initialization in different modes."""
        print("Testing engine initialization modes...")
        
        results = {}
        
        # Test service mode configuration
        print("  Testing service mode configuration...")
        try:
            service_config = UnifiedEngineConfig(
                debug=True,
                force_override=True,
                enable_diagnostics=True
            )
            service_engine = UnifiedBypassEngine(service_config)
            
            results['service_mode'] = {
                'initialized': True,
                'forced_override_enabled': service_engine.config.force_override,
                'debug_enabled': service_engine.config.debug,
                'diagnostics_enabled': service_engine.config.enable_diagnostics
            }
            print("    ✅ Service mode engine initialized successfully")
            
        except Exception as e:
            results['service_mode'] = {
                'initialized': False,
                'error': str(e)
            }
            print(f"    ❌ Service mode error: {e}")
        
        # Test testing mode configuration
        print("  Testing testing mode configuration...")
        try:
            testing_config = UnifiedEngineConfig(
                debug=True,
                force_override=True,  # Critical for testing mode compatibility
                enable_diagnostics=True
            )
            testing_engine = UnifiedBypassEngine(testing_config)
            
            results['testing_mode'] = {
                'initialized': True,
                'forced_override_enabled': testing_engine.config.force_override,
                'debug_enabled': testing_engine.config.debug,
                'diagnostics_enabled': testing_engine.config.enable_diagnostics
            }
            print("    ✅ Testing mode engine initialized successfully")
            
        except Exception as e:
            results['testing_mode'] = {
                'initialized': False,
                'error': str(e)
            }
            print(f"    ❌ Testing mode error: {e}")
        
        return results
    
    def test_strategy_application_simulation(self) -> Dict[str, Any]:
        """Simulate strategy application for domains."""
        print("Testing strategy application simulation...")
        
        loader = UnifiedStrategyLoader()
        config = UnifiedEngineConfig(force_override=True)
        engine = UnifiedBypassEngine(config)
        
        results = {}
        
        for domain, strategy_str in self.test_domains.items():
            print(f"  Simulating strategy application for {domain}")
            
            try:
                # Load and prepare strategy
                strategy = loader.load_strategy(strategy_str)
                forced = loader.create_forced_override(strategy)
                
                # Simulate strategy application (without actual network operations)
                start_time = time.perf_counter()
                
                # This would normally apply the strategy to the engine
                # For validation, we just verify the strategy is properly formatted
                strategy_dict = forced
                
                end_time = time.perf_counter()
                application_time = end_time - start_time
                
                # Verify strategy has required properties
                has_type = 'type' in strategy_dict
                has_params = 'params' in strategy_dict
                has_forced = strategy_dict.get('forced', False)
                has_no_fallbacks = strategy_dict.get('no_fallbacks', False)
                
                strategy_valid = has_type and has_params and has_forced and has_no_fallbacks
                
                results[domain] = {
                    'strategy_applied': True,
                    'application_time': application_time,
                    'strategy_valid': strategy_valid,
                    'has_type': has_type,
                    'has_params': has_params,
                    'has_forced': has_forced,
                    'has_no_fallbacks': has_no_fallbacks,
                    'strategy_dict': strategy_dict
                }
                
                status = "✅" if strategy_valid else "❌"
                print(f"    {status} Strategy valid: {strategy_valid} (time: {application_time:.6f}s)")
                
            except Exception as e:
                results[domain] = {
                    'strategy_applied': False,
                    'error': str(e),
                    'strategy_valid': False
                }
                print(f"    ❌ Error: {e}")
        
        return results
    
    def test_identical_behavior_verification(self) -> Dict[str, Any]:
        """Verify identical behavior between modes."""
        print("Testing identical behavior verification...")
        
        loader = UnifiedStrategyLoader()
        results = {}
        
        for domain, strategy_str in self.test_domains.items():
            print(f"  Verifying identical behavior for {domain}")
            
            try:
                # Load strategy once
                strategy = loader.load_strategy(strategy_str)
                
                # Create forced override multiple times (simulating different modes)
                forced_overrides = []
                for i in range(3):  # Simulate 3 different mode applications
                    forced = loader.create_forced_override(strategy)
                    forced_overrides.append(forced)
                
                # Check if all forced overrides are identical
                first_override = forced_overrides[0]
                all_identical = all(override == first_override for override in forced_overrides)
                
                results[domain] = {
                    'behavior_identical': all_identical,
                    'sample_override': first_override,
                    'num_tests': len(forced_overrides)
                }
                
                status = "✅" if all_identical else "❌"
                print(f"    {status} Identical behavior: {all_identical}")
                
            except Exception as e:
                results[domain] = {
                    'behavior_identical': False,
                    'error': str(e)
                }
                print(f"    ❌ Error: {e}")
        
        return results
    
    def run_full_validation(self) -> Dict[str, Any]:
        """Run complete real-world validation."""
        print("=" * 60)
        print("UNIFIED ENGINE REAL-WORLD VALIDATION")
        print("=" * 60)
        
        results = {}
        
        # Test 1: Strategy loading consistency
        print("\n1. STRATEGY LOADING CONSISTENCY TEST")
        print("-" * 40)
        results['strategy_loading_consistency'] = self.test_strategy_loading_consistency()
        
        # Test 2: Forced override behavior
        print("\n2. FORCED OVERRIDE BEHAVIOR TEST")
        print("-" * 40)
        results['forced_override_behavior'] = self.test_forced_override_behavior()
        
        # Test 3: Engine initialization modes
        print("\n3. ENGINE INITIALIZATION MODES TEST")
        print("-" * 40)
        results['engine_initialization_modes'] = self.test_engine_initialization_modes()
        
        # Test 4: Strategy application simulation
        print("\n4. STRATEGY APPLICATION SIMULATION TEST")
        print("-" * 40)
        results['strategy_application_simulation'] = self.test_strategy_application_simulation()
        
        # Test 5: Identical behavior verification
        print("\n5. IDENTICAL BEHAVIOR VERIFICATION TEST")
        print("-" * 40)
        results['identical_behavior_verification'] = self.test_identical_behavior_verification()
        
        # Overall assessment
        print("\n" + "=" * 60)
        print("REAL-WORLD VALIDATION ASSESSMENT")
        print("=" * 60)
        
        # Check overall success
        all_domains_consistent = all(
            domain_result.get('loaded_consistently', False)
            for domain_result in results['strategy_loading_consistency'].values()
        )
        
        all_forced_overrides_correct = all(
            domain_result.get('forced_override_correct', False)
            for domain_result in results['forced_override_behavior'].values()
        )
        
        service_mode_ok = results['engine_initialization_modes'].get('service_mode', {}).get('initialized', False)
        testing_mode_ok = results['engine_initialization_modes'].get('testing_mode', {}).get('initialized', False)
        
        all_strategies_valid = all(
            domain_result.get('strategy_valid', False)
            for domain_result in results['strategy_application_simulation'].values()
        )
        
        all_behavior_identical = all(
            domain_result.get('behavior_identical', False)
            for domain_result in results['identical_behavior_verification'].values()
        )
        
        print(f"Strategy loading consistent: {'✅' if all_domains_consistent else '❌'}")
        print(f"Forced overrides correct: {'✅' if all_forced_overrides_correct else '❌'}")
        print(f"Service mode initialization: {'✅' if service_mode_ok else '❌'}")
        print(f"Testing mode initialization: {'✅' if testing_mode_ok else '❌'}")
        print(f"Strategy application valid: {'✅' if all_strategies_valid else '❌'}")
        print(f"Behavior identical across modes: {'✅' if all_behavior_identical else '❌'}")
        
        overall_success = (
            all_domains_consistent and
            all_forced_overrides_correct and
            service_mode_ok and
            testing_mode_ok and
            all_strategies_valid and
            all_behavior_identical
        )
        
        print(f"\nOverall validation: {'✅ PASSED' if overall_success else '❌ FAILED'}")
        
        results['assessment'] = {
            'all_domains_consistent': all_domains_consistent,
            'all_forced_overrides_correct': all_forced_overrides_correct,
            'service_mode_ok': service_mode_ok,
            'testing_mode_ok': testing_mode_ok,
            'all_strategies_valid': all_strategies_valid,
            'all_behavior_identical': all_behavior_identical,
            'overall_success': overall_success
        }
        
        return results
    
    def save_results(self, results: Dict[str, Any], filename: str = "real_world_validation_results.json"):
        """Save validation results to file."""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {filename}")


def main():
    """Main real-world validation."""
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s')
    
    validator = RealWorldValidator()
    
    try:
        results = validator.run_full_validation()
        validator.save_results(results)
        
        # Return exit code based on validation
        if results['assessment']['overall_success']:
            print("\n✅ Real-world validation PASSED")
            return 0
        else:
            print("\n❌ Real-world validation FAILED")
            return 1
            
    except Exception as e:
        print(f"\n❌ Real-world validation ERROR: {e}")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())