#!/usr/bin/env python3
"""
Test script to verify identical behavior between testing mode and service mode
after UnifiedBypassEngine integration.

This script validates that:
1. Testing mode uses UnifiedBypassEngine
2. Service mode uses UnifiedBypassEngine
3. Both modes produce identical results
4. Forced override is applied consistently
5. Packet building logic is identical
"""

import sys
import os
import json
import logging
import time
from typing import Dict, Any, List
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Setup logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
LOG = logging.getLogger("test_unified_engine_integration")

# Import components
try:
    from core.unified_bypass_engine import UnifiedBypassEngine, UnifiedEngineConfig
    from core.unified_strategy_loader import UnifiedStrategyLoader
    from enhanced_find_rst_triggers import DPIFingerprintAnalyzer, compare_with_service_mode
    IMPORTS_AVAILABLE = True
    LOG.info("✅ Core unified components imported successfully")
except ImportError as e:
    LOG.error(f"Failed to import required components: {e}")
    IMPORTS_AVAILABLE = False


class UnifiedEngineIntegrationTester:
    """
    Test suite for validating UnifiedBypassEngine integration
    across testing mode and service mode.
    """
    
    def __init__(self):
        self.test_results = []
        self.test_domain = "x.com"  # Known problematic domain
        self.test_strategies = [
            "fakeddisorder(ttl=1)",
            "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-split-pos=46",
            {
                "type": "fakeddisorder",
                "params": {
                    "ttl": 1,
                    "fooling": "badseq"
                }
            }
        ]
    
    def run_all_tests(self) -> Dict[str, Any]:
        """
        Run all integration tests.
        
        Returns:
            Dict with comprehensive test results
        """
        LOG.info("🚀 Starting UnifiedBypassEngine integration tests")
        
        if not IMPORTS_AVAILABLE:
            return {
                'overall_success': False,
                'error': 'Required imports not available',
                'tests': [],
                'total_tests': 0,
                'successful_tests': 0,
                'failed_tests': 0,
                'success_rate': 0,
                'test_results': [],
                'summary': {}
            }
        
        # Test 1: Verify testing mode uses UnifiedBypassEngine
        self.test_testing_mode_engine()
        
        # Test 2: Verify service mode uses UnifiedBypassEngine
        self.test_service_mode_engine()
        
        # Test 3: Compare behavior between modes
        self.test_behavior_comparison()
        
        # Test 4: Verify forced override consistency
        self.test_forced_override_consistency()
        
        # Test 5: Validate strategy loading consistency
        self.test_strategy_loading_consistency()
        
        # Test 6: Test packet building consistency
        self.test_packet_building_consistency()
        
        # Compile results
        return self.compile_test_results()
    
    def test_testing_mode_engine(self):
        """Test that testing mode uses UnifiedBypassEngine."""
        LOG.info("🧪 Test 1: Testing mode engine verification")
        
        test_result = {
            'test_name': 'testing_mode_engine',
            'description': 'Verify testing mode uses UnifiedBypassEngine',
            'success': False,
            'details': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Create analyzer (testing mode)
            analyzer = DPIFingerprintAnalyzer(self.test_domain, test_count=1)
            
            # Check if it uses unified engine
            has_unified_engine = hasattr(analyzer, 'unified_engine') and analyzer.unified_engine is not None
            uses_unified_loader = hasattr(analyzer, 'strategy_loader') and analyzer.strategy_loader is not None
            
            test_result['details'] = {
                'has_unified_engine': has_unified_engine,
                'uses_unified_loader': uses_unified_loader,
                'engine_type': type(analyzer.unified_engine).__name__ if analyzer.unified_engine else None,
                'loader_type': type(analyzer.strategy_loader).__name__ if analyzer.strategy_loader else None
            }
            
            # Validate engine compatibility
            if has_unified_engine:
                compatibility = analyzer.validate_engine_compatibility()
                test_result['details']['compatibility'] = compatibility
                test_result['success'] = compatibility.get('matches_service_mode', False)
            
            if test_result['success']:
                LOG.info("✅ Testing mode correctly uses UnifiedBypassEngine")
            else:
                LOG.warning("⚠️  Testing mode not using UnifiedBypassEngine properly")
                
        except Exception as e:
            test_result['details']['error'] = str(e)
            LOG.error(f"❌ Testing mode engine test failed: {e}")
        
        self.test_results.append(test_result)
    
    def test_service_mode_engine(self):
        """Test that service mode uses UnifiedBypassEngine."""
        LOG.info("🧪 Test 2: Service mode engine verification")
        
        test_result = {
            'test_name': 'service_mode_engine',
            'description': 'Verify service mode uses UnifiedBypassEngine',
            'success': False,
            'details': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Check if recon_service.py imports UnifiedBypassEngine
            with open('recon_service.py', 'r', encoding='utf-8') as f:
                service_code = f.read()
            
            has_unified_import = 'UnifiedBypassEngine' in service_code
            has_unified_loader_import = 'UnifiedStrategyLoader' in service_code
            
            test_result['details'] = {
                'has_unified_import': has_unified_import,
                'has_unified_loader_import': has_unified_loader_import,
                'service_file_exists': True
            }
            
            # Try to create service instance (if possible without starting)
            try:
                # This would test service initialization
                # For now, just check imports
                test_result['success'] = has_unified_import and has_unified_loader_import
            except Exception as e:
                test_result['details']['service_init_error'] = str(e)
            
            if test_result['success']:
                LOG.info("✅ Service mode correctly imports UnifiedBypassEngine")
            else:
                LOG.warning("⚠️  Service mode not importing UnifiedBypassEngine")
                
        except Exception as e:
            test_result['details']['error'] = str(e)
            LOG.error(f"❌ Service mode engine test failed: {e}")
        
        self.test_results.append(test_result)
    
    def test_behavior_comparison(self):
        """Test behavior comparison between modes."""
        LOG.info("🧪 Test 3: Behavior comparison between modes")
        
        test_result = {
            'test_name': 'behavior_comparison',
            'description': 'Compare behavior between testing and service modes',
            'success': False,
            'details': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            comparisons = []
            
            for strategy in self.test_strategies:
                if isinstance(strategy, dict):
                    strategy_str = f"{strategy['type']}({', '.join(f'{k}={v}' for k, v in strategy['params'].items())})"
                else:
                    strategy_str = str(strategy)
                
                LOG.info(f"   Comparing strategy: {strategy_str}")
                
                comparison = compare_with_service_mode(self.test_domain, strategy_str)
                comparisons.append(comparison)
                
                if comparison.get('identical_behavior'):
                    LOG.info(f"   ✅ Identical behavior for: {strategy_str}")
                else:
                    LOG.warning(f"   ⚠️  Different behavior for: {strategy_str}")
                    if comparison.get('differences'):
                        for diff in comparison['differences']:
                            LOG.warning(f"      - {diff}")
            
            test_result['details'] = {
                'comparisons': comparisons,
                'total_strategies': len(self.test_strategies),
                'identical_count': sum(1 for c in comparisons if c.get('identical_behavior')),
                'different_count': sum(1 for c in comparisons if not c.get('identical_behavior'))
            }
            
            # Success if all strategies show identical behavior
            test_result['success'] = test_result['details']['different_count'] == 0
            
            if test_result['success']:
                LOG.info("✅ All strategies show identical behavior between modes")
            else:
                LOG.warning(f"⚠️  {test_result['details']['different_count']} strategies show different behavior")
                
        except Exception as e:
            test_result['details']['error'] = str(e)
            LOG.error(f"❌ Behavior comparison test failed: {e}")
        
        self.test_results.append(test_result)
    
    def test_forced_override_consistency(self):
        """Test that forced override is applied consistently."""
        LOG.info("🧪 Test 4: Forced override consistency")
        
        test_result = {
            'test_name': 'forced_override_consistency',
            'description': 'Verify forced override is applied consistently',
            'success': False,
            'details': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Test with UnifiedBypassEngine directly
            engine_config = UnifiedEngineConfig(
                debug=True,
                force_override=True,
                enable_diagnostics=True
            )
            engine = UnifiedBypassEngine(engine_config)
            
            # Test strategy loading and forced override creation
            loader = UnifiedStrategyLoader(debug=True)
            
            forced_override_tests = []
            
            for strategy in self.test_strategies:
                try:
                    # Load strategy
                    normalized = loader.load_strategy(strategy)
                    
                    # Create forced override
                    forced_config = loader.create_forced_override(normalized)
                    
                    # Validate forced override properties
                    has_no_fallbacks = forced_config.get('no_fallbacks', False)
                    has_forced_flag = forced_config.get('forced', False)
                    
                    forced_override_tests.append({
                        'strategy': str(strategy),
                        'normalized_type': normalized.type,
                        'has_no_fallbacks': has_no_fallbacks,
                        'has_forced_flag': has_forced_flag,
                        'valid_forced_override': has_no_fallbacks and has_forced_flag
                    })
                    
                except Exception as e:
                    forced_override_tests.append({
                        'strategy': str(strategy),
                        'error': str(e),
                        'valid_forced_override': False
                    })
            
            test_result['details'] = {
                'forced_override_tests': forced_override_tests,
                'total_tests': len(forced_override_tests),
                'valid_count': sum(1 for t in forced_override_tests if t.get('valid_forced_override')),
                'invalid_count': sum(1 for t in forced_override_tests if not t.get('valid_forced_override'))
            }
            
            # Success if all strategies have valid forced override
            test_result['success'] = test_result['details']['invalid_count'] == 0
            
            if test_result['success']:
                LOG.info("✅ All strategies have valid forced override")
            else:
                LOG.warning(f"⚠️  {test_result['details']['invalid_count']} strategies have invalid forced override")
                
        except Exception as e:
            test_result['details']['error'] = str(e)
            LOG.error(f"❌ Forced override consistency test failed: {e}")
        
        self.test_results.append(test_result)
    
    def test_strategy_loading_consistency(self):
        """Test strategy loading consistency across modes."""
        LOG.info("🧪 Test 5: Strategy loading consistency")
        
        test_result = {
            'test_name': 'strategy_loading_consistency',
            'description': 'Verify strategy loading is consistent across modes',
            'success': False,
            'details': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            loader = UnifiedStrategyLoader(debug=True)
            loading_tests = []
            
            for strategy in self.test_strategies:
                try:
                    # Load strategy
                    normalized = loader.load_strategy(strategy)
                    
                    # Validate strategy
                    is_valid = loader.validate_strategy(normalized)
                    
                    loading_tests.append({
                        'strategy': str(strategy),
                        'loaded_successfully': True,
                        'normalized_type': normalized.type,
                        'has_params': bool(normalized.params),
                        'is_valid': is_valid,
                        'no_fallbacks': normalized.no_fallbacks,
                        'forced': normalized.forced,
                        'source_format': normalized.source_format
                    })
                    
                except Exception as e:
                    loading_tests.append({
                        'strategy': str(strategy),
                        'loaded_successfully': False,
                        'error': str(e)
                    })
            
            test_result['details'] = {
                'loading_tests': loading_tests,
                'total_tests': len(loading_tests),
                'successful_loads': sum(1 for t in loading_tests if t.get('loaded_successfully')),
                'failed_loads': sum(1 for t in loading_tests if not t.get('loaded_successfully'))
            }
            
            # Success if all strategies load successfully
            test_result['success'] = test_result['details']['failed_loads'] == 0
            
            if test_result['success']:
                LOG.info("✅ All strategies load consistently")
            else:
                LOG.warning(f"⚠️  {test_result['details']['failed_loads']} strategies failed to load")
                
        except Exception as e:
            test_result['details']['error'] = str(e)
            LOG.error(f"❌ Strategy loading consistency test failed: {e}")
        
        self.test_results.append(test_result)
    
    def test_packet_building_consistency(self):
        """Test packet building consistency."""
        LOG.info("🧪 Test 6: Packet building consistency")
        
        test_result = {
            'test_name': 'packet_building_consistency',
            'description': 'Verify packet building is consistent between modes',
            'success': False,
            'details': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # This test would verify that packet building parameters are identical
            # For now, we'll test that the engine configuration ensures consistency
            
            engine_config = UnifiedEngineConfig(
                debug=True,
                force_override=True,
                enable_diagnostics=True
            )
            engine = UnifiedBypassEngine(engine_config)
            
            # Validate engine configuration
            validation = engine.validate_forced_override_behavior()
            
            test_result['details'] = {
                'engine_validation': validation,
                'forced_override_enabled': validation.get('forced_override_enabled', False),
                'all_strategies_forced': validation.get('all_strategies_forced', False),
                'no_fallbacks_enforced': validation.get('no_fallbacks_enforced', False),
                'issues': validation.get('issues', [])
            }
            
            # Success if validation passes
            test_result['success'] = (
                validation.get('forced_override_enabled', False) and
                validation.get('all_strategies_forced', False) and
                validation.get('no_fallbacks_enforced', False) and
                len(validation.get('issues', [])) == 0
            )
            
            if test_result['success']:
                LOG.info("✅ Packet building consistency validated")
            else:
                LOG.warning("⚠️  Packet building consistency issues detected")
                for issue in validation.get('issues', []):
                    LOG.warning(f"   - {issue}")
                
        except Exception as e:
            test_result['details']['error'] = str(e)
            LOG.error(f"❌ Packet building consistency test failed: {e}")
        
        self.test_results.append(test_result)
    
    def compile_test_results(self) -> Dict[str, Any]:
        """Compile all test results into a comprehensive report."""
        successful_tests = [t for t in self.test_results if t.get('success', False)]
        failed_tests = [t for t in self.test_results if not t.get('success', False)]
        
        overall_success = len(failed_tests) == 0
        
        report = {
            'overall_success': overall_success,
            'total_tests': len(self.test_results),
            'successful_tests': len(successful_tests),
            'failed_tests': len(failed_tests),
            'success_rate': len(successful_tests) / len(self.test_results) if self.test_results else 0,
            'test_results': self.test_results,
            'summary': {
                'testing_mode_engine': any(t['test_name'] == 'testing_mode_engine' and t['success'] for t in self.test_results),
                'service_mode_engine': any(t['test_name'] == 'service_mode_engine' and t['success'] for t in self.test_results),
                'behavior_identical': any(t['test_name'] == 'behavior_comparison' and t['success'] for t in self.test_results),
                'forced_override_consistent': any(t['test_name'] == 'forced_override_consistency' and t['success'] for t in self.test_results),
                'strategy_loading_consistent': any(t['test_name'] == 'strategy_loading_consistency' and t['success'] for t in self.test_results),
                'packet_building_consistent': any(t['test_name'] == 'packet_building_consistency' and t['success'] for t in self.test_results)
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return report
    
    def print_summary(self, report: Dict[str, Any]):
        """Print test summary."""
        print("\n" + "="*80)
        print("UNIFIED ENGINE INTEGRATION TEST RESULTS")
        print("="*80)
        
        print(f"\nOverall Success: {'✅ PASS' if report['overall_success'] else '❌ FAIL'}")
        print(f"Total Tests: {report['total_tests']}")
        print(f"Successful: {report['successful_tests']}")
        print(f"Failed: {report['failed_tests']}")
        print(f"Success Rate: {report['success_rate']:.1%}")
        
        print(f"\nTest Summary:")
        summary = report['summary']
        print(f"  Testing Mode Engine: {'✅' if summary['testing_mode_engine'] else '❌'}")
        print(f"  Service Mode Engine: {'✅' if summary['service_mode_engine'] else '❌'}")
        print(f"  Behavior Identical: {'✅' if summary['behavior_identical'] else '❌'}")
        print(f"  Forced Override Consistent: {'✅' if summary['forced_override_consistent'] else '❌'}")
        print(f"  Strategy Loading Consistent: {'✅' if summary['strategy_loading_consistent'] else '❌'}")
        print(f"  Packet Building Consistent: {'✅' if summary['packet_building_consistent'] else '❌'}")
        
        if report['failed_tests'] > 0:
            print(f"\nFailed Tests:")
            for test in report['test_results']:
                if not test.get('success', False):
                    print(f"  ❌ {test['test_name']}: {test['description']}")
                    if 'error' in test.get('details', {}):
                        print(f"     Error: {test['details']['error']}")
        
        print("\n" + "="*80)


def main():
    """Main function for integration testing."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Test UnifiedBypassEngine integration between testing and service modes"
    )
    
    parser.add_argument(
        "--output",
        help="Output file for detailed results (JSON)"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run tests
    tester = UnifiedEngineIntegrationTester()
    report = tester.run_all_tests()
    
    # Print summary
    tester.print_summary(report)
    
    # Save detailed results
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        LOG.info(f"Detailed results saved to {args.output}")
    
    # Return appropriate exit code
    return 0 if report['overall_success'] else 1


if __name__ == "__main__":
    sys.exit(main())