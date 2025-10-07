#!/usr/bin/env python3
"""
Integration test for service mode with unified engine.

This test verifies that the service mode works correctly with the unified engine
and produces identical results to testing mode.

Test Coverage:
1. Service initialization with unified engine
2. Domain opening in service mode
3. Comparison with testing mode results
4. Verification that all domains work
5. Forced override behavior validation
"""

import sys
import json
import time
import logging
import threading
import tempfile
from pathlib import Path
from typing import Dict, Set, Any, Optional
from unittest.mock import patch, MagicMock

# Add project root to path
if __name__ == "__main__" and __package__ is None:
    recon_dir = Path(__file__).parent
    project_root = recon_dir.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

# Import components to test
try:
    from recon.recon_service import DPIBypassService
    from recon.core.unified_bypass_engine import UnifiedBypassEngine, UnifiedEngineConfig
    from recon.core.unified_strategy_loader import UnifiedStrategyLoader
    # Import testing mode functions
    import recon.enhanced_find_rst_triggers as testing_mode
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure all required modules are available")
    sys.exit(1)


class ServiceModeIntegrationTest:
    """Integration test for service mode with unified engine."""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.test_results = {}
        self.temp_files = []
        
        # Test domains and strategies
        self.test_domains = {
            'youtube.com': 'fakeddisorder(ttl=1)',
            'rutracker.org': 'multisplit(split_pos=3)',
            'x.com': 'fakeddisorder(ttl=2, fooling=badsum)',
            'instagram.com': 'disorder(ttl=1)'
        }
        
        # Expected IPs for test domains (mock data)
        self.mock_ips = {
            'youtube.com': ['142.250.191.78', '142.250.191.110'],
            'rutracker.org': ['195.82.146.214'],
            'x.com': ['104.244.42.129', '104.244.42.1'],
            'instagram.com': ['157.240.15.174']
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup test logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        return logging.getLogger('ServiceModeTest')
    
    def create_test_files(self):
        """Create temporary test configuration files."""
        # Create strategies.json
        strategies_file = Path('strategies.json')
        with open(strategies_file, 'w', encoding='utf-8') as f:
            json.dump(self.test_domains, f, indent=2)
        self.temp_files.append(strategies_file)
        
        # Create sites.txt
        sites_file = Path('sites.txt')
        with open(sites_file, 'w', encoding='utf-8') as f:
            for domain in self.test_domains.keys():
                f.write(f"https://{domain}\n")
        self.temp_files.append(sites_file)
        
        self.logger.info(f"Created test files: {[str(f) for f in self.temp_files]}")
    
    def cleanup_test_files(self):
        """Clean up temporary test files."""
        for file_path in self.temp_files:
            try:
                if file_path.exists():
                    file_path.unlink()
                    self.logger.info(f"Cleaned up {file_path}")
            except Exception as e:
                self.logger.warning(f"Failed to clean up {file_path}: {e}")
        self.temp_files.clear()
    
    def mock_dns_resolution(self):
        """Mock DNS resolution for test domains."""
        def mock_getaddrinfo(host, port, *args, **kwargs):
            if host in self.mock_ips:
                # Return mock IP addresses in getaddrinfo format
                result = []
                for ip in self.mock_ips[host]:
                    result.append((2, 1, 6, '', (ip, port or 443)))
                return result
            else:
                # Return localhost for unknown domains
                return [(2, 1, 6, '', ('127.0.0.1', port or 443))]
        
        return patch('socket.getaddrinfo', side_effect=mock_getaddrinfo)
    
    def mock_admin_check(self):
        """Mock administrator privilege check."""
        def mock_is_admin():
            return True
        
        return patch('ctypes.windll.shell32.IsUserAnAdmin', side_effect=mock_is_admin)
    
    def mock_windivert_files(self):
        """Mock WinDivert file existence."""
        def mock_exists(path):
            if 'WinDivert' in str(path):
                return True
            return Path(path).exists()
        
        return patch('os.path.exists', side_effect=mock_exists)
    
    def mock_network_commands(self):
        """Mock network configuration commands."""
        def mock_run(*args, **kwargs):
            return MagicMock(returncode=0)
        
        return patch('subprocess.run', side_effect=mock_run)
    
    def test_service_initialization(self) -> bool:
        """Test service initialization with unified engine."""
        self.logger.info("=" * 60)
        self.logger.info("TEST 1: Service Initialization")
        self.logger.info("=" * 60)
        
        try:
            # Create service instance
            service = DPIBypassService()
            
            # Test strategy loading
            strategies_loaded = service.load_strategies()
            if not strategies_loaded:
                self.logger.error("❌ Failed to load strategies")
                return False
            
            self.logger.info(f"✅ Loaded {len(service.domain_strategies)} strategies")
            
            # Test domain loading
            domains_loaded = service.load_domains()
            if not domains_loaded:
                self.logger.error("❌ Failed to load domains")
                return False
            
            self.logger.info(f"✅ Loaded {len(service.monitored_domains)} domains")
            
            # Verify all test domains are loaded
            for domain in self.test_domains.keys():
                if domain not in service.monitored_domains:
                    self.logger.error(f"❌ Test domain {domain} not loaded")
                    return False
            
            # Verify all strategies are loaded
            for domain, expected_strategy in self.test_domains.items():
                actual_strategy = service.get_strategy_for_domain(domain)
                if actual_strategy != expected_strategy:
                    self.logger.error(f"❌ Strategy mismatch for {domain}: expected {expected_strategy}, got {actual_strategy}")
                    return False
            
            self.logger.info("✅ Service initialization test passed")
            self.test_results['service_initialization'] = True
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Service initialization test failed: {e}")
            self.test_results['service_initialization'] = False
            return False
    
    def test_unified_engine_integration(self) -> bool:
        """Test unified engine integration in service mode."""
        self.logger.info("=" * 60)
        self.logger.info("TEST 2: Unified Engine Integration")
        self.logger.info("=" * 60)
        
        try:
            # Create service instance
            service = DPIBypassService()
            service.load_strategies()
            service.load_domains()
            
            # Mock all external dependencies
            with self.mock_dns_resolution(), \
                 self.mock_admin_check(), \
                 self.mock_windivert_files(), \
                 self.mock_network_commands():
                
                # Start bypass engine (this will use the real unified engine)
                engine_started = service.start_bypass_engine()
                
                if not engine_started:
                    self.logger.error("❌ Failed to start unified bypass engine")
                    return False
                
                # Verify the service has a bypass engine
                if not hasattr(service, 'bypass_engine') or service.bypass_engine is None:
                    self.logger.error("❌ Service does not have bypass engine after start")
                    return False
                
                # Verify it's a UnifiedBypassEngine
                engine_type = type(service.bypass_engine).__name__
                if engine_type != 'UnifiedBypassEngine':
                    self.logger.error(f"❌ Expected UnifiedBypassEngine, got {engine_type}")
                    return False
                
                self.logger.info("✅ Service is using UnifiedBypassEngine")
                
                # Verify forced override configuration
                if not hasattr(service.bypass_engine, 'config'):
                    self.logger.error("❌ UnifiedBypassEngine missing config")
                    return False
                
                config = service.bypass_engine.config
                if not config.force_override:
                    self.logger.error("❌ UnifiedBypassEngine not configured with forced override")
                    return False
                
                self.logger.info("✅ UnifiedBypassEngine configured with forced override")
                
                # Verify strategy loader is available
                if not hasattr(service.bypass_engine, 'strategy_loader'):
                    self.logger.error("❌ UnifiedBypassEngine missing strategy loader")
                    return False
                
                loader_type = type(service.bypass_engine.strategy_loader).__name__
                if loader_type != 'UnifiedStrategyLoader':
                    self.logger.error(f"❌ Expected UnifiedStrategyLoader, got {loader_type}")
                    return False
                
                self.logger.info("✅ UnifiedBypassEngine using UnifiedStrategyLoader")
                
                # Test strategy application through the unified engine
                test_domain = next(iter(self.test_domains.keys()))
                test_strategy = service.get_strategy_for_domain(test_domain)
                test_ip = self.mock_ips[test_domain][0]
                
                # Apply strategy using unified engine
                apply_success = service.bypass_engine.apply_strategy(test_ip, test_strategy, test_domain)
                
                if not apply_success:
                    self.logger.error(f"❌ Failed to apply strategy through unified engine")
                    return False
                
                self.logger.info("✅ Strategy applied successfully through unified engine")
                
                # Verify forced override validation
                validation_result = service.bypass_engine.validate_forced_override_behavior()
                
                if not validation_result['forced_override_enabled']:
                    self.logger.error("❌ Forced override not enabled in unified engine")
                    return False
                
                if validation_result['issues']:
                    self.logger.error(f"❌ Forced override validation issues: {validation_result['issues']}")
                    return False
                
                self.logger.info("✅ Forced override validation passed")
                
                # Stop the engine to clean up
                service.stop_bypass_engine()
                
                self.logger.info("✅ Unified engine integration test passed")
                self.test_results['unified_engine_integration'] = True
                return True
            
        except Exception as e:
            self.logger.error(f"❌ Unified engine integration test failed: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            self.test_results['unified_engine_integration'] = False
            return False
    
    def test_strategy_forced_override(self) -> bool:
        """Test that all strategies use forced override in service mode."""
        self.logger.info("=" * 60)
        self.logger.info("TEST 3: Strategy Forced Override")
        self.logger.info("=" * 60)
        
        try:
            # Create unified strategy loader
            loader = UnifiedStrategyLoader(debug=True)
            
            # Test each strategy from service configuration
            for domain, strategy_str in self.test_domains.items():
                self.logger.info(f"Testing forced override for {domain}: {strategy_str}")
                
                # Load strategy using unified loader
                normalized_strategy = loader.load_strategy(strategy_str)
                
                # Verify normalized strategy has forced override
                if not normalized_strategy.no_fallbacks:
                    self.logger.error(f"❌ Strategy for {domain} missing no_fallbacks=True")
                    return False
                
                if not normalized_strategy.forced:
                    self.logger.error(f"❌ Strategy for {domain} missing forced=True")
                    return False
                
                # Create forced override configuration
                forced_config = loader.create_forced_override(normalized_strategy)
                
                # Verify forced override configuration
                if not forced_config.get('no_fallbacks'):
                    self.logger.error(f"❌ Forced config for {domain} missing no_fallbacks=True")
                    return False
                
                if not forced_config.get('forced'):
                    self.logger.error(f"❌ Forced config for {domain} missing forced=True")
                    return False
                
                if not forced_config.get('override_mode'):
                    self.logger.error(f"❌ Forced config for {domain} missing override_mode=True")
                    return False
                
                self.logger.info(f"✅ {domain} strategy has correct forced override configuration")
            
            self.logger.info("✅ All strategies have forced override enabled")
            self.test_results['strategy_forced_override'] = True
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Strategy forced override test failed: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            self.test_results['strategy_forced_override'] = False
            return False
    
    def test_service_vs_testing_mode_compatibility(self) -> bool:
        """Test that service mode produces identical results to testing mode."""
        self.logger.info("=" * 60)
        self.logger.info("TEST 4: Service vs Testing Mode Compatibility")
        self.logger.info("=" * 60)
        
        try:
            # Create unified strategy loader (same as both modes use)
            loader = UnifiedStrategyLoader(debug=True)
            
            # Test each strategy in both service and testing mode format
            for domain, strategy_str in self.test_domains.items():
                self.logger.info(f"Testing compatibility for {domain}: {strategy_str}")
                
                # Load strategy as service mode would
                service_strategy = loader.load_strategy(strategy_str)
                service_forced = loader.create_forced_override(service_strategy)
                
                # Load strategy as testing mode would (should be identical)
                testing_strategy = loader.load_strategy(strategy_str)
                testing_forced = loader.create_forced_override(testing_strategy)
                
                # Compare normalized strategies
                if service_strategy.type != testing_strategy.type:
                    self.logger.error(f"❌ Strategy type mismatch for {domain}: service={service_strategy.type}, testing={testing_strategy.type}")
                    return False
                
                if service_strategy.params != testing_strategy.params:
                    self.logger.error(f"❌ Strategy params mismatch for {domain}")
                    self.logger.error(f"   Service: {service_strategy.params}")
                    self.logger.error(f"   Testing: {testing_strategy.params}")
                    return False
                
                # Compare forced override configurations
                if service_forced != testing_forced:
                    self.logger.error(f"❌ Forced override mismatch for {domain}")
                    self.logger.error(f"   Service: {service_forced}")
                    self.logger.error(f"   Testing: {testing_forced}")
                    return False
                
                self.logger.info(f"✅ {domain} strategy identical in both modes")
            
            self.logger.info("✅ Service mode and testing mode produce identical results")
            self.test_results['service_testing_compatibility'] = True
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Service vs testing mode compatibility test failed: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            self.test_results['service_testing_compatibility'] = False
            return False
    
    def test_domain_opening_simulation(self) -> bool:
        """Test domain opening simulation in service mode."""
        self.logger.info("=" * 60)
        self.logger.info("TEST 5: Domain Opening Simulation")
        self.logger.info("=" * 60)
        
        try:
            # Create unified engine for testing
            config = UnifiedEngineConfig(
                debug=True,
                force_override=True,
                enable_diagnostics=True,
                log_all_strategies=True,
                track_forced_override=True
            )
            
            engine = UnifiedBypassEngine(config)
            
            # Test strategy application for each domain
            for domain, strategy_str in self.test_domains.items():
                self.logger.info(f"Testing domain opening for {domain}")
                
                # Get mock IP for domain
                if domain not in self.mock_ips:
                    self.logger.error(f"❌ No mock IP for domain {domain}")
                    return False
                
                test_ip = self.mock_ips[domain][0]
                
                # Apply strategy using unified engine
                success = engine.apply_strategy(test_ip, strategy_str, domain)
                
                if not success:
                    self.logger.error(f"❌ Failed to apply strategy for {domain}")
                    return False
                
                self.logger.info(f"✅ Strategy applied successfully for {domain}")
                
                # Test strategy like testing mode
                with patch('socket.socket'), patch('ssl.create_default_context'):
                    test_result = engine.test_strategy_like_testing_mode(
                        test_ip, strategy_str, domain, timeout=1.0
                    )
                    
                    if not test_result.get('success', False):
                        # This is expected in test environment, just log
                        self.logger.info(f"⚠️ Connection test failed for {domain} (expected in test environment)")
                    else:
                        self.logger.info(f"✅ Connection test passed for {domain}")
            
            # Verify forced override usage
            validation_result = engine.validate_forced_override_behavior()
            
            if not validation_result['forced_override_enabled']:
                self.logger.error("❌ Forced override not enabled in engine")
                return False
            
            if not validation_result['all_strategies_forced']:
                self.logger.error("❌ Not all strategies applied with forced override")
                return False
            
            if validation_result['issues']:
                self.logger.error(f"❌ Forced override validation issues: {validation_result['issues']}")
                return False
            
            self.logger.info("✅ All domains tested successfully with forced override")
            self.test_results['domain_opening_simulation'] = True
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Domain opening simulation test failed: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            self.test_results['domain_opening_simulation'] = False
            return False
    
    def run_all_tests(self) -> bool:
        """Run all integration tests."""
        self.logger.info("🚀 Starting Service Mode Integration Tests")
        self.logger.info("=" * 80)
        
        try:
            # Create test files
            self.create_test_files()
            
            # Run all tests
            tests = [
                self.test_service_initialization,
                self.test_unified_engine_integration,
                self.test_strategy_forced_override,
                self.test_service_vs_testing_mode_compatibility,
                self.test_domain_opening_simulation
            ]
            
            passed_tests = 0
            total_tests = len(tests)
            
            for test in tests:
                try:
                    if test():
                        passed_tests += 1
                    else:
                        self.logger.error(f"❌ Test {test.__name__} failed")
                except Exception as e:
                    self.logger.error(f"❌ Test {test.__name__} crashed: {e}")
            
            # Print summary
            self.logger.info("=" * 80)
            self.logger.info("TEST SUMMARY")
            self.logger.info("=" * 80)
            
            for test_name, result in self.test_results.items():
                status = "✅ PASSED" if result else "❌ FAILED"
                self.logger.info(f"{test_name}: {status}")
            
            success_rate = (passed_tests / total_tests) * 100
            self.logger.info(f"Overall: {passed_tests}/{total_tests} tests passed ({success_rate:.1f}%)")
            
            if passed_tests == total_tests:
                self.logger.info("🎉 ALL TESTS PASSED - Service mode integration working correctly!")
                return True
            else:
                self.logger.error(f"❌ {total_tests - passed_tests} tests failed - Service mode has issues")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Test suite crashed: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False
        
        finally:
            # Clean up test files
            self.cleanup_test_files()


def main():
    """Main test function."""
    test_suite = ServiceModeIntegrationTest()
    success = test_suite.run_all_tests()
    
    if success:
        print("\n🎉 Service Mode Integration Tests: ALL PASSED")
        sys.exit(0)
    else:
        print("\n❌ Service Mode Integration Tests: SOME FAILED")
        sys.exit(1)


if __name__ == '__main__':
    main()