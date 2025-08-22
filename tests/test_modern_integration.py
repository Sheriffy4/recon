"""
Integration tests for modernized bypass engine components.
Tests the integration between HybridEngine, strategy generation, pool management, and monitoring.
"""
import unittest
from unittest.mock import patch, AsyncMock
import tempfile
from recon.tests.hybrid_engine import HybridEngine
from recon.tests.monitoring_system import MonitoringSystem, MonitoringConfig
from recon.ml.zapret_strategy_generator import ZapretStrategyGenerator
try:
    from recon.tests.bypass.attacks.modern_registry import ModernAttackRegistry
    from recon.tests.bypass.strategies.pool_management import StrategyPoolManager, BypassStrategy
    from recon.tests.bypass.modes.mode_controller import ModeController, OperationMode
    from recon.tests.bypass.validation.reliability_validator import ReliabilityValidator
    MODERN_COMPONENTS_AVAILABLE = True
except ImportError:
    MODERN_COMPONENTS_AVAILABLE = False

class TestModernBypassIntegration(unittest.TestCase):
    """Test integration of modern bypass engine components."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_domain = 'example.com'
        self.test_port = 443
        self.test_ips = {'1.1.1.1'}
        self.dns_cache = {'example.com': '1.1.1.1'}

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @unittest.skipUnless(MODERN_COMPONENTS_AVAILABLE, 'Modern bypass components not available')
    def test_hybrid_engine_modern_initialization(self):
        """Test HybridEngine initialization with modern components."""
        engine = HybridEngine(debug=True, enable_modern_bypass=True)
        self.assertTrue(engine.modern_bypass_enabled)
        self.assertIsNotNone(engine.attack_registry)
        self.assertIsNotNone(engine.pool_manager)
        self.assertIsNotNone(engine.mode_controller)
        self.assertIsNotNone(engine.reliability_validator)
        self.assertIsNotNone(engine.multi_port_handler)
        self.assertIn('modern_engine_tests', engine.bypass_stats)
        self.assertIn('pool_assignments', engine.bypass_stats)
        engine.cleanup()

    @unittest.skipUnless(MODERN_COMPONENTS_AVAILABLE, 'Modern bypass components not available')
    def test_pool_management_integration(self):
        """Test pool management integration with HybridEngine."""
        engine = HybridEngine(debug=True, enable_modern_bypass=True)
        test_strategy = BypassStrategy(id='test_strategy', name='Test Strategy', attacks=['tcp_fragmentation'], parameters={'split_pos': 3, 'ttl': 2})
        success = engine.assign_domain_to_pool(self.test_domain, self.test_port, test_strategy)
        self.assertTrue(success)
        retrieved_strategy = engine.get_pool_strategy_for_domain(self.test_domain, self.test_port)
        self.assertIsNotNone(retrieved_strategy)
        self.assertEqual(retrieved_strategy.name, 'Test Strategy')
        engine.cleanup()

    @unittest.skipUnless(MODERN_COMPONENTS_AVAILABLE, 'Modern bypass components not available')
    def test_mode_controller_integration(self):
        """Test mode controller integration."""
        engine = HybridEngine(debug=True, enable_modern_bypass=True)
        success = engine.switch_bypass_mode(OperationMode.EMULATED)
        self.assertTrue(success)
        self.assertGreater(engine.bypass_stats['mode_switches'], 0)
        engine.cleanup()

    @unittest.skipUnless(MODERN_COMPONENTS_AVAILABLE, 'Modern bypass components not available')
    def test_strategy_generator_registry_integration(self):
        """Test strategy generator integration with attack registry."""
        generator = ZapretStrategyGenerator(use_modern_registry=True)
        if generator.use_modern_registry:
            strategies = generator.generate_strategies(count=10)
            self.assertGreater(len(strategies), 0)
            self.assertLessEqual(len(strategies), 10)
            for strategy in strategies:
                self.assertIn('--dpi-desync', strategy)

    @unittest.skipUnless(MODERN_COMPONENTS_AVAILABLE, 'Modern bypass components not available')
    def test_monitoring_system_modern_integration(self):
        """Test monitoring system integration with modern bypass engine."""
        config = MonitoringConfig(check_interval_seconds=1, enable_auto_recovery=True)
        monitoring = MonitoringSystem(config, enable_modern_bypass=True)
        self.assertTrue(monitoring.modern_bypass_enabled)
        self.assertIsNotNone(monitoring.attack_registry)
        self.assertIsNotNone(monitoring.pool_manager)
        monitoring.add_site(self.test_domain, self.test_port)
        report = monitoring.get_status_report()
        self.assertIn('modern_bypass_enabled', report)
        self.assertIn('monitoring_stats', report)
        self.assertTrue(report['modern_bypass_enabled'])

    @unittest.skipUnless(MODERN_COMPONENTS_AVAILABLE, 'Modern bypass components not available')
    async def test_strategy_testing_with_modern_engine(self):
        """Test strategy testing with modern engine integration."""
        engine = HybridEngine(debug=True, enable_modern_bypass=True)
        test_strategies = ['--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum', '--dpi-desync=multisplit --dpi-desync-split-count=2']
        test_sites = [f'https://{self.test_domain}']
        with patch.object(engine, '_test_sites_connectivity') as mock_test:
            mock_test.return_value = {test_sites[0]: ('WORKING', '1.1.1.1', 100.0, 200)}
            results = await engine.test_strategies_hybrid(strategies=test_strategies, test_sites=test_sites, ips=self.test_ips, dns_cache=self.dns_cache, port=self.test_port, domain=self.test_domain, use_modern_engine=True)
            self.assertGreater(len(results), 0)
            self.assertGreater(engine.bypass_stats['modern_engine_tests'], 0)
        engine.cleanup()

    @unittest.skipUnless(MODERN_COMPONENTS_AVAILABLE, 'Modern bypass components not available')
    def test_comprehensive_stats_collection(self):
        """Test comprehensive statistics collection from all components."""
        engine = HybridEngine(debug=True, enable_modern_bypass=True)
        stats = engine.get_comprehensive_stats()
        self.assertIn('fingerprint_stats', stats)
        self.assertIn('bypass_stats', stats)
        self.assertIn('modern_engine_enabled', stats)
        self.assertTrue(stats['modern_engine_enabled'])
        bypass_stats = stats['bypass_stats']
        self.assertIn('modern_engine_tests', bypass_stats)
        self.assertIn('pool_assignments', bypass_stats)
        engine.cleanup()

    def test_fallback_to_legacy_when_modern_unavailable(self):
        """Test fallback to legacy components when modern components unavailable."""
        engine = HybridEngine(debug=True, enable_modern_bypass=False)
        self.assertFalse(engine.modern_bypass_enabled)
        self.assertIsNone(engine.attack_registry)
        self.assertIsNone(engine.pool_manager)
        self.assertIsNotNone(engine.parser)
        engine.cleanup()

    @unittest.skipUnless(MODERN_COMPONENTS_AVAILABLE, 'Modern bypass components not available')
    async def test_reliability_validation_integration(self):
        """Test reliability validation integration."""
        engine = HybridEngine(debug=True, enable_modern_bypass=True)
        test_strategy = BypassStrategy(id='test_reliability', name='Test Reliability Strategy', attacks=['tcp_fragmentation'], parameters={'split_pos': 3})
        with patch.object(engine.reliability_validator, 'validate_strategy') as mock_validate:
            mock_validate.return_value = AsyncMock()
            mock_validate.return_value.reliability_score = 0.8
            score = engine.validate_strategy_reliability(self.test_domain, test_strategy, self.test_port)
        engine.cleanup()

class TestModernIntegrationEndToEnd(unittest.TestCase):
    """End-to-end integration tests."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @unittest.skipUnless(MODERN_COMPONENTS_AVAILABLE, 'Modern bypass components not available')
    async def test_full_integration_workflow(self):
        """Test full integration workflow from strategy generation to monitoring."""
        engine = HybridEngine(debug=True, enable_modern_bypass=True)
        generator = ZapretStrategyGenerator(use_modern_registry=True)
        config = MonitoringConfig(check_interval_seconds=1)
        monitoring = MonitoringSystem(config, enable_modern_bypass=True)
        try:
            strategies = generator.generate_strategies(count=5)
            self.assertGreater(len(strategies), 0)
            test_strategy = BypassStrategy(id='integration_test', name='Integration Test Strategy', attacks=['tcp_fragmentation'], parameters={'split_pos': 3})
            success = engine.assign_domain_to_pool('test.example.com', 443, test_strategy)
            self.assertTrue(success)
            monitoring.add_site('test.example.com', 443)
            engine_stats = engine.get_comprehensive_stats()
            monitoring_report = monitoring.get_status_report()
            self.assertTrue(engine_stats['modern_engine_enabled'])
            self.assertTrue(monitoring_report['modern_bypass_enabled'])
            self.assertIn('test.example.com:443', monitoring_report['sites'])
        finally:
            engine.cleanup()

def run_integration_tests():
    """Run all integration tests."""
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestModernBypassIntegration))
    suite.addTest(unittest.makeSuite(TestModernIntegrationEndToEnd))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()
if __name__ == '__main__':
    success = run_integration_tests()
    if success:
        print('\n✅ All integration tests passed!')
    else:
        print('\n❌ Some integration tests failed!')
        exit(1)