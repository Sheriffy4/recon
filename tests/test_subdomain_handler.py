"""
Comprehensive tests for subdomain-specific strategy support.
"""
import unittest
import tempfile
import os
try:
    from core.bypass.strategies.subdomain_handler import SubdomainStrategyHandler, EnhancedPoolManager, SubdomainType, PlatformType, SubdomainPattern, SubdomainStrategy, PlatformConfiguration, analyze_subdomain_structure, suggest_subdomain_tests
    from core.bypass.strategies.pool_management import BypassStrategy, StrategyPoolManager
except ImportError:
    import sys
    sys.path.append(os.path.dirname(__file__))
    from core.bypass.strategies.subdomain_handler import SubdomainStrategyHandler, EnhancedPoolManager, SubdomainType, PlatformType, SubdomainPattern, SubdomainStrategy, analyze_subdomain_structure, suggest_subdomain_tests
    from pool_management import BypassStrategy, StrategyPoolManager

class TestSubdomainPattern(unittest.TestCase):
    """Test subdomain pattern matching."""

    def setUp(self):
        self.youtube_pattern = SubdomainPattern(pattern='^www\\.youtube\\.com$', subdomain_type=SubdomainType.WEB_INTERFACE, platform=PlatformType.YOUTUBE, description='Main YouTube interface')
        self.video_pattern = SubdomainPattern(pattern='^.*\\.googlevideo\\.com$', subdomain_type=SubdomainType.MEDIA_CONTENT, platform=PlatformType.YOUTUBE, description='YouTube video content')

    def test_exact_match(self):
        """Test exact domain matching."""
        self.assertTrue(self.youtube_pattern.matches('www.youtube.com'))
        self.assertFalse(self.youtube_pattern.matches('m.youtube.com'))
        self.assertFalse(self.youtube_pattern.matches('youtube.com'))

    def test_wildcard_match(self):
        """Test wildcard domain matching."""
        self.assertTrue(self.video_pattern.matches('r1---sn-4g5e6nls.googlevideo.com'))
        self.assertTrue(self.video_pattern.matches('r2---sn-4g5lh7ne.googlevideo.com'))
        self.assertFalse(self.video_pattern.matches('youtube.com'))

    def test_case_insensitive(self):
        """Test case insensitive matching."""
        self.assertTrue(self.youtube_pattern.matches('WWW.YOUTUBE.COM'))
        self.assertTrue(self.youtube_pattern.matches('Www.YouTube.Com'))

class TestSubdomainStrategy(unittest.TestCase):
    """Test subdomain strategy functionality."""

    def setUp(self):
        self.strategy = BypassStrategy(id='test_strategy', name='Test Strategy', attacks=['tcp_fragmentation'], parameters={'split_pos': 3})
        self.subdomain_strategy = SubdomainStrategy(subdomain='www.youtube.com', subdomain_type=SubdomainType.WEB_INTERFACE, platform=PlatformType.YOUTUBE, strategy=self.strategy)

    def test_metrics_update_success(self):
        """Test metrics update on successful test."""
        self.subdomain_strategy.update_metrics(True, 150.0)
        self.assertEqual(self.subdomain_strategy.test_count, 1)
        self.assertEqual(self.subdomain_strategy.failure_count, 0)
        self.assertEqual(self.subdomain_strategy.success_rate, 1.0)
        self.assertEqual(self.subdomain_strategy.avg_latency_ms, 150.0)
        self.assertIsNotNone(self.subdomain_strategy.last_tested)

    def test_metrics_update_failure(self):
        """Test metrics update on failed test."""
        self.subdomain_strategy.update_metrics(False, 500.0)
        self.assertEqual(self.subdomain_strategy.test_count, 1)
        self.assertEqual(self.subdomain_strategy.failure_count, 1)
        self.assertEqual(self.subdomain_strategy.success_rate, 0.0)
        self.assertEqual(self.subdomain_strategy.avg_latency_ms, 500.0)

    def test_metrics_update_multiple(self):
        """Test metrics update with multiple tests."""
        self.subdomain_strategy.update_metrics(True, 100.0)
        self.subdomain_strategy.update_metrics(False, 200.0)
        self.subdomain_strategy.update_metrics(True, 150.0)
        self.assertEqual(self.subdomain_strategy.test_count, 3)
        self.assertEqual(self.subdomain_strategy.failure_count, 1)
        self.assertAlmostEqual(self.subdomain_strategy.success_rate, 2 / 3, places=2)
        self.assertGreater(self.subdomain_strategy.avg_latency_ms, 100.0)
        self.assertLess(self.subdomain_strategy.avg_latency_ms, 200.0)

class TestSubdomainStrategyHandler(unittest.TestCase):
    """Test subdomain strategy handler functionality."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, 'test_subdomain_config.json')
        self.pool_manager = StrategyPoolManager()
        self.handler = SubdomainStrategyHandler(self.pool_manager, self.config_path)

    def tearDown(self):
        if os.path.exists(self.config_path):
            os.remove(self.config_path)
        os.rmdir(self.temp_dir)

    def test_platform_detection(self):
        """Test platform detection from domains."""
        test_cases = [('www.youtube.com', PlatformType.YOUTUBE), ('r1---sn-4g5e6nls.googlevideo.com', PlatformType.YOUTUBE), ('twitter.com', PlatformType.TWITTER), ('pbs.twimg.com', PlatformType.TWITTER), ('instagram.com', PlatformType.INSTAGRAM), ('scontent.cdninstagram.com', PlatformType.INSTAGRAM), ('tiktok.com', PlatformType.TIKTOK), ('example.com', PlatformType.GENERIC)]
        for domain, expected_platform in test_cases:
            detected_platform = self.handler._detect_platform(domain)
            self.assertEqual(detected_platform, expected_platform, f'Failed for domain: {domain}')

    def test_subdomain_type_detection(self):
        """Test subdomain type detection."""
        test_cases = [('www.youtube.com', PlatformType.YOUTUBE, SubdomainType.WEB_INTERFACE), ('r1---sn-4g5e6nls.googlevideo.com', PlatformType.YOUTUBE, SubdomainType.MEDIA_CONTENT), ('i.ytimg.com', PlatformType.YOUTUBE, SubdomainType.STATIC_ASSETS), ('pbs.twimg.com', PlatformType.TWITTER, SubdomainType.MEDIA_CONTENT), ('api.twitter.com', PlatformType.TWITTER, SubdomainType.API_ENDPOINT), ('upload.twitter.com', PlatformType.TWITTER, SubdomainType.UPLOAD)]
        for domain, platform, expected_type in test_cases:
            detected_type = self.handler._get_subdomain_type(domain, platform)
            self.assertEqual(detected_type, expected_type, f'Failed for domain: {domain}')

    def test_strategy_retrieval_youtube(self):
        """Test strategy retrieval for YouTube domains."""
        test_domains = ['www.youtube.com', 'm.youtube.com', 'r1---sn-4g5e6nls.googlevideo.com', 'i.ytimg.com']
        for domain in test_domains:
            strategy = self.handler.get_strategy_for_subdomain(domain)
            self.assertIsNotNone(strategy, f'No strategy found for {domain}')
            self.assertIn('youtube', strategy.id.lower(), f"Strategy ID should contain 'youtube' for {domain}")

    def test_strategy_retrieval_twitter(self):
        """Test strategy retrieval for Twitter domains."""
        test_domains = ['twitter.com', 'mobile.twitter.com', 'pbs.twimg.com', 'api.twitter.com', 'upload.twitter.com']
        for domain in test_domains:
            strategy = self.handler.get_strategy_for_subdomain(domain)
            self.assertIsNotNone(strategy, f'No strategy found for {domain}')
            self.assertIn('twitter', strategy.id.lower(), f"Strategy ID should contain 'twitter' for {domain}")

    def test_strategy_retrieval_instagram(self):
        """Test strategy retrieval for Instagram domains."""
        test_domains = ['www.instagram.com', 'scontent.cdninstagram.com', 'i.instagram.com']
        for domain in test_domains:
            strategy = self.handler.get_strategy_for_subdomain(domain)
            self.assertIsNotNone(strategy, f'No strategy found for {domain}')
            self.assertIn('instagram', strategy.id.lower(), f"Strategy ID should contain 'instagram' for {domain}")

    def test_custom_strategy_setting(self):
        """Test setting custom strategies for subdomains."""
        domain = 'test.youtube.com'
        custom_strategy = BypassStrategy(id='custom_test', name='Custom Test Strategy', attacks=['http_manipulation'], parameters={'split_pos': 5})
        success = self.handler.set_subdomain_strategy(domain, custom_strategy)
        self.assertTrue(success)
        retrieved_strategy = self.handler.get_strategy_for_subdomain(domain)
        self.assertIsNotNone(retrieved_strategy)
        self.assertEqual(retrieved_strategy.id, custom_strategy.id)
        self.assertEqual(retrieved_strategy.name, custom_strategy.name)

    def test_strategy_testing(self):
        """Test strategy testing functionality."""
        domain = 'www.youtube.com'
        result = self.handler.test_subdomain_strategy(domain)
        self.assertIn('success', result)
        self.assertIn('latency_ms', result)
        self.assertIn('strategy_id', result)
        self.assertIn('timestamp', result)
        self.assertIsInstance(result['success'], bool)
        self.assertIsInstance(result['latency_ms'], (int, float))

    def test_auto_discovery(self):
        """Test subdomain auto-discovery."""
        base_domains = ['youtube.com', 'twitter.com', 'instagram.com']
        for base_domain in base_domains:
            discovered = self.handler.auto_discover_subdomains(base_domain)
            self.assertIsInstance(discovered, list)
            if base_domain != 'example.com':
                self.assertGreater(len(discovered), 0, f'Should discover subdomains for {base_domain}')

    def test_recommendations(self):
        """Test strategy recommendations."""
        test_domains = ['www.youtube.com', 'pbs.twimg.com', 'scontent.cdninstagram.com']
        for domain in test_domains:
            recommendations = self.handler.get_subdomain_recommendations(domain)
            self.assertIsInstance(recommendations, list)
            self.assertGreater(len(recommendations), 0, f'Should have recommendations for {domain}')
            for strategy, confidence in recommendations:
                self.assertIsInstance(strategy, BypassStrategy)
                self.assertIsInstance(confidence, (int, float))
                self.assertGreaterEqual(confidence, 0.0)
                self.assertLessEqual(confidence, 1.0)

    def test_configuration_persistence(self):
        """Test configuration saving and loading."""
        domain = 'test.example.com'
        strategy = BypassStrategy(id='test_persist', name='Test Persistence Strategy', attacks=['tcp_fragmentation'], parameters={'split_pos': 3})
        self.handler.set_subdomain_strategy(domain, strategy)
        new_handler = SubdomainStrategyHandler(self.pool_manager, self.config_path)
        retrieved_strategy = new_handler.get_strategy_for_subdomain(domain)
        self.assertIsNotNone(retrieved_strategy)
        self.assertEqual(retrieved_strategy.id, strategy.id)
        self.assertEqual(retrieved_strategy.name, strategy.name)

    def test_platform_statistics(self):
        """Test platform statistics generation."""
        test_strategies = [('www.youtube.com', PlatformType.YOUTUBE, SubdomainType.WEB_INTERFACE), ('pbs.twimg.com', PlatformType.TWITTER, SubdomainType.MEDIA_CONTENT), ('instagram.com', PlatformType.INSTAGRAM, SubdomainType.WEB_INTERFACE)]
        for domain, platform, subdomain_type in test_strategies:
            strategy = BypassStrategy(id=f'test_{domain}', name=f'Test Strategy for {domain}', attacks=['tcp_fragmentation'])
            self.handler.set_subdomain_strategy(domain, strategy, platform, subdomain_type)
        stats = self.handler.get_platform_statistics()
        self.assertIn('total_subdomains', stats)
        self.assertIn('platforms', stats)
        self.assertIn('subdomain_types', stats)
        self.assertEqual(stats['total_subdomains'], 3)
        self.assertIn('youtube', stats['platforms'])
        self.assertIn('twitter', stats['platforms'])
        self.assertIn('instagram', stats['platforms'])

class TestEnhancedPoolManager(unittest.TestCase):
    """Test enhanced pool manager with subdomain support."""

    def setUp(self):
        self.manager = EnhancedPoolManager()

    def test_enhanced_strategy_resolution(self):
        """Test enhanced strategy resolution with subdomain support."""
        test_domains = ['www.youtube.com', 'r1---sn-4g5e6nls.googlevideo.com', 'twitter.com', 'pbs.twimg.com', 'instagram.com']
        for domain in test_domains:
            strategy = self.manager.get_strategy_for_domain(domain)
            self.assertIsNotNone(strategy, f'Should find strategy for {domain}')

    def test_subdomain_strategy_setting(self):
        """Test setting subdomain strategies through enhanced manager."""
        domain = 'test.youtube.com'
        strategy = BypassStrategy(id='enhanced_test', name='Enhanced Test Strategy', attacks=['http_manipulation'])
        success = self.manager.set_subdomain_strategy(domain, strategy)
        self.assertTrue(success)
        retrieved = self.manager.get_strategy_for_domain(domain)
        self.assertEqual(retrieved.id, strategy.id)

    def test_subdomain_testing(self):
        """Test subdomain strategy testing through enhanced manager."""
        domain = 'www.youtube.com'
        result = self.manager.test_subdomain_strategy(domain)
        self.assertIn('success', result)
        self.assertIn('latency_ms', result)

    def test_subdomain_recommendations(self):
        """Test subdomain recommendations through enhanced manager."""
        domain = 'www.youtube.com'
        recommendations = self.manager.get_subdomain_recommendations(domain)
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)

class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions for subdomain analysis."""

    def test_analyze_subdomain_structure(self):
        """Test subdomain structure analysis."""
        test_cases = [{'domain': 'www.youtube.com', 'expected': {'depth': 1, 'tld': 'com', 'sld': 'youtube', 'is_subdomain': True, 'subdomains': ['www']}}, {'domain': 'r1---sn-4g5e6nls.googlevideo.com', 'expected': {'depth': 1, 'tld': 'com', 'sld': 'googlevideo', 'is_subdomain': True, 'subdomains': ['r1---sn-4g5e6nls']}}, {'domain': 'youtube.com', 'expected': {'depth': 0, 'tld': 'com', 'sld': 'youtube', 'is_subdomain': False, 'subdomains': []}}]
        for test_case in test_cases:
            analysis = analyze_subdomain_structure(test_case['domain'])
            expected = test_case['expected']
            self.assertEqual(analysis['depth'], expected['depth'])
            self.assertEqual(analysis['tld'], expected['tld'])
            self.assertEqual(analysis['sld'], expected['sld'])
            self.assertEqual(analysis['is_subdomain'], expected['is_subdomain'])
            self.assertEqual(analysis['subdomains'], expected['subdomains'])

    def test_suggest_subdomain_tests(self):
        """Test subdomain test suggestions."""
        test_domains = ['www.youtube.com', 'r1---sn-4g5e6nls.googlevideo.com', 'pbs.twimg.com']
        for domain in test_domains:
            tests = suggest_subdomain_tests(domain)
            self.assertIsInstance(tests, list)
            self.assertGreater(len(tests), 0, f'Should suggest tests for {domain}')
            for test in tests:
                self.assertIn('type', test)
                self.assertIn('description', test)

class TestIntegration(unittest.TestCase):
    """Integration tests for subdomain strategy support."""

    def setUp(self):
        self.manager = EnhancedPoolManager()

    def test_youtube_integration(self):
        """Test complete YouTube subdomain integration."""
        youtube_domains = ['www.youtube.com', 'm.youtube.com', 'r1---sn-4g5e6nls.googlevideo.com', 'i.ytimg.com']
        for domain in youtube_domains:
            strategy = self.manager.get_strategy_for_domain(domain)
            self.assertIsNotNone(strategy)
            result = self.manager.test_subdomain_strategy(domain)
            self.assertIn('success', result)
            recommendations = self.manager.get_subdomain_recommendations(domain)
            self.assertGreater(len(recommendations), 0)

    def test_twitter_integration(self):
        """Test complete Twitter subdomain integration."""
        twitter_domains = ['twitter.com', 'mobile.twitter.com', 'pbs.twimg.com', 'api.twitter.com']
        for domain in twitter_domains:
            strategy = self.manager.get_strategy_for_domain(domain)
            self.assertIsNotNone(strategy)
            result = self.manager.test_subdomain_strategy(domain)
            self.assertIn('success', result)

    def test_instagram_integration(self):
        """Test complete Instagram subdomain integration."""
        instagram_domains = ['www.instagram.com', 'scontent.cdninstagram.com', 'i.instagram.com']
        for domain in instagram_domains:
            strategy = self.manager.get_strategy_for_domain(domain)
            self.assertIsNotNone(strategy)
            result = self.manager.test_subdomain_strategy(domain)
            self.assertIn('success', result)

    def test_cross_platform_consistency(self):
        """Test consistency across different platforms."""
        test_domains = [('www.youtube.com', 'youtube'), ('twitter.com', 'twitter'), ('instagram.com', 'instagram'), ('tiktok.com', 'tiktok')]
        for domain, platform_name in test_domains:
            strategy = self.manager.get_strategy_for_domain(domain)
            self.assertIsNotNone(strategy)
            self.assertIn(platform_name, strategy.id.lower())

    def test_fallback_behavior(self):
        """Test fallback behavior for unknown domains."""
        unknown_domains = ['unknown.example.com', 'test.unknown-platform.org']
        for domain in unknown_domains:
            strategy = self.manager.get_strategy_for_domain(domain)

def run_simple_test():
    """Run a simple test to verify basic functionality."""
    print('Running simple subdomain handler test...')
    try:
        manager = EnhancedPoolManager()
        youtube_strategy = manager.get_strategy_for_domain('www.youtube.com')
        print(f"✅ YouTube strategy: {(youtube_strategy.name if youtube_strategy else 'None')}")
        twitter_strategy = manager.get_strategy_for_domain('pbs.twimg.com')
        print(f"✅ Twitter media strategy: {(twitter_strategy.name if twitter_strategy else 'None')}")
        instagram_strategy = manager.get_strategy_for_domain('scontent.cdninstagram.com')
        print(f"✅ Instagram media strategy: {(instagram_strategy.name if instagram_strategy else 'None')}")
        analysis = analyze_subdomain_structure('r1---sn-4g5e6nls.googlevideo.com')
        print(f"✅ Subdomain analysis depth: {analysis['depth']}")
        recommendations = manager.get_subdomain_recommendations('www.youtube.com')
        print(f'✅ YouTube recommendations: {len(recommendations)} strategies')
        print('✅ Simple subdomain handler test passed!')
        return True
    except Exception as e:
        print(f'❌ Simple test failed: {e}')
        return False
if __name__ == '__main__':
    if run_simple_test():
        print('\n' + '=' * 50)
        print('Running comprehensive test suite...')
        unittest.main(verbosity=2)
    else:
        print('❌ Simple test failed, skipping comprehensive tests')