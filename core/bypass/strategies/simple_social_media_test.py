"""
Simple Test for Social Media Platform Support

This script provides basic testing for the social media bypass handler
to verify core functionality works correctly.
"""
import asyncio
import tempfile
import logging
from pathlib import Path
try:
    from recon.core.bypass.strategies.social_media_handler import SocialMediaBypassHandler, PlatformType
    from recon.core.bypass.strategies.subdomain_handler import SubdomainStrategyHandler
    from recon.core.bypass.strategies.pool_management import BypassStrategy, StrategyPoolManager
except ImportError:
    import sys
    import os
    sys.path.append(os.path.dirname(__file__))
    from social_media_handler import SocialMediaBypassHandler, PlatformType
    from subdomain_handler import SubdomainStrategyHandler
    from pool_management import BypassStrategy
logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger('SimpleSocialMediaTest')

class MockPoolManager:
    """Simple mock pool manager."""

    def get_strategy_for_domain(self, domain: str, port: int=443) -> BypassStrategy:
        return BypassStrategy(id='mock_fallback', name='Mock Fallback Strategy', attacks=['http_manipulation'], parameters={'split_pos': 'midsld'})

async def test_platform_detection():
    """Test basic platform detection."""
    print('Testing platform detection...')
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'test_subdomain.json')
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        config_path = f.name
    try:
        social_handler = SocialMediaBypassHandler(subdomain_handler, config_path)
        test_cases = [('www.youtube.com', PlatformType.YOUTUBE), ('googlevideo.com', PlatformType.YOUTUBE), ('twitter.com', PlatformType.TWITTER), ('twimg.com', PlatformType.TWITTER), ('instagram.com', PlatformType.INSTAGRAM), ('cdninstagram.com', PlatformType.INSTAGRAM), ('tiktok.com', PlatformType.TIKTOK), ('tiktokcdn.com', PlatformType.TIKTOK), ('example.com', PlatformType.GENERIC)]
        success_count = 0
        for domain, expected in test_cases:
            detected = social_handler._detect_platform(domain)
            if detected == expected:
                print(f'  ✅ {domain} -> {detected.value}')
                success_count += 1
            else:
                print(f'  ❌ {domain} -> {detected.value} (expected {expected.value})')
        print(f'Platform detection: {success_count}/{len(test_cases)} passed')
        return success_count == len(test_cases)
    finally:
        Path(config_path).unlink(missing_ok=True)
        Path('test_subdomain.json').unlink(missing_ok=True)

async def test_strategy_optimization():
    """Test strategy optimization for different platforms."""
    print('\nTesting strategy optimization...')
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'test_subdomain.json')
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        config_path = f.name
    try:
        social_handler = SocialMediaBypassHandler(subdomain_handler, config_path)
        test_domains = ['www.youtube.com', 'r1---sn-4g5e6nez.googlevideo.com', 'twitter.com', 'pbs.twimg.com', 'instagram.com', 'scontent.cdninstagram.com', 'www.tiktok.com', 'v16-web.tiktokcdn.com']
        success_count = 0
        for domain in test_domains:
            try:
                strategy = await social_handler.get_optimized_strategy(domain, 443)
                if strategy and strategy.id and strategy.attacks:
                    print(f'  ✅ {domain} -> {strategy.name} ({len(strategy.attacks)} attacks)')
                    success_count += 1
                else:
                    print(f'  ❌ {domain} -> Invalid strategy')
            except Exception as e:
                print(f'  ❌ {domain} -> Error: {e}')
        print(f'Strategy optimization: {success_count}/{len(test_domains)} passed')
        return success_count == len(test_domains)
    finally:
        Path(config_path).unlink(missing_ok=True)
        Path('test_subdomain.json').unlink(missing_ok=True)

async def test_instagram_http_port_handling():
    """Test Instagram HTTP port issue handling."""
    print('\nTesting Instagram HTTP port handling...')
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'test_subdomain.json')
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        config_path = f.name
    try:
        social_handler = SocialMediaBypassHandler(subdomain_handler, config_path)
        strategy_http = await social_handler.optimize_instagram_access('instagram.com', 80)
        http_fix_enabled = strategy_http.parameters.get('http_port_fix', False)
        http_manipulation_added = 'http_manipulation' in strategy_http.attacks
        strategy_https = await social_handler.optimize_instagram_access('instagram.com', 443)
        if http_fix_enabled and http_manipulation_added:
            print('  ✅ Instagram HTTP port (80) handling: ENABLED')
            print('  ✅ HTTP manipulation attack added for port 80')
            return True
        else:
            print('  ❌ Instagram HTTP port handling not working correctly')
            return False
    finally:
        Path(config_path).unlink(missing_ok=True)
        Path('test_subdomain.json').unlink(missing_ok=True)

async def test_effectiveness_testing():
    """Test effectiveness testing functionality."""
    print('\nTesting effectiveness testing...')
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'test_subdomain.json')
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        config_path = f.name
    try:
        social_handler = SocialMediaBypassHandler(subdomain_handler, config_path)
        test_domains = ['www.youtube.com', 'twitter.com', 'instagram.com']
        success_count = 0
        for domain in test_domains:
            try:
                results = await social_handler.test_platform_effectiveness(domain)
                required_fields = ['domain', 'strategy_id', 'tests', 'overall_success', 'success_rate']
                if all((field in results for field in required_fields)):
                    print(f'  ✅ {domain} -> Effectiveness test completed')
                    success_count += 1
                else:
                    print(f'  ❌ {domain} -> Missing required fields in results')
            except Exception as e:
                print(f'  ❌ {domain} -> Error: {e}')
        print(f'Effectiveness testing: {success_count}/{len(test_domains)} passed')
        return success_count == len(test_domains)
    finally:
        Path(config_path).unlink(missing_ok=True)
        Path('test_subdomain.json').unlink(missing_ok=True)

async def test_strategy_recommendations():
    """Test strategy recommendations."""
    print('\nTesting strategy recommendations...')
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'test_subdomain.json')
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        config_path = f.name
    try:
        social_handler = SocialMediaBypassHandler(subdomain_handler, config_path)
        test_domains = ['www.youtube.com', 'r1---sn-4g5e6nez.googlevideo.com', 'pbs.twimg.com', 'scontent.cdninstagram.com']
        success_count = 0
        for domain in test_domains:
            try:
                recommendations = social_handler.get_platform_recommendations(domain)
                if recommendations and len(recommendations) > 0:
                    strategy, confidence, reason = recommendations[0]
                    if strategy.id and 0.0 <= confidence <= 1.0 and reason:
                        print(f'  ✅ {domain} -> {len(recommendations)} recommendations')
                        success_count += 1
                    else:
                        print(f'  ❌ {domain} -> Invalid recommendation format')
                else:
                    print(f'  ❌ {domain} -> No recommendations')
            except Exception as e:
                print(f'  ❌ {domain} -> Error: {e}')
        print(f'Strategy recommendations: {success_count}/{len(test_domains)} passed')
        return success_count == len(test_domains)
    finally:
        Path(config_path).unlink(missing_ok=True)
        Path('test_subdomain.json').unlink(missing_ok=True)

async def main():
    """Run all simple tests."""
    print('🧪 SIMPLE SOCIAL MEDIA HANDLER TESTS')
    print('=' * 50)
    tests = [('Platform Detection', test_platform_detection), ('Strategy Optimization', test_strategy_optimization), ('Instagram HTTP Port Handling', test_instagram_http_port_handling), ('Effectiveness Testing', test_effectiveness_testing), ('Strategy Recommendations', test_strategy_recommendations)]
    passed_tests = 0
    total_tests = len(tests)
    for test_name, test_func in tests:
        try:
            print(f'\n📋 {test_name}')
            print('-' * 30)
            result = await test_func()
            if result:
                passed_tests += 1
                print(f'✅ {test_name}: PASSED')
            else:
                print(f'❌ {test_name}: FAILED')
        except Exception as e:
            print(f'❌ {test_name}: ERROR - {e}')
    print('\n' + '=' * 50)
    print(f'📊 TEST RESULTS: {passed_tests}/{total_tests} PASSED')
    if passed_tests == total_tests:
        print('🎉 ALL TESTS PASSED!')
        return True
    else:
        print('⚠️  SOME TESTS FAILED')
        return False
if __name__ == '__main__':
    success = asyncio.run(main())
    exit(0 if success else 1)