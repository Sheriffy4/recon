"""
Demonstration of Specialized Social Media and Video Platform Support

This script demonstrates the advanced bypass strategies for social media
and video platforms including YouTube, Twitter/X, Instagram, and TikTok.
"""
import asyncio
import logging
from pathlib import Path
try:
    from recon.core.bypass.strategies.social_media_handler import SocialMediaBypassHandler, MediaType, BlockingPattern, PlatformType
    from recon.core.bypass.strategies.subdomain_handler import SubdomainStrategyHandler
    from recon.core.bypass.strategies.pool_management import BypassStrategy, StrategyPoolManager
except ImportError:
    import sys
    import os
    sys.path.append(os.path.dirname(__file__))
    from social_media_handler import SocialMediaBypassHandler, PlatformType
    from subdomain_handler import SubdomainStrategyHandler
    from pool_management import BypassStrategy
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
LOG = logging.getLogger('SocialMediaDemo')

class MockPoolManager:
    """Mock pool manager for demonstration."""

    def get_strategy_for_domain(self, domain: str, port: int=443) -> BypassStrategy:
        """Return a basic fallback strategy."""
        return BypassStrategy(id='fallback_strategy', name='Basic Fallback Strategy', attacks=['http_manipulation', 'tls_evasion'], parameters={'split_pos': 'midsld', 'ttl': 2})

async def demonstrate_platform_detection():
    """Demonstrate platform detection capabilities."""
    print('\n' + '=' * 60)
    print('PLATFORM DETECTION DEMONSTRATION')
    print('=' * 60)
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'demo_subdomain_config.json')
    social_handler = SocialMediaBypassHandler(subdomain_handler, 'demo_social_config.json')
    test_domains = ['www.youtube.com', 'm.youtube.com', 'r1---sn-4g5e6nez.googlevideo.com', 'i.ytimg.com', 'youtube.com/shorts/abc123', 'twitter.com', 'mobile.twitter.com', 'pbs.twimg.com', 'api.twitter.com', 'upload.twitter.com', 'instagram.com', 'www.instagram.com', 'scontent.cdninstagram.com', 'scontent-lga3-2.xx.fbcdn.net', 'i.instagram.com', 'www.tiktok.com', 'v16-web.tiktokcdn.com', 'api.tiktok.com', 'musically.ly', 'example.com', 'google.com', 'facebook.com']
    print(f"{'Domain':<40} {'Platform':<15} {'Confidence'}")
    print('-' * 70)
    for domain in test_domains:
        platform = social_handler._detect_platform(domain)
        confidence = 'High' if platform != PlatformType.GENERIC else 'N/A'
        print(f'{domain:<40} {platform.value:<15} {confidence}')

async def demonstrate_youtube_optimization():
    """Demonstrate YouTube-specific optimizations."""
    print('\n' + '=' * 60)
    print('YOUTUBE OPTIMIZATION DEMONSTRATION')
    print('=' * 60)
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'demo_subdomain_config.json')
    social_handler = SocialMediaBypassHandler(subdomain_handler, 'demo_social_config.json')
    youtube_domains = [('www.youtube.com', 'Main YouTube interface'), ('r1---sn-4g5e6nez.googlevideo.com', 'Video content delivery'), ('i.ytimg.com', 'Thumbnail images'), ('youtube.com/shorts/abc123', 'YouTube Shorts'), ('youtube.com/live/stream123', 'Live streaming')]
    print('YouTube Domain Optimizations:')
    print('-' * 50)
    for domain, description in youtube_domains:
        strategy = await social_handler.optimize_youtube_access(domain)
        print(f'\nDomain: {domain}')
        print(f'Description: {description}')
        print(f'Strategy: {strategy.name}')
        print(f"Attacks: {', '.join(strategy.attacks)}")
        print('Key Parameters:')
        for key, value in strategy.parameters.items():
            if key in ['split_count', 'ttl', 'jitter_ms', 'burst_size', 'video_acceleration', 'mobile_optimization']:
                print(f'  - {key}: {value}')

async def demonstrate_twitter_optimization():
    """Demonstrate Twitter-specific optimizations."""
    print('\n' + '=' * 60)
    print('TWITTER/X OPTIMIZATION DEMONSTRATION')
    print('=' * 60)
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'demo_subdomain_config.json')
    social_handler = SocialMediaBypassHandler(subdomain_handler, 'demo_social_config.json')
    twitter_domains = [('twitter.com', 'Main Twitter interface'), ('mobile.twitter.com', 'Mobile Twitter interface'), ('pbs.twimg.com', 'Twitter media content'), ('api.twitter.com', 'Twitter API'), ('upload.twitter.com', 'Upload service')]
    print('Twitter Domain Optimizations:')
    print('-' * 50)
    for domain, description in twitter_domains:
        strategy = await social_handler.optimize_twitter_access(domain)
        print(f'\nDomain: {domain}')
        print(f'Description: {description}')
        print(f'Strategy: {strategy.name}')
        print(f"Attacks: {', '.join(strategy.attacks)}")
        print('Key Parameters:')
        for key, value in strategy.parameters.items():
            if key in ['split_count', 'ttl', 'media_subdomain_handling', 'image_optimization']:
                print(f'  - {key}: {value}')

async def demonstrate_instagram_optimization():
    """Demonstrate Instagram-specific optimizations."""
    print('\n' + '=' * 60)
    print('INSTAGRAM OPTIMIZATION DEMONSTRATION')
    print('=' * 60)
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'demo_subdomain_config.json')
    social_handler = SocialMediaBypassHandler(subdomain_handler, 'demo_social_config.json')
    instagram_test_cases = [('instagram.com', 443, 'Main Instagram interface (HTTPS)'), ('instagram.com', 80, 'Main Instagram interface (HTTP - with port issues)'), ('scontent.cdninstagram.com', 443, 'Instagram media CDN'), ('instagram.com/stories', 443, 'Instagram Stories'), ('instagram.com/reels', 443, 'Instagram Reels'), ('i.instagram.com', 443, 'Instagram API')]
    print('Instagram Domain Optimizations:')
    print('-' * 50)
    for domain, port, description in instagram_test_cases:
        strategy = await social_handler.optimize_instagram_access(domain, port)
        print(f'\nDomain: {domain}:{port}')
        print(f'Description: {description}')
        print(f'Strategy: {strategy.name}')
        print(f"Attacks: {', '.join(strategy.attacks)}")
        print('Key Parameters:')
        for key, value in strategy.parameters.items():
            if key in ['split_count', 'ttl', 'http_port_fix', 'cdn_optimization', 'jitter_ms']:
                print(f'  - {key}: {value}')
        if port == 80 and strategy.parameters.get('http_port_fix', False):
            print('  ⚠️  HTTP Port Issue Fix: ENABLED')

async def demonstrate_tiktok_optimization():
    """Demonstrate TikTok-specific optimizations."""
    print('\n' + '=' * 60)
    print('TIKTOK OPTIMIZATION DEMONSTRATION')
    print('=' * 60)
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'demo_subdomain_config.json')
    social_handler = SocialMediaBypassHandler(subdomain_handler, 'demo_social_config.json')
    tiktok_domains = [('www.tiktok.com', 'Main TikTok interface'), ('v16-web.tiktokcdn.com', 'TikTok video CDN'), ('tiktok.com/live/stream123', 'TikTok live streaming'), ('api.tiktok.com', 'TikTok API')]
    print('TikTok Domain Optimizations:')
    print('-' * 50)
    for domain, description in tiktok_domains:
        strategy = await social_handler.optimize_tiktok_access(domain)
        print(f'\nDomain: {domain}')
        print(f'Description: {description}')
        print(f'Strategy: {strategy.name}')
        print(f"Attacks: {', '.join(strategy.attacks)}")
        print('Key Parameters:')
        for key, value in strategy.parameters.items():
            if key in ['split_count', 'ttl', 'jitter_ms', 'cdn_rotation_handling', 'mobile_optimization']:
                print(f'  - {key}: {value}')

async def demonstrate_blocking_pattern_detection():
    """Demonstrate blocking pattern detection and optimization."""
    print('\n' + '=' * 60)
    print('BLOCKING PATTERN DETECTION DEMONSTRATION')
    print('=' * 60)
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'demo_subdomain_config.json')
    social_handler = SocialMediaBypassHandler(subdomain_handler, 'demo_social_config.json')
    test_cases = [('r1---sn-4g5e6nez.googlevideo.com', 443, 'YouTube video content'), ('pbs.twimg.com', 443, 'Twitter media'), ('instagram.com', 80, 'Instagram HTTP'), ('v16-web.tiktokcdn.com', 443, 'TikTok CDN')]
    print('Blocking Pattern Detection:')
    print('-' * 40)
    for domain, port, description in test_cases:
        print(f'\nDomain: {domain}:{port}')
        print(f'Description: {description}')
        patterns = await social_handler._detect_blocking_patterns(domain, port)
        print('Detected Patterns:')
        for pattern in patterns:
            print(f'  - {pattern.value}')
        strategy = await social_handler.get_optimized_strategy(domain, port)
        print(f'Optimized Strategy: {strategy.name}')
        print(f"Applied Attacks: {', '.join(strategy.attacks)}")

async def demonstrate_effectiveness_testing():
    """Demonstrate comprehensive effectiveness testing."""
    print('\n' + '=' * 60)
    print('EFFECTIVENESS TESTING DEMONSTRATION')
    print('=' * 60)
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'demo_subdomain_config.json')
    social_handler = SocialMediaBypassHandler(subdomain_handler, 'demo_social_config.json')
    test_domains = ['www.youtube.com', 'r1---sn-4g5e6nez.googlevideo.com', 'twitter.com', 'pbs.twimg.com', 'instagram.com', 'www.tiktok.com']
    print('Platform Effectiveness Testing:')
    print('-' * 40)
    for domain in test_domains:
        print(f'\nTesting: {domain}')
        platform = social_handler._detect_platform(domain)
        print(f'Platform: {platform.value}')
        results = await social_handler.test_platform_effectiveness(domain)
        print(f"Overall Success: {('✅' if results['overall_success'] else '❌')}")
        print(f"Success Rate: {results['success_rate']:.1%}")
        for test_name, test_result in results['tests'].items():
            status = '✅' if test_result.get('success', False) else '❌'
            print(f'  {test_name}: {status}')
            if test_name == 'speed' and test_result.get('success', False):
                improvement = test_result.get('improvement_percent', 0)
                print(f'    Speed Improvement: {improvement:.1f}%')
            elif test_name == 'connectivity' and test_result.get('success', False):
                latency = test_result.get('latency_ms', 0)
                print(f'    Latency: {latency:.1f}ms')

async def demonstrate_strategy_recommendations():
    """Demonstrate strategy recommendations."""
    print('\n' + '=' * 60)
    print('STRATEGY RECOMMENDATIONS DEMONSTRATION')
    print('=' * 60)
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'demo_subdomain_config.json')
    social_handler = SocialMediaBypassHandler(subdomain_handler, 'demo_social_config.json')
    test_domains = ['www.youtube.com', 'r1---sn-4g5e6nez.googlevideo.com', 'pbs.twimg.com', 'scontent.cdninstagram.com', 'v16-web.tiktokcdn.com']
    print('Strategy Recommendations:')
    print('-' * 30)
    for domain in test_domains:
        print(f'\nDomain: {domain}')
        recommendations = social_handler.get_platform_recommendations(domain)
        for i, (strategy, confidence, reason) in enumerate(recommendations[:3], 1):
            print(f'  {i}. {strategy.name}')
            print(f'     Confidence: {confidence:.1%}')
            print(f'     Reason: {reason}')
            print(f"     Attacks: {', '.join(strategy.attacks[:3])}{('...' if len(strategy.attacks) > 3 else '')}")

async def demonstrate_configuration_management():
    """Demonstrate configuration persistence."""
    print('\n' + '=' * 60)
    print('CONFIGURATION MANAGEMENT DEMONSTRATION')
    print('=' * 60)
    pool_manager = MockPoolManager()
    subdomain_handler = SubdomainStrategyHandler(pool_manager, 'demo_subdomain_config.json')
    social_handler = SocialMediaBypassHandler(subdomain_handler, 'demo_social_config.json')
    print('Configuration Management:')
    print('-' * 30)
    test_domains = ['www.youtube.com', 'twitter.com', 'instagram.com']
    for domain in test_domains:
        await social_handler.test_platform_effectiveness(domain)
    stats = social_handler.get_platform_statistics() if hasattr(social_handler, 'get_platform_statistics') else {}
    print(f'Total Platform Strategies: {len(social_handler.platform_strategies)}')
    if social_handler.platform_strategies:
        print('\nPlatform Strategy Summary:')
        for key, platform_strategy in list(social_handler.platform_strategies.items())[:5]:
            print(f'  - {platform_strategy.platform.value}: {platform_strategy.strategy.name}')
            print(f'    Effectiveness: {platform_strategy.effectiveness_score:.1%}')
            if platform_strategy.avg_speed_improvement > 0:
                print(f'    Speed Improvement: {platform_strategy.avg_speed_improvement:.1f}%')
    social_handler._save_configuration()
    print(f'\nConfiguration saved to: {social_handler.config_path}')
    config_file = Path(social_handler.config_path)
    if config_file.exists():
        file_size = config_file.stat().st_size
        print(f'Configuration file size: {file_size} bytes')

async def cleanup_demo_files():
    """Clean up demonstration files."""
    demo_files = ['demo_subdomain_config.json', 'demo_social_config.json']
    for file_path in demo_files:
        try:
            Path(file_path).unlink(missing_ok=True)
        except Exception as e:
            LOG.warning(f'Failed to cleanup {file_path}: {e}')

async def main():
    """Run all demonstrations."""
    print('🚀 SOCIAL MEDIA BYPASS HANDLER DEMONSTRATION')
    print('=' * 80)
    print('This demonstration shows specialized bypass strategies for:')
    print('• YouTube (web interface, video content, shorts, live streams)')
    print('• Twitter/X (web interface, media content, API)')
    print('• Instagram (web interface, media CDN, stories, reels, HTTP port issues)')
    print('• TikTok (web interface, video CDN, live streams)')
    print('• Advanced blocking pattern detection and optimization')
    print('• Comprehensive effectiveness testing')
    try:
        await demonstrate_platform_detection()
        await demonstrate_youtube_optimization()
        await demonstrate_twitter_optimization()
        await demonstrate_instagram_optimization()
        await demonstrate_tiktok_optimization()
        await demonstrate_blocking_pattern_detection()
        await demonstrate_effectiveness_testing()
        await demonstrate_strategy_recommendations()
        await demonstrate_configuration_management()
        print('\n' + '=' * 80)
        print('✅ DEMONSTRATION COMPLETED SUCCESSFULLY')
        print('=' * 80)
        print('\nKey Features Demonstrated:')
        print('• Platform-specific strategy optimization')
        print('• Blocking pattern detection and mitigation')
        print('• Comprehensive effectiveness testing')
        print('• Strategy recommendations with confidence scores')
        print('• Configuration persistence and management')
        print('• Instagram HTTP port issue handling')
        print('• YouTube video acceleration optimizations')
        print('• Twitter media subdomain specialized handling')
        print('• TikTok CDN rotation support')
    except Exception as e:
        LOG.error(f'Demonstration failed: {e}')
        raise
    finally:
        await cleanup_demo_files()
if __name__ == '__main__':
    asyncio.run(main())