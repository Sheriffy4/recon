#!/usr/bin/env python3
"""
Demo script showcasing subdomain-specific strategy support.
"""

import sys
import os
import json
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))


def demo_subdomain_support():
    """Demonstrate subdomain-specific strategy support capabilities."""
    print("🚀 Subdomain-Specific Strategy Support Demo")
    print("=" * 60)

    try:
        import subdomain_handler

        # Create enhanced pool manager
        manager = subdomain_handler.EnhancedPoolManager()
        print("✅ Enhanced Pool Manager initialized with subdomain support")

        # Demo 1: YouTube Platform Support
        print("\n📺 YouTube Platform Support Demo")
        print("-" * 40)

        youtube_subdomains = {
            "www.youtube.com": "Main YouTube web interface",
            "m.youtube.com": "Mobile YouTube interface",
            "r1---sn-4g5e6nls.googlevideo.com": "YouTube video content server",
            "r2---sn-4g5lh7ne.googlevideo.com": "Another video content server",
            "i.ytimg.com": "YouTube thumbnail images",
            "s.ytimg.com": "YouTube static assets",
        }

        for domain, description in youtube_subdomains.items():
            strategy = manager.get_strategy_for_domain(domain)
            if strategy:
                print(f"  {domain}")
                print(f"    Description: {description}")
                print(f"    Strategy: {strategy.name}")
                print(f"    Attacks: {', '.join(strategy.attacks)}")
                print(f"    Parameters: {strategy.parameters}")
                print()

        # Demo 2: Twitter Platform Support
        print("🐦 Twitter Platform Support Demo")
        print("-" * 40)

        twitter_subdomains = {
            "twitter.com": "Main Twitter interface",
            "mobile.twitter.com": "Mobile Twitter interface",
            "pbs.twimg.com": "Twitter media content (images)",
            "video.twimg.com": "Twitter video content",
            "api.twitter.com": "Twitter API endpoint",
            "upload.twitter.com": "Twitter upload service",
            "abs.twimg.com": "Twitter static assets",
        }

        for domain, description in twitter_subdomains.items():
            strategy = manager.get_strategy_for_domain(domain)
            if strategy:
                print(f"  {domain}")
                print(f"    Description: {description}")
                print(f"    Strategy: {strategy.name}")
                print(f"    Attacks: {', '.join(strategy.attacks)}")
                print(f"    Parameters: {strategy.parameters}")
                print()

        # Demo 3: Instagram Platform Support
        print("📷 Instagram Platform Support Demo")
        print("-" * 40)

        instagram_subdomains = {
            "www.instagram.com": "Main Instagram interface",
            "scontent.cdninstagram.com": "Instagram media CDN",
            "scontent-lhr8-1.cdninstagram.com": "Regional Instagram CDN",
            "i.instagram.com": "Instagram API endpoint",
            "upload.instagram.com": "Instagram upload service",
        }

        for domain, description in instagram_subdomains.items():
            strategy = manager.get_strategy_for_domain(domain)
            if strategy:
                print(f"  {domain}")
                print(f"    Description: {description}")
                print(f"    Strategy: {strategy.name}")
                print(f"    Attacks: {', '.join(strategy.attacks)}")
                print(f"    Parameters: {strategy.parameters}")
                print()

        # Demo 4: TikTok Platform Support
        print("🎵 TikTok Platform Support Demo")
        print("-" * 40)

        tiktok_subdomains = {
            "www.tiktok.com": "Main TikTok interface",
            "v16-web.tiktokcdn.com": "TikTok video CDN",
            "p16-sign-va.tiktokcdn.com": "TikTok signed content CDN",
            "api.tiktok.com": "TikTok API endpoint",
        }

        for domain, description in tiktok_subdomains.items():
            strategy = manager.get_strategy_for_domain(domain)
            if strategy:
                print(f"  {domain}")
                print(f"    Description: {description}")
                print(f"    Strategy: {strategy.name}")
                print(f"    Attacks: {', '.join(strategy.attacks)}")
                print(f"    Parameters: {strategy.parameters}")
                print()

        # Demo 5: Custom Strategy Configuration
        print("⚙️  Custom Strategy Configuration Demo")
        print("-" * 40)

        # Set custom strategy for a specific subdomain
        custom_domain = "custom.youtube.com"
        custom_strategy = subdomain_handler.BypassStrategy(
            id="custom_youtube_experimental",
            name="Custom YouTube Experimental Strategy",
            attacks=["tcp_fragmentation", "http_manipulation", "packet_timing"],
            parameters={
                "split_count": 10,
                "ttl": 5,
                "fake_sni": True,
                "timing_jitter": 50,
            },
        )

        success = manager.set_subdomain_strategy(custom_domain, custom_strategy)
        if success:
            print(f"✅ Set custom strategy for {custom_domain}")
            retrieved = manager.get_strategy_for_domain(custom_domain)
            print(f"  Strategy: {retrieved.name}")
            print(f"  Attacks: {', '.join(retrieved.attacks)}")
            print(f"  Parameters: {retrieved.parameters}")

        # Demo 6: Strategy Recommendations
        print("\n💡 Strategy Recommendations Demo")
        print("-" * 40)

        test_domains = [
            "www.youtube.com",
            "pbs.twimg.com",
            "scontent.cdninstagram.com",
            "v16-web.tiktokcdn.com",
        ]

        for domain in test_domains:
            recommendations = manager.get_subdomain_recommendations(domain)
            print(f"Recommendations for {domain}:")
            for i, (strategy, confidence) in enumerate(recommendations[:3], 1):
                print(f"  {i}. {strategy.name} (confidence: {confidence:.2f})")
                print(f"     Attacks: {', '.join(strategy.attacks)}")
            print()

        # Demo 7: Subdomain Analysis
        print("🔍 Subdomain Analysis Demo")
        print("-" * 40)

        analysis_domains = [
            "www.youtube.com",
            "r1---sn-4g5e6nls.googlevideo.com",
            "scontent-lhr8-1.cdninstagram.com",
            "p16-sign-va.tiktokcdn.com",
        ]

        for domain in analysis_domains:
            analysis = subdomain_handler.analyze_subdomain_structure(domain)
            print(f"Analysis for {domain}:")
            print(f"  Depth: {analysis['depth']} levels")
            print(f"  TLD: {analysis['tld']}")
            print(f"  SLD: {analysis['sld']}")
            print(f"  Subdomains: {analysis['subdomains']}")
            print(f"  Is subdomain: {analysis['is_subdomain']}")
            print()

        # Demo 8: Strategy Testing
        print("🧪 Strategy Testing Demo")
        print("-" * 40)

        test_domains_for_testing = [
            "www.youtube.com",
            "pbs.twimg.com",
            "scontent.cdninstagram.com",
        ]

        for domain in test_domains_for_testing:
            result = manager.test_subdomain_strategy(domain)
            print(f"Test result for {domain}:")
            print(f"  Success: {'✅' if result['success'] else '❌'}")
            print(f"  Latency: {result['latency_ms']:.1f}ms")
            print(f"  Strategy: {result['strategy_id']}")
            print(f"  Timestamp: {result['timestamp']}")
            print()

        # Demo 9: Platform Statistics
        print("📊 Platform Statistics Demo")
        print("-" * 40)

        stats = manager.subdomain_handler.get_platform_statistics()
        print(f"Total configured subdomains: {stats['total_subdomains']}")
        print("\nSubdomains by platform:")
        for platform, count in stats["platforms"].items():
            print(f"  {platform.capitalize()}: {count} subdomains")

        print("\nSubdomains by type:")
        for subdomain_type, count in stats["subdomain_types"].items():
            print(f"  {subdomain_type.replace('_', ' ').title()}: {count} subdomains")

        if stats["success_rates"]:
            print("\nAverage success rates by platform:")
            for platform, rate in stats["success_rates"].items():
                print(f"  {platform.capitalize()}: {rate:.1%}")

        # Demo 10: Auto-Discovery
        print("\n🔎 Auto-Discovery Demo")
        print("-" * 40)

        base_domains = ["youtube.com", "twitter.com", "instagram.com", "tiktok.com"]

        for base_domain in base_domains:
            discovered = manager.subdomain_handler.auto_discover_subdomains(base_domain)
            if discovered:
                print(f"Auto-discovered subdomains for {base_domain}:")
                for subdomain in discovered[:5]:  # Show first 5
                    print(f"  - {subdomain}")
                if len(discovered) > 5:
                    print(f"  ... and {len(discovered) - 5} more")
                print()

        # Demo 11: Configuration Export
        print("💾 Configuration Export Demo")
        print("-" * 40)

        # Export current configuration
        config_data = {
            "subdomain_strategies": {},
            "platform_statistics": stats,
            "export_timestamp": datetime.now().isoformat(),
        }

        # Add some sample strategies to export
        sample_domains = [
            "www.youtube.com",
            "pbs.twimg.com",
            "scontent.cdninstagram.com",
        ]
        for domain in sample_domains:
            strategy = manager.get_strategy_for_domain(domain)
            if strategy:
                config_data["subdomain_strategies"][domain] = {
                    "strategy_id": strategy.id,
                    "strategy_name": strategy.name,
                    "attacks": strategy.attacks,
                    "parameters": strategy.parameters,
                }

        print("Sample configuration export:")
        print(json.dumps(config_data, indent=2)[:500] + "...")

        print("\n🎉 Subdomain-Specific Strategy Support Demo Complete!")
        print("\nKey Features Demonstrated:")
        print(
            "✅ Platform-specific strategy selection (YouTube, Twitter, Instagram, TikTok)"
        )
        print("✅ Subdomain type detection (web interface, media content, API, etc.)")
        print("✅ Custom strategy configuration and persistence")
        print("✅ Strategy recommendations with confidence scores")
        print("✅ Subdomain structure analysis")
        print("✅ Strategy testing and metrics tracking")
        print("✅ Platform statistics and reporting")
        print("✅ Auto-discovery of platform subdomains")
        print("✅ Configuration export and management")

        return True

    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback

        traceback.print_exc()
        return False


def demo_real_world_scenarios():
    """Demonstrate real-world usage scenarios."""
    print("\n🌍 Real-World Usage Scenarios")
    print("=" * 60)

    try:
        import subdomain_handler

        manager = subdomain_handler.EnhancedPoolManager()

        # Scenario 1: YouTube Video Streaming Optimization
        print("\n📺 Scenario 1: YouTube Video Streaming Optimization")
        print("-" * 50)

        youtube_video_domains = [
            "r1---sn-4g5e6nls.googlevideo.com",
            "r2---sn-4g5lh7ne.googlevideo.com",
            "r3---sn-4g5e6nez.googlevideo.com",
        ]

        print("Optimizing strategies for YouTube video streaming:")
        for domain in youtube_video_domains:
            strategy = manager.get_strategy_for_domain(domain)
            print(f"  {domain}")
            print(f"    Strategy: {strategy.name}")
            print("    Optimized for: Video streaming with high throughput")
            print(f"    Attacks: {', '.join(strategy.attacks)}")

            # Test the strategy
            result = manager.test_subdomain_strategy(domain)
            print(
                f"    Test result: {'✅ Success' if result['success'] else '❌ Failed'} ({result['latency_ms']:.1f}ms)"
            )
            print()

        # Scenario 2: Social Media Multi-Platform Setup
        print("📱 Scenario 2: Social Media Multi-Platform Setup")
        print("-" * 50)

        social_platforms = {
            "Twitter": ["twitter.com", "pbs.twimg.com", "api.twitter.com"],
            "Instagram": [
                "instagram.com",
                "scontent.cdninstagram.com",
                "i.instagram.com",
            ],
            "TikTok": ["tiktok.com", "v16-web.tiktokcdn.com"],
        }

        print("Configuring strategies for multiple social media platforms:")
        for platform, domains in social_platforms.items():
            print(f"\n{platform} Configuration:")
            for domain in domains:
                strategy = manager.get_strategy_for_domain(domain)
                print(f"  {domain}: {strategy.name}")

        # Scenario 3: Custom Enterprise Configuration
        print("\n🏢 Scenario 3: Custom Enterprise Configuration")
        print("-" * 50)

        # Create custom strategies for enterprise domains
        enterprise_configs = [
            {
                "domain": "enterprise-youtube.company.com",
                "description": "Enterprise YouTube proxy",
                "strategy": subdomain_handler.BypassStrategy(
                    id="enterprise_youtube",
                    name="Enterprise YouTube Strategy",
                    attacks=["tcp_fragmentation", "http_manipulation"],
                    parameters={"split_pos": 3, "ttl": 1, "enterprise_mode": True},
                ),
            },
            {
                "domain": "social-proxy.company.com",
                "description": "Social media proxy gateway",
                "strategy": subdomain_handler.BypassStrategy(
                    id="enterprise_social",
                    name="Enterprise Social Media Strategy",
                    attacks=["tls_evasion", "packet_timing"],
                    parameters={"timing_variance": 100, "tls_version": "1.2"},
                ),
            },
        ]

        print("Setting up custom enterprise configurations:")
        for config in enterprise_configs:
            success = manager.set_subdomain_strategy(
                config["domain"], config["strategy"]
            )
            if success:
                print(f"✅ {config['domain']}: {config['description']}")
                print(f"   Strategy: {config['strategy'].name}")
                print(f"   Attacks: {', '.join(config['strategy'].attacks)}")
                print()

        # Scenario 4: Performance Monitoring and Optimization
        print("📈 Scenario 4: Performance Monitoring and Optimization")
        print("-" * 50)

        # Monitor performance across different platforms
        monitoring_domains = [
            "www.youtube.com",
            "twitter.com",
            "instagram.com",
            "tiktok.com",
        ]

        print("Performance monitoring results:")
        performance_data = []

        for domain in monitoring_domains:
            # Run multiple tests to get average performance
            results = []
            for _ in range(3):
                result = manager.test_subdomain_strategy(domain)
                results.append(result)

            avg_latency = sum(r["latency_ms"] for r in results) / len(results)
            success_rate = sum(1 for r in results if r["success"]) / len(results)

            performance_data.append(
                {
                    "domain": domain,
                    "avg_latency": avg_latency,
                    "success_rate": success_rate,
                }
            )

            print(f"  {domain}:")
            print(f"    Average latency: {avg_latency:.1f}ms")
            print(f"    Success rate: {success_rate:.1%}")

        # Find best and worst performing domains
        best_latency = min(performance_data, key=lambda x: x["avg_latency"])
        worst_latency = max(performance_data, key=lambda x: x["avg_latency"])

        print(
            f"\n  🏆 Best performance: {best_latency['domain']} ({best_latency['avg_latency']:.1f}ms)"
        )
        print(
            f"  ⚠️  Needs optimization: {worst_latency['domain']} ({worst_latency['avg_latency']:.1f}ms)"
        )

        # Scenario 5: Troubleshooting and Diagnostics
        print("\n🔧 Scenario 5: Troubleshooting and Diagnostics")
        print("-" * 50)

        problematic_domain = "problematic.youtube.com"

        print(f"Diagnosing issues with {problematic_domain}:")

        # Get current strategy
        current_strategy = manager.get_strategy_for_domain(problematic_domain)
        print(f"  Current strategy: {current_strategy.name}")

        # Get alternative recommendations
        recommendations = manager.get_subdomain_recommendations(problematic_domain)
        print("  Alternative strategies:")
        for i, (strategy, confidence) in enumerate(recommendations[:3], 1):
            print(f"    {i}. {strategy.name} (confidence: {confidence:.2f})")

        # Analyze subdomain structure
        analysis = subdomain_handler.analyze_subdomain_structure(problematic_domain)
        print("  Subdomain analysis:")
        print(f"    Depth: {analysis['depth']} levels")
        print(f"    Type: {'Complex' if analysis['depth'] > 2 else 'Simple'} subdomain")

        # Suggest tests
        suggested_tests = subdomain_handler.suggest_subdomain_tests(problematic_domain)
        print(f"  Suggested diagnostic tests: {len(suggested_tests)} tests available")

        print("\n✅ All real-world scenarios demonstrated successfully!")

        return True

    except Exception as e:
        print(f"\n❌ Real-world scenarios demo failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("Starting Subdomain-Specific Strategy Support Demo...")

    success = True
    success &= demo_subdomain_support()
    success &= demo_real_world_scenarios()

    if success:
        print("\n🎉 All demos completed successfully!")
        print("\nThe subdomain-specific strategy support system provides:")
        print("• Intelligent platform detection (YouTube, Twitter, Instagram, TikTok)")
        print("• Subdomain type classification (web, media, API, CDN, etc.)")
        print("• Specialized bypass strategies for each platform and subdomain type")
        print("• Custom strategy configuration and persistence")
        print("• Performance monitoring and optimization")
        print("• Auto-discovery of platform subdomains")
        print("• Comprehensive testing and diagnostics")
        print("• Real-world enterprise deployment scenarios")
    else:
        print("\n❌ Some demos failed!")
        sys.exit(1)
