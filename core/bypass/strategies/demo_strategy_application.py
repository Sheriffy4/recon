#!/usr/bin/env python3
"""
Demonstration of Enhanced Strategy Application Algorithm

This demo shows the complete functionality of the enhanced strategy application system,
including intelligent strategy selection, user preference prioritization, automatic pool
assignment, and conflict resolution.
"""

import sys
import os
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))


def create_mock_registry():
    """Create a mock attack registry for demonstration."""

    class MockAttackDefinition:
        def __init__(self, attack_id, stability="STABLE"):
            self.id = attack_id
            self.name = attack_id.replace("_", " ").title()
            self.stability = MockStability(stability)

    class MockStability:
        def __init__(self, name):
            self.name = name

    class MockAttackRegistry:
        def __init__(self):
            self.attacks = {
                "tcp_fragmentation": MockAttackDefinition(
                    "tcp_fragmentation", "STABLE"
                ),
                "http_manipulation": MockAttackDefinition(
                    "http_manipulation", "STABLE"
                ),
                "tls_evasion": MockAttackDefinition("tls_evasion", "MOSTLY_STABLE"),
                "dns_tunneling": MockAttackDefinition("dns_tunneling", "EXPERIMENTAL"),
                "packet_timing": MockAttackDefinition("packet_timing", "STABLE"),
                "protocol_obfuscation": MockAttackDefinition(
                    "protocol_obfuscation", "EXPERIMENTAL"
                ),
            }

        def get_attack_definition(self, attack_id):
            return self.attacks.get(attack_id)

    return MockAttackRegistry()


def demo_basic_functionality():
    """Demonstrate basic functionality of the strategy selector."""
    print("🎯 Demo: Basic Strategy Selection Functionality")
    print("-" * 50)

    from pool_management import StrategyPoolManager
    from strategy_application import EnhancedStrategySelector

    # Create components
    mock_registry = create_mock_registry()
    pool_manager = StrategyPoolManager()

    # Create temporary file for user preferences
    temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    temp_file.close()

    try:
        selector = EnhancedStrategySelector(
            pool_manager=pool_manager,
            attack_registry=mock_registry,
            user_preferences_path=temp_file.name,
        )

        print("✅ Created EnhancedStrategySelector")

        # Test domain analysis
        print("\n📊 Domain Analysis Examples:")

        domains_to_analyze = [
            "youtube.com",
            "twitter.com",
            "instagram.com",
            "netflix.com",
            "cloudflare.com",
            "example.com",
        ]

        for domain in domains_to_analyze:
            analysis = selector._analyze_domain(domain)
            print(f"  {domain}:")
            print(f"    - TLD: {analysis.tld}")
            print(f"    - Social Media: {analysis.is_social_media}")
            print(f"    - Video Platform: {analysis.is_video_platform}")
            print(f"    - CDN: {analysis.is_cdn}")
            print(f"    - Complexity: {analysis.estimated_complexity}/5")
            print(f"    - Tags: {analysis.tags}")

        return selector, pool_manager, temp_file.name

    except Exception as e:
        print(f"❌ Error in basic functionality demo: {e}")
        Path(temp_file.name).unlink(missing_ok=True)
        raise


def demo_pool_management(selector, pool_manager):
    """Demonstrate pool management and strategy assignment."""
    print("\n🏊 Demo: Pool Management and Strategy Assignment")
    print("-" * 50)

    from pool_management import BypassStrategy, PoolPriority

    # Create different strategies for different types of sites
    strategies = {
        "social_media": BypassStrategy(
            id="social_media_strategy",
            name="Social Media Optimized Strategy",
            attacks=["http_manipulation", "tls_evasion"],
            parameters={"split_pos": "midsld", "ttl": 2},
            success_rate=0.85,
            last_tested=datetime.now() - timedelta(days=1),
        ),
        "video_platform": BypassStrategy(
            id="video_platform_strategy",
            name="Video Platform Strategy",
            attacks=["tcp_fragmentation", "packet_timing"],
            parameters={"split_count": 5, "ttl": 3},
            success_rate=0.78,
            last_tested=datetime.now() - timedelta(days=2),
        ),
        "general": BypassStrategy(
            id="general_strategy",
            name="General Purpose Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_pos": 3, "ttl": 2},
            success_rate=0.65,
            last_tested=datetime.now() - timedelta(days=5),
        ),
        "cdn": BypassStrategy(
            id="cdn_strategy",
            name="CDN Optimized Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_pos": 2, "ttl": 1},
            success_rate=0.72,
            last_tested=datetime.now() - timedelta(days=3),
        ),
    }

    # Create pools
    pools = {}

    print("📦 Creating Strategy Pools:")

    # Social Media Pool
    pools["social"] = pool_manager.create_pool(
        "Social Media Sites",
        strategies["social_media"],
        "Optimized for social media platforms",
    )
    pools["social"].priority = PoolPriority.HIGH
    pools["social"].tags = ["social", "interactive"]
    print(f"  ✅ Created '{pools['social'].name}' pool (HIGH priority)")

    # Video Platform Pool
    pools["video"] = pool_manager.create_pool(
        "Video Platforms",
        strategies["video_platform"],
        "Optimized for video streaming sites",
    )
    pools["video"].priority = PoolPriority.HIGH
    pools["video"].tags = ["video", "streaming"]
    print(f"  ✅ Created '{pools['video'].name}' pool (HIGH priority)")

    # CDN Pool
    pools["cdn"] = pool_manager.create_pool(
        "CDN Sites", strategies["cdn"], "Optimized for CDN-hosted content"
    )
    pools["cdn"].priority = PoolPriority.NORMAL
    pools["cdn"].tags = ["cdn", "infrastructure"]
    print(f"  ✅ Created '{pools['cdn'].name}' pool (NORMAL priority)")

    # General Pool (default)
    pools["general"] = pool_manager.create_pool(
        "General Sites",
        strategies["general"],
        "General purpose strategy for most sites",
    )
    pools["general"].priority = PoolPriority.LOW
    pool_manager.set_default_pool(pools["general"].id)
    print(f"  ✅ Created '{pools['general'].name}' pool (LOW priority, DEFAULT)")

    # Manually assign some domains to demonstrate
    print("\n🎯 Manual Domain Assignments:")

    manual_assignments = [
        ("youtube.com", pools["social"].id),
        ("twitter.com", pools["social"].id),
        ("netflix.com", pools["video"].id),
        ("twitch.tv", pools["video"].id),
        ("cloudflare.com", pools["cdn"].id),
    ]

    for domain, pool_id in manual_assignments:
        pool_manager.add_domain_to_pool(pool_id, domain)
        pool_name = pool_manager.get_pool(pool_id).name
        print(f"  ✅ Assigned {domain} to '{pool_name}'")

    # Test automatic assignment
    print("\n🤖 Automatic Domain Assignments:")

    auto_domains = [
        "instagram.com",
        "tiktok.com",
        "vimeo.com",
        "fastly.com",
        "unknown-site.com",
    ]

    for domain in auto_domains:
        pool_id = selector.auto_assign_domain(domain)
        if pool_id:
            pool_name = pool_manager.get_pool(pool_id).name
            print(f"  ✅ Auto-assigned {domain} to '{pool_name}'")
        else:
            print(f"  ❌ Failed to auto-assign {domain}")

    return strategies


def demo_user_preferences(selector, temp_file_path):
    """Demonstrate user preference handling."""
    print("\n👤 Demo: User Preference Management")
    print("-" * 50)

    # Create sample user preferences
    user_preferences = {
        "preferences": {
            "youtube.com": {
                "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-ttl=3",
                "success_rate": 0.92,
                "avg_latency_ms": 280.0,
                "fingerprint_used": True,
                "dpi_type": "deep_packet_inspection",
                "dpi_confidence": 0.85,
            },
            "twitter.com": {
                "strategy": "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum",
                "success_rate": 0.88,
                "avg_latency_ms": 220.0,
                "fingerprint_used": True,
                "dpi_type": "sni_blocking",
                "dpi_confidence": 0.75,
            },
            "instagram.com": {
                "strategy": "--dpi-desync=split2 --dpi-desync-split-pos=midsld",
                "success_rate": 0.83,
                "avg_latency_ms": 310.0,
                "fingerprint_used": False,
                "dpi_type": "unknown",
                "dpi_confidence": 0.0,
            },
        }
    }

    # Save preferences to file
    with open(temp_file_path, "w") as f:
        json.dump(user_preferences, f, indent=2)

    print("💾 Saved user preferences to file:")
    for domain, prefs in user_preferences["preferences"].items():
        print(f"  {domain}:")
        print(f"    Strategy: {prefs['strategy']}")
        print(f"    Success Rate: {prefs['success_rate']:.1%}")
        print(f"    Avg Latency: {prefs['avg_latency_ms']:.0f}ms")

    # Reload selector to pick up preferences
    selector._load_user_preferences()

    print(f"\n✅ Loaded {len(selector.user_preferences)} user preferences")

    # Test updating preferences
    print("\n📝 Updating User Preferences:")

    selector.update_user_preference(
        domain="example.com",
        strategy="--dpi-desync=disorder --dpi-desync-ttl=1",
        success_rate=0.75,
        latency_ms=400.0,
        dpi_type="content_filtering",
        dpi_confidence=0.6,
    )

    print("  ✅ Added preference for example.com")
    print(f"  📊 Total preferences: {len(selector.user_preferences)}")


def demo_strategy_selection(selector, pool_manager):
    """Demonstrate intelligent strategy selection."""
    print("\n🧠 Demo: Intelligent Strategy Selection")
    print("-" * 50)

    test_domains = [
        "youtube.com",  # Has both pool assignment and user preference
        "twitter.com",  # Has both pool assignment and user preference
        "instagram.com",  # Has user preference, auto-assigned to pool
        "netflix.com",  # Has pool assignment only
        "example.com",  # Has user preference only
        "unknown-site.xyz",  # No preferences, should use default
    ]

    print("🎯 Strategy Selection Results:")

    for domain in test_domains:
        print(f"\n  Domain: {domain}")

        # Get strategy recommendations first
        recommendations = selector.get_strategy_recommendations(domain, count=3)

        if recommendations:
            print("    📋 Top Recommendations:")
            for i, (strategy, confidence) in enumerate(recommendations, 1):
                print(f"      {i}. {strategy.name} (confidence: {confidence:.2f})")

        # Select best strategy
        selected_strategy = selector.select_strategy(domain, port=443)

        if selected_strategy:
            print(f"    ✅ Selected: {selected_strategy.name}")
            print(f"       Strategy ID: {selected_strategy.id}")
            print(f"       Attacks: {', '.join(selected_strategy.attacks)}")
            print(f"       Success Rate: {selected_strategy.success_rate:.1%}")

            # Show zapret format
            zapret_format = selected_strategy.to_zapret_format()
            print(f"       Zapret Format: {zapret_format}")
        else:
            print("    ❌ No strategy selected")


def demo_conflict_resolution(selector):
    """Demonstrate conflict resolution mechanisms."""
    print("\n⚖️ Demo: Strategy Conflict Resolution")
    print("-" * 50)

    from pool_management import BypassStrategy
    from strategy_application import ConflictResolution

    # Create conflicting strategies
    conflicting_strategies = [
        BypassStrategy(
            id="strategy_a",
            name="High Success Strategy",
            attacks=["tcp_fragmentation"],
            success_rate=0.95,
            last_tested=datetime.now() - timedelta(days=10),
        ),
        BypassStrategy(
            id="strategy_b",
            name="Low Latency Strategy",
            attacks=["http_manipulation"],
            success_rate=0.70,
            last_tested=datetime.now() - timedelta(days=1),
        ),
        BypassStrategy(
            id="strategy_c",
            name="Balanced Strategy",
            attacks=["tls_evasion"],
            success_rate=0.80,
            last_tested=datetime.now() - timedelta(days=5),
        ),
    ]

    # Add latency information for demonstration
    conflicting_strategies[0].avg_latency_ms = 500.0  # High success, high latency
    conflicting_strategies[1].avg_latency_ms = 150.0  # Low success, low latency
    conflicting_strategies[2].avg_latency_ms = 300.0  # Balanced

    print("🥊 Conflicting Strategies:")
    for strategy in conflicting_strategies:
        print(f"  - {strategy.name}:")
        print(f"    Success Rate: {strategy.success_rate:.1%}")
        print(f"    Avg Latency: {getattr(strategy, 'avg_latency_ms', 'N/A')}ms")
        print(
            f"    Last Tested: {strategy.last_tested.strftime('%Y-%m-%d') if strategy.last_tested else 'Never'}"
        )

    # Test different resolution methods
    resolution_methods = [
        ConflictResolution.HIGHEST_SUCCESS_RATE,
        ConflictResolution.LOWEST_LATENCY,
        ConflictResolution.MOST_RECENT,
        ConflictResolution.MERGE_STRATEGIES,
    ]

    print("\n🎯 Resolution Results:")

    for method in resolution_methods:
        resolved = selector.resolve_strategy_conflicts(
            "conflict-test.com",
            conflicting_strategies.copy(),  # Copy to avoid modification
            method,
        )

        if resolved:
            print(f"  {method.value}: {resolved.name}")
        else:
            print(f"  {method.value}: No resolution")


def demo_statistics_and_analysis(pool_manager):
    """Demonstrate statistics and analysis features."""
    print("\n📊 Demo: Statistics and Analysis")
    print("-" * 50)

    # Get pool statistics
    stats = pool_manager.get_pool_statistics()

    print("📈 Pool Statistics:")
    print(f"  Total Pools: {stats['total_pools']}")
    print(f"  Total Domains: {stats['total_domains']}")
    print(f"  Subdomain Overrides: {stats['subdomain_overrides']}")
    print(f"  Port Overrides: {stats['port_overrides']}")

    print("\n📊 Pools by Priority:")
    for priority, count in stats["pools_by_priority"].items():
        print(f"  {priority}: {count} pools")

    print("\n🏊 Domains per Pool:")
    for pool_name, domain_count in stats["domains_per_pool"].items():
        print(f"  {pool_name}: {domain_count} domains")

    # List all pools with details
    print("\n📋 Pool Details:")
    for pool in pool_manager.list_pools():
        print(f"  Pool: {pool.name}")
        print(f"    ID: {pool.id}")
        print(f"    Priority: {pool.priority.name}")
        print(f"    Strategy: {pool.strategy.name}")
        print(f"    Domains: {len(pool.domains)}")
        if pool.domains:
            print(f"    Sample Domains: {', '.join(pool.domains[:3])}")
            if len(pool.domains) > 3:
                print(f"    ... and {len(pool.domains) - 3} more")
        print(f"    Tags: {', '.join(pool.tags) if pool.tags else 'None'}")


def main():
    """Run the complete demonstration."""
    print("🚀 Enhanced Strategy Application Algorithm - Complete Demo")
    print("=" * 70)

    try:
        # Basic functionality
        selector, pool_manager, temp_file_path = demo_basic_functionality()

        # Pool management
        strategies = demo_pool_management(selector, pool_manager)

        # User preferences
        demo_user_preferences(selector, temp_file_path)

        # Strategy selection
        demo_strategy_selection(selector, pool_manager)

        # Conflict resolution
        demo_conflict_resolution(selector)

        # Statistics and analysis
        demo_statistics_and_analysis(pool_manager)

        print("\n" + "=" * 70)
        print("✅ Demo completed successfully!")
        print("🎯 Enhanced Strategy Application Algorithm is fully functional!")
        print("\nKey Features Demonstrated:")
        print("  ✅ Intelligent domain analysis and classification")
        print("  ✅ Automatic pool creation and domain assignment")
        print("  ✅ User preference loading and management")
        print("  ✅ Multi-criteria strategy scoring and selection")
        print("  ✅ Conflict resolution with multiple methods")
        print("  ✅ Comprehensive statistics and reporting")
        print("  ✅ Integration with existing pool management system")

        # Clean up
        Path(temp_file_path).unlink(missing_ok=True)

        return 0

    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
