#!/usr/bin/env python3
# recon/core/bypass/strategies/demo_pool_management.py
"""
Demonstration of Strategy Pool Management System

This script shows how to use the strategy pool management system for
organizing bypass strategies across different domains and use cases.
"""

import logging
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from pool_management import (
    StrategyPoolManager,
    BypassStrategy,
    PoolPriority,
    analyze_domain_patterns,
    suggest_pool_strategies,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("PoolManagementDemo")


def create_sample_strategies():
    """Create sample bypass strategies for demonstration"""
    strategies = {}

    # Basic TCP fragmentation strategy
    strategies["tcp_basic"] = BypassStrategy(
        id="tcp_basic",
        name="Basic TCP Fragmentation",
        attacks=["tcp_fragmentation"],
        parameters={"split_pos": 3, "ttl": 2},
        target_ports=[443],
    )

    # Advanced multi-split strategy
    strategies["multisplit"] = BypassStrategy(
        id="multisplit_advanced",
        name="Advanced Multi-Split",
        attacks=["multisplit"],
        parameters={"positions": [1, 3, 8, 15]},
        target_ports=[443, 80],
    )

    # Social media optimized strategy
    strategies["social_media"] = BypassStrategy(
        id="social_media_opt",
        name="Social Media Optimized",
        attacks=["http_manipulation", "tls_evasion"],
        parameters={"split_pos": "midsld", "ttl": 1},
        target_ports=[443, 80],
    )

    # CDN bypass strategy
    strategies["cdn_bypass"] = BypassStrategy(
        id="cdn_bypass",
        name="CDN Bypass Strategy",
        attacks=["tcp_fragmentation", "packet_timing"],
        parameters={"split_pos": 5, "ttl": 1, "jitter": True},
        target_ports=[443],
    )

    # Experimental obfuscation strategy
    strategies["experimental"] = BypassStrategy(
        id="experimental_obf",
        name="Experimental Obfuscation",
        attacks=["protocol_obfuscation", "payload_encryption"],
        parameters={"encryption_key": "demo_key", "obfuscation_level": 3},
        target_ports=[443, 80, 8080],
    )

    return strategies


def demo_basic_pool_operations():
    """Demonstrate basic pool operations"""
    logger.info("=== Basic Pool Operations Demo ===")

    # Create manager
    manager = StrategyPoolManager()
    strategies = create_sample_strategies()

    # Create pools
    logger.info("Creating strategy pools...")

    social_pool = manager.create_pool(
        "Social Media Sites",
        strategies["social_media"],
        "Optimized strategies for social media platforms",
    )
    social_pool.priority = PoolPriority.HIGH

    cdn_pool = manager.create_pool(
        "CDN Sites", strategies["cdn_bypass"], "Strategies for CDN-hosted content"
    )

    default_pool = manager.create_pool(
        "Default Sites", strategies["tcp_basic"], "Default strategy for most sites"
    )

    # Add domains to pools
    logger.info("Adding domains to pools...")

    social_domains = [
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "twitter.com",
        "mobile.twitter.com",
        "api.twitter.com",
        "instagram.com",
        "www.instagram.com",
        "facebook.com",
        "www.facebook.com",
        "m.facebook.com",
    ]

    cdn_domains = [
        "cloudflare.com",
        "fastly.com",
        "akamai.com",
        "jsdelivr.net",
        "unpkg.com",
        "cdnjs.cloudflare.com",
    ]

    default_domains = [
        "example.com",
        "test.com",
        "demo.org",
        "github.com",
        "stackoverflow.com",
    ]

    for domain in social_domains:
        manager.add_domain_to_pool(social_pool.id, domain)

    for domain in cdn_domains:
        manager.add_domain_to_pool(cdn_pool.id, domain)

    for domain in default_domains:
        manager.add_domain_to_pool(default_pool.id, domain)

    # Set default pool
    manager.set_default_pool(default_pool.id)

    # Set fallback strategy
    manager.set_fallback_strategy(strategies["tcp_basic"])

    logger.info(
        f"Created {len(manager.pools)} pools with total {sum(len(p.domains) for p in manager.pools.values())} domains"
    )

    return manager, strategies


def demo_subdomain_strategies(manager, strategies):
    """Demonstrate subdomain-specific strategies"""
    logger.info("=== Subdomain Strategy Demo ===")

    # Find social media pool
    social_pool = None
    for pool in manager.pools.values():
        if "Social Media" in pool.name:
            social_pool = pool
            break

    if not social_pool:
        logger.error("Social media pool not found")
        return

    # Set subdomain-specific strategies
    logger.info("Setting subdomain-specific strategies...")

    # YouTube video content needs different handling
    youtube_video_strategy = BypassStrategy(
        id="youtube_video",
        name="YouTube Video Strategy",
        attacks=["multisplit", "packet_timing"],
        parameters={"positions": [1, 2, 4], "delay": 0.01},
    )

    manager.set_subdomain_strategy(
        social_pool.id, "www.youtube.com", youtube_video_strategy
    )
    manager.set_subdomain_strategy(
        social_pool.id, "m.youtube.com", youtube_video_strategy
    )

    # Twitter API needs special handling
    twitter_api_strategy = BypassStrategy(
        id="twitter_api",
        name="Twitter API Strategy",
        attacks=["http_manipulation"],
        parameters={"split_pos": 1, "ttl": 3},
    )

    manager.set_subdomain_strategy(
        social_pool.id, "api.twitter.com", twitter_api_strategy
    )

    # Test strategy resolution
    logger.info("Testing strategy resolution:")

    test_domains = [
        ("youtube.com", 443),
        ("www.youtube.com", 443),
        ("api.twitter.com", 443),
        ("twitter.com", 443),
    ]

    for domain, port in test_domains:
        strategy = manager.get_strategy_for_domain(domain, port)
        logger.info(
            f"  {domain}:{port} -> {strategy.name if strategy else 'No strategy'}"
        )


def demo_port_strategies(manager, strategies):
    """Demonstrate port-specific strategies"""
    logger.info("=== Port Strategy Demo ===")

    # Find default pool
    default_pool = None
    for pool in manager.pools.values():
        if "Default" in pool.name:
            default_pool = pool
            break

    if not default_pool:
        logger.error("Default pool not found")
        return

    # Set port-specific strategies
    logger.info("Setting port-specific strategies...")

    # HTTP (port 80) strategy
    http_strategy = BypassStrategy(
        id="http_strategy",
        name="HTTP Strategy",
        attacks=["http_manipulation"],
        parameters={"split_pos": 2, "method": "GET"},
    )

    manager.set_port_strategy(default_pool.id, 80, http_strategy)

    # Test strategy resolution for different ports
    logger.info("Testing port-specific strategy resolution:")

    test_cases = [
        ("example.com", 80),
        ("example.com", 443),
        ("test.com", 80),
        ("test.com", 443),
    ]

    for domain, port in test_cases:
        strategy = manager.get_strategy_for_domain(domain, port)
        logger.info(
            f"  {domain}:{port} -> {strategy.name if strategy else 'No strategy'}"
        )


def demo_assignment_rules(manager, strategies):
    """Demonstrate automatic domain assignment rules"""
    logger.info("=== Assignment Rules Demo ===")

    # Add assignment rules
    logger.info("Adding automatic assignment rules...")

    # Find pool IDs
    social_pool_id = None
    cdn_pool_id = None

    for pool_id, pool in manager.pools.items():
        if "Social Media" in pool.name:
            social_pool_id = pool_id
        elif "CDN" in pool.name:
            cdn_pool_id = pool_id

    if not social_pool_id or not cdn_pool_id:
        logger.error("Required pools not found")
        return

    # Add rules with different priorities
    manager.add_assignment_rule(
        pattern=r".*\.(youtube|twitter|instagram|facebook)\.com$",
        pool_id=social_pool_id,
        priority=10,
        conditions={"category": "social"},
    )

    manager.add_assignment_rule(
        pattern=r".*(cloudflare|fastly|akamai|cdn).*",
        pool_id=cdn_pool_id,
        priority=8,
        conditions={"category": "cdn"},
    )

    manager.add_assignment_rule(
        pattern=r".*\.googleapis\.com$", pool_id=cdn_pool_id, priority=9
    )

    # Test automatic assignment
    logger.info("Testing automatic domain assignment:")

    test_domains = [
        ("music.youtube.com", {"category": "social"}),
        ("api.twitter.com", {"category": "social"}),
        ("fonts.googleapis.com", {}),
        ("cdn.cloudflare.com", {"category": "cdn"}),
        ("unknown.example.com", {}),
    ]

    for domain, kwargs in test_domains:
        assigned_pool_id = manager.auto_assign_domain(domain, **kwargs)
        if assigned_pool_id:
            pool = manager.get_pool(assigned_pool_id)
            logger.info(f"  {domain} -> {pool.name}")
        else:
            logger.info(f"  {domain} -> No assignment (using default)")


def demo_pool_merging(manager, strategies):
    """Demonstrate pool merging functionality"""
    logger.info("=== Pool Merging Demo ===")

    # Create two small pools to merge
    logger.info("Creating pools for merging...")

    video_pool = manager.create_pool(
        "Video Sites", strategies["multisplit"], "Strategies for video streaming sites"
    )

    streaming_pool = manager.create_pool(
        "Streaming Services",
        strategies["experimental"],
        "Strategies for streaming services",
    )

    # Add domains to pools
    video_domains = ["vimeo.com", "dailymotion.com"]
    streaming_domains = ["netflix.com", "hulu.com"]

    for domain in video_domains:
        manager.add_domain_to_pool(video_pool.id, domain)

    for domain in streaming_domains:
        manager.add_domain_to_pool(streaming_pool.id, domain)

    # Add tags
    video_pool.tags = ["video", "streaming"]
    streaming_pool.tags = ["streaming", "premium"]

    logger.info(f"Before merge: {len(manager.pools)} pools")

    # Merge pools
    merged_strategy = BypassStrategy(
        id="merged_media",
        name="Merged Media Strategy",
        attacks=["multisplit", "tls_evasion"],
        parameters={"positions": [1, 3, 7], "split_pos": "midsld"},
    )

    merged_pool = manager.merge_pools(
        [video_pool.id, streaming_pool.id], "Media Streaming Sites", merged_strategy
    )

    logger.info(f"After merge: {len(manager.pools)} pools")
    logger.info(
        f"Merged pool has {len(merged_pool.domains)} domains and tags: {merged_pool.tags}"
    )


def demo_pool_splitting(manager, strategies):
    """Demonstrate pool splitting functionality"""
    logger.info("=== Pool Splitting Demo ===")

    # Find a pool with multiple domains to split
    target_pool = None
    for pool in manager.pools.values():
        if len(pool.domains) >= 4:
            target_pool = pool
            break

    if not target_pool:
        logger.error("No suitable pool found for splitting")
        return

    logger.info(
        f"Splitting pool '{target_pool.name}' with {len(target_pool.domains)} domains"
    )

    # Define split groups based on domain patterns
    domain_groups = {}
    split_strategies = {}

    for domain in target_pool.domains:
        if "youtube" in domain or "video" in domain:
            if "video" not in domain_groups:
                domain_groups["video"] = []
                split_strategies["video"] = BypassStrategy(
                    id="video_split",
                    name="Video Split Strategy",
                    attacks=["multisplit", "packet_timing"],
                    parameters={"positions": [1, 2, 5]},
                )
            domain_groups["video"].append(domain)
        elif "twitter" in domain or "social" in domain:
            if "social" not in domain_groups:
                domain_groups["social"] = []
                split_strategies["social"] = BypassStrategy(
                    id="social_split",
                    name="Social Split Strategy",
                    attacks=["http_manipulation"],
                    parameters={"split_pos": 2},
                )
            domain_groups["social"].append(domain)
        else:
            if "other" not in domain_groups:
                domain_groups["other"] = []
                split_strategies["other"] = target_pool.strategy
            domain_groups["other"].append(domain)

    # Only split if we have meaningful groups
    if len(domain_groups) > 1:
        new_pools = manager.split_pool(target_pool.id, domain_groups, split_strategies)
        logger.info(f"Split into {len(new_pools)} new pools:")
        for pool in new_pools:
            logger.info(f"  {pool.name}: {len(pool.domains)} domains")
    else:
        logger.info("Pool doesn't have suitable domains for splitting")


def demo_statistics_and_analysis():
    """Demonstrate statistics and analysis features"""
    logger.info("=== Statistics and Analysis Demo ===")

    # Create manager with sample data
    manager, strategies = demo_basic_pool_operations()

    # Get statistics
    stats = manager.get_pool_statistics()

    logger.info("Pool Statistics:")
    logger.info(f"  Total pools: {stats['total_pools']}")
    logger.info(f"  Total domains: {stats['total_domains']}")
    logger.info(f"  Subdomain overrides: {stats['subdomain_overrides']}")
    logger.info(f"  Port overrides: {stats['port_overrides']}")

    logger.info("  Pools by priority:")
    for priority, count in stats["pools_by_priority"].items():
        logger.info(f"    {priority}: {count}")

    logger.info("  Domains per pool:")
    for pool_name, count in stats["domains_per_pool"].items():
        logger.info(f"    {pool_name}: {count}")

    # Analyze domain patterns
    all_domains = []
    for pool in manager.pools.values():
        all_domains.extend(pool.domains)

    patterns = analyze_domain_patterns(all_domains)
    logger.info(f"\nDomain Pattern Analysis ({len(patterns)} patterns found):")
    for pattern, domains in patterns.items():
        if len(domains) > 2:  # Only show significant patterns
            logger.info(f"  {pattern}: {len(domains)} domains")

    # Strategy suggestions
    sample_domains = ["tiktok.com", "discord.com", "reddit.com"]
    suggestions = suggest_pool_strategies(sample_domains)

    logger.info("\nStrategy Suggestions for new domains:")
    for domain, strategy in suggestions.items():
        logger.info(f"  {domain}: {strategy.name} ({', '.join(strategy.attacks)})")


def demo_configuration_persistence(manager):
    """Demonstrate configuration save/load"""
    logger.info("=== Configuration Persistence Demo ===")

    # Save configuration
    config_file = "demo_pool_config.json"
    logger.info(f"Saving configuration to {config_file}...")

    success = manager.save_configuration(config_file)
    if success:
        logger.info("Configuration saved successfully")

        # Load configuration in new manager
        logger.info("Loading configuration in new manager...")
        new_manager = StrategyPoolManager(config_path=config_file)

        logger.info(f"Loaded {len(new_manager.pools)} pools")
        logger.info(f"Loaded {len(new_manager.assignment_rules)} assignment rules")

        # Verify data integrity
        original_stats = manager.get_pool_statistics()
        loaded_stats = new_manager.get_pool_statistics()

        if original_stats["total_pools"] == loaded_stats["total_pools"]:
            logger.info("Configuration loaded successfully - data integrity verified")
        else:
            logger.error("Configuration load failed - data mismatch")
    else:
        logger.error("Failed to save configuration")


def demo_format_conversions():
    """Demonstrate strategy format conversions"""
    logger.info("=== Format Conversion Demo ===")

    # Create sample strategy
    strategy = BypassStrategy(
        id="conversion_demo",
        name="Conversion Demo Strategy",
        attacks=["tcp_fragmentation", "http_manipulation", "tls_evasion"],
        parameters={"split_pos": 5, "ttl": 2},
    )

    logger.info("Original strategy:")
    logger.info(f"  Name: {strategy.name}")
    logger.info(f"  Attacks: {', '.join(strategy.attacks)}")
    logger.info(f"  Parameters: {strategy.parameters}")

    logger.info("\nFormat conversions:")

    # Zapret format
    zapret_format = strategy.to_zapret_format()
    logger.info(f"  Zapret: {zapret_format}")

    # GoodbyeDPI format
    gdpi_format = strategy.to_goodbyedpi_format()
    logger.info(f"  GoodbyeDPI: {gdpi_format}")

    # Native format
    native_format = strategy.to_native_format()
    logger.info(f"  Native: {native_format}")


def main():
    """Main demonstration function"""
    logger.info("Starting Strategy Pool Management System Demo")
    logger.info("=" * 60)

    try:
        # Basic operations
        manager, strategies = demo_basic_pool_operations()

        # Advanced features
        demo_subdomain_strategies(manager, strategies)
        demo_port_strategies(manager, strategies)
        demo_assignment_rules(manager, strategies)
        demo_pool_merging(manager, strategies)
        demo_pool_splitting(manager, strategies)

        # Analysis and statistics
        demo_statistics_and_analysis()

        # Configuration persistence
        demo_configuration_persistence(manager)

        # Format conversions
        demo_format_conversions()

        logger.info("=" * 60)
        logger.info("Demo completed successfully!")

    except Exception as e:
        logger.error(f"Demo failed with error: {e}", exc_info=True)


if __name__ == "__main__":
    main()
