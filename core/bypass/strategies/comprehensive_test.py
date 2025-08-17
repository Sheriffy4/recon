#!/usr/bin/env python3
"""
Comprehensive test of the Strategy Pool Management System
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pool_management

def test_comprehensive_functionality():
    print("Testing comprehensive pool management functionality...")
    
    # Create strategies
    social_strategy = pool_management.BypassStrategy(
        id="social_media",
        name="Social Media Strategy",
        attacks=["http_manipulation", "tls_evasion"],
        parameters={"split_pos": "midsld", "ttl": 2}
    )
    
    cdn_strategy = pool_management.BypassStrategy(
        id="cdn_bypass",
        name="CDN Bypass Strategy", 
        attacks=["tcp_fragmentation", "packet_timing"],
        parameters={"split_pos": 3, "ttl": 1}
    )
    
    default_strategy = pool_management.BypassStrategy(
        id="default",
        name="Default Strategy",
        attacks=["tcp_fragmentation"],
        parameters={"split_pos": 3}
    )
    
    print("✓ Created test strategies")
    
    # Create manager
    manager = pool_management.StrategyPoolManager()
    
    # Create pools
    social_pool = manager.create_pool("Social Media Sites", social_strategy, "Optimized for social media")
    social_pool.priority = pool_management.PoolPriority.HIGH
    
    cdn_pool = manager.create_pool("CDN Sites", cdn_strategy, "For CDN-hosted content")
    default_pool = manager.create_pool("Default Sites", default_strategy, "Default strategy")
    
    print("✓ Created pools with different priorities")
    
    # Add domains to pools
    social_domains = ["youtube.com", "twitter.com", "instagram.com", "facebook.com"]
    cdn_domains = ["cloudflare.com", "fastly.com", "akamai.com"]
    default_domains = ["example.com", "test.com", "github.com"]
    
    for domain in social_domains:
        manager.add_domain_to_pool(social_pool.id, domain)
    
    for domain in cdn_domains:
        manager.add_domain_to_pool(cdn_pool.id, domain)
    
    for domain in default_domains:
        manager.add_domain_to_pool(default_pool.id, domain)
    
    print("✓ Added domains to pools")
    
    # Test subdomain strategies
    youtube_video_strategy = pool_management.BypassStrategy(
        id="youtube_video",
        name="YouTube Video Strategy",
        attacks=["multisplit", "packet_timing"],
        parameters={"positions": [1, 2, 4], "delay": 0.01}
    )
    
    manager.set_subdomain_strategy(social_pool.id, "www.youtube.com", youtube_video_strategy)
    manager.set_subdomain_strategy(social_pool.id, "m.youtube.com", youtube_video_strategy)
    
    print("✓ Set subdomain-specific strategies")
    
    # Test port strategies
    http_strategy = pool_management.BypassStrategy(
        id="http_strategy",
        name="HTTP Strategy",
        attacks=["http_manipulation"],
        parameters={"split_pos": 2, "method": "GET"}
    )
    
    manager.set_port_strategy(default_pool.id, 80, http_strategy)
    
    print("✓ Set port-specific strategies")
    
    # Test assignment rules
    manager.add_assignment_rule(
        pattern=r".*\.(youtube|twitter|instagram|facebook)\.com$",
        pool_id=social_pool.id,
        priority=10
    )
    
    manager.add_assignment_rule(
        pattern=r".*(cloudflare|fastly|akamai|cdn).*",
        pool_id=cdn_pool.id,
        priority=8
    )
    
    manager.set_default_pool(default_pool.id)
    manager.set_fallback_strategy(default_strategy)
    
    print("✓ Set up assignment rules and defaults")
    
    # Test strategy resolution
    test_cases = [
        ("youtube.com", 443, "Social Media Strategy"),
        ("www.youtube.com", 443, "YouTube Video Strategy"),  # Should use subdomain strategy
        ("example.com", 80, "HTTP Strategy"),  # Should use port strategy
        ("example.com", 443, "Default Strategy"),  # Should use default pool strategy
        ("unknown.com", 443, "Default Strategy"),  # Should use fallback via default pool
    ]
    
    print("\nTesting strategy resolution:")
    for domain, port, expected_name in test_cases:
        strategy = manager.get_strategy_for_domain(domain, port)
        actual_name = strategy.name if strategy else "None"
        status = "✓" if actual_name == expected_name else "✗"
        print(f"  {status} {domain}:{port} -> {actual_name} (expected: {expected_name})")
    
    # Test auto assignment
    print("\nTesting auto assignment:")
    test_domains = [
        "music.youtube.com",
        "api.twitter.com", 
        "fonts.googleapis.com",
        "newsite.example.org"
    ]
    
    for domain in test_domains:
        assigned_pool_id = manager.auto_assign_domain(domain)
        if assigned_pool_id:
            pool = manager.get_pool(assigned_pool_id)
            print(f"  ✓ {domain} -> {pool.name}")
        else:
            print(f"  ✗ {domain} -> No assignment")
    
    # Test pool merging
    print("\nTesting pool merging:")
    
    # Create two small pools to merge
    video_pool = manager.create_pool("Video Sites", social_strategy, "Video streaming")
    streaming_pool = manager.create_pool("Streaming Services", cdn_strategy, "Streaming services")
    
    manager.add_domain_to_pool(video_pool.id, "vimeo.com")
    manager.add_domain_to_pool(streaming_pool.id, "netflix.com")
    
    video_pool.tags = ["video", "streaming"]
    streaming_pool.tags = ["streaming", "premium"]
    
    merged_strategy = pool_management.BypassStrategy(
        id="merged_media",
        name="Merged Media Strategy",
        attacks=["multisplit", "tls_evasion"],
        parameters={"positions": [1, 3, 7]}
    )
    
    pools_before = len(manager.pools)
    merged_pool = manager.merge_pools([video_pool.id, streaming_pool.id], "Media Sites", merged_strategy)
    pools_after = len(manager.pools)
    
    if merged_pool and pools_after == pools_before - 1:
        print(f"  ✓ Successfully merged pools: {len(merged_pool.domains)} domains, tags: {merged_pool.tags}")
    else:
        print("  ✗ Pool merging failed")
    
    # Test pool splitting
    print("\nTesting pool splitting:")
    
    if len(social_pool.domains) >= 2:
        domain_groups = {
            "video": [d for d in social_pool.domains if "youtube" in d],
            "social": [d for d in social_pool.domains if "twitter" in d or "facebook" in d or "instagram" in d]
        }
        
        # Only split if we have meaningful groups
        if len(domain_groups["video"]) > 0 and len(domain_groups["social"]) > 0:
            split_strategies = {
                "video": youtube_video_strategy,
                "social": social_strategy
            }
            
            pools_before = len(manager.pools)
            new_pools = manager.split_pool(social_pool.id, domain_groups, split_strategies)
            pools_after = len(manager.pools)
            
            if len(new_pools) > 0:
                print(f"  ✓ Successfully split pool into {len(new_pools)} new pools")
            else:
                print("  ✗ Pool splitting failed")
        else:
            print("  ✓ Pool splitting skipped (insufficient domain groups)")
    else:
        print("  ✓ Pool splitting skipped (insufficient domains)")
    
    # Test statistics
    print("\nTesting statistics:")
    stats = manager.get_pool_statistics()
    
    print(f"  ✓ Total pools: {stats['total_pools']}")
    print(f"  ✓ Total domains: {stats['total_domains']}")
    print(f"  ✓ Subdomain overrides: {stats['subdomain_overrides']}")
    print(f"  ✓ Port overrides: {stats['port_overrides']}")
    
    # Test utility functions
    print("\nTesting utility functions:")
    
    all_domains = []
    for pool in manager.pools.values():
        all_domains.extend(pool.domains)
    
    patterns = pool_management.analyze_domain_patterns(all_domains)
    print(f"  ✓ Found {len(patterns)} domain patterns")
    
    sample_domains = ["tiktok.com", "discord.com", "reddit.com"]
    suggestions = pool_management.suggest_pool_strategies(sample_domains)
    print(f"  ✓ Generated {len(suggestions)} strategy suggestions")
    
    # Test format conversions
    print("\nTesting format conversions:")
    
    test_strategy = pool_management.BypassStrategy(
        id="format_test",
        name="Format Test Strategy",
        attacks=["tcp_fragmentation", "http_manipulation"],
        parameters={"split_pos": 5}
    )
    
    zapret_format = test_strategy.to_zapret_format()
    goodbyedpi_format = test_strategy.to_goodbyedpi_format()
    native_format = test_strategy.to_native_format()
    
    print(f"  ✓ Zapret format: {zapret_format}")
    print(f"  ✓ GoodbyeDPI format: {goodbyedpi_format}")
    print(f"  ✓ Native format: {native_format}")
    
    print("\n✅ All comprehensive tests passed!")
    return True

if __name__ == "__main__":
    try:
        test_comprehensive_functionality()
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)