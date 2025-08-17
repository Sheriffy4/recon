#!/usr/bin/env python3
"""
Simple test for subdomain-specific strategy support.
"""

import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

def test_subdomain_handler():
    """Test subdomain handler functionality."""
    print("Testing subdomain handler functionality...")
    
    try:
        # Import the module
        import subdomain_handler
        
        # Test that we can create an enhanced pool manager
        manager = subdomain_handler.EnhancedPoolManager()
        print("✅ Enhanced pool manager created successfully")
        
        # Test YouTube subdomain handling
        youtube_domains = [
            "www.youtube.com",
            "m.youtube.com", 
            "r1---sn-4g5e6nls.googlevideo.com",
            "i.ytimg.com"
        ]
        
        print("\n=== YouTube Subdomain Tests ===")
        for domain in youtube_domains:
            strategy = manager.get_strategy_for_domain(domain)
            if strategy:
                print(f"✅ {domain}: {strategy.name}")
                assert "youtube" in strategy.id.lower(), f"Strategy should be YouTube-specific for {domain}"
            else:
                print(f"❌ {domain}: No strategy found")
                assert False, f"Should find strategy for {domain}"
        
        # Test Twitter subdomain handling
        twitter_domains = [
            "twitter.com",
            "mobile.twitter.com",
            "pbs.twimg.com",
            "api.twitter.com"
        ]
        
        print("\n=== Twitter Subdomain Tests ===")
        for domain in twitter_domains:
            strategy = manager.get_strategy_for_domain(domain)
            if strategy:
                print(f"✅ {domain}: {strategy.name}")
                assert "twitter" in strategy.id.lower(), f"Strategy should be Twitter-specific for {domain}"
            else:
                print(f"❌ {domain}: No strategy found")
                assert False, f"Should find strategy for {domain}"
        
        # Test Instagram subdomain handling
        instagram_domains = [
            "www.instagram.com",
            "scontent.cdninstagram.com",
            "i.instagram.com"
        ]
        
        print("\n=== Instagram Subdomain Tests ===")
        for domain in instagram_domains:
            strategy = manager.get_strategy_for_domain(domain)
            if strategy:
                print(f"✅ {domain}: {strategy.name}")
                assert "instagram" in strategy.id.lower(), f"Strategy should be Instagram-specific for {domain}"
            else:
                print(f"❌ {domain}: No strategy found")
                assert False, f"Should find strategy for {domain}"
        
        # Test TikTok subdomain handling
        tiktok_domains = [
            "www.tiktok.com",
            "v16-web.tiktokcdn.com"
        ]
        
        print("\n=== TikTok Subdomain Tests ===")
        for domain in tiktok_domains:
            strategy = manager.get_strategy_for_domain(domain)
            if strategy:
                print(f"✅ {domain}: {strategy.name}")
                assert "tiktok" in strategy.id.lower(), f"Strategy should be TikTok-specific for {domain}"
            else:
                print(f"❌ {domain}: No strategy found")
                assert False, f"Should find strategy for {domain}"
        
        # Test subdomain analysis
        print("\n=== Subdomain Analysis Tests ===")
        test_domains = [
            "www.youtube.com",
            "r1---sn-4g5e6nls.googlevideo.com",
            "pbs.twimg.com"
        ]
        
        for domain in test_domains:
            analysis = subdomain_handler.analyze_subdomain_structure(domain)
            print(f"Domain: {domain}")
            print(f"  Depth: {analysis['depth']}")
            print(f"  Is subdomain: {analysis['is_subdomain']}")
            print(f"  Subdomain levels: {analysis['subdomain_levels']}")
            
            assert isinstance(analysis['depth'], int), "Depth should be integer"
            assert isinstance(analysis['is_subdomain'], bool), "is_subdomain should be boolean"
            assert isinstance(analysis['subdomain_levels'], list), "subdomain_levels should be list"
        
        # Test strategy recommendations
        print("\n=== Strategy Recommendations ===")
        for domain in ["www.youtube.com", "pbs.twimg.com"]:
            recommendations = manager.get_subdomain_recommendations(domain)
            print(f"{domain}:")
            assert len(recommendations) > 0, f"Should have recommendations for {domain}"
            
            for strategy, confidence in recommendations[:3]:
                print(f"  {strategy.name} (confidence: {confidence:.2f})")
                assert 0.0 <= confidence <= 1.0, "Confidence should be between 0 and 1"
        
        # Test custom strategy setting
        print("\n=== Custom Strategy Tests ===")
        custom_domain = "test.youtube.com"
        custom_strategy = subdomain_handler.BypassStrategy(
            id="custom_test_strategy",
            name="Custom Test Strategy",
            attacks=["http_manipulation"],
            parameters={"split_pos": 5}
        )
        
        success = manager.set_subdomain_strategy(custom_domain, custom_strategy)
        assert success, "Should successfully set custom strategy"
        print(f"✅ Set custom strategy for {custom_domain}")
        
        retrieved_strategy = manager.get_strategy_for_domain(custom_domain)
        assert retrieved_strategy is not None, "Should retrieve custom strategy"
        assert retrieved_strategy.id == custom_strategy.id, "Retrieved strategy should match set strategy"
        print(f"✅ Retrieved custom strategy: {retrieved_strategy.name}")
        
        # Test strategy testing
        print("\n=== Strategy Testing ===")
        test_result = manager.test_subdomain_strategy("www.youtube.com")
        assert "success" in test_result, "Test result should contain success field"
        assert "latency_ms" in test_result, "Test result should contain latency_ms field"
        assert "strategy_id" in test_result, "Test result should contain strategy_id field"
        print(f"✅ Strategy test result: {test_result}")
        
        # Test platform statistics
        print("\n=== Platform Statistics ===")
        stats = manager.subdomain_handler.get_platform_statistics()
        print(f"Total subdomains: {stats['total_subdomains']}")
        print(f"Platforms: {stats['platforms']}")
        assert isinstance(stats['total_subdomains'], int), "Total subdomains should be integer"
        assert isinstance(stats['platforms'], dict), "Platforms should be dictionary"
        
        print("\n✅ All subdomain handler tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_subdomain_patterns():
    """Test subdomain pattern matching."""
    print("\nTesting subdomain pattern matching...")
    
    try:
        import subdomain_handler
        
        # Test platform detection
        test_cases = [
            ("www.youtube.com", subdomain_handler.PlatformType.YOUTUBE),
            ("r1---sn-4g5e6nls.googlevideo.com", subdomain_handler.PlatformType.YOUTUBE),
            ("twitter.com", subdomain_handler.PlatformType.TWITTER),
            ("pbs.twimg.com", subdomain_handler.PlatformType.TWITTER),
            ("instagram.com", subdomain_handler.PlatformType.INSTAGRAM),
            ("scontent.cdninstagram.com", subdomain_handler.PlatformType.INSTAGRAM),
            ("tiktok.com", subdomain_handler.PlatformType.TIKTOK),
            ("example.com", subdomain_handler.PlatformType.GENERIC)
        ]
        
        # Create a handler to test platform detection
        from pool_management import StrategyPoolManager
        pool_manager = StrategyPoolManager()
        handler = subdomain_handler.SubdomainStrategyHandler(pool_manager)
        
        print("Platform detection tests:")
        for domain, expected_platform in test_cases:
            detected_platform = handler._detect_platform(domain)
            if detected_platform == expected_platform:
                print(f"✅ {domain} -> {detected_platform.value}")
            else:
                print(f"❌ {domain} -> Expected: {expected_platform.value}, Got: {detected_platform.value}")
                assert False, f"Platform detection failed for {domain}"
        
        # Test subdomain type detection
        print("\nSubdomain type detection tests:")
        type_test_cases = [
            ("www.youtube.com", subdomain_handler.PlatformType.YOUTUBE, subdomain_handler.SubdomainType.WEB_INTERFACE),
            ("r1---sn-4g5e6nls.googlevideo.com", subdomain_handler.PlatformType.YOUTUBE, subdomain_handler.SubdomainType.MEDIA_CONTENT),
            ("i.ytimg.com", subdomain_handler.PlatformType.YOUTUBE, subdomain_handler.SubdomainType.STATIC_ASSETS),
            ("pbs.twimg.com", subdomain_handler.PlatformType.TWITTER, subdomain_handler.SubdomainType.MEDIA_CONTENT),
            ("api.twitter.com", subdomain_handler.PlatformType.TWITTER, subdomain_handler.SubdomainType.API_ENDPOINT),
        ]
        
        for domain, platform, expected_type in type_test_cases:
            detected_type = handler._get_subdomain_type(domain, platform)
            if detected_type == expected_type:
                print(f"✅ {domain} -> {detected_type.value}")
            else:
                print(f"❌ {domain} -> Expected: {expected_type.value}, Got: {detected_type.value}")
                assert False, f"Subdomain type detection failed for {domain}"
        
        print("✅ All pattern matching tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Pattern matching test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_configuration_persistence():
    """Test configuration saving and loading."""
    print("\nTesting configuration persistence...")
    
    try:
        import subdomain_handler
        import tempfile
        import os
        
        # Create temporary config file
        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "test_config.json")
        
        # Create handler with temporary config
        from pool_management import StrategyPoolManager
        pool_manager = StrategyPoolManager()
        handler = subdomain_handler.SubdomainStrategyHandler(pool_manager, config_path)
        
        # Set a custom strategy
        domain = "test.example.com"
        strategy = subdomain_handler.BypassStrategy(
            id="test_persist",
            name="Test Persistence Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_pos": 3}
        )
        
        success = handler.set_subdomain_strategy(domain, strategy)
        assert success, "Should successfully set strategy"
        print(f"✅ Set strategy for {domain}")
        
        # Create new handler with same config file
        new_handler = subdomain_handler.SubdomainStrategyHandler(pool_manager, config_path)
        retrieved_strategy = new_handler.get_strategy_for_subdomain(domain)
        
        assert retrieved_strategy is not None, "Should retrieve saved strategy"
        assert retrieved_strategy.id == strategy.id, "Retrieved strategy should match saved strategy"
        print(f"✅ Retrieved saved strategy: {retrieved_strategy.name}")
        
        # Clean up
        if os.path.exists(config_path):
            os.remove(config_path)
        os.rmdir(temp_dir)
        
        print("✅ Configuration persistence test passed!")
        return True
        
    except Exception as e:
        print(f"❌ Configuration persistence test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("Running simple subdomain handler tests...")
    
    success = True
    
    # Run all tests
    success &= test_subdomain_handler()
    success &= test_subdomain_patterns()
    success &= test_configuration_persistence()
    
    if success:
        print("\n🎉 All tests passed successfully!")
        print("\nSubdomain-specific strategy support is working correctly with:")
        print("- YouTube subdomain handling (web interface, video content, thumbnails)")
        print("- Twitter subdomain handling (interface, media content, API)")
        print("- Instagram subdomain handling (interface, media CDN)")
        print("- TikTok subdomain handling (interface, video CDN)")
        print("- Custom strategy setting and retrieval")
        print("- Configuration persistence")
        print("- Platform and subdomain type detection")
        print("- Strategy recommendations")
        print("- Strategy testing")
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)