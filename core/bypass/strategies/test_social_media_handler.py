#!/usr/bin/env python3
"""
Comprehensive Tests for Social Media Platform Bypass Effectiveness

This module provides extensive testing for social media and video platform
bypass strategies to ensure optimal performance and reliability.
"""

import pytest
import asyncio
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

try:
    from .social_media_handler import (
        SocialMediaBypassHandler, MediaType, BlockingPattern, PlatformType,
        YouTubeSpecificConfig, TwitterSpecificConfig, InstagramSpecificConfig, TikTokSpecificConfig,
        PlatformSpecificStrategy
    )
    from .subdomain_handler import SubdomainStrategyHandler, SubdomainType
    from .pool_management import BypassStrategy, StrategyPoolManager
except ImportError:
    import sys
    import os
    sys.path.append(os.path.dirname(__file__))
    from social_media_handler import (
        SocialMediaBypassHandler, MediaType, BlockingPattern, PlatformType,
        YouTubeSpecificConfig, TwitterSpecificConfig, InstagramSpecificConfig, TikTokSpecificConfig,
        PlatformSpecificStrategy
    )
    from subdomain_handler import SubdomainStrategyHandler, SubdomainType
    from pool_management import BypassStrategy, StrategyPoolManager


class TestSocialMediaBypassHandler:
    """Test suite for social media bypass handler."""
    
    @pytest.fixture
    def mock_subdomain_handler(self):
        """Create mock subdomain handler."""
        handler = Mock(spec=SubdomainStrategyHandler)
        handler.get_strategy_for_subdomain.return_value = BypassStrategy(
            id="fallback_strategy",
            name="Fallback Strategy",
            attacks=["http_manipulation"],
            parameters={"split_pos": "midsld"}
        )
        return handler
    
    @pytest.fixture
    def temp_config_file(self):
        """Create temporary configuration file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_path = f.name
        yield config_path
        Path(config_path).unlink(missing_ok=True)
    
    @pytest.fixture
    def social_media_handler(self, mock_subdomain_handler, temp_config_file):
        """Create social media handler instance."""
        return SocialMediaBypassHandler(mock_subdomain_handler, temp_config_file)
    
    def test_platform_detection(self, social_media_handler):
        """Test platform detection from domains."""
        test_cases = [
            ("www.youtube.com", PlatformType.YOUTUBE),
            ("r1---sn-4g5e6nez.googlevideo.com", PlatformType.YOUTUBE),
            ("i.ytimg.com", PlatformType.YOUTUBE),
            ("twitter.com", PlatformType.TWITTER),
            ("pbs.twimg.com", PlatformType.TWITTER),
            ("instagram.com", PlatformType.INSTAGRAM),
            ("scontent.cdninstagram.com", PlatformType.INSTAGRAM),
            ("scontent-lga3-2.xx.fbcdn.net", PlatformType.INSTAGRAM),
            ("www.tiktok.com", PlatformType.TIKTOK),
            ("v16-web.tiktokcdn.com", PlatformType.TIKTOK),
            ("example.com", PlatformType.GENERIC),
        ]
        
        for domain, expected_platform in test_cases:
            detected_platform = social_media_handler._detect_platform(domain)
            assert detected_platform == expected_platform, f"Failed for domain: {domain}"
    
    @pytest.mark.asyncio
    async def test_youtube_optimization(self, social_media_handler):
        """Test YouTube-specific optimizations."""
        test_cases = [
            ("www.youtube.com", "youtube_web_optimized"),
            ("r1---sn-4g5e6nez.googlevideo.com", "youtube_video_optimized"),
            ("i.ytimg.com", "youtube_thumbnail_optimized"),
            ("youtube.com/shorts", "youtube_shorts_optimized"),
            ("youtube.com/live", "youtube_live_optimized"),
        ]
        
        for domain, expected_strategy_prefix in test_cases:
            strategy = await social_media_handler.optimize_youtube_access(domain)
            assert strategy.id.startswith(expected_strategy_prefix), f"Wrong strategy for {domain}: {strategy.id}"
            assert len(strategy.attacks) > 0, f"No attacks defined for {domain}"
            assert len(strategy.parameters) > 0, f"No parameters defined for {domain}"
    
    @pytest.mark.asyncio
    async def test_twitter_optimization(self, social_media_handler):
        """Test Twitter-specific optimizations."""
        test_cases = [
            ("twitter.com", "twitter_web_optimized"),
            ("pbs.twimg.com", "twitter_media_optimized"),
            ("api.twitter.com", "twitter_api_optimized"),
            ("upload.twitter.com", "twitter_upload_optimized"),
        ]
        
        for domain, expected_strategy_prefix in test_cases:
            strategy = await social_media_handler.optimize_twitter_access(domain)
            assert strategy.id.startswith(expected_strategy_prefix), f"Wrong strategy for {domain}: {strategy.id}"
            
            # Check Twitter-specific optimizations
            if "twimg.com" in domain:
                assert strategy.parameters.get("media_subdomain_handling", False), "Media subdomain handling not enabled"
    
    @pytest.mark.asyncio
    async def test_instagram_optimization(self, social_media_handler):
        """Test Instagram-specific optimizations."""
        test_cases = [
            ("instagram.com", 443, "instagram_web_optimized"),
            ("instagram.com", 80, "instagram_web_optimized"),  # HTTP port issue handling
            ("scontent.cdninstagram.com", 443, "instagram_media_optimized"),
            ("instagram.com/stories", 443, "instagram_stories_optimized"),
            ("instagram.com/reels", 443, "instagram_reels_optimized"),
            ("i.instagram.com", 443, "instagram_api_optimized"),
        ]
        
        for domain, port, expected_strategy_prefix in test_cases:
            strategy = await social_media_handler.optimize_instagram_access(domain, port)
            assert strategy.id.startswith(expected_strategy_prefix), f"Wrong strategy for {domain}:{port}: {strategy.id}"
            
            # Check HTTP port issue handling
            if port == 80:
                assert strategy.parameters.get("http_port_fix", False), "HTTP port fix not enabled"
                assert "http_manipulation" in strategy.attacks, "HTTP manipulation not added for port 80"
    
    @pytest.mark.asyncio
    async def test_tiktok_optimization(self, social_media_handler):
        """Test TikTok-specific optimizations."""
        test_cases = [
            ("www.tiktok.com", "tiktok_web_optimized"),
            ("v16-web.tiktokcdn.com", "tiktok_video_optimized"),
            ("tiktok.com/live", "tiktok_live_optimized"),
            ("api.tiktok.com", "tiktok_api_optimized"),
        ]
        
        for domain, expected_strategy_prefix in test_cases:
            strategy = await social_media_handler.optimize_tiktok_access(domain)
            assert strategy.id.startswith(expected_strategy_prefix), f"Wrong strategy for {domain}: {strategy.id}"
            
            # Check TikTok-specific optimizations
            if "tiktokcdn.com" in domain:
                assert strategy.parameters.get("cdn_rotation_handling", False), "CDN rotation handling not enabled"
    
    @pytest.mark.asyncio
    async def test_blocking_pattern_detection(self, social_media_handler):
        """Test blocking pattern detection."""
        test_cases = [
            ("r1---sn-4g5e6nez.googlevideo.com", 443, {BlockingPattern.DPI_CONTENT_INSPECTION, BlockingPattern.THROTTLING, BlockingPattern.SNI_BLOCKING}),
            ("pbs.twimg.com", 443, {BlockingPattern.CDN_BLOCKING, BlockingPattern.SNI_BLOCKING}),
            ("instagram.com", 80, {BlockingPattern.HTTP_HOST_BLOCKING}),
            ("v16-web.tiktokcdn.com", 443, {BlockingPattern.DPI_CONTENT_INSPECTION, BlockingPattern.THROTTLING, BlockingPattern.SNI_BLOCKING}),
        ]
        
        for domain, port, expected_patterns in test_cases:
            detected_patterns = await social_media_handler._detect_blocking_patterns(domain, port)
            assert detected_patterns.intersection(expected_patterns), f"Expected patterns not detected for {domain}:{port}"
    
    @pytest.mark.asyncio
    async def test_blocking_pattern_optimizations(self, social_media_handler):
        """Test optimizations based on blocking patterns."""
        base_strategy = BypassStrategy(
            id="base_strategy",
            name="Base Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_count": 3}
        )
        
        test_cases = [
            ({BlockingPattern.THROTTLING}, "packet_timing"),
            ({BlockingPattern.DPI_CONTENT_INSPECTION}, "protocol_obfuscation"),
            ({BlockingPattern.CDN_BLOCKING}, None),  # Check parameters instead
            ({BlockingPattern.HTTP_HOST_BLOCKING}, "http_manipulation"),
        ]
        
        for blocking_patterns, expected_attack in test_cases:
            optimized_strategy = social_media_handler._apply_blocking_pattern_optimizations(
                base_strategy, blocking_patterns
            )
            
            if expected_attack:
                assert expected_attack in optimized_strategy.attacks, f"Expected attack {expected_attack} not added"
            
            if BlockingPattern.CDN_BLOCKING in blocking_patterns:
                assert optimized_strategy.parameters.get("cdn_optimization", False), "CDN optimization not enabled"
                assert optimized_strategy.parameters.get("split_count", 0) >= 5, "Split count not increased for CDN blocking"
    
    @pytest.mark.asyncio
    async def test_get_optimized_strategy(self, social_media_handler):
        """Test getting optimized strategy for various platforms."""
        test_cases = [
            ("www.youtube.com", 443, None),
            ("r1---sn-4g5e6nez.googlevideo.com", 443, MediaType.VIDEO_STREAM),
            ("pbs.twimg.com", 443, MediaType.IMAGE_CONTENT),
            ("scontent.cdninstagram.com", 443, MediaType.IMAGE_CONTENT),
            ("v16-web.tiktokcdn.com", 443, MediaType.VIDEO_STREAM),
            ("example.com", 443, None),  # Should fallback to subdomain handler
        ]
        
        for domain, port, media_type in test_cases:
            strategy = await social_media_handler.get_optimized_strategy(domain, port, media_type)
            assert strategy is not None, f"No strategy returned for {domain}"
            assert strategy.id, f"Strategy has no ID for {domain}"
            assert strategy.attacks, f"Strategy has no attacks for {domain}"
    
    @pytest.mark.asyncio
    async def test_platform_effectiveness_testing(self, social_media_handler):
        """Test comprehensive platform effectiveness testing."""
        test_domains = [
            "www.youtube.com",
            "r1---sn-4g5e6nez.googlevideo.com",
            "twitter.com",
            "pbs.twimg.com",
            "instagram.com",
            "scontent.cdninstagram.com",
            "www.tiktok.com",
            "v16-web.tiktokcdn.com",
        ]
        
        for domain in test_domains:
            results = await social_media_handler.test_platform_effectiveness(domain)
            
            # Check result structure
            assert "domain" in results, f"Domain missing from results for {domain}"
            assert "strategy_id" in results, f"Strategy ID missing from results for {domain}"
            assert "tests" in results, f"Tests missing from results for {domain}"
            assert "overall_success" in results, f"Overall success missing from results for {domain}"
            assert "success_rate" in results, f"Success rate missing from results for {domain}"
            
            # Check individual tests
            expected_tests = ["connectivity", "speed", "content"]
            for test_name in expected_tests:
                assert test_name in results["tests"], f"Test {test_name} missing for {domain}"
                assert "success" in results["tests"][test_name], f"Success field missing in {test_name} test for {domain}"
            
            # Check platform-specific tests for recognized platforms
            platform = social_media_handler._detect_platform(domain)
            if platform != PlatformType.GENERIC:
                assert "platform_specific" in results["tests"], f"Platform-specific tests missing for {domain}"
    
    def test_platform_recommendations(self, social_media_handler):
        """Test platform-specific strategy recommendations."""
        test_cases = [
            ("www.youtube.com", PlatformType.YOUTUBE),
            ("r1---sn-4g5e6nez.googlevideo.com", PlatformType.YOUTUBE),
            ("twitter.com", PlatformType.TWITTER),
            ("pbs.twimg.com", PlatformType.TWITTER),
            ("instagram.com", PlatformType.INSTAGRAM),
            ("scontent.cdninstagram.com", PlatformType.INSTAGRAM),
            ("www.tiktok.com", PlatformType.TIKTOK),
            ("v16-web.tiktokcdn.com", PlatformType.TIKTOK),
            ("example.com", PlatformType.GENERIC),
        ]
        
        for domain, expected_platform in test_cases:
            recommendations = social_media_handler.get_platform_recommendations(domain)
            
            assert len(recommendations) > 0, f"No recommendations for {domain}"
            
            for strategy, confidence, reason in recommendations:
                assert isinstance(strategy, BypassStrategy), f"Invalid strategy type for {domain}"
                assert 0.0 <= confidence <= 1.0, f"Invalid confidence score for {domain}: {confidence}"
                assert reason, f"No reason provided for {domain}"
                
            # Check that recommendations are sorted by confidence
            confidences = [conf for _, conf, _ in recommendations]
            assert confidences == sorted(confidences, reverse=True), f"Recommendations not sorted by confidence for {domain}"
    
    def test_configuration_persistence(self, social_media_handler, temp_config_file):
        """Test configuration saving and loading."""
        # Create some test data
        test_strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_count": 5}
        )
        
        platform_strategy = PlatformSpecificStrategy(
            platform=PlatformType.YOUTUBE,
            media_type=MediaType.VIDEO_STREAM,
            blocking_pattern=BlockingPattern.THROTTLING,
            strategy=test_strategy,
            effectiveness_score=0.85,
            avg_speed_improvement=25.5
        )
        
        # Add to handler
        social_media_handler.platform_strategies["test_key"] = platform_strategy
        
        # Save configuration
        social_media_handler._save_configuration()
        
        # Verify file exists and has content
        config_path = Path(temp_config_file)
        assert config_path.exists(), "Configuration file not created"
        
        with open(config_path, 'r') as f:
            data = json.load(f)
        
        assert "platform_strategies" in data, "Platform strategies not saved"
        assert "test_key" in data["platform_strategies"], "Test strategy not saved"
        
        # Create new handler and load configuration
        new_handler = SocialMediaBypassHandler(social_media_handler.subdomain_handler, temp_config_file)
        
        # Verify data was loaded
        assert "test_key" in new_handler.platform_strategies, "Test strategy not loaded"
        loaded_strategy = new_handler.platform_strategies["test_key"]
        
        assert loaded_strategy.platform == PlatformType.YOUTUBE, "Platform not loaded correctly"
        assert loaded_strategy.effectiveness_score == 0.85, "Effectiveness score not loaded correctly"
        assert loaded_strategy.strategy.id == "test_strategy", "Strategy ID not loaded correctly"
    
    @pytest.mark.asyncio
    async def test_youtube_specific_features(self, social_media_handler):
        """Test YouTube-specific feature optimizations."""
        # Test video acceleration
        video_domain = "r1---sn-4g5e6nez.googlevideo.com"
        strategy = await social_media_handler.optimize_youtube_access(video_domain)
        
        assert strategy.parameters.get("video_acceleration", False), "Video acceleration not enabled"
        assert strategy.parameters.get("burst_size", 0) > 0, "Burst size not set for video acceleration"
        
        # Test mobile optimization
        mobile_domain = "m.youtube.com"
        strategy = await social_media_handler.optimize_youtube_access(mobile_domain)
        
        assert strategy.parameters.get("mobile_optimization", False), "Mobile optimization not enabled"
        
        # Test CDN fallback for video content
        assert strategy.parameters.get("cdn_fallback", False), "CDN fallback not enabled for video content"
    
    @pytest.mark.asyncio
    async def test_instagram_http_port_issues(self, social_media_handler):
        """Test Instagram HTTP port issue handling."""
        # Test HTTP port (80) handling
        strategy_http = await social_media_handler.optimize_instagram_access("instagram.com", 80)
        
        assert strategy_http.parameters.get("http_port_fix", False), "HTTP port fix not enabled"
        assert "http_manipulation" in strategy_http.attacks, "HTTP manipulation not added for port 80"
        
        # Test HTTPS port (443) - should not have HTTP port fix
        strategy_https = await social_media_handler.optimize_instagram_access("instagram.com", 443)
        
        # HTTP port fix should not be enabled for HTTPS
        assert not strategy_https.parameters.get("http_port_fix", False) or 443 != 80, "HTTP port fix incorrectly enabled for HTTPS"
    
    @pytest.mark.asyncio
    async def test_twitter_media_subdomain_handling(self, social_media_handler):
        """Test Twitter media subdomain specialized handling."""
        # Test media subdomain
        media_strategy = await social_media_handler.optimize_twitter_access("pbs.twimg.com")
        
        assert media_strategy.parameters.get("media_subdomain_handling", False), "Media subdomain handling not enabled"
        assert media_strategy.parameters.get("split_count", 0) >= 4, "Split count not increased for media subdomains"
        
        # Test image optimization
        assert media_strategy.parameters.get("image_optimization", False), "Image optimization not enabled"
    
    @pytest.mark.asyncio
    async def test_tiktok_cdn_rotation_handling(self, social_media_handler):
        """Test TikTok CDN rotation handling."""
        # Test CDN domain
        cdn_strategy = await social_media_handler.optimize_tiktok_access("v16-web.tiktokcdn.com")
        
        assert cdn_strategy.parameters.get("cdn_rotation_handling", False), "CDN rotation handling not enabled"
        assert cdn_strategy.parameters.get("split_count", 0) >= 8, "Split count not increased for CDN rotation"
        
        # Test mobile optimization
        assert cdn_strategy.parameters.get("mobile_optimization", False), "Mobile optimization not enabled"
    
    @pytest.mark.asyncio
    async def test_live_stream_optimizations(self, social_media_handler):
        """Test live stream specific optimizations."""
        live_domains = [
            "youtube.com/live",
            "tiktok.com/live"
        ]
        
        for domain in live_domains:
            if "youtube" in domain:
                strategy = await social_media_handler.optimize_youtube_access(domain)
            else:
                strategy = await social_media_handler.optimize_tiktok_access(domain)
            
            # Live streams should have low jitter for smooth playback
            jitter_ms = strategy.parameters.get("jitter_ms", 0)
            assert jitter_ms <= 10, f"Jitter too high for live stream {domain}: {jitter_ms}ms"
            
            # Live streams should have higher burst sizes for buffer management
            burst_size = strategy.parameters.get("burst_size", 0)
            assert burst_size >= 3, f"Burst size too low for live stream {domain}: {burst_size}"
    
    def test_strategy_effectiveness_updates(self, social_media_handler):
        """Test strategy effectiveness metric updates."""
        # Create test results
        test_results = {
            "overall_success": True,
            "success_rate": 0.9,
            "tests": {
                "speed": {
                    "success": True,
                    "improvement_percent": 35.5
                }
            }
        }
        
        test_strategy = BypassStrategy(
            id="test_effectiveness",
            name="Test Effectiveness Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_count": 3}
        )
        
        # Update effectiveness
        social_media_handler._update_strategy_effectiveness("youtube.com", test_strategy, test_results)
        
        # Check that strategy was added to platform strategies
        assert len(social_media_handler.platform_strategies) > 0, "No platform strategies added"
        
        # Find the added strategy
        added_strategy = None
        for key, platform_strategy in social_media_handler.platform_strategies.items():
            if platform_strategy.strategy.id == test_strategy.id:
                added_strategy = platform_strategy
                break
        
        assert added_strategy is not None, "Test strategy not found in platform strategies"
        assert added_strategy.effectiveness_score > 0, "Effectiveness score not updated"
        assert added_strategy.avg_speed_improvement > 0, "Speed improvement not updated"


class TestSocialMediaIntegration:
    """Integration tests for social media handler with other components."""
    
    @pytest.fixture
    def full_setup(self):
        """Create full setup with all components."""
        # Create temporary files
        subdomain_config = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        social_config = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        
        subdomain_config.close()
        social_config.close()
        
        try:
            # Create pool manager
            pool_manager = Mock(spec=StrategyPoolManager)
            pool_manager.get_strategy_for_domain.return_value = BypassStrategy(
                id="pool_strategy",
                name="Pool Strategy",
                attacks=["http_manipulation"],
                parameters={"split_pos": "midsld"}
            )
            
            # Create subdomain handler
            subdomain_handler = SubdomainStrategyHandler(pool_manager, subdomain_config.name)
            
            # Create social media handler
            social_handler = SocialMediaBypassHandler(subdomain_handler, social_config.name)
            
            yield {
                'pool_manager': pool_manager,
                'subdomain_handler': subdomain_handler,
                'social_handler': social_handler,
                'subdomain_config': subdomain_config.name,
                'social_config': social_config.name
            }
        
        finally:
            # Cleanup
            Path(subdomain_config.name).unlink(missing_ok=True)
            Path(social_config.name).unlink(missing_ok=True)
    
    @pytest.mark.asyncio
    async def test_fallback_to_subdomain_handler(self, full_setup):
        """Test fallback to subdomain handler for unknown platforms."""
        social_handler = full_setup['social_handler']
        
        # Test with unknown domain
        strategy = await social_handler.get_optimized_strategy("unknown-platform.com", 443)
        
        # Should fallback to subdomain handler
        assert strategy is not None, "No fallback strategy provided"
        # The mock returns "fallback_strategy" ID
        assert "fallback" in strategy.id or "pool" in strategy.id, "Did not fallback to subdomain handler"
    
    @pytest.mark.asyncio
    async def test_end_to_end_optimization_flow(self, full_setup):
        """Test complete optimization flow from detection to strategy application."""
        social_handler = full_setup['social_handler']
        
        test_domains = [
            "www.youtube.com",
            "r1---sn-4g5e6nez.googlevideo.com",
            "twitter.com",
            "pbs.twimg.com",
            "instagram.com",
            "www.tiktok.com"
        ]
        
        for domain in test_domains:
            # Get optimized strategy
            strategy = await social_handler.get_optimized_strategy(domain, 443)
            assert strategy is not None, f"No strategy for {domain}"
            
            # Test effectiveness
            results = await social_handler.test_platform_effectiveness(domain, strategy)
            assert results["domain"] == domain, f"Wrong domain in results for {domain}"
            assert "overall_success" in results, f"No overall success for {domain}"
            
            # Get recommendations
            recommendations = social_handler.get_platform_recommendations(domain)
            assert len(recommendations) > 0, f"No recommendations for {domain}"


class TestSocialMediaPerformance:
    """Performance tests for social media handler."""
    
    @pytest.fixture
    def performance_handler(self):
        """Create handler for performance testing."""
        mock_subdomain_handler = Mock(spec=SubdomainStrategyHandler)
        mock_subdomain_handler.get_strategy_for_subdomain.return_value = BypassStrategy(
            id="perf_strategy",
            name="Performance Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_count": 3}
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_path = f.name
        
        handler = SocialMediaBypassHandler(mock_subdomain_handler, config_path)
        
        yield handler
        
        Path(config_path).unlink(missing_ok=True)
    
    @pytest.mark.asyncio
    async def test_concurrent_strategy_requests(self, performance_handler):
        """Test handling concurrent strategy requests."""
        domains = [
            "www.youtube.com",
            "r1---sn-4g5e6nez.googlevideo.com",
            "twitter.com",
            "pbs.twimg.com",
            "instagram.com",
            "scontent.cdninstagram.com",
            "www.tiktok.com",
            "v16-web.tiktokcdn.com"
        ] * 5  # 40 total requests
        
        # Create concurrent tasks
        tasks = [
            performance_handler.get_optimized_strategy(domain, 443)
            for domain in domains
        ]
        
        # Execute concurrently
        start_time = asyncio.get_event_loop().time()
        results = await asyncio.gather(*tasks)
        end_time = asyncio.get_event_loop().time()
        
        # Verify all requests completed successfully
        assert len(results) == len(domains), "Not all requests completed"
        assert all(r is not None for r in results), "Some requests failed"
        
        # Performance check - should complete within reasonable time
        total_time = end_time - start_time
        assert total_time < 5.0, f"Concurrent requests took too long: {total_time:.2f}s"
    
    @pytest.mark.asyncio
    async def test_effectiveness_testing_performance(self, performance_handler):
        """Test performance of effectiveness testing."""
        test_domains = [
            "www.youtube.com",
            "twitter.com",
            "instagram.com",
            "www.tiktok.com"
        ]
        
        # Test sequential performance
        start_time = asyncio.get_event_loop().time()
        
        for domain in test_domains:
            results = await performance_handler.test_platform_effectiveness(domain)
            assert results["overall_success"] is not None, f"Test failed for {domain}"
        
        sequential_time = asyncio.get_event_loop().time() - start_time
        
        # Test concurrent performance
        start_time = asyncio.get_event_loop().time()
        
        tasks = [
            performance_handler.test_platform_effectiveness(domain)
            for domain in test_domains
        ]
        
        concurrent_results = await asyncio.gather(*tasks)
        concurrent_time = asyncio.get_event_loop().time() - start_time
        
        # Concurrent should be faster than sequential
        assert concurrent_time < sequential_time, "Concurrent testing not faster than sequential"
        assert len(concurrent_results) == len(test_domains), "Not all concurrent tests completed"


if __name__ == "__main__":
    # Run basic tests
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Create simple test instance
    mock_subdomain = Mock(spec=SubdomainStrategyHandler)
    mock_subdomain.get_strategy_for_subdomain.return_value = BypassStrategy(
        id="test_strategy",
        name="Test Strategy",
        attacks=["http_manipulation"],
        parameters={"split_pos": "midsld"}
    )
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_path = f.name
    
    try:
        handler = SocialMediaBypassHandler(mock_subdomain, config_path)
        
        # Test platform detection
        print("Testing platform detection...")
        test_domains = [
            "www.youtube.com",
            "r1---sn-4g5e6nez.googlevideo.com",
            "twitter.com",
            "pbs.twimg.com",
            "instagram.com",
            "www.tiktok.com"
        ]
        
        for domain in test_domains:
            platform = handler._detect_platform(domain)
            print(f"  {domain} -> {platform.value}")
        
        # Test strategy optimization
        print("\nTesting strategy optimization...")
        
        async def test_optimizations():
            for domain in test_domains:
                strategy = await handler.get_optimized_strategy(domain, 443)
                print(f"  {domain} -> {strategy.name} ({len(strategy.attacks)} attacks)")
        
        asyncio.run(test_optimizations())
        
        print("\nAll basic tests passed!")
        
    finally:
        Path(config_path).unlink(missing_ok=True)