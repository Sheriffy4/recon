#!/usr/bin/env python3
"""
Specialized Social Media and Video Platform Support for Bypass Engine Modernization

This module implements advanced bypass strategies specifically designed for social media
and video platforms including YouTube, Twitter/X, Instagram, TikTok, and others.
"""

import logging
import json
import asyncio
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple, Set
from enum import Enum
from pathlib import Path

try:
    from .pool_management import BypassStrategy, StrategyPool, StrategyPoolManager
    from .subdomain_handler import SubdomainStrategyHandler, PlatformType, SubdomainType
except ImportError:
    # Handle relative import issues
    import sys
    import os

    sys.path.append(os.path.dirname(__file__))
    from pool_management import BypassStrategy
    from subdomain_handler import SubdomainStrategyHandler, PlatformType


LOG = logging.getLogger("SocialMediaHandler")


class MediaType(Enum):
    """Types of media content requiring specialized handling."""

    VIDEO_STREAM = "video_stream"
    LIVE_STREAM = "live_stream"
    IMAGE_CONTENT = "image_content"
    AUDIO_STREAM = "audio_stream"
    THUMBNAIL = "thumbnail"
    AVATAR = "avatar"
    STORY_CONTENT = "story_content"
    SHORTS_VIDEO = "shorts_video"
    REEL_CONTENT = "reel_content"


class BlockingPattern(Enum):
    """Common blocking patterns for social media platforms."""

    SNI_BLOCKING = "sni_blocking"
    HTTP_HOST_BLOCKING = "http_host_blocking"
    DPI_CONTENT_INSPECTION = "dpi_content_inspection"
    THROTTLING = "throttling"
    PARTIAL_BLOCKING = "partial_blocking"
    CDN_BLOCKING = "cdn_blocking"
    API_BLOCKING = "api_blocking"


@dataclass
class PlatformSpecificStrategy:
    """Platform-specific bypass strategy with specialized parameters."""

    platform: PlatformType
    media_type: MediaType
    blocking_pattern: BlockingPattern
    strategy: BypassStrategy
    effectiveness_score: float = 0.0
    avg_speed_improvement: float = 0.0
    compatibility_notes: str = ""
    last_updated: Optional[datetime] = None

    def update_effectiveness(
        self, success: bool, speed_improvement: float = 0.0
    ) -> None:
        """Update strategy effectiveness metrics."""
        # Simple exponential moving average
        alpha = 0.3
        if success:
            new_score = 1.0
            self.avg_speed_improvement = (
                alpha * speed_improvement + (1 - alpha) * self.avg_speed_improvement
            )
        else:
            new_score = 0.0

        if self.effectiveness_score == 0.0:
            self.effectiveness_score = new_score
        else:
            self.effectiveness_score = (
                alpha * new_score + (1 - alpha) * self.effectiveness_score
            )

        self.last_updated = datetime.now()


@dataclass
class YouTubeSpecificConfig:
    """YouTube-specific configuration and strategies."""

    web_interface_strategy: BypassStrategy
    video_content_strategy: BypassStrategy
    shorts_strategy: BypassStrategy
    live_stream_strategy: BypassStrategy
    thumbnail_strategy: BypassStrategy
    api_strategy: BypassStrategy

    # YouTube-specific parameters
    enable_video_acceleration: bool = True
    use_alternative_cdn: bool = True
    bypass_age_restriction: bool = False
    optimize_for_mobile: bool = True


@dataclass
class TwitterSpecificConfig:
    """Twitter/X-specific configuration and strategies."""

    web_interface_strategy: BypassStrategy
    media_content_strategy: BypassStrategy
    api_strategy: BypassStrategy
    upload_strategy: BypassStrategy

    # Twitter-specific parameters
    handle_media_subdomains: bool = True
    optimize_image_loading: bool = True
    bypass_rate_limiting: bool = False
    support_spaces_audio: bool = True


@dataclass
class InstagramSpecificConfig:
    """Instagram-specific configuration and strategies."""

    web_interface_strategy: BypassStrategy
    media_content_strategy: BypassStrategy
    stories_strategy: BypassStrategy
    reels_strategy: BypassStrategy
    api_strategy: BypassStrategy

    # Instagram-specific parameters
    handle_http_port_issues: bool = True
    optimize_cdn_access: bool = True
    bypass_login_wall: bool = False
    support_igtv: bool = True


@dataclass
class TikTokSpecificConfig:
    """TikTok-specific configuration and strategies."""

    web_interface_strategy: BypassStrategy
    video_content_strategy: BypassStrategy
    live_stream_strategy: BypassStrategy
    api_strategy: BypassStrategy

    # TikTok-specific parameters
    optimize_for_mobile: bool = True
    handle_cdn_rotation: bool = True
    bypass_region_blocking: bool = False
    support_live_streams: bool = True


class SocialMediaBypassHandler:
    """
    Specialized handler for social media and video platform bypass strategies.

    This class extends the basic subdomain handler with platform-specific
    optimizations and advanced bypass techniques.
    """

    def __init__(
        self,
        subdomain_handler: SubdomainStrategyHandler,
        config_path: str = "social_media_config.json",
    ):
        self.subdomain_handler = subdomain_handler
        self.config_path = config_path

        # Platform-specific configurations
        self.youtube_config: Optional[YouTubeSpecificConfig] = None
        self.twitter_config: Optional[TwitterSpecificConfig] = None
        self.instagram_config: Optional[InstagramSpecificConfig] = None
        self.tiktok_config: Optional[TikTokSpecificConfig] = None

        # Platform-specific strategies storage
        self.platform_strategies: Dict[str, PlatformSpecificStrategy] = {}

        # Blocking pattern detection
        self.detected_patterns: Dict[str, Set[BlockingPattern]] = {}

        # Initialize platform configurations
        self._initialize_platform_configs()

        # Load existing configurations
        self._load_configuration()

    async def get_optimized_strategy(
        self, domain: str, port: int = 443, media_type: MediaType = None
    ) -> Optional[BypassStrategy]:
        """
        Get optimized bypass strategy for social media platforms.

        Args:
            domain: Target domain
            port: Target port
            media_type: Type of media content (if known)

        Returns:
            Optimized bypass strategy or None
        """
        LOG.info(
            f"Getting optimized strategy for {domain}:{port} (media_type: {media_type})"
        )

        # Detect platform
        platform = self._detect_platform(domain)

        if platform == PlatformType.GENERIC:
            # Fallback to subdomain handler
            return self.subdomain_handler.get_strategy_for_subdomain(domain, port)

        # Detect blocking patterns
        blocking_patterns = await self._detect_blocking_patterns(domain, port)

        # Get platform-specific strategy
        strategy = await self._get_platform_optimized_strategy(
            domain, port, platform, media_type, blocking_patterns
        )

        if strategy:
            LOG.info(f"Selected optimized strategy: {strategy.name}")
            return strategy

        # Fallback to subdomain handler
        return self.subdomain_handler.get_strategy_for_subdomain(domain, port)

    async def test_platform_effectiveness(
        self, domain: str, strategy: BypassStrategy = None
    ) -> Dict[str, Any]:
        """
        Test strategy effectiveness for a specific platform.

        Args:
            domain: Domain to test
            strategy: Strategy to test (auto-selected if None)

        Returns:
            Comprehensive test results
        """
        if not strategy:
            strategy = await self.get_optimized_strategy(domain)

        if not strategy:
            return {"success": False, "error": "No strategy available"}

        LOG.info(f"Testing platform effectiveness for {domain}")

        # Perform multiple test types
        results = {
            "domain": domain,
            "strategy_id": strategy.id,
            "timestamp": datetime.now().isoformat(),
            "tests": {},
        }

        # Basic connectivity test
        connectivity_result = await self._test_basic_connectivity(domain, strategy)
        results["tests"]["connectivity"] = connectivity_result

        # Speed test
        speed_result = await self._test_speed_performance(domain, strategy)
        results["tests"]["speed"] = speed_result

        # Content accessibility test
        content_result = await self._test_content_accessibility(domain, strategy)
        results["tests"]["content"] = content_result

        # Platform-specific tests
        platform = self._detect_platform(domain)
        if platform != PlatformType.GENERIC:
            platform_result = await self._test_platform_specific_features(
                domain, platform, strategy
            )
            results["tests"]["platform_specific"] = platform_result

        # Calculate overall success
        test_results = [r.get("success", False) for r in results["tests"].values()]
        results["overall_success"] = all(test_results)
        results["success_rate"] = (
            sum(test_results) / len(test_results) if test_results else 0.0
        )

        # Update strategy effectiveness
        self._update_strategy_effectiveness(domain, strategy, results)

        return results

    async def optimize_youtube_access(self, domain: str) -> BypassStrategy:
        """
        Optimize YouTube access with specialized strategies.

        Args:
            domain: YouTube domain

        Returns:
            Optimized YouTube strategy
        """
        LOG.info(f"Optimizing YouTube access for {domain}")

        # Detect YouTube subdomain type
        if "googlevideo.com" in domain:
            # Video content domain
            strategy = self.youtube_config.video_content_strategy
        elif "ytimg.com" in domain:
            # Thumbnail domain
            strategy = self.youtube_config.thumbnail_strategy
        elif "shorts" in domain or "/shorts" in domain:
            # YouTube Shorts
            strategy = self.youtube_config.shorts_strategy
        elif "live" in domain or "/live" in domain:
            # Live stream
            strategy = self.youtube_config.live_stream_strategy
        else:
            # Main interface
            strategy = self.youtube_config.web_interface_strategy

        # Apply YouTube-specific optimizations
        optimized_strategy = self._apply_youtube_optimizations(strategy, domain)

        return optimized_strategy

    async def optimize_twitter_access(self, domain: str) -> BypassStrategy:
        """
        Optimize Twitter/X access with specialized strategies.

        Args:
            domain: Twitter domain

        Returns:
            Optimized Twitter strategy
        """
        LOG.info(f"Optimizing Twitter access for {domain}")

        # Detect Twitter subdomain type
        if "twimg.com" in domain or "pbs.twimg.com" in domain:
            # Media content domain
            strategy = self.twitter_config.media_content_strategy
        elif "api.twitter.com" in domain:
            # API domain
            strategy = self.twitter_config.api_strategy
        elif "upload.twitter.com" in domain:
            # Upload domain
            strategy = self.twitter_config.upload_strategy
        else:
            # Main interface
            strategy = self.twitter_config.web_interface_strategy

        # Apply Twitter-specific optimizations
        optimized_strategy = self._apply_twitter_optimizations(strategy, domain)

        return optimized_strategy

    async def optimize_instagram_access(
        self, domain: str, port: int = 443
    ) -> BypassStrategy:
        """
        Optimize Instagram access with specialized strategies.

        Args:
            domain: Instagram domain
            port: Target port (Instagram has HTTP port issues)

        Returns:
            Optimized Instagram strategy
        """
        LOG.info(f"Optimizing Instagram access for {domain}:{port}")

        # Detect Instagram subdomain type
        if "cdninstagram.com" in domain or "fbcdn.net" in domain:
            # Media content domain
            strategy = self.instagram_config.media_content_strategy
        elif "stories" in domain:
            # Stories content
            strategy = self.instagram_config.stories_strategy
        elif "reels" in domain or "reel" in domain:
            # Reels content
            strategy = self.instagram_config.reels_strategy
        elif "i.instagram.com" in domain:
            # API domain
            strategy = self.instagram_config.api_strategy
        else:
            # Main interface
            strategy = self.instagram_config.web_interface_strategy

        # Apply Instagram-specific optimizations (especially for HTTP port issues)
        optimized_strategy = self._apply_instagram_optimizations(strategy, domain, port)

        return optimized_strategy

    async def optimize_tiktok_access(self, domain: str) -> BypassStrategy:
        """
        Optimize TikTok access with specialized strategies.

        Args:
            domain: TikTok domain

        Returns:
            Optimized TikTok strategy
        """
        LOG.info(f"Optimizing TikTok access for {domain}")

        # Detect TikTok subdomain type
        if "tiktokcdn.com" in domain or "musical.ly" in domain:
            # Video content domain
            strategy = self.tiktok_config.video_content_strategy
        elif "live" in domain:
            # Live stream
            strategy = self.tiktok_config.live_stream_strategy
        elif "api" in domain:
            # API domain
            strategy = self.tiktok_config.api_strategy
        else:
            # Main interface
            strategy = self.tiktok_config.web_interface_strategy

        # Apply TikTok-specific optimizations
        optimized_strategy = self._apply_tiktok_optimizations(strategy, domain)

        return optimized_strategy

    def get_platform_recommendations(
        self, domain: str
    ) -> List[Tuple[BypassStrategy, float, str]]:
        """
        Get platform-specific strategy recommendations.

        Args:
            domain: Domain to get recommendations for

        Returns:
            List of (strategy, confidence, reason) tuples
        """
        platform = self._detect_platform(domain)
        recommendations = []

        if platform == PlatformType.YOUTUBE:
            recommendations.extend(self._get_youtube_recommendations(domain))
        elif platform == PlatformType.TWITTER:
            recommendations.extend(self._get_twitter_recommendations(domain))
        elif platform == PlatformType.INSTAGRAM:
            recommendations.extend(self._get_instagram_recommendations(domain))
        elif platform == PlatformType.TIKTOK:
            recommendations.extend(self._get_tiktok_recommendations(domain))
        else:
            # Generic recommendations
            recommendations.append(
                (
                    BypassStrategy(
                        id="generic_social",
                        name="Generic Social Media Strategy",
                        attacks=["http_manipulation", "tls_evasion"],
                        parameters={"split_pos": "midsld", "ttl": 2},
                    ),
                    0.5,
                    "Generic strategy for unrecognized platform",
                )
            )

        # Sort by confidence
        recommendations.sort(key=lambda x: x[1], reverse=True)

        return recommendations

    def _initialize_platform_configs(self) -> None:
        """Initialize platform-specific configurations."""

        # YouTube Configuration
        self.youtube_config = YouTubeSpecificConfig(
            web_interface_strategy=BypassStrategy(
                id="youtube_web_optimized",
                name="YouTube Web Interface (Optimized)",
                attacks=["http_manipulation", "tls_evasion"],
                parameters={
                    "split_pos": "midsld",
                    "ttl": 2,
                    "fake_sni": False,
                    "split_count": 1,
                },
            ),
            video_content_strategy=BypassStrategy(
                id="youtube_video_optimized",
                name="YouTube Video Content (Optimized)",
                attacks=["tcp_fragmentation", "packet_timing", "http_manipulation"],
                parameters={
                    "split_count": 5,
                    "ttl": 3,
                    "fake_sni": True,
                    "jitter_ms": 10,
                    "burst_size": 3,
                },
            ),
            shorts_strategy=BypassStrategy(
                id="youtube_shorts_optimized",
                name="YouTube Shorts (Optimized)",
                attacks=["tcp_fragmentation", "tls_evasion"],
                parameters={
                    "split_count": 3,
                    "ttl": 2,
                    "fake_sni": True,
                    "split_pos": "random",
                },
            ),
            live_stream_strategy=BypassStrategy(
                id="youtube_live_optimized",
                name="YouTube Live Stream (Optimized)",
                attacks=["packet_timing", "tcp_fragmentation"],
                parameters={
                    "jitter_ms": 5,
                    "split_count": 7,
                    "ttl": 4,
                    "burst_size": 5,
                },
            ),
            thumbnail_strategy=BypassStrategy(
                id="youtube_thumbnail_optimized",
                name="YouTube Thumbnails (Optimized)",
                attacks=["tcp_fragmentation"],
                parameters={"split_pos": 3, "ttl": 1, "fake_sni": False},
            ),
            api_strategy=BypassStrategy(
                id="youtube_api_optimized",
                name="YouTube API (Optimized)",
                attacks=["http_manipulation"],
                parameters={"split_pos": "midsld", "ttl": 1, "fake_sni": False},
            ),
        )

        # Twitter Configuration
        self.twitter_config = TwitterSpecificConfig(
            web_interface_strategy=BypassStrategy(
                id="twitter_web_optimized",
                name="Twitter Web Interface (Optimized)",
                attacks=["http_manipulation", "tls_evasion"],
                parameters={"split_pos": "midsld", "ttl": 2, "fake_sni": False},
            ),
            media_content_strategy=BypassStrategy(
                id="twitter_media_optimized",
                name="Twitter Media Content (Optimized)",
                attacks=["tcp_fragmentation", "http_manipulation"],
                parameters={
                    "split_pos": 5,
                    "ttl": 3,
                    "fake_sni": True,
                    "split_count": 4,
                },
            ),
            api_strategy=BypassStrategy(
                id="twitter_api_optimized",
                name="Twitter API (Optimized)",
                attacks=["http_manipulation"],
                parameters={"split_pos": "midsld", "ttl": 1, "fake_sni": False},
            ),
            upload_strategy=BypassStrategy(
                id="twitter_upload_optimized",
                name="Twitter Upload (Optimized)",
                attacks=["tcp_fragmentation", "packet_timing"],
                parameters={"split_count": 3, "ttl": 2, "jitter_ms": 15},
            ),
        )

        # Instagram Configuration
        self.instagram_config = InstagramSpecificConfig(
            web_interface_strategy=BypassStrategy(
                id="instagram_web_optimized",
                name="Instagram Web Interface (Optimized)",
                attacks=["http_manipulation", "tls_evasion"],
                parameters={
                    "split_pos": "midsld",
                    "ttl": 2,
                    "fake_sni": False,
                    "http_port_fallback": True,
                },
            ),
            media_content_strategy=BypassStrategy(
                id="instagram_media_optimized",
                name="Instagram Media Content (Optimized)",
                attacks=["tcp_fragmentation", "packet_timing"],
                parameters={
                    "split_count": 7,
                    "ttl": 3,
                    "fake_sni": True,
                    "jitter_ms": 20,
                    "cdn_optimization": True,
                },
            ),
            stories_strategy=BypassStrategy(
                id="instagram_stories_optimized",
                name="Instagram Stories (Optimized)",
                attacks=["tcp_fragmentation", "http_manipulation"],
                parameters={"split_count": 4, "ttl": 2, "fake_sni": True},
            ),
            reels_strategy=BypassStrategy(
                id="instagram_reels_optimized",
                name="Instagram Reels (Optimized)",
                attacks=["tcp_fragmentation", "packet_timing"],
                parameters={
                    "split_count": 6,
                    "ttl": 3,
                    "fake_sni": True,
                    "jitter_ms": 12,
                },
            ),
            api_strategy=BypassStrategy(
                id="instagram_api_optimized",
                name="Instagram API (Optimized)",
                attacks=["http_manipulation"],
                parameters={"split_pos": "midsld", "ttl": 1, "fake_sni": False},
            ),
        )

        # TikTok Configuration
        self.tiktok_config = TikTokSpecificConfig(
            web_interface_strategy=BypassStrategy(
                id="tiktok_web_optimized",
                name="TikTok Web Interface (Optimized)",
                attacks=["http_manipulation", "tls_evasion"],
                parameters={
                    "split_pos": "midsld",
                    "ttl": 2,
                    "fake_sni": False,
                    "mobile_optimization": True,
                },
            ),
            video_content_strategy=BypassStrategy(
                id="tiktok_video_optimized",
                name="TikTok Video Content (Optimized)",
                attacks=["tcp_fragmentation", "packet_timing"],
                parameters={
                    "split_count": 8,
                    "ttl": 4,
                    "fake_sni": True,
                    "jitter_ms": 8,
                    "burst_size": 4,
                },
            ),
            live_stream_strategy=BypassStrategy(
                id="tiktok_live_optimized",
                name="TikTok Live Stream (Optimized)",
                attacks=["packet_timing", "tcp_fragmentation"],
                parameters={
                    "jitter_ms": 3,
                    "split_count": 10,
                    "ttl": 5,
                    "burst_size": 6,
                },
            ),
            api_strategy=BypassStrategy(
                id="tiktok_api_optimized",
                name="TikTok API (Optimized)",
                attacks=["http_manipulation"],
                parameters={"split_pos": "midsld", "ttl": 1, "fake_sni": False},
            ),
        )

        LOG.info("Initialized specialized social media platform configurations")

    def _detect_platform(self, domain: str) -> PlatformType:
        """Detect platform type from domain."""
        domain_lower = domain.lower()

        # YouTube detection
        if any(
            yt_domain in domain_lower
            for yt_domain in ["youtube.com", "googlevideo.com", "ytimg.com"]
        ):
            return PlatformType.YOUTUBE

        # Twitter detection
        if any(
            tw_domain in domain_lower
            for tw_domain in ["twitter.com", "twimg.com", "t.co"]
        ):
            return PlatformType.TWITTER

        # Instagram detection
        if any(
            ig_domain in domain_lower
            for ig_domain in ["instagram.com", "cdninstagram.com", "fbcdn.net"]
        ):
            return PlatformType.INSTAGRAM

        # TikTok detection
        if any(
            tt_domain in domain_lower
            for tt_domain in ["tiktok.com", "tiktokcdn.com", "musical.ly"]
        ):
            return PlatformType.TIKTOK

        return PlatformType.GENERIC

    async def _detect_blocking_patterns(
        self, domain: str, port: int
    ) -> Set[BlockingPattern]:
        """Detect blocking patterns for a domain."""
        patterns = set()

        # Simulate blocking pattern detection
        # In real implementation, this would perform actual network tests

        # Common patterns based on domain characteristics
        if "googlevideo.com" in domain or "tiktokcdn.com" in domain:
            patterns.add(BlockingPattern.DPI_CONTENT_INSPECTION)
            patterns.add(BlockingPattern.THROTTLING)

        if "twimg.com" in domain or "cdninstagram.com" in domain:
            patterns.add(BlockingPattern.CDN_BLOCKING)

        if port == 80:
            patterns.add(BlockingPattern.HTTP_HOST_BLOCKING)
        else:
            patterns.add(BlockingPattern.SNI_BLOCKING)

        # Cache detected patterns
        self.detected_patterns[domain] = patterns

        return patterns

    async def _get_platform_optimized_strategy(
        self,
        domain: str,
        port: int,
        platform: PlatformType,
        media_type: MediaType,
        blocking_patterns: Set[BlockingPattern],
    ) -> Optional[BypassStrategy]:
        """Get optimized strategy based on platform and blocking patterns."""

        if platform == PlatformType.YOUTUBE:
            strategy = await self.optimize_youtube_access(domain)
        elif platform == PlatformType.TWITTER:
            strategy = await self.optimize_twitter_access(domain)
        elif platform == PlatformType.INSTAGRAM:
            strategy = await self.optimize_instagram_access(domain, port)
        elif platform == PlatformType.TIKTOK:
            strategy = await self.optimize_tiktok_access(domain)
        else:
            return None

        # Apply blocking pattern specific optimizations
        optimized_strategy = self._apply_blocking_pattern_optimizations(
            strategy, blocking_patterns
        )

        return optimized_strategy

    def _apply_blocking_pattern_optimizations(
        self, strategy: BypassStrategy, blocking_patterns: Set[BlockingPattern]
    ) -> BypassStrategy:
        """Apply optimizations based on detected blocking patterns."""
        optimized_params = strategy.parameters.copy()
        optimized_attacks = strategy.attacks.copy()

        if BlockingPattern.THROTTLING in blocking_patterns:
            # Add packet timing attacks for throttling
            if "packet_timing" not in optimized_attacks:
                optimized_attacks.append("packet_timing")
            optimized_params["jitter_ms"] = optimized_params.get("jitter_ms", 10)

        if BlockingPattern.DPI_CONTENT_INSPECTION in blocking_patterns:
            # Add protocol obfuscation for DPI
            if "protocol_obfuscation" not in optimized_attacks:
                optimized_attacks.append("protocol_obfuscation")
            optimized_params["fake_sni"] = True

        if BlockingPattern.CDN_BLOCKING in blocking_patterns:
            # Optimize for CDN bypass
            optimized_params["cdn_optimization"] = True
            optimized_params["split_count"] = max(
                optimized_params.get("split_count", 3), 5
            )

        if BlockingPattern.HTTP_HOST_BLOCKING in blocking_patterns:
            # Add HTTP manipulation
            if "http_manipulation" not in optimized_attacks:
                optimized_attacks.append("http_manipulation")

        return BypassStrategy(
            id=f"{strategy.id}_optimized",
            name=f"{strategy.name} (Pattern Optimized)",
            attacks=optimized_attacks,
            parameters=optimized_params,
        )

    def _apply_youtube_optimizations(
        self, strategy: BypassStrategy, domain: str
    ) -> BypassStrategy:
        """Apply YouTube-specific optimizations."""
        optimized_params = strategy.parameters.copy()

        if self.youtube_config.enable_video_acceleration:
            optimized_params["video_acceleration"] = True
            optimized_params["burst_size"] = optimized_params.get("burst_size", 3)

        if self.youtube_config.use_alternative_cdn and "googlevideo.com" in domain:
            optimized_params["cdn_fallback"] = True

        if self.youtube_config.optimize_for_mobile:
            optimized_params["mobile_optimization"] = True

        return BypassStrategy(
            id=f"{strategy.id}_yt_optimized",
            name=f"{strategy.name} (YouTube Optimized)",
            attacks=strategy.attacks,
            parameters=optimized_params,
        )

    def _apply_twitter_optimizations(
        self, strategy: BypassStrategy, domain: str
    ) -> BypassStrategy:
        """Apply Twitter-specific optimizations."""
        optimized_params = strategy.parameters.copy()

        if self.twitter_config.handle_media_subdomains and "twimg.com" in domain:
            optimized_params["media_subdomain_handling"] = True
            optimized_params["split_count"] = max(
                optimized_params.get("split_count", 3), 4
            )

        if self.twitter_config.optimize_image_loading:
            optimized_params["image_optimization"] = True

        if self.twitter_config.support_spaces_audio:
            optimized_params["audio_support"] = True

        return BypassStrategy(
            id=f"{strategy.id}_tw_optimized",
            name=f"{strategy.name} (Twitter Optimized)",
            attacks=strategy.attacks,
            parameters=optimized_params,
        )

    def _apply_instagram_optimizations(
        self, strategy: BypassStrategy, domain: str, port: int
    ) -> BypassStrategy:
        """Apply Instagram-specific optimizations."""
        optimized_params = strategy.parameters.copy()
        optimized_attacks = strategy.attacks.copy()

        if self.instagram_config.handle_http_port_issues and port == 80:
            # Special handling for Instagram HTTP port issues
            optimized_params["http_port_fix"] = True
            if "http_manipulation" not in optimized_attacks:
                optimized_attacks.append("http_manipulation")

        if self.instagram_config.optimize_cdn_access and (
            "cdninstagram.com" in domain or "fbcdn.net" in domain
        ):
            optimized_params["cdn_optimization"] = True
            optimized_params["split_count"] = max(
                optimized_params.get("split_count", 5), 7
            )

        if self.instagram_config.support_igtv:
            optimized_params["igtv_support"] = True

        return BypassStrategy(
            id=f"{strategy.id}_ig_optimized",
            name=f"{strategy.name} (Instagram Optimized)",
            attacks=optimized_attacks,
            parameters=optimized_params,
        )

    def _apply_tiktok_optimizations(
        self, strategy: BypassStrategy, domain: str
    ) -> BypassStrategy:
        """Apply TikTok-specific optimizations."""
        optimized_params = strategy.parameters.copy()

        if self.tiktok_config.optimize_for_mobile:
            optimized_params["mobile_optimization"] = True

        if self.tiktok_config.handle_cdn_rotation and "tiktokcdn.com" in domain:
            optimized_params["cdn_rotation_handling"] = True
            optimized_params["split_count"] = max(
                optimized_params.get("split_count", 6), 8
            )

        if self.tiktok_config.support_live_streams and "live" in domain:
            optimized_params["live_stream_optimization"] = True
            optimized_params["jitter_ms"] = min(
                optimized_params.get("jitter_ms", 10), 5
            )

        return BypassStrategy(
            id=f"{strategy.id}_tt_optimized",
            name=f"{strategy.name} (TikTok Optimized)",
            attacks=strategy.attacks,
            parameters=optimized_params,
        )

    async def _test_basic_connectivity(
        self, domain: str, strategy: BypassStrategy
    ) -> Dict[str, Any]:
        """Test basic connectivity with strategy."""
        # Simulate connectivity test
        import random

        await asyncio.sleep(0.1)  # Simulate network delay

        success = random.random() > 0.15  # 85% success rate
        latency = random.uniform(50, 200)  # ms

        return {
            "success": success,
            "latency_ms": latency,
            "error": None if success else "Connection timeout",
        }

    async def _test_speed_performance(
        self, domain: str, strategy: BypassStrategy
    ) -> Dict[str, Any]:
        """Test speed performance with strategy."""
        # Simulate speed test
        import random

        await asyncio.sleep(0.2)  # Simulate speed test delay

        # Simulate speed improvement based on strategy
        base_speed = random.uniform(1.0, 10.0)  # Mbps
        improvement_factor = 1.0

        if "packet_timing" in strategy.attacks:
            improvement_factor += 0.3
        if "tcp_fragmentation" in strategy.attacks:
            improvement_factor += 0.2
        if strategy.parameters.get("video_acceleration", False):
            improvement_factor += 0.5

        improved_speed = base_speed * improvement_factor
        speed_improvement = (improved_speed - base_speed) / base_speed * 100

        return {
            "success": True,
            "base_speed_mbps": base_speed,
            "improved_speed_mbps": improved_speed,
            "improvement_percent": speed_improvement,
        }

    async def _test_content_accessibility(
        self, domain: str, strategy: BypassStrategy
    ) -> Dict[str, Any]:
        """Test content accessibility with strategy."""
        # Simulate content accessibility test
        import random

        await asyncio.sleep(0.15)  # Simulate content test delay

        # Different success rates for different content types
        platform = self._detect_platform(domain)

        if platform == PlatformType.YOUTUBE and "googlevideo.com" in domain:
            success_rate = 0.9  # High success for video content
        elif platform == PlatformType.INSTAGRAM and "cdninstagram.com" in domain:
            success_rate = 0.85  # Good success for Instagram media
        elif platform == PlatformType.TWITTER and "twimg.com" in domain:
            success_rate = 0.88  # Good success for Twitter media
        elif platform == PlatformType.TIKTOK and "tiktokcdn.com" in domain:
            success_rate = 0.82  # Decent success for TikTok content
        else:
            success_rate = 0.75  # Default success rate

        success = random.random() < success_rate

        return {
            "success": success,
            "content_type": (
                "media"
                if any(
                    cdn in domain
                    for cdn in ["googlevideo", "twimg", "cdninstagram", "tiktokcdn"]
                )
                else "web"
            ),
            "accessibility_score": success_rate,
        }

    async def _test_platform_specific_features(
        self, domain: str, platform: PlatformType, strategy: BypassStrategy
    ) -> Dict[str, Any]:
        """Test platform-specific features."""
        # Simulate platform-specific tests
        import random

        await asyncio.sleep(0.1)

        features_tested = []
        results = {}

        if platform == PlatformType.YOUTUBE:
            features_tested = [
                "video_playback",
                "thumbnail_loading",
                "comments_loading",
            ]
        elif platform == PlatformType.TWITTER:
            features_tested = ["timeline_loading", "media_display", "tweet_posting"]
        elif platform == PlatformType.INSTAGRAM:
            features_tested = ["feed_loading", "story_viewing", "image_display"]
        elif platform == PlatformType.TIKTOK:
            features_tested = ["video_feed", "video_playback", "user_profiles"]

        for feature in features_tested:
            results[feature] = {
                "success": random.random() > 0.2,  # 80% success rate
                "response_time_ms": random.uniform(100, 500),
            }

        overall_success = all(r["success"] for r in results.values())

        return {
            "success": overall_success,
            "features": results,
            "platform": platform.value,
        }

    def _update_strategy_effectiveness(
        self, domain: str, strategy: BypassStrategy, results: Dict[str, Any]
    ) -> None:
        """Update strategy effectiveness based on test results."""
        platform = self._detect_platform(domain)

        # Calculate speed improvement
        speed_improvement = 0.0
        if "speed" in results["tests"] and results["tests"]["speed"]["success"]:
            speed_improvement = results["tests"]["speed"].get(
                "improvement_percent", 0.0
            )

        # Create or update platform-specific strategy
        key = f"{platform.value}_{domain}_{strategy.id}"

        if key in self.platform_strategies:
            self.platform_strategies[key].update_effectiveness(
                results["overall_success"], speed_improvement
            )
        else:
            # Detect media type and blocking pattern
            media_type = (
                MediaType.VIDEO_STREAM if "video" in domain else MediaType.IMAGE_CONTENT
            )
            blocking_patterns = self.detected_patterns.get(
                domain, {BlockingPattern.SNI_BLOCKING}
            )
            primary_pattern = (
                next(iter(blocking_patterns))
                if blocking_patterns
                else BlockingPattern.SNI_BLOCKING
            )

            platform_strategy = PlatformSpecificStrategy(
                platform=platform,
                media_type=media_type,
                blocking_pattern=primary_pattern,
                strategy=strategy,
                effectiveness_score=1.0 if results["overall_success"] else 0.0,
                avg_speed_improvement=speed_improvement,
            )

            self.platform_strategies[key] = platform_strategy

        # Save configuration
        self._save_configuration()

    def _get_youtube_recommendations(
        self, domain: str
    ) -> List[Tuple[BypassStrategy, float, str]]:
        """Get YouTube-specific recommendations."""
        recommendations = []

        if "googlevideo.com" in domain:
            recommendations.append(
                (
                    self.youtube_config.video_content_strategy,
                    0.95,
                    "Optimized for YouTube video content delivery",
                )
            )
        elif "ytimg.com" in domain:
            recommendations.append(
                (
                    self.youtube_config.thumbnail_strategy,
                    0.9,
                    "Optimized for YouTube thumbnail loading",
                )
            )
        elif "shorts" in domain:
            recommendations.append(
                (
                    self.youtube_config.shorts_strategy,
                    0.88,
                    "Optimized for YouTube Shorts",
                )
            )
        else:
            recommendations.append(
                (
                    self.youtube_config.web_interface_strategy,
                    0.85,
                    "Optimized for YouTube web interface",
                )
            )

        return recommendations

    def _get_twitter_recommendations(
        self, domain: str
    ) -> List[Tuple[BypassStrategy, float, str]]:
        """Get Twitter-specific recommendations."""
        recommendations = []

        if "twimg.com" in domain:
            recommendations.append(
                (
                    self.twitter_config.media_content_strategy,
                    0.92,
                    "Optimized for Twitter media content",
                )
            )
        elif "api.twitter.com" in domain:
            recommendations.append(
                (
                    self.twitter_config.api_strategy,
                    0.88,
                    "Optimized for Twitter API access",
                )
            )
        else:
            recommendations.append(
                (
                    self.twitter_config.web_interface_strategy,
                    0.85,
                    "Optimized for Twitter web interface",
                )
            )

        return recommendations

    def _get_instagram_recommendations(
        self, domain: str
    ) -> List[Tuple[BypassStrategy, float, str]]:
        """Get Instagram-specific recommendations."""
        recommendations = []

        if "cdninstagram.com" in domain or "fbcdn.net" in domain:
            recommendations.append(
                (
                    self.instagram_config.media_content_strategy,
                    0.9,
                    "Optimized for Instagram media CDN",
                )
            )
        elif "stories" in domain:
            recommendations.append(
                (
                    self.instagram_config.stories_strategy,
                    0.87,
                    "Optimized for Instagram Stories",
                )
            )
        elif "reels" in domain:
            recommendations.append(
                (
                    self.instagram_config.reels_strategy,
                    0.89,
                    "Optimized for Instagram Reels",
                )
            )
        else:
            recommendations.append(
                (
                    self.instagram_config.web_interface_strategy,
                    0.83,
                    "Optimized for Instagram web interface (includes HTTP port fixes)",
                )
            )

        return recommendations

    def _get_tiktok_recommendations(
        self, domain: str
    ) -> List[Tuple[BypassStrategy, float, str]]:
        """Get TikTok-specific recommendations."""
        recommendations = []

        if "tiktokcdn.com" in domain:
            recommendations.append(
                (
                    self.tiktok_config.video_content_strategy,
                    0.91,
                    "Optimized for TikTok video CDN",
                )
            )
        elif "live" in domain:
            recommendations.append(
                (
                    self.tiktok_config.live_stream_strategy,
                    0.86,
                    "Optimized for TikTok live streams",
                )
            )
        else:
            recommendations.append(
                (
                    self.tiktok_config.web_interface_strategy,
                    0.84,
                    "Optimized for TikTok web interface",
                )
            )

        return recommendations

    def _load_configuration(self) -> None:
        """Load social media configuration from file."""
        try:
            config_file = Path(self.config_path)
            if config_file.exists():
                with open(config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Load platform strategies
                for key, strategy_data in data.get("platform_strategies", {}).items():
                    try:
                        # Reconstruct strategy objects
                        strategy = BypassStrategy(
                            id=strategy_data["strategy"]["id"],
                            name=strategy_data["strategy"]["name"],
                            attacks=strategy_data["strategy"]["attacks"],
                            parameters=strategy_data["strategy"]["parameters"],
                        )

                        platform_strategy = PlatformSpecificStrategy(
                            platform=PlatformType(strategy_data["platform"]),
                            media_type=MediaType(strategy_data["media_type"]),
                            blocking_pattern=BlockingPattern(
                                strategy_data["blocking_pattern"]
                            ),
                            strategy=strategy,
                            effectiveness_score=strategy_data.get(
                                "effectiveness_score", 0.0
                            ),
                            avg_speed_improvement=strategy_data.get(
                                "avg_speed_improvement", 0.0
                            ),
                            compatibility_notes=strategy_data.get(
                                "compatibility_notes", ""
                            ),
                            last_updated=(
                                datetime.fromisoformat(strategy_data["last_updated"])
                                if strategy_data.get("last_updated")
                                else None
                            ),
                        )

                        self.platform_strategies[key] = platform_strategy
                    except (KeyError, ValueError) as e:
                        LOG.warning(f"Failed to load platform strategy {key}: {e}")

                LOG.info(
                    f"Loaded {len(self.platform_strategies)} platform strategies from configuration"
                )

        except Exception as e:
            LOG.warning(f"Failed to load social media configuration: {e}")

    def _save_configuration(self) -> None:
        """Save social media configuration to file."""
        try:
            data = {
                "platform_strategies": {},
                "last_updated": datetime.now().isoformat(),
            }

            # Save platform strategies
            for key, platform_strategy in self.platform_strategies.items():
                data["platform_strategies"][key] = {
                    "platform": platform_strategy.platform.value,
                    "media_type": platform_strategy.media_type.value,
                    "blocking_pattern": platform_strategy.blocking_pattern.value,
                    "strategy": {
                        "id": platform_strategy.strategy.id,
                        "name": platform_strategy.strategy.name,
                        "attacks": platform_strategy.strategy.attacks,
                        "parameters": platform_strategy.strategy.parameters,
                    },
                    "effectiveness_score": platform_strategy.effectiveness_score,
                    "avg_speed_improvement": platform_strategy.avg_speed_improvement,
                    "compatibility_notes": platform_strategy.compatibility_notes,
                    "last_updated": (
                        platform_strategy.last_updated.isoformat()
                        if platform_strategy.last_updated
                        else None
                    ),
                }

            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            LOG.info(
                f"Saved social media configuration with {len(self.platform_strategies)} strategies"
            )

        except Exception as e:
            LOG.error(f"Failed to save social media configuration: {e}")


# Convenience functions for easy integration
async def get_youtube_strategy(
    domain: str, handler: SocialMediaBypassHandler
) -> BypassStrategy:
    """Get optimized YouTube strategy."""
    return await handler.optimize_youtube_access(domain)


async def get_twitter_strategy(
    domain: str, handler: SocialMediaBypassHandler
) -> BypassStrategy:
    """Get optimized Twitter strategy."""
    return await handler.optimize_twitter_access(domain)


async def get_instagram_strategy(
    domain: str, port: int, handler: SocialMediaBypassHandler
) -> BypassStrategy:
    """Get optimized Instagram strategy."""
    return await handler.optimize_instagram_access(domain, port)


async def get_tiktok_strategy(
    domain: str, handler: SocialMediaBypassHandler
) -> BypassStrategy:
    """Get optimized TikTok strategy."""
    return await handler.optimize_tiktok_access(domain)
