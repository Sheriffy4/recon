#!/usr/bin/env python3
"""
Subdomain-Specific Strategy Support for Bypass Engine Modernization

This module implements advanced subdomain strategy handling with specialized
support for YouTube, Twitter, Instagram, and other social media platforms.
"""

import re
import logging
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from pathlib import Path

try:
    from .pool_management import BypassStrategy, StrategyPool, StrategyPoolManager
except ImportError:
    # Handle relative import issues
    import sys
    import os

    sys.path.append(os.path.dirname(__file__))
    from pool_management import BypassStrategy, StrategyPoolManager


LOG = logging.getLogger("SubdomainHandler")


class SubdomainType(Enum):
    """Types of subdomains with different bypass requirements."""

    WEB_INTERFACE = "web_interface"  # Main website interface
    MEDIA_CONTENT = "media_content"  # Video, images, audio
    API_ENDPOINT = "api_endpoint"  # API services
    CDN_CONTENT = "cdn_content"  # CDN-hosted content
    STREAMING = "streaming"  # Live streaming content
    UPLOAD = "upload"  # File upload services
    AUTHENTICATION = "authentication"  # Login/auth services
    ANALYTICS = "analytics"  # Tracking/analytics
    STATIC_ASSETS = "static_assets"  # CSS, JS, images
    MOBILE_API = "mobile_api"  # Mobile app APIs


class PlatformType(Enum):
    """Supported social media and video platforms."""

    YOUTUBE = "youtube"
    TWITTER = "twitter"
    INSTAGRAM = "instagram"
    TIKTOK = "tiktok"
    FACEBOOK = "facebook"
    VK = "vk"
    TELEGRAM = "telegram"
    DISCORD = "discord"
    TWITCH = "twitch"
    NETFLIX = "netflix"
    GENERIC = "generic"


@dataclass
class SubdomainPattern:
    """Pattern for matching subdomains to their types."""

    pattern: str
    subdomain_type: SubdomainType
    platform: PlatformType
    description: str
    priority: int = 1
    requires_special_handling: bool = False

    def matches(self, subdomain: str) -> bool:
        """Check if subdomain matches this pattern."""
        try:
            return bool(re.match(self.pattern, subdomain, re.IGNORECASE))
        except re.error:
            return False


@dataclass
class SubdomainStrategy:
    """Strategy configuration for a specific subdomain."""

    subdomain: str
    subdomain_type: SubdomainType
    platform: PlatformType
    strategy: BypassStrategy
    success_rate: float = 0.0
    avg_latency_ms: float = 0.0
    last_tested: Optional[datetime] = None
    test_count: int = 0
    failure_count: int = 0
    notes: str = ""

    def update_metrics(self, success: bool, latency_ms: float) -> None:
        """Update strategy metrics based on test results."""
        self.test_count += 1
        if not success:
            self.failure_count += 1

        # Update success rate
        self.success_rate = (self.test_count - self.failure_count) / self.test_count

        # Update average latency (exponential moving average)
        if self.avg_latency_ms == 0.0:
            self.avg_latency_ms = latency_ms
        else:
            alpha = 0.3  # Smoothing factor
            self.avg_latency_ms = alpha * latency_ms + (1 - alpha) * self.avg_latency_ms

        self.last_tested = datetime.now()


@dataclass
class PlatformConfiguration:
    """Configuration for a specific platform's subdomain handling."""

    platform: PlatformType
    base_domains: List[str]
    subdomain_patterns: List[SubdomainPattern]
    default_strategies: Dict[SubdomainType, BypassStrategy]
    special_rules: Dict[str, Any] = field(default_factory=dict)

    def get_subdomain_type(self, subdomain: str) -> SubdomainType:
        """Determine subdomain type based on patterns."""
        # Sort patterns by priority (higher first)
        sorted_patterns = sorted(
            self.subdomain_patterns, key=lambda p: p.priority, reverse=True
        )

        for pattern in sorted_patterns:
            if pattern.matches(subdomain):
                return pattern.subdomain_type

        return SubdomainType.WEB_INTERFACE  # Default


class SubdomainStrategyHandler:
    """
    Advanced subdomain strategy handler with specialized platform support.
    """

    def __init__(
        self,
        pool_manager: StrategyPoolManager,
        config_path: str = "subdomain_config.json",
    ):
        self.pool_manager = pool_manager
        self.config_path = config_path

        # Subdomain strategies storage
        self.subdomain_strategies: Dict[str, SubdomainStrategy] = {}

        # Platform configurations
        self.platform_configs: Dict[PlatformType, PlatformConfiguration] = {}

        # Initialize platform configurations
        self._initialize_platform_configs()

        # Load existing configurations
        self._load_configuration()

    def get_strategy_for_subdomain(
        self, domain: str, port: int = 443
    ) -> Optional[BypassStrategy]:
        """
        Get the most appropriate strategy for a specific subdomain.

        Args:
            domain: Full domain (including subdomain)
            port: Target port

        Returns:
            Bypass strategy or None if not found
        """
        LOG.info(f"Getting strategy for subdomain: {domain}:{port}")

        # Check if we have a specific strategy for this subdomain
        if domain in self.subdomain_strategies:
            subdomain_strategy = self.subdomain_strategies[domain]
            LOG.info(
                f"Found specific strategy for {domain}: {subdomain_strategy.strategy.name}"
            )
            return subdomain_strategy.strategy

        # Determine platform and subdomain type
        platform = self._detect_platform(domain)
        subdomain_type = self._get_subdomain_type(domain, platform)

        LOG.info(f"Detected platform: {platform.value}, type: {subdomain_type.value}")

        # Get platform-specific strategy
        strategy = self._get_platform_strategy(domain, platform, subdomain_type, port)

        if strategy:
            # Cache the strategy for future use
            self._cache_subdomain_strategy(domain, platform, subdomain_type, strategy)
            return strategy

        # Fallback to pool manager
        return self.pool_manager.get_strategy_for_domain(domain, port)

    def set_subdomain_strategy(
        self,
        domain: str,
        strategy: BypassStrategy,
        platform: PlatformType = None,
        subdomain_type: SubdomainType = None,
    ) -> bool:
        """
        Set a specific strategy for a subdomain.

        Args:
            domain: Full domain (including subdomain)
            strategy: Bypass strategy to use
            platform: Platform type (auto-detected if None)
            subdomain_type: Subdomain type (auto-detected if None)

        Returns:
            True if successful, False otherwise
        """
        if not platform:
            platform = self._detect_platform(domain)

        if not subdomain_type:
            subdomain_type = self._get_subdomain_type(domain, platform)

        subdomain_strategy = SubdomainStrategy(
            subdomain=domain,
            subdomain_type=subdomain_type,
            platform=platform,
            strategy=strategy,
        )

        self.subdomain_strategies[domain] = subdomain_strategy
        self._save_configuration()

        LOG.info(f"Set strategy for {domain}: {strategy.name}")
        return True

    def test_subdomain_strategy(
        self, domain: str, strategy: BypassStrategy = None
    ) -> Dict[str, Any]:
        """
        Test a strategy for a specific subdomain.

        Args:
            domain: Full domain to test
            strategy: Strategy to test (uses current if None)

        Returns:
            Test results dictionary
        """
        if not strategy:
            strategy = self.get_strategy_for_subdomain(domain)

        if not strategy:
            return {"success": False, "error": "No strategy available"}

        LOG.info(f"Testing strategy for {domain}: {strategy.name}")

        # Simulate test (in real implementation, this would perform actual connectivity test)
        import random
        import time

        start_time = time.time()

        # Simulate test delay
        time.sleep(random.uniform(0.1, 0.5))

        # Simulate success/failure
        success = random.random() > 0.2  # 80% success rate
        latency_ms = (time.time() - start_time) * 1000

        # Update metrics if we have a cached strategy
        if domain in self.subdomain_strategies:
            self.subdomain_strategies[domain].update_metrics(success, latency_ms)
            self._save_configuration()

        result = {
            "success": success,
            "latency_ms": latency_ms,
            "strategy_id": strategy.id,
            "timestamp": datetime.now().isoformat(),
        }

        LOG.info(
            f"Test result for {domain}: {'SUCCESS' if success else 'FAILED'} ({latency_ms:.1f}ms)"
        )
        return result

    def auto_discover_subdomains(
        self, base_domain: str, max_depth: int = 2
    ) -> List[str]:
        """
        Auto-discover subdomains for a base domain.

        Args:
            base_domain: Base domain to discover subdomains for
            max_depth: Maximum subdomain depth to discover

        Returns:
            List of discovered subdomains
        """
        platform = self._detect_platform(base_domain)

        if platform == PlatformType.GENERIC:
            return []

        # Get known subdomains for this platform
        platform_config = self.platform_configs.get(platform)
        if not platform_config:
            return []

        discovered = []

        # Generate common subdomains based on platform patterns
        for pattern in platform_config.subdomain_patterns:
            # Convert regex pattern to actual subdomain examples
            subdomain_examples = self._pattern_to_examples(pattern.pattern, base_domain)
            discovered.extend(subdomain_examples)

        LOG.info(f"Auto-discovered {len(discovered)} subdomains for {base_domain}")
        return discovered

    def get_subdomain_recommendations(
        self, domain: str
    ) -> List[Tuple[BypassStrategy, float]]:
        """
        Get strategy recommendations for a subdomain.

        Args:
            domain: Domain to get recommendations for

        Returns:
            List of (strategy, confidence) tuples
        """
        platform = self._detect_platform(domain)
        subdomain_type = self._get_subdomain_type(domain, platform)

        recommendations = []

        # Get platform-specific recommendations
        platform_config = self.platform_configs.get(platform)
        if platform_config and subdomain_type in platform_config.default_strategies:
            strategy = platform_config.default_strategies[subdomain_type]
            confidence = 0.9  # High confidence for platform-specific strategies
            recommendations.append((strategy, confidence))

        # Add general recommendations based on subdomain type
        general_strategies = self._get_general_strategies_for_type(subdomain_type)
        for strategy in general_strategies:
            confidence = 0.6  # Medium confidence for general strategies
            recommendations.append((strategy, confidence))

        # Sort by confidence
        recommendations.sort(key=lambda x: x[1], reverse=True)

        return recommendations[:5]  # Return top 5

    def get_platform_statistics(self) -> Dict[str, Any]:
        """Get statistics about subdomain strategies by platform."""
        stats = {
            "total_subdomains": len(self.subdomain_strategies),
            "platforms": {},
            "subdomain_types": {},
            "success_rates": {},
        }

        for subdomain_strategy in self.subdomain_strategies.values():
            platform = subdomain_strategy.platform.value
            subdomain_type = subdomain_strategy.subdomain_type.value

            # Platform stats
            if platform not in stats["platforms"]:
                stats["platforms"][platform] = 0
            stats["platforms"][platform] += 1

            # Subdomain type stats
            if subdomain_type not in stats["subdomain_types"]:
                stats["subdomain_types"][subdomain_type] = 0
            stats["subdomain_types"][subdomain_type] += 1

            # Success rate stats
            if subdomain_strategy.test_count > 0:
                if platform not in stats["success_rates"]:
                    stats["success_rates"][platform] = []
                stats["success_rates"][platform].append(subdomain_strategy.success_rate)

        # Calculate average success rates
        for platform, rates in stats["success_rates"].items():
            stats["success_rates"][platform] = sum(rates) / len(rates) if rates else 0.0

        return stats

    def _initialize_platform_configs(self) -> None:
        """Initialize platform-specific configurations."""

        # YouTube Configuration
        youtube_patterns = [
            SubdomainPattern(
                r"^www\.youtube\.com$",
                SubdomainType.WEB_INTERFACE,
                PlatformType.YOUTUBE,
                "Main YouTube interface",
                10,
            ),
            SubdomainPattern(
                r"^m\.youtube\.com$",
                SubdomainType.WEB_INTERFACE,
                PlatformType.YOUTUBE,
                "Mobile YouTube interface",
                9,
            ),
            SubdomainPattern(
                r"^.*\.googlevideo\.com$",
                SubdomainType.MEDIA_CONTENT,
                PlatformType.YOUTUBE,
                "YouTube video content",
                10,
                True,
            ),
            SubdomainPattern(
                r"^i\.ytimg\.com$",
                SubdomainType.STATIC_ASSETS,
                PlatformType.YOUTUBE,
                "YouTube thumbnails",
                8,
            ),
            SubdomainPattern(
                r"^.*\.youtube\.com$",
                SubdomainType.API_ENDPOINT,
                PlatformType.YOUTUBE,
                "YouTube API endpoints",
                5,
            ),
        ]

        youtube_strategies = {
            SubdomainType.WEB_INTERFACE: BypassStrategy(
                id="youtube_web",
                name="YouTube Web Interface",
                attacks=["http_manipulation", "tls_evasion"],
                parameters={"split_pos": "midsld", "ttl": 2},
            ),
            SubdomainType.MEDIA_CONTENT: BypassStrategy(
                id="youtube_video",
                name="YouTube Video Content",
                attacks=["tcp_fragmentation", "packet_timing"],
                parameters={"split_count": 5, "ttl": 3, "fake_sni": True},
            ),
            SubdomainType.STATIC_ASSETS: BypassStrategy(
                id="youtube_assets",
                name="YouTube Static Assets",
                attacks=["tcp_fragmentation"],
                parameters={"split_pos": 3, "ttl": 1},
            ),
            SubdomainType.API_ENDPOINT: BypassStrategy(
                id="youtube_api",
                name="YouTube API",
                attacks=["http_manipulation"],
                parameters={"split_pos": "midsld", "ttl": 2},
            ),
        }

        self.platform_configs[PlatformType.YOUTUBE] = PlatformConfiguration(
            platform=PlatformType.YOUTUBE,
            base_domains=["youtube.com", "googlevideo.com", "ytimg.com"],
            subdomain_patterns=youtube_patterns,
            default_strategies=youtube_strategies,
            special_rules={
                "video_acceleration": True,
                "thumbnail_optimization": True,
                "api_rate_limiting": False,
            },
        )

        # Twitter Configuration
        twitter_patterns = [
            SubdomainPattern(
                r"^(www\.)?twitter\.com$",
                SubdomainType.WEB_INTERFACE,
                PlatformType.TWITTER,
                "Main Twitter interface",
                10,
            ),
            SubdomainPattern(
                r"^mobile\.twitter\.com$",
                SubdomainType.WEB_INTERFACE,
                PlatformType.TWITTER,
                "Mobile Twitter interface",
                9,
            ),
            SubdomainPattern(
                r"^.*\.twimg\.com$",
                SubdomainType.MEDIA_CONTENT,
                PlatformType.TWITTER,
                "Twitter media content",
                10,
                True,
            ),
            SubdomainPattern(
                r"^api\.twitter\.com$",
                SubdomainType.API_ENDPOINT,
                PlatformType.TWITTER,
                "Twitter API",
                8,
            ),
            SubdomainPattern(
                r"^upload\.twitter\.com$",
                SubdomainType.UPLOAD,
                PlatformType.TWITTER,
                "Twitter upload service",
                7,
            ),
            SubdomainPattern(
                r"^abs\.twimg\.com$",
                SubdomainType.STATIC_ASSETS,
                PlatformType.TWITTER,
                "Twitter static assets",
                6,
            ),
        ]

        twitter_strategies = {
            SubdomainType.WEB_INTERFACE: BypassStrategy(
                id="twitter_web",
                name="Twitter Web Interface",
                attacks=["http_manipulation", "tls_evasion"],
                parameters={"split_pos": "midsld", "ttl": 2},
            ),
            SubdomainType.MEDIA_CONTENT: BypassStrategy(
                id="twitter_media",
                name="Twitter Media Content",
                attacks=["tcp_fragmentation", "http_manipulation"],
                parameters={"split_pos": 5, "ttl": 3, "fake_sni": True},
            ),
            SubdomainType.API_ENDPOINT: BypassStrategy(
                id="twitter_api",
                name="Twitter API",
                attacks=["http_manipulation"],
                parameters={"split_pos": "midsld", "ttl": 1},
            ),
            SubdomainType.UPLOAD: BypassStrategy(
                id="twitter_upload",
                name="Twitter Upload",
                attacks=["tcp_fragmentation", "packet_timing"],
                parameters={"split_count": 3, "ttl": 2},
            ),
            SubdomainType.STATIC_ASSETS: BypassStrategy(
                id="twitter_assets",
                name="Twitter Static Assets",
                attacks=["tcp_fragmentation"],
                parameters={"split_pos": 3, "ttl": 1},
            ),
        }

        self.platform_configs[PlatformType.TWITTER] = PlatformConfiguration(
            platform=PlatformType.TWITTER,
            base_domains=["twitter.com", "twimg.com"],
            subdomain_patterns=twitter_patterns,
            default_strategies=twitter_strategies,
            special_rules={
                "media_optimization": True,
                "api_authentication": True,
                "upload_acceleration": True,
            },
        )

        # Instagram Configuration
        instagram_patterns = [
            SubdomainPattern(
                r"^(www\.)?instagram\.com$",
                SubdomainType.WEB_INTERFACE,
                PlatformType.INSTAGRAM,
                "Main Instagram interface",
                10,
            ),
            SubdomainPattern(
                r"^.*\.cdninstagram\.com$",
                SubdomainType.MEDIA_CONTENT,
                PlatformType.INSTAGRAM,
                "Instagram media CDN",
                10,
                True,
            ),
            SubdomainPattern(
                r"^.*\.fbcdn\.net$",
                SubdomainType.MEDIA_CONTENT,
                PlatformType.INSTAGRAM,
                "Facebook CDN for Instagram",
                9,
                True,
            ),
            SubdomainPattern(
                r"^i\.instagram\.com$",
                SubdomainType.API_ENDPOINT,
                PlatformType.INSTAGRAM,
                "Instagram API",
                8,
            ),
            SubdomainPattern(
                r"^upload\.instagram\.com$",
                SubdomainType.UPLOAD,
                PlatformType.INSTAGRAM,
                "Instagram upload service",
                7,
            ),
        ]

        instagram_strategies = {
            SubdomainType.WEB_INTERFACE: BypassStrategy(
                id="instagram_web",
                name="Instagram Web Interface",
                attacks=["http_manipulation", "tls_evasion"],
                parameters={"split_pos": "midsld", "ttl": 2},
            ),
            SubdomainType.MEDIA_CONTENT: BypassStrategy(
                id="instagram_media",
                name="Instagram Media Content",
                attacks=["tcp_fragmentation", "packet_timing"],
                parameters={"split_count": 7, "ttl": 3, "fake_sni": True},
            ),
            SubdomainType.API_ENDPOINT: BypassStrategy(
                id="instagram_api",
                name="Instagram API",
                attacks=["http_manipulation"],
                parameters={"split_pos": "midsld", "ttl": 1},
            ),
            SubdomainType.UPLOAD: BypassStrategy(
                id="instagram_upload",
                name="Instagram Upload",
                attacks=["tcp_fragmentation", "http_manipulation"],
                parameters={"split_count": 5, "ttl": 2},
            ),
        }

        self.platform_configs[PlatformType.INSTAGRAM] = PlatformConfiguration(
            platform=PlatformType.INSTAGRAM,
            base_domains=["instagram.com", "cdninstagram.com", "fbcdn.net"],
            subdomain_patterns=instagram_patterns,
            default_strategies=instagram_strategies,
            special_rules={
                "media_optimization": True,
                "cdn_acceleration": True,
                "upload_chunking": True,
            },
        )

        # TikTok Configuration
        tiktok_patterns = [
            SubdomainPattern(
                r"^(www\.)?tiktok\.com$",
                SubdomainType.WEB_INTERFACE,
                PlatformType.TIKTOK,
                "Main TikTok interface",
                10,
            ),
            SubdomainPattern(
                r"^.*\.tiktokcdn\.com$",
                SubdomainType.MEDIA_CONTENT,
                PlatformType.TIKTOK,
                "TikTok video CDN",
                10,
                True,
            ),
            SubdomainPattern(
                r"^.*\.musical\.ly$",
                SubdomainType.MEDIA_CONTENT,
                PlatformType.TIKTOK,
                "Legacy Musical.ly content",
                8,
                True,
            ),
            SubdomainPattern(
                r"^api.*\.tiktok\.com$",
                SubdomainType.API_ENDPOINT,
                PlatformType.TIKTOK,
                "TikTok API",
                7,
            ),
        ]

        tiktok_strategies = {
            SubdomainType.WEB_INTERFACE: BypassStrategy(
                id="tiktok_web",
                name="TikTok Web Interface",
                attacks=["http_manipulation", "tls_evasion"],
                parameters={"split_pos": "midsld", "ttl": 2},
            ),
            SubdomainType.MEDIA_CONTENT: BypassStrategy(
                id="tiktok_video",
                name="TikTok Video Content",
                attacks=["tcp_fragmentation", "packet_timing"],
                parameters={"split_count": 8, "ttl": 4, "fake_sni": True},
            ),
            SubdomainType.API_ENDPOINT: BypassStrategy(
                id="tiktok_api",
                name="TikTok API",
                attacks=["http_manipulation"],
                parameters={"split_pos": "midsld", "ttl": 1},
            ),
        }

        self.platform_configs[PlatformType.TIKTOK] = PlatformConfiguration(
            platform=PlatformType.TIKTOK,
            base_domains=["tiktok.com", "tiktokcdn.com", "musical.ly"],
            subdomain_patterns=tiktok_patterns,
            default_strategies=tiktok_strategies,
            special_rules={
                "video_optimization": True,
                "mobile_priority": True,
                "cdn_acceleration": True,
            },
        )

        LOG.info(
            "Initialized platform configurations for YouTube, Twitter, Instagram, and TikTok"
        )

    def _detect_platform(self, domain: str) -> PlatformType:
        """Detect platform type from domain."""
        domain_lower = domain.lower()

        for platform, config in self.platform_configs.items():
            for base_domain in config.base_domains:
                if base_domain in domain_lower:
                    return platform

        return PlatformType.GENERIC

    def _get_subdomain_type(self, domain: str, platform: PlatformType) -> SubdomainType:
        """Get subdomain type for a domain."""
        platform_config = self.platform_configs.get(platform)
        if platform_config:
            return platform_config.get_subdomain_type(domain)

        return SubdomainType.WEB_INTERFACE

    def _get_platform_strategy(
        self,
        domain: str,
        platform: PlatformType,
        subdomain_type: SubdomainType,
        port: int,
    ) -> Optional[BypassStrategy]:
        """Get platform-specific strategy."""
        platform_config = self.platform_configs.get(platform)
        if not platform_config:
            return None

        # Get default strategy for subdomain type
        strategy = platform_config.default_strategies.get(subdomain_type)
        if strategy:
            # Clone strategy and customize for this domain
            customized_strategy = BypassStrategy(
                id=f"{strategy.id}_{domain}",
                name=f"{strategy.name} for {domain}",
                attacks=strategy.attacks.copy(),
                parameters=strategy.parameters.copy(),
                target_ports=(
                    strategy.target_ports.copy()
                    if hasattr(strategy, "target_ports")
                    else [port]
                ),
                priority=strategy.priority if hasattr(strategy, "priority") else 1,
            )

            # Apply port-specific customizations
            if port == 80:
                # HTTP-specific optimizations
                if "http_manipulation" not in customized_strategy.attacks:
                    customized_strategy.attacks.append("http_manipulation")
            elif port == 443:
                # HTTPS-specific optimizations
                if "tls_evasion" not in customized_strategy.attacks:
                    customized_strategy.attacks.append("tls_evasion")

            return customized_strategy

        return None

    def _cache_subdomain_strategy(
        self,
        domain: str,
        platform: PlatformType,
        subdomain_type: SubdomainType,
        strategy: BypassStrategy,
    ) -> None:
        """Cache a subdomain strategy for future use."""
        subdomain_strategy = SubdomainStrategy(
            subdomain=domain,
            subdomain_type=subdomain_type,
            platform=platform,
            strategy=strategy,
        )

        self.subdomain_strategies[domain] = subdomain_strategy

    def _pattern_to_examples(self, pattern: str, base_domain: str) -> List[str]:
        """Convert regex pattern to example subdomains."""
        examples = []

        # Simple pattern-to-example conversion
        if "www" in pattern:
            examples.append(f"www.{base_domain}")
        if "m\\." in pattern:
            examples.append(f"m.{base_domain}")
        if "mobile" in pattern:
            examples.append(f"mobile.{base_domain}")
        if "api" in pattern:
            examples.append(f"api.{base_domain}")
        if "upload" in pattern:
            examples.append(f"upload.{base_domain}")

        return examples

    def _get_general_strategies_for_type(
        self, subdomain_type: SubdomainType
    ) -> List[BypassStrategy]:
        """Get general strategies for a subdomain type."""
        strategies = []

        if subdomain_type == SubdomainType.MEDIA_CONTENT:
            strategies.append(
                BypassStrategy(
                    id="general_media",
                    name="General Media Strategy",
                    attacks=["tcp_fragmentation", "packet_timing"],
                    parameters={"split_count": 5, "ttl": 3},
                )
            )
        elif subdomain_type == SubdomainType.API_ENDPOINT:
            strategies.append(
                BypassStrategy(
                    id="general_api",
                    name="General API Strategy",
                    attacks=["http_manipulation"],
                    parameters={"split_pos": "midsld", "ttl": 1},
                )
            )
        elif subdomain_type == SubdomainType.UPLOAD:
            strategies.append(
                BypassStrategy(
                    id="general_upload",
                    name="General Upload Strategy",
                    attacks=["tcp_fragmentation", "http_manipulation"],
                    parameters={"split_count": 3, "ttl": 2},
                )
            )
        else:
            strategies.append(
                BypassStrategy(
                    id="general_web",
                    name="General Web Strategy",
                    attacks=["http_manipulation", "tls_evasion"],
                    parameters={"split_pos": "midsld", "ttl": 2},
                )
            )

        return strategies

    def _load_configuration(self) -> None:
        """Load subdomain configuration from file."""
        try:
            config_file = Path(self.config_path)
            if config_file.exists():
                with open(config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Load subdomain strategies
                for domain, strategy_data in data.get(
                    "subdomain_strategies", {}
                ).items():
                    try:
                        # Reconstruct BypassStrategy
                        strategy = BypassStrategy(
                            id=strategy_data["strategy"]["id"],
                            name=strategy_data["strategy"]["name"],
                            attacks=strategy_data["strategy"]["attacks"],
                            parameters=strategy_data["strategy"]["parameters"],
                        )

                        # Reconstruct SubdomainStrategy
                        subdomain_strategy = SubdomainStrategy(
                            subdomain=domain,
                            subdomain_type=SubdomainType(
                                strategy_data["subdomain_type"]
                            ),
                            platform=PlatformType(strategy_data["platform"]),
                            strategy=strategy,
                            success_rate=strategy_data.get("success_rate", 0.0),
                            avg_latency_ms=strategy_data.get("avg_latency_ms", 0.0),
                            test_count=strategy_data.get("test_count", 0),
                            failure_count=strategy_data.get("failure_count", 0),
                            notes=strategy_data.get("notes", ""),
                        )

                        if strategy_data.get("last_tested"):
                            subdomain_strategy.last_tested = datetime.fromisoformat(
                                strategy_data["last_tested"]
                            )

                        self.subdomain_strategies[domain] = subdomain_strategy

                    except Exception as e:
                        LOG.error(f"Failed to load strategy for {domain}: {e}")

                LOG.info(
                    f"Loaded {len(self.subdomain_strategies)} subdomain strategies from {self.config_path}"
                )

        except Exception as e:
            LOG.error(f"Failed to load configuration: {e}")

    def _save_configuration(self) -> None:
        """Save subdomain configuration to file."""
        try:
            data = {
                "subdomain_strategies": {},
                "last_updated": datetime.now().isoformat(),
            }

            # Serialize subdomain strategies
            for domain, subdomain_strategy in self.subdomain_strategies.items():
                strategy_data = {
                    "subdomain_type": subdomain_strategy.subdomain_type.value,
                    "platform": subdomain_strategy.platform.value,
                    "strategy": {
                        "id": subdomain_strategy.strategy.id,
                        "name": subdomain_strategy.strategy.name,
                        "attacks": subdomain_strategy.strategy.attacks,
                        "parameters": subdomain_strategy.strategy.parameters,
                    },
                    "success_rate": subdomain_strategy.success_rate,
                    "avg_latency_ms": subdomain_strategy.avg_latency_ms,
                    "test_count": subdomain_strategy.test_count,
                    "failure_count": subdomain_strategy.failure_count,
                    "notes": subdomain_strategy.notes,
                }

                if subdomain_strategy.last_tested:
                    strategy_data["last_tested"] = (
                        subdomain_strategy.last_tested.isoformat()
                    )

                data["subdomain_strategies"][domain] = strategy_data

            # Save to file
            config_file = Path(self.config_path)
            config_file.parent.mkdir(parents=True, exist_ok=True)

            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            LOG.info(
                f"Saved {len(self.subdomain_strategies)} subdomain strategies to {self.config_path}"
            )

        except Exception as e:
            LOG.error(f"Failed to save configuration: {e}")


# Integration with existing pool management
class EnhancedPoolManager(StrategyPoolManager):
    """Enhanced pool manager with subdomain support."""

    def __init__(self, config_path: Optional[str] = None):
        super().__init__(config_path)
        self.subdomain_handler = SubdomainStrategyHandler(self)

    def get_strategy_for_domain(
        self, domain: str, port: int = 443
    ) -> Optional[BypassStrategy]:
        """Enhanced domain strategy resolution with subdomain support."""
        # First try subdomain-specific strategy
        subdomain_strategy = self.subdomain_handler.get_strategy_for_subdomain(
            domain, port
        )
        if subdomain_strategy:
            return subdomain_strategy

        # Fallback to original pool management
        return super().get_strategy_for_domain(domain, port)

    def set_subdomain_strategy(self, domain: str, strategy: BypassStrategy) -> bool:
        """Set subdomain-specific strategy."""
        return self.subdomain_handler.set_subdomain_strategy(domain, strategy)

    def test_subdomain_strategy(self, domain: str) -> Dict[str, Any]:
        """Test subdomain strategy."""
        return self.subdomain_handler.test_subdomain_strategy(domain)

    def get_subdomain_recommendations(
        self, domain: str
    ) -> List[Tuple[BypassStrategy, float]]:
        """Get subdomain strategy recommendations."""
        return self.subdomain_handler.get_subdomain_recommendations(domain)


# Utility functions for subdomain analysis
def analyze_subdomain_structure(domain: str) -> Dict[str, Any]:
    """Analyze the structure of a subdomain."""
    parts = domain.split(".")

    analysis = {
        "full_domain": domain,
        "parts": parts,
        "depth": len(parts) - 2 if len(parts) >= 2 else 0,  # Exclude TLD and SLD
        "tld": parts[-1] if parts else "",
        "sld": parts[-2] if len(parts) >= 2 else "",
        "subdomains": parts[:-2] if len(parts) > 2 else [],
        "is_subdomain": len(parts) > 2,
        "subdomain_levels": [],
    }

    # Build subdomain levels
    if analysis["is_subdomain"]:
        for i in range(len(analysis["subdomains"])):
            level_parts = analysis["subdomains"][i:] + [
                analysis["sld"],
                analysis["tld"],
            ]
            analysis["subdomain_levels"].append(".".join(level_parts))

    return analysis


def suggest_subdomain_tests(domain: str) -> List[Dict[str, Any]]:
    """Suggest tests for subdomain strategy validation."""
    handler = SubdomainStrategyHandler(None)  # Create temporary handler
    platform = handler._detect_platform(domain)
    subdomain_type = handler._get_subdomain_type(domain, platform)

    tests = []

    # Basic connectivity test
    tests.append(
        {
            "type": "connectivity",
            "description": f"Test basic connectivity to {domain}",
            "ports": [80, 443],
            "timeout": 10,
        }
    )

    # Platform-specific tests
    if platform == PlatformType.YOUTUBE:
        if subdomain_type == SubdomainType.MEDIA_CONTENT:
            tests.append(
                {
                    "type": "video_streaming",
                    "description": "Test video streaming capability",
                    "test_urls": [f"https://{domain}/test_video"],
                    "expected_content_type": "video/*",
                }
            )
    elif platform == PlatformType.TWITTER:
        if subdomain_type == SubdomainType.MEDIA_CONTENT:
            tests.append(
                {
                    "type": "image_loading",
                    "description": "Test image loading capability",
                    "test_urls": [f"https://{domain}/test_image.jpg"],
                    "expected_content_type": "image/*",
                }
            )

    # Strategy-specific tests
    recommendations = handler.get_subdomain_recommendations(domain)
    for strategy, confidence in recommendations:
        tests.append(
            {
                "type": "strategy_test",
                "description": f"Test {strategy.name} strategy",
                "strategy": strategy,
                "confidence": confidence,
            }
        )

    return tests


# Test the implementation
if __name__ == "__main__":
    print("Testing subdomain-specific strategy support...")

    # Create enhanced pool manager
    pool_manager = EnhancedPoolManager()

    # Test YouTube subdomain handling
    youtube_domains = [
        "www.youtube.com",
        "m.youtube.com",
        "r1---sn-4g5e6nls.googlevideo.com",
        "i.ytimg.com",
    ]

    print("\n=== YouTube Subdomain Tests ===")
    for domain in youtube_domains:
        strategy = pool_manager.get_strategy_for_domain(domain)
        if strategy:
            print(f"✅ {domain}: {strategy.name}")
        else:
            print(f"❌ {domain}: No strategy found")

    # Test Twitter subdomain handling
    twitter_domains = [
        "twitter.com",
        "mobile.twitter.com",
        "pbs.twimg.com",
        "api.twitter.com",
    ]

    print("\n=== Twitter Subdomain Tests ===")
    for domain in twitter_domains:
        strategy = pool_manager.get_strategy_for_domain(domain)
        if strategy:
            print(f"✅ {domain}: {strategy.name}")
        else:
            print(f"❌ {domain}: No strategy found")

    # Test Instagram subdomain handling
    instagram_domains = [
        "www.instagram.com",
        "scontent.cdninstagram.com",
        "i.instagram.com",
    ]

    print("\n=== Instagram Subdomain Tests ===")
    for domain in instagram_domains:
        strategy = pool_manager.get_strategy_for_domain(domain)
        if strategy:
            print(f"✅ {domain}: {strategy.name}")
        else:
            print(f"❌ {domain}: No strategy found")

    # Test subdomain analysis
    print("\n=== Subdomain Analysis Tests ===")
    test_domains = [
        "www.youtube.com",
        "r1---sn-4g5e6nls.googlevideo.com",
        "pbs.twimg.com",
    ]

    for domain in test_domains:
        analysis = analyze_subdomain_structure(domain)
        print(f"Domain: {domain}")
        print(f"  Depth: {analysis['depth']}")
        print(f"  Is subdomain: {analysis['is_subdomain']}")
        print(f"  Subdomain levels: {analysis['subdomain_levels']}")

    # Test strategy recommendations
    print("\n=== Strategy Recommendations ===")
    for domain in ["www.youtube.com", "pbs.twimg.com"]:
        recommendations = pool_manager.get_subdomain_recommendations(domain)
        print(f"{domain}:")
        for strategy, confidence in recommendations[:3]:
            print(f"  {strategy.name} (confidence: {confidence:.2f})")

    # Test platform statistics
    print("\n=== Platform Statistics ===")
    stats = pool_manager.subdomain_handler.get_platform_statistics()
    print(f"Total subdomains: {stats['total_subdomains']}")
    print(f"Platforms: {stats['platforms']}")

    print("\n✅ Subdomain-specific strategy support test completed!")
