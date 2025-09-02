import random
from typing import Optional, List, Dict, Set
import logging
from dataclasses import dataclass
from core.dns.robust_dns_handler import RobustDNSHandler

LOG = logging.getLogger("CDNResolver")


@dataclass
class CDNResolutionResult:
    """Result of CDN domain resolution."""

    original_domain: str
    cdn_domains: List[str]
    resolved_ips: Dict[str, Optional[str]]
    successful_resolutions: int
    failed_resolutions: int


class CDNResolver:
    """
    Enhanced CDN resolver with improved domain detection and IP resolution.
    Continues service operation even if some CDN domains fail to resolve.
    """

    CDN_MAPPINGS: Dict[str, List[str]] = {
        "instagram.com": [
            "instagram.fhel2-1.fna.fbcdn.net",
            "instagram.frix7-1.fna.fbcdn.net",
            "scontent-hel3-1.cdninstagram.com",
            "scontent.cdninstagram.com",
            "instagram.c10r.facebook.com",
        ],
        "x.com": [
            "abs.twimg.com",
            "pbs.twimg.com",
            "video.twimg.com",
            "ton.twimg.com",
            "api.twitter.com",
        ],
        "twitter.com": [
            "abs.twimg.com",
            "pbs.twimg.com",
            "video.twimg.com",
            "ton.twimg.com",
            "api.twitter.com",
        ],
        "youtube.com": [
            "www.youtube-nocookie.com",
            "youtubei.googleapis.com",
            "googlevideo.com",
            "yt3.ggpht.com",
            "i.ytimg.com",
        ],
        "facebook.com": [
            "facebook.fhel2-1.fna.fbcdn.net",
            "scontent.fhel2-1.fna.fbcdn.net",
            "static.xx.fbcdn.net",
            "connect.facebook.net",
            "graph.facebook.com",
        ],
        "tiktok.com": [
            "p16-sign-sg.tiktokcdn.com",
            "sf16-website-login.neutral.ttwstatic.com",
            "lf16-tiktok-common.ttwstatic.com",
        ],
        "discord.com": [
            "cdn.discordapp.com",
            "media.discordapp.net",
            "images-ext-1.discordapp.net",
        ],
    }

    def __init__(self):
        self.dns_handler = RobustDNSHandler()
        self._domain_cache: Dict[str, List[str]] = {}

    def get_cdn_domains(self, blocked_domain: str) -> List[str]:
        """
        Returns all CDN domains for a blocked main domain.
        Improved detection with better domain matching.
        """
        if blocked_domain in self._domain_cache:
            return self._domain_cache[blocked_domain]
        cdn_domains = []
        if blocked_domain in self.CDN_MAPPINGS:
            cdn_domains = self.CDN_MAPPINGS[blocked_domain].copy()
        else:
            for main_domain, cdn_list in self.CDN_MAPPINGS.items():
                if self._is_domain_match(blocked_domain, main_domain):
                    cdn_domains = cdn_list.copy()
                    break
        self._domain_cache[blocked_domain] = cdn_domains
        if cdn_domains:
            LOG.info(
                f"Found {len(cdn_domains)} CDN domains for {blocked_domain}: {cdn_domains}"
            )
        else:
            LOG.debug(f"No CDN domains found for {blocked_domain}")
        return cdn_domains

    def get_cdn_domain(self, blocked_domain: str) -> Optional[str]:
        """
        Returns a random CDN domain for backward compatibility.
        """
        cdn_domains = self.get_cdn_domains(blocked_domain)
        if cdn_domains:
            cdn_domain = random.choice(cdn_domains)
            LOG.info(f"Selected CDN domain for {blocked_domain}: {cdn_domain}")
            return cdn_domain
        return None

    def resolve_cdn_domains(self, blocked_domain: str) -> CDNResolutionResult:
        """
        Resolve all CDN domains for a blocked domain.
        Continues operation even if some CDN domains fail to resolve.
        """
        cdn_domains = self.get_cdn_domains(blocked_domain)
        if not cdn_domains:
            return CDNResolutionResult(
                original_domain=blocked_domain,
                cdn_domains=[],
                resolved_ips={},
                successful_resolutions=0,
                failed_resolutions=0,
            )
        LOG.info(f"Resolving {len(cdn_domains)} CDN domains for {blocked_domain}")
        resolved_ips = self.dns_handler.resolve_multiple_domains(cdn_domains)
        successful = sum((1 for ip in resolved_ips.values() if ip is not None))
        failed = len(resolved_ips) - successful
        for domain, ip in resolved_ips.items():
            if ip:
                LOG.info(f"  ✓ {domain} -> {ip}")
            else:
                LOG.warning(f"  ✗ Failed to resolve {domain}")
        if successful > 0:
            LOG.info(
                f"Successfully resolved {successful}/{len(cdn_domains)} CDN domains for {blocked_domain}"
            )
        else:
            LOG.error(f"Failed to resolve any CDN domains for {blocked_domain}")
        return CDNResolutionResult(
            original_domain=blocked_domain,
            cdn_domains=cdn_domains,
            resolved_ips=resolved_ips,
            successful_resolutions=successful,
            failed_resolutions=failed,
        )

    def get_all_resolved_ips(self, blocked_domain: str) -> Set[str]:
        """
        Get all successfully resolved IP addresses for CDN domains.
        Returns empty set if no domains could be resolved.
        """
        result = self.resolve_cdn_domains(blocked_domain)
        return {ip for ip in result.resolved_ips.values() if ip is not None}

    def validate_cdn_resolution(
        self, blocked_domain: str, min_success_rate: float = 0.5
    ) -> bool:
        """
        Validate that CDN resolution meets minimum success criteria.
        """
        result = self.resolve_cdn_domains(blocked_domain)
        if not result.cdn_domains:
            return True
        success_rate = result.successful_resolutions / len(result.cdn_domains)
        is_valid = success_rate >= min_success_rate
        if not is_valid:
            LOG.warning(
                f"CDN resolution validation failed for {blocked_domain}: success rate {success_rate:.2f} < {min_success_rate}"
            )
        return is_valid

    def _is_domain_match(self, domain: str, pattern: str) -> bool:
        """
        Check if domain matches pattern (supports subdomains).
        """
        if domain == pattern:
            return True
        if domain.endswith("." + pattern):
            return True
        if pattern.endswith("." + domain):
            return True
        return False

    def add_cdn_mapping(self, main_domain: str, cdn_domains: List[str]):
        """
        Add or update CDN mapping for a domain.
        """
        self.CDN_MAPPINGS[main_domain] = cdn_domains
        if main_domain in self._domain_cache:
            del self._domain_cache[main_domain]
        LOG.info(f"Added CDN mapping for {main_domain}: {cdn_domains}")

    def get_mapping_stats(self) -> Dict[str, int]:
        """
        Get statistics about CDN mappings.
        """
        return {
            "total_main_domains": len(self.CDN_MAPPINGS),
            "total_cdn_domains": sum(
                (len(domains) for domains in self.CDN_MAPPINGS.values())
            ),
            "cached_lookups": len(self._domain_cache),
        }
