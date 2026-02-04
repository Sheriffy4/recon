"""
Hierarchical Domain Matcher

This module implements hierarchical domain matching that walks up the domain
hierarchy to find the most specific matching rule.
"""

from typing import Dict, Any, Optional, List, Tuple
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


class HierarchicalDomainMatcher:
    """
    Implements hierarchical domain matching with parent domain resolution.

    This class searches for strategy rules by walking up the domain hierarchy
    (subdomain → parent domain → default) and includes LRU cache for performance.
    """

    def __init__(self, domain_rules: Dict[str, Dict[str, Any]], default_strategy: Dict[str, Any]):
        """
        Initialize the hierarchical domain matcher.

        Args:
            domain_rules: Dictionary mapping domains to strategy configurations
            default_strategy: Default strategy to use when no domain rule matches
        """
        self.domain_rules = domain_rules
        self.default_strategy = default_strategy
        self._cache_hits = 0
        self._cache_misses = 0

        logger.debug("HierarchicalDomainMatcher initialized with %d rules", len(domain_rules))

    def find_matching_rule(
        self, domain: str, strict: bool = False
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str], str]:
        """
        Walk up domain hierarchy to find matching rule.

        Algorithm with priority:
        1. Check exact match: "www.youtube.com" → ('www.youtube.com', 'exact')
        2. Check wildcard: "*.youtube.com" → ('*.youtube.com', 'wildcard')
        3. Check parent: "youtube.com" → ('youtube.com', 'parent') [only if strict=False]
        4. Return None if no matches found (caller should use default)

        Args:
            domain: The domain to find a matching rule for
            strict: If True, disable parent fallback (only exact and wildcard matches)

        Returns:
            Tuple of (strategy configuration dictionary or None, matched rule name or None, match_type)
            match_type is one of: 'exact', 'wildcard', 'parent', 'none'
        """
        if not domain:
            logger.debug("📋 No domain provided, will apply default strategy")
            return None, None, "none"

        # Normalize before caching to reduce cache duplication.
        d = str(domain).strip().lower().rstrip(".")
        return self._find_matching_rule_cached(d, strict)

    @lru_cache(maxsize=1000)
    def _find_matching_rule_cached(
        self, domain: str, strict: bool = False
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str], str]:
        """
        Cached version of domain matching for performance optimization.
        Supports wildcard patterns like *.googlevideo.com

        Priority order:
        1. Exact match (highest priority)
        2. Wildcard match
        3. Parent fallback (only if strict=False)

        Args:
            domain: The domain to find a matching rule for
            strict: If True, disable parent fallback

        Returns:
            Tuple of (strategy configuration dictionary or None, matched rule name or None, match_type)
            match_type is one of: 'exact', 'wildcard', 'parent', 'none'
        """
        try:
            # domain already normalized in find_matching_rule()

            # Priority 1: Check exact match first
            if domain in self.domain_rules:
                rule = self.domain_rules[domain]
                logger.debug("📋 Exact match: %r → %r", domain, domain)
                self._cache_hits += 1
                return rule, domain, "exact"

            # Priority 2: Check wildcard match for immediate parent
            parts = domain.split(".")
            if len(parts) > 1:
                parent_domain = ".".join(parts[1:])
                wildcard_pattern = f"*.{parent_domain}"
                if wildcard_pattern in self.domain_rules:
                    rule = self.domain_rules[wildcard_pattern]
                    logger.info(f"📋 Wildcard match found: '{domain}' → rule '{wildcard_pattern}'")
                    self._cache_hits += 1
                    return rule, wildcard_pattern, "wildcard"

            # Priority 3: Parent domain fallback (only if strict=False)
            if not strict:
                # Get all parent domains to check
                domains_to_check = self.get_parent_domains(domain)

                # Skip the first domain (already checked as exact match)
                for check_domain in domains_to_check[1:]:
                    if check_domain in self.domain_rules:
                        rule = self.domain_rules[check_domain]
                        logger.warning(
                            f"📋 Parent domain fallback: '{domain}' → rule '{check_domain}'"
                        )
                        logger.warning(
                            f"💡 Consider creating specific rule for '{domain}' or using wildcard '*.{check_domain}'"
                        )
                        self._cache_hits += 1
                        return rule, check_domain, "parent"

                    # Also check wildcard for parent domains
                    wildcard_pattern = f"*.{check_domain}"
                    if wildcard_pattern in self.domain_rules:
                        rule = self.domain_rules[wildcard_pattern]
                        logger.warning(
                            f"📋 Parent wildcard fallback: '{domain}' → rule '{wildcard_pattern}'"
                        )
                        self._cache_hits += 1
                        return rule, wildcard_pattern, "parent"

            # No rule found in hierarchy
            logger.info(
                f"📋 No matching rule found for domain '{domain}', will apply default strategy"
            )
            self._cache_misses += 1
            return None, None, "none"

        except Exception as e:
            logger.error(f"Error finding matching rule for domain '{domain}': {e}")
            self._cache_misses += 1
            return None, None, "none"

    def get_parent_domains(self, domain: str) -> List[str]:
        """
        Generate parent domain list for hierarchical matching.

        Example:
        Input: "rr5---sn-4pvgq-n8vs.googlevideo.com"
        Output: [
            "rr5---sn-4pvgq-n8vs.googlevideo.com",  # exact match
            "googlevideo.com",                       # parent
            "com"                                    # grandparent
        ]

        Args:
            domain: The domain to generate parent domains for

        Returns:
            List of domains to check, ordered from most specific to least specific
        """
        if not domain:
            return []

        domains = []
        current_domain = domain.lower().strip()

        # Add the original domain first (exact match)
        domains.append(current_domain)

        # Walk up the domain hierarchy
        parts = current_domain.split(".")

        # Generate parent domains by removing subdomains
        for i in range(1, len(parts)):
            parent_domain = ".".join(parts[i:])
            if parent_domain and parent_domain not in domains:
                domains.append(parent_domain)

        return domains

    def clear_cache(self):
        """Clear the LRU cache and reset statistics."""
        self._find_matching_rule_cached.cache_clear()
        self._cache_hits = 0
        self._cache_misses = 0
        logger.debug("Domain matcher cache cleared")

    def get_cache_statistics(self) -> Dict[str, Any]:
        """
        Get cache performance statistics.

        Returns:
            Dictionary containing cache statistics
        """
        cache_info = self._find_matching_rule_cached.cache_info()

        return {
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_size": cache_info.currsize,
            "cache_maxsize": cache_info.maxsize,
            "hit_rate": self._cache_hits / max(1, self._cache_hits + self._cache_misses),
        }

    def update_rules(
        self, domain_rules: Dict[str, Dict[str, Any]], default_strategy: Dict[str, Any]
    ):
        """
        Update domain rules and clear cache.

        Args:
            domain_rules: New dictionary mapping domains to strategy configurations
            default_strategy: New default strategy configuration
        """
        self.domain_rules = domain_rules
        self.default_strategy = default_strategy
        self.clear_cache()

        logger.info(f"Domain rules updated, cache cleared. New rule count: {len(domain_rules)}")
