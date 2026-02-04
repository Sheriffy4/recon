"""
Domain Matcher component for runtime packet filtering.

This module provides functionality to match extracted domains against
blacklist/whitelist rules with support for wildcards and subdomains.
"""

import re
from typing import Set, List, Pattern, Optional
from functools import lru_cache

from .config import FilterMode


class DomainMatcher:
    """
    Matches domains against filtering rules with pattern support.

    This class provides efficient domain matching with support for:
    - Exact domain matches
    - Wildcard patterns (*.example.com)
    - Subdomain matching
    - Blacklist and whitelist modes
    """

    def __init__(self, mode: FilterMode, domain_list: Set[str]):
        """
        Initialize Domain Matcher with performance optimizations.

        Args:
            mode: Filtering mode (NONE, BLACKLIST, WHITELIST)
            domain_list: Set of domains/patterns to match against

        Requirements: 5.1, 5.2, 5.4
        """
        self.mode = mode
        # Normalize all domains to lowercase during initialization
        self.domain_list = {domain.lower().strip() for domain in domain_list}

        # Separate exact domains from patterns for faster lookup
        self.exact_domains = set()
        self.wildcard_patterns = []
        self.subdomain_patterns = set()

        self._categorize_domains()
        self.compiled_patterns = self._compile_patterns()

        # Cache for performance optimization
        self._match_cache = {}
        self._cache_size_limit = 1000

        # Performance statistics
        self._exact_matches = 0
        self._pattern_matches = 0
        self._cache_hits = 0

    def matches(self, domain: str) -> bool:
        """
        Check if domain matches filtering rules with optimized lookup.

        Args:
            domain: Domain name to check

        Returns:
            True if domain should be processed, False otherwise

        Requirements: 5.1, 5.2, 5.4
        """
        if not domain:
            return False

        # Normalize domain (lowercase, strip)
        normalized_domain = domain.lower().strip()

        # Check cache first
        if normalized_domain in self._match_cache:
            self._cache_hits += 1
            return self._match_cache[normalized_domain]

        # Determine match result based on mode
        result = self._evaluate_match_optimized(normalized_domain)

        # Cache result (with size limit)
        if len(self._match_cache) < self._cache_size_limit:
            self._match_cache[normalized_domain] = result

        return result

    def _categorize_domains(self) -> None:
        """
        Categorize domains into exact matches, wildcards, and subdomain patterns.

        This optimization separates different types of patterns for faster lookup.
        """
        for domain_pattern in self.domain_list:
            if "*" in domain_pattern or "?" in domain_pattern:
                # Wildcard pattern
                self.wildcard_patterns.append(domain_pattern)
            elif domain_pattern.startswith("."):
                # Subdomain pattern (e.g., ".example.com")
                self.subdomain_patterns.add(domain_pattern[1:])  # Remove leading dot
            else:
                # Exact domain
                self.exact_domains.add(domain_pattern)

    def _evaluate_match_optimized(self, domain: str) -> bool:
        """
        Evaluate if domain matches based on current mode with optimizations.

        Args:
            domain: Normalized domain name

        Returns:
            True if domain should be processed
        """
        if self.mode == FilterMode.NONE:
            # Apply to all traffic
            return True

        domain_matches = self._domain_matches_patterns_optimized(domain)

        if self.mode == FilterMode.BLACKLIST:
            # Apply only to domains in blacklist
            return domain_matches
        elif self.mode == FilterMode.WHITELIST:
            # Apply only to domains in whitelist
            return domain_matches

        return False

    def _evaluate_match(self, domain: str) -> bool:
        """
        Evaluate if domain matches based on current mode (legacy method).

        Args:
            domain: Normalized domain name

        Returns:
            True if domain should be processed
        """
        return self._evaluate_match_optimized(domain)

    def _domain_matches_patterns_optimized(self, domain: str) -> bool:
        """
        Check if domain matches any patterns with optimized lookup order.

        Args:
            domain: Domain name to check

        Returns:
            True if domain matches any pattern
        """
        # 1. Check exact matches first (fastest - O(1) hash lookup)
        if domain in self.exact_domains:
            self._exact_matches += 1
            return True

        # 2. Check subdomain patterns (fast string operations)
        if self._check_subdomain_matches_optimized(domain):
            return True

        # 3. Check compiled regex patterns (slowest - only if needed)
        for pattern in self.compiled_patterns:
            if pattern.match(domain):
                self._pattern_matches += 1
                return True

        return False

    def _domain_matches_patterns(self, domain: str) -> bool:
        """
        Check if domain matches any of the compiled patterns (legacy method).

        Args:
            domain: Domain name to check

        Returns:
            True if domain matches any pattern
        """
        return self._domain_matches_patterns_optimized(domain)

    def _check_subdomain_matches_optimized(self, domain: str) -> bool:
        """
        Check if domain matches any parent domain patterns with optimizations.

        Args:
            domain: Domain name to check

        Returns:
            True if domain is a subdomain of any pattern
        """
        domain_parts = domain.split(".")

        # Check all possible parent domains
        for i in range(1, len(domain_parts)):
            parent_domain = ".".join(domain_parts[i:])

            # Check if parent domain is in exact domains
            if parent_domain in self.exact_domains:
                return True

            # Check if parent domain is in subdomain patterns
            if parent_domain in self.subdomain_patterns:
                return True

            # Check wildcard pattern for parent (only if we have wildcard patterns)
            if self.wildcard_patterns:
                wildcard_pattern = f"*.{parent_domain}"
                if wildcard_pattern in self.domain_list:
                    return True

        return False

    def _check_subdomain_matches(self, domain: str) -> bool:
        """
        Check if domain matches any parent domain patterns (legacy method).

        Args:
            domain: Domain name to check

        Returns:
            True if domain is a subdomain of any pattern
        """
        return self._check_subdomain_matches_optimized(domain)

    def _compile_patterns(self) -> List[Pattern]:
        """
        Compile domain patterns for efficient matching.

        Returns:
            List of compiled regex patterns

        Requirements: 5.4
        """
        patterns = []

        for domain_pattern in self.domain_list:
            # Skip exact domain names (handled separately)
            if "*" not in domain_pattern and "?" not in domain_pattern:
                continue

            try:
                # Convert wildcard pattern to regex
                regex_pattern = self._wildcard_to_regex(domain_pattern)
                compiled_pattern = re.compile(regex_pattern, re.IGNORECASE)
                patterns.append(compiled_pattern)
            except re.error:
                # Skip invalid patterns
                continue

        return patterns

    def _wildcard_to_regex(self, pattern: str) -> str:
        """
        Convert wildcard pattern to regex pattern.

        Args:
            pattern: Wildcard pattern (e.g., "*.example.com")

        Returns:
            Regex pattern string
        """
        # Escape special regex characters except * and ?
        escaped = re.escape(pattern)

        # Replace escaped wildcards with regex equivalents
        escaped = escaped.replace(r"\*", ".*")
        escaped = escaped.replace(r"\?", ".")

        # Anchor the pattern to match full domain
        return f"^{escaped}$"

    def add_domain(self, domain: str) -> None:
        """
        Add a domain to the matcher.

        Args:
            domain: Domain or pattern to add
        """
        self.domain_list.add(domain.lower().strip())

        # Recompile patterns if needed
        if "*" in domain or "?" in domain:
            self.compiled_patterns = self._compile_patterns()

        # Clear cache to ensure consistency
        self._match_cache.clear()

    def remove_domain(self, domain: str) -> None:
        """
        Remove a domain from the matcher.

        Args:
            domain: Domain or pattern to remove
        """
        normalized_domain = domain.lower().strip()
        self.domain_list.discard(normalized_domain)

        # Recompile patterns
        self.compiled_patterns = self._compile_patterns()

        # Clear cache
        self._match_cache.clear()

    def clear_cache(self) -> None:
        """Clear the internal match cache."""
        self._match_cache.clear()

    def get_cache_stats(self) -> dict:
        """
        Get cache and performance statistics for monitoring.

        Returns:
            Dictionary with cache and performance statistics
        """
        return {
            "cache_size": len(self._match_cache),
            "cache_limit": self._cache_size_limit,
            "cache_hits": self._cache_hits,
            "domain_count": len(self.domain_list),
            "exact_domains": len(self.exact_domains),
            "wildcard_patterns": len(self.wildcard_patterns),
            "subdomain_patterns": len(self.subdomain_patterns),
            "compiled_patterns": len(self.compiled_patterns),
            "exact_matches": self._exact_matches,
            "pattern_matches": self._pattern_matches,
        }
