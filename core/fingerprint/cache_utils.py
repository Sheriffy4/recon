"""
Cache Utilities Module

This module provides reusable cache management utilities for fingerprinting operations.
Extracted from various fingerprinting classes to reduce code duplication.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple, TypeVar, Generic
from datetime import datetime, timedelta

LOG = logging.getLogger("cache_utils")

T = TypeVar("T")


class TimestampedCache(Generic[T]):
    """
    Generic cache with timestamp-based expiration and size limits.

    Features:
    - TTL-based expiration
    - LRU eviction when size limit reached
    - Thread-safe operations (basic)
    - Statistics tracking
    """

    def __init__(self, max_size: int = 1000, ttl: timedelta = timedelta(hours=1)):
        """
        Initialize the cache.

        Args:
            max_size: Maximum number of entries (default: 1000)
            ttl: Time-to-live for entries (default: 1 hour)
        """
        self.max_size = max_size
        self.ttl = ttl
        self._cache: Dict[str, Tuple[T, datetime]] = {}
        self._stats = {"hits": 0, "misses": 0, "evictions": 0, "updates": 0}

    def get(self, key: str, default: Optional[T] = None) -> Optional[T]:
        """
        Get value from cache if not expired.

        Args:
            key: Cache key
            default: Default value if not found or expired

        Returns:
            Cached value or default
        """
        if key not in self._cache:
            self._stats["misses"] += 1
            return default

        value, timestamp = self._cache[key]
        if datetime.now() - timestamp >= self.ttl:
            # Expired
            del self._cache[key]
            self._stats["misses"] += 1
            return default

        self._stats["hits"] += 1
        return value

    def set(self, key: str, value: T) -> None:
        """
        Set value in cache with current timestamp.

        Args:
            key: Cache key
            value: Value to cache
        """
        # Evict oldest if at capacity
        if len(self._cache) >= self.max_size and key not in self._cache:
            self._evict_oldest()

        self._cache[key] = (value, datetime.now())
        self._stats["updates"] += 1

    def _evict_oldest(self) -> None:
        """Evict the oldest entry from cache."""
        if not self._cache:
            return

        oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][1])
        del self._cache[oldest_key]
        self._stats["evictions"] += 1
        LOG.debug(f"Evicted oldest cache entry: {oldest_key}")

    def contains(self, key: str) -> bool:
        """
        Check if key exists and is not expired.

        Args:
            key: Cache key

        Returns:
            True if key exists and not expired
        """
        if key not in self._cache:
            return False

        _, timestamp = self._cache[key]
        if datetime.now() - timestamp >= self.ttl:
            del self._cache[key]
            return False

        return True

    def find_by_prefix(self, prefix: str) -> Optional[T]:
        """
        Find first value with key starting with prefix.

        Args:
            prefix: Key prefix to search for

        Returns:
            First matching value or None
        """
        now = datetime.now()
        # iterate on snapshot to allow safe deletion
        for key, (value, timestamp) in list(self._cache.items()):
            if key.startswith(prefix):
                # Check if expired
                if now - timestamp < self.ttl:
                    return value
                else:
                    self._cache.pop(key, None)
        return None

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
        LOG.debug("Cache cleared")

    def size(self) -> int:
        """Get current cache size."""
        return len(self._cache)

    def get_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        stats = self._stats.copy()
        stats["size"] = len(self._cache)
        stats["max_size"] = self.max_size
        if stats["hits"] + stats["misses"] > 0:
            stats["hit_rate"] = stats["hits"] / (stats["hits"] + stats["misses"])
        else:
            stats["hit_rate"] = 0.0
        return stats

    def cleanup_expired(self) -> int:
        """
        Remove all expired entries.

        Returns:
            Number of entries removed
        """
        now = datetime.now()
        expired_keys = [
            key for key, (_, timestamp) in self._cache.items() if now - timestamp >= self.ttl
        ]
        for key in expired_keys:
            del self._cache[key]
        if expired_keys:
            LOG.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
        return len(expired_keys)


def generate_cache_key(domain: str, ips: Optional[List[str]] = None) -> str:
    """
    Generate stable cache key for domain and IPs.

    Uses sorted IPs to ensure consistent keys regardless of order.

    Args:
        domain: Domain name
        ips: List of IP addresses (optional)

    Returns:
        Stable cache key string
    """
    if ips:
        ip_part = "_".join(sorted(ips))
        return f"{domain}_{ip_part}"
    else:
        return f"{domain}_no_ips"


def find_fingerprint_by_domain(
    cache: Dict[str, Tuple[Any, datetime]], domain: str
) -> Optional[Any]:
    """
    Find fingerprint in cache by domain prefix.

    This is a helper for legacy cache format: Dict[str, Tuple[value, timestamp]]

    Args:
        cache: Cache dictionary
        domain: Domain to search for

    Returns:
        First matching fingerprint or None
    """
    for key, (fp, _) in cache.items():
        if key.startswith(domain):
            return fp
    return None


def collect_effectiveness_stats(
    technique_effectiveness: Dict[str, Dict[str, List[float]]],
) -> Dict[str, Any]:
    """
    Collect statistics from technique effectiveness data.

    Args:
        technique_effectiveness: Nested dict of domain -> technique -> scores

    Returns:
        Statistics dictionary with avg, total, etc.
    """
    all_effectiveness = []
    for domain_data in technique_effectiveness.values():
        for scores in domain_data.values():
            all_effectiveness.extend(scores)

    stats = {}
    if all_effectiveness:
        try:
            import numpy as np

            stats["avg_attack_effectiveness"] = float(np.mean(all_effectiveness))
            stats["std_attack_effectiveness"] = float(np.std(all_effectiveness))
            stats["min_attack_effectiveness"] = float(np.min(all_effectiveness))
            stats["max_attack_effectiveness"] = float(np.max(all_effectiveness))
        except ImportError:
            stats["avg_attack_effectiveness"] = sum(all_effectiveness) / len(all_effectiveness)
            stats["std_attack_effectiveness"] = 0.0
            stats["min_attack_effectiveness"] = min(all_effectiveness)
            stats["max_attack_effectiveness"] = max(all_effectiveness)

        stats["total_attacks_tracked"] = len(all_effectiveness)
    else:
        stats["avg_attack_effectiveness"] = 0.0
        stats["total_attacks_tracked"] = 0

    return stats


class CacheManager:
    """
    High-level cache manager for fingerprinting operations.

    Provides convenience methods for common caching patterns.
    """

    def __init__(self, max_size: int = 1000, ttl_hours: float = 1.0):
        """
        Initialize cache manager.

        Args:
            max_size: Maximum cache size
            ttl_hours: TTL in hours
        """
        self.fingerprint_cache = TimestampedCache(max_size=max_size, ttl=timedelta(hours=ttl_hours))
        self.behavior_cache = TimestampedCache(max_size=max_size, ttl=timedelta(hours=ttl_hours))

    def get_fingerprint(self, domain: str, ips: Optional[List[str]] = None):
        """Get fingerprint from cache."""
        key = generate_cache_key(domain, ips)
        return self.fingerprint_cache.get(key)

    def set_fingerprint(self, domain: str, fingerprint, ips: Optional[List[str]] = None):
        """Set fingerprint in cache."""
        key = generate_cache_key(domain, ips)
        self.fingerprint_cache.set(key, fingerprint)

    def get_behavior_profile(self, domain: str):
        """Get behavior profile from cache."""
        return self.behavior_cache.get(domain)

    def set_behavior_profile(self, domain: str, profile):
        """Set behavior profile in cache."""
        self.behavior_cache.set(domain, profile)

    def get_stats(self) -> Dict[str, Any]:
        """Get combined statistics."""
        return {
            "fingerprint_cache": self.fingerprint_cache.get_stats(),
            "behavior_cache": self.behavior_cache.get_stats(),
        }

    def cleanup(self) -> Dict[str, int]:
        """Cleanup expired entries from all caches."""
        return {
            "fingerprint_expired": self.fingerprint_cache.cleanup_expired(),
            "behavior_expired": self.behavior_cache.cleanup_expired(),
        }
