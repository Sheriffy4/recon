"""
Attack instance caching system with LRU eviction and metrics.

This module provides efficient caching of attack instances to avoid
repeated instantiation overhead:
- LRU (Least Recently Used) cache eviction
- Configurable cache size limits
- Cache hit/miss metrics
- TTL (Time To Live) support
- Thread-safe operations
"""

import logging
import time
import threading
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from collections import OrderedDict


logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Entry in the attack instance cache."""

    instance: Any
    creation_time: float
    last_access_time: float
    access_count: int = 0
    ttl_seconds: Optional[float] = None

    def is_expired(self) -> bool:
        """Check if entry has expired based on TTL."""
        if self.ttl_seconds is None:
            return False
        return (time.time() - self.creation_time) > self.ttl_seconds


@dataclass
class CacheMetrics:
    """Metrics for cache operations."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0
    total_accesses: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate as percentage."""
        if self.total_accesses == 0:
            return 0.0
        return (self.hits / self.total_accesses) * 100

    @property
    def miss_rate(self) -> float:
        """Calculate cache miss rate as percentage."""
        if self.total_accesses == 0:
            return 0.0
        return (self.misses / self.total_accesses) * 100


class AttackInstanceCache:
    """
    LRU cache for attack instances with metrics and TTL support.

    Features:
    - LRU eviction when cache is full
    - Configurable size limits
    - TTL (Time To Live) for entries
    - Thread-safe operations
    - Detailed metrics (hits, misses, evictions)
    - Cache invalidation by key or pattern
    """

    def __init__(
        self,
        max_size: int = 100,
        default_ttl_seconds: Optional[float] = None,
        enable_metrics: bool = True,
    ):
        """
        Initialize the instance cache.

        Args:
            max_size: Maximum number of cached instances
            default_ttl_seconds: Default TTL for cache entries (None = no expiration)
            enable_metrics: Enable cache metrics tracking
        """
        self.max_size = max_size
        self.default_ttl_seconds = default_ttl_seconds
        self.enable_metrics = enable_metrics

        # OrderedDict for LRU behavior
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()

        # Thread lock for thread-safe operations
        self._lock = threading.RLock()

        # Metrics
        self._metrics = CacheMetrics() if enable_metrics else None

        logger.info(
            f"AttackInstanceCache initialized (max_size={max_size}, "
            f"ttl={default_ttl_seconds}, metrics={enable_metrics})"
        )

    def get(self, key: str) -> Optional[Any]:
        """
        Get an instance from cache.

        Args:
            key: Cache key (typically attack class name)

        Returns:
            Cached instance or None if not found/expired
        """
        with self._lock:
            if self.enable_metrics:
                self._metrics.total_accesses += 1

            if key not in self._cache:
                if self.enable_metrics:
                    self._metrics.misses += 1
                logger.debug(f"Cache miss: {key}")
                return None

            entry = self._cache[key]

            # Check if expired
            if entry.is_expired():
                self._remove_entry(key, reason="expired")
                if self.enable_metrics:
                    self._metrics.misses += 1
                    self._metrics.expirations += 1
                logger.debug(f"Cache miss (expired): {key}")
                return None

            # Update access info
            entry.last_access_time = time.time()
            entry.access_count += 1

            # Move to end (most recently used)
            self._cache.move_to_end(key)

            if self.enable_metrics:
                self._metrics.hits += 1

            logger.debug(f"Cache hit: {key} (access_count={entry.access_count})")
            return entry.instance

    def put(self, key: str, instance: Any, ttl_seconds: Optional[float] = None) -> None:
        """
        Put an instance into cache.

        Args:
            key: Cache key
            instance: Instance to cache
            ttl_seconds: TTL for this entry (overrides default)
        """
        with self._lock:
            # Check if we need to evict
            if key not in self._cache and len(self._cache) >= self.max_size:
                self._evict_lru()

            # Use provided TTL or default
            entry_ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds

            # Create cache entry
            entry = CacheEntry(
                instance=instance,
                creation_time=time.time(),
                last_access_time=time.time(),
                access_count=0,
                ttl_seconds=entry_ttl,
            )

            # Add to cache (or update existing)
            if key in self._cache:
                logger.debug(f"Updating cache entry: {key}")
            else:
                logger.debug(f"Adding to cache: {key}")

            self._cache[key] = entry
            self._cache.move_to_end(key)

    def _evict_lru(self) -> None:
        """Evict the least recently used entry."""
        if not self._cache:
            return

        # Get first item (least recently used)
        lru_key = next(iter(self._cache))
        self._remove_entry(lru_key, reason="evicted")

        if self.enable_metrics:
            self._metrics.evictions += 1

    def _remove_entry(self, key: str, reason: str = "removed") -> None:
        """Remove an entry from cache."""
        if key in self._cache:
            self._cache.pop(key)
            logger.debug(f"Cache entry {reason}: {key}")

    def invalidate(self, key: str) -> bool:
        """
        Invalidate a specific cache entry.

        Args:
            key: Cache key to invalidate

        Returns:
            True if entry was found and removed
        """
        with self._lock:
            if key in self._cache:
                self._remove_entry(key, reason="invalidated")
                return True
            return False

    def invalidate_pattern(self, pattern: str) -> int:
        """
        Invalidate all entries matching a pattern.

        Args:
            pattern: Pattern to match (substring match)

        Returns:
            Number of entries invalidated
        """
        with self._lock:
            keys_to_remove = [key for key in self._cache.keys() if pattern in key]

            for key in keys_to_remove:
                self._remove_entry(key, reason="invalidated (pattern)")

            logger.info(f"Invalidated {len(keys_to_remove)} entries matching '{pattern}'")
            return len(keys_to_remove)

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            logger.info(f"Cleared {count} cache entries")

    def cleanup_expired(self) -> int:
        """
        Remove all expired entries.

        Returns:
            Number of entries removed
        """
        with self._lock:
            expired_keys = [key for key, entry in self._cache.items() if entry.is_expired()]

            for key in expired_keys:
                self._remove_entry(key, reason="expired (cleanup)")
                if self.enable_metrics:
                    self._metrics.expirations += 1

            if expired_keys:
                logger.info(f"Cleaned up {len(expired_keys)} expired entries")

            return len(expired_keys)

    def get_metrics(self) -> Optional[CacheMetrics]:
        """
        Get cache metrics.

        Returns:
            CacheMetrics object or None if metrics disabled
        """
        return self._metrics

    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        with self._lock:
            stats = {
                "max_size": self.max_size,
                "current_size": len(self._cache),
                "utilization_percent": (
                    (len(self._cache) / self.max_size * 100) if self.max_size > 0 else 0
                ),
                "default_ttl_seconds": self.default_ttl_seconds,
                "metrics_enabled": self.enable_metrics,
            }

            if self.enable_metrics and self._metrics:
                stats.update(
                    {
                        "hits": self._metrics.hits,
                        "misses": self._metrics.misses,
                        "hit_rate_percent": self._metrics.hit_rate,
                        "miss_rate_percent": self._metrics.miss_rate,
                        "evictions": self._metrics.evictions,
                        "expirations": self._metrics.expirations,
                        "total_accesses": self._metrics.total_accesses,
                    }
                )

            # Entry statistics
            if self._cache:
                total_accesses = sum(e.access_count for e in self._cache.values())
                avg_age = sum(time.time() - e.creation_time for e in self._cache.values()) / len(
                    self._cache
                )

                stats.update(
                    {
                        "total_entry_accesses": total_accesses,
                        "avg_entry_age_seconds": avg_age,
                    }
                )

            return stats

    def get_entry_info(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific cache entry.

        Args:
            key: Cache key

        Returns:
            Dictionary with entry information or None if not found
        """
        with self._lock:
            if key not in self._cache:
                return None

            entry = self._cache[key]
            return {
                "key": key,
                "access_count": entry.access_count,
                "age_seconds": time.time() - entry.creation_time,
                "time_since_last_access": time.time() - entry.last_access_time,
                "ttl_seconds": entry.ttl_seconds,
                "is_expired": entry.is_expired(),
            }

    def get_all_entries_info(self) -> List[Dict[str, Any]]:
        """
        Get information about all cache entries.

        Returns:
            List of entry information dictionaries
        """
        with self._lock:
            return [self.get_entry_info(key) for key in self._cache.keys()]

    def get_most_accessed(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get the most frequently accessed entries.

        Args:
            limit: Maximum number of results

        Returns:
            List of entry information sorted by access count
        """
        with self._lock:
            sorted_entries = sorted(
                self._cache.items(), key=lambda x: x[1].access_count, reverse=True
            )

            return [
                {
                    "key": key,
                    "access_count": entry.access_count,
                    "age_seconds": time.time() - entry.creation_time,
                }
                for key, entry in sorted_entries[:limit]
            ]

    def reset_metrics(self) -> None:
        """Reset cache metrics."""
        if self.enable_metrics:
            self._metrics = CacheMetrics()
            logger.info("Cache metrics reset")

    def resize(self, new_max_size: int) -> None:
        """
        Resize the cache.

        Args:
            new_max_size: New maximum cache size
        """
        with self._lock:
            old_size = self.max_size
            self.max_size = new_max_size

            # Evict entries if new size is smaller
            while len(self._cache) > new_max_size:
                self._evict_lru()

            logger.info(
                f"Cache resized: {old_size} -> {new_max_size} " f"(current: {len(self._cache)})"
            )


# Global cache instance
_global_cache: Optional[AttackInstanceCache] = None


def get_instance_cache(
    max_size: int = 100, default_ttl_seconds: Optional[float] = None, enable_metrics: bool = True
) -> AttackInstanceCache:
    """
    Get the global instance cache.

    Args:
        max_size: Maximum cache size
        default_ttl_seconds: Default TTL for entries
        enable_metrics: Enable metrics tracking

    Returns:
        Global AttackInstanceCache instance
    """
    global _global_cache

    if _global_cache is None:
        _global_cache = AttackInstanceCache(
            max_size=max_size,
            default_ttl_seconds=default_ttl_seconds,
            enable_metrics=enable_metrics,
        )

    return _global_cache


def configure_instance_cache(
    max_size: int = 100, default_ttl_seconds: Optional[float] = None, enable_metrics: bool = True
) -> None:
    """
    Configure the global instance cache.

    Args:
        max_size: Maximum cache size
        default_ttl_seconds: Default TTL for entries
        enable_metrics: Enable metrics tracking
    """
    global _global_cache

    _global_cache = AttackInstanceCache(
        max_size=max_size, default_ttl_seconds=default_ttl_seconds, enable_metrics=enable_metrics
    )

    logger.info(
        f"Configured instance cache: max_size={max_size}, "
        f"ttl={default_ttl_seconds}, metrics={enable_metrics}"
    )
