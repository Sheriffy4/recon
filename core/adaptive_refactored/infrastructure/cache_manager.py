"""
Cache Manager implementation for the refactored Adaptive Engine.

This component handles all caching operations with configurable TTL and size limits,
including performance optimization features like hit/miss tracking and eviction policies.
"""

import asyncio
import logging
import threading
from typing import Dict, Optional, Any, List, Tuple
from datetime import datetime, timedelta
from collections import OrderedDict
from ..interfaces import ICacheManager
from ..models import CacheType, CacheEntry
from ..config import CacheConfig


logger = logging.getLogger(__name__)


class EvictionPolicy:
    """Enumeration of cache eviction policies."""

    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In, First Out
    TTL = "ttl"  # Time To Live based


class CacheManager(ICacheManager):
    """
    Implementation of cache management with TTL and size limits.

    Provides in-memory caching with configurable size limits,
    TTL support, automatic cleanup, and performance optimization
    features including hit/miss tracking and advanced eviction policies.
    """

    def __init__(self, config: CacheConfig):
        self.config = config
        self._caches: Dict[CacheType, OrderedDict[str, CacheEntry]] = {}
        self._cache_sizes: Dict[CacheType, int] = {
            CacheType.FINGERPRINT: config.fingerprint_cache_size,
            CacheType.STRATEGY: config.strategy_cache_size,
            CacheType.DOMAIN_ACCESSIBILITY: config.domain_cache_size,
            CacheType.PROTOCOL_PREFERENCE: config.domain_cache_size,
            CacheType.METRICS: config.metrics_cache_size,
            CacheType.FAILURE_ANALYSIS: config.strategy_cache_size,
        }

        # Performance tracking
        self._hit_counts: Dict[CacheType, int] = {}
        self._miss_counts: Dict[CacheType, int] = {}
        self._eviction_counts: Dict[CacheType, int] = {}
        self._total_operations: Dict[CacheType, int] = {}

        # Thread safety
        self._cache_locks: Dict[CacheType, threading.RLock] = {}

        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None

        # Eviction policy (can be configured per cache type)
        self._eviction_policy: str = EvictionPolicy.LRU

        self._initialize_caches()

    def _initialize_caches(self) -> None:
        """Initialize all cache types with performance tracking."""
        for cache_type in CacheType:
            self._caches[cache_type] = OrderedDict()
            self._hit_counts[cache_type] = 0
            self._miss_counts[cache_type] = 0
            self._eviction_counts[cache_type] = 0
            self._total_operations[cache_type] = 0
            self._cache_locks[cache_type] = threading.RLock()

        if self.config.enable_caching:
            logger.info("Cache manager initialized with caching enabled and performance tracking")
        else:
            logger.info("Cache manager initialized with caching disabled")

    async def get(self, key: str, cache_type: CacheType) -> Optional[Any]:
        """Get value from cache with performance tracking."""
        if not self.config.enable_caching:
            return None

        with self._cache_locks[cache_type]:
            self._total_operations[cache_type] += 1
            cache = self._caches[cache_type]
            entry = cache.get(key)

            if entry is None:
                self._miss_counts[cache_type] += 1
                logger.debug(f"Cache miss for {cache_type.value}:{key}")
                return None

            if entry.is_expired():
                # Remove expired entry
                del cache[key]
                self._miss_counts[cache_type] += 1
                logger.debug(f"Cache miss (expired) for {cache_type.value}:{key}")
                return None

            # Update access tracking and move to end for LRU
            entry.touch()
            if self._eviction_policy == EvictionPolicy.LRU:
                cache.move_to_end(key)

            self._hit_counts[cache_type] += 1
            logger.debug(f"Cache hit for {cache_type.value}:{key}")
            return entry.value

    async def set(
        self, key: str, value: Any, cache_type: CacheType, ttl: Optional[int] = None
    ) -> None:
        """Set value in cache with optional TTL and eviction policy enforcement."""
        if not self.config.enable_caching:
            return

        with self._cache_locks[cache_type]:
            cache = self._caches[cache_type]

            # Check size limits and evict if necessary
            max_size = self._cache_sizes[cache_type]
            if len(cache) >= max_size:
                await self._evict_entries(cache_type, 1)

            # Use default TTL if not specified
            if ttl is None:
                ttl = self.config.cache_ttl_hours * 3600

            entry = CacheEntry(key=key, value=value, cache_type=cache_type, ttl_seconds=ttl)

            cache[key] = entry

            # Move to end for LRU policy
            if self._eviction_policy == EvictionPolicy.LRU:
                cache.move_to_end(key)

            logger.debug(f"Cache set for {cache_type.value}:{key} with TTL {ttl}s")

    async def invalidate(self, key: str, cache_type: CacheType) -> None:
        """Invalidate specific cache entry."""
        with self._cache_locks[cache_type]:
            cache = self._caches.get(cache_type, OrderedDict())
            if key in cache:
                del cache[key]
                logger.debug(f"Cache invalidated for {cache_type.value}:{key}")

    async def clear_cache(self, cache_type: Optional[CacheType] = None) -> None:
        """Clear entire cache or specific cache type."""
        if cache_type is None:
            for ct in CacheType:
                with self._cache_locks[ct]:
                    self._caches[ct].clear()
                    # Reset performance counters
                    self._hit_counts[ct] = 0
                    self._miss_counts[ct] = 0
                    self._eviction_counts[ct] = 0
                    self._total_operations[ct] = 0
            logger.info("All caches cleared")
        else:
            with self._cache_locks[cache_type]:
                self._caches[cache_type].clear()
                # Reset performance counters for this cache type
                self._hit_counts[cache_type] = 0
                self._miss_counts[cache_type] = 0
                self._eviction_counts[cache_type] = 0
                self._total_operations[cache_type] = 0
            logger.info(f"Cache cleared for {cache_type.value}")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics including performance metrics."""
        stats = {}

        for cache_type, cache in self._caches.items():
            with self._cache_locks[cache_type]:
                total_entries = len(cache)
                expired_entries = sum(1 for entry in cache.values() if entry.is_expired())
                total_accesses = sum(entry.access_count for entry in cache.values())

                hits = self._hit_counts[cache_type]
                misses = self._miss_counts[cache_type]
                total_ops = self._total_operations[cache_type]
                evictions = self._eviction_counts[cache_type]

                hit_rate = hits / total_ops if total_ops > 0 else 0.0
                miss_rate = misses / total_ops if total_ops > 0 else 0.0

                stats[cache_type.value] = {
                    "total_entries": total_entries,
                    "expired_entries": expired_entries,
                    "active_entries": total_entries - expired_entries,
                    "total_accesses": total_accesses,
                    "max_size": self._cache_sizes[cache_type],
                    "utilization": (
                        total_entries / self._cache_sizes[cache_type]
                        if self._cache_sizes[cache_type] > 0
                        else 0
                    ),
                    "hit_count": hits,
                    "miss_count": misses,
                    "hit_rate": hit_rate,
                    "miss_rate": miss_rate,
                    "total_operations": total_ops,
                    "eviction_count": evictions,
                    "eviction_policy": self._eviction_policy,
                }

        return stats

    def get_performance_metrics(self) -> Dict[str, float]:
        """Get performance-focused cache metrics."""
        total_hits = sum(self._hit_counts.values())
        total_misses = sum(self._miss_counts.values())
        total_ops = total_hits + total_misses

        overall_hit_rate = total_hits / total_ops if total_ops > 0 else 0.0
        overall_miss_rate = total_misses / total_ops if total_ops > 0 else 0.0

        total_entries = sum(len(cache) for cache in self._caches.values())
        total_capacity = sum(self._cache_sizes.values())
        overall_utilization = total_entries / total_capacity if total_capacity > 0 else 0.0

        return {
            "overall_hit_rate": overall_hit_rate,
            "overall_miss_rate": overall_miss_rate,
            "overall_utilization": overall_utilization,
            "total_operations": total_ops,
            "total_entries": total_entries,
            "total_capacity": total_capacity,
            "total_evictions": sum(self._eviction_counts.values()),
        }

    async def _evict_entries(self, cache_type: CacheType, count: int = 1) -> None:
        """Evict entries from cache based on configured eviction policy."""
        cache = self._caches[cache_type]
        if not cache:
            return

        evicted = 0

        while evicted < count and cache:
            key_to_evict = self._select_eviction_key(cache)
            if key_to_evict:
                del cache[key_to_evict]
                evicted += 1
                self._eviction_counts[cache_type] += 1
                logger.debug(
                    f"{self._eviction_policy} evicted entry from {cache_type.value}: {key_to_evict}"
                )

    def _select_eviction_key(self, cache: dict) -> Optional[str]:
        """Select key to evict based on eviction policy."""
        if not cache:
            return None

        if self._eviction_policy == EvictionPolicy.LRU:
            return next(iter(cache))  # First key in OrderedDict (oldest)
        elif self._eviction_policy == EvictionPolicy.LFU:
            return min(cache.keys(), key=lambda k: cache[k].access_count)
        elif self._eviction_policy == EvictionPolicy.FIFO:
            return min(cache.keys(), key=lambda k: cache[k].created_at)
        elif self._eviction_policy == EvictionPolicy.TTL:
            return min(
                cache.keys(),
                key=lambda k: cache[k].created_at + timedelta(seconds=cache[k].ttl_seconds or 0),
            )
        else:
            return next(iter(cache))  # Default to LRU behavior

    def set_eviction_policy(self, policy: str) -> None:
        """Set the eviction policy for all caches."""
        if policy in [
            EvictionPolicy.LRU,
            EvictionPolicy.LFU,
            EvictionPolicy.FIFO,
            EvictionPolicy.TTL,
        ]:
            self._eviction_policy = policy
            logger.info(f"Cache eviction policy set to {policy}")
        else:
            raise ValueError(f"Invalid eviction policy: {policy}")

    def get_eviction_policy(self) -> str:
        """Get the current eviction policy."""
        return self._eviction_policy

    async def optimize_cache(self, cache_type: Optional[CacheType] = None) -> Dict[str, int]:
        """Optimize cache by removing expired entries and compacting."""
        optimization_stats = {}

        cache_types = [cache_type] if cache_type else list(CacheType)

        for ct in cache_types:
            with self._cache_locks[ct]:
                cache = self._caches[ct]
                initial_size = len(cache)

                # Remove expired entries
                expired_keys = [key for key, entry in cache.items() if entry.is_expired()]

                for key in expired_keys:
                    del cache[key]

                final_size = len(cache)
                removed_count = initial_size - final_size

                optimization_stats[ct.value] = {
                    "initial_size": initial_size,
                    "final_size": final_size,
                    "removed_expired": removed_count,
                }

                if removed_count > 0:
                    logger.info(
                        f"Cache optimization for {ct.value}: removed {removed_count} expired entries"
                    )

        return optimization_stats

    async def start_cleanup_task(self) -> None:
        """Start background cleanup task."""
        if self._cleanup_task is not None:
            return

        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Cache cleanup task started")

    async def stop_cleanup_task(self) -> None:
        """Stop background cleanup task."""
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
            logger.info("Cache cleanup task stopped")

    async def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        interval = self.config.cache_cleanup_interval_minutes * 60

        while True:
            try:
                await asyncio.sleep(interval)
                await self._cleanup_expired_entries()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cache cleanup: {e}")

    async def _cleanup_expired_entries(self) -> None:
        """Clean up expired entries from all caches."""
        total_cleaned = 0

        for cache_type, cache in self._caches.items():
            expired_keys = [key for key, entry in cache.items() if entry.is_expired()]

            for key in expired_keys:
                del cache[key]
                total_cleaned += 1

        if total_cleaned > 0:
            logger.debug(f"Cleaned up {total_cleaned} expired cache entries")
