"""
Analysis caching system for PCAP analysis (fixed version).
Implements intelligent caching to avoid repeated computations and improve performance.
"""

import pickle
import time
import logging
from typing import Any, Dict, Optional, Union
from dataclasses import dataclass
import threading

logger = logging.getLogger(__name__)


@dataclass
class CacheStats:
    """Cache statistics."""

    total_entries: int
    total_size_bytes: int
    hit_count: int
    miss_count: int
    hit_rate: float
    eviction_count: int


class MemoryCache:
    """In-memory cache with LRU eviction."""

    def __init__(self, max_size_mb: int = 256):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._cache: Dict[str, Any] = {}
        self._access_times: Dict[str, float] = {}
        self._lock = threading.RLock()
        self._stats = CacheStats(0, 0, 0, 0, 0.0, 0)

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self._lock:
            if key not in self._cache:
                self._stats.miss_count += 1
                self._update_hit_rate()
                return None

            # Update access time
            self._access_times[key] = time.time()
            self._stats.hit_count += 1
            self._update_hit_rate()

            return self._cache[key]

    def put(self, key: str, value: Any, ttl_seconds: Optional[float] = None) -> bool:
        """Put value in cache."""
        with self._lock:
            try:
                # Calculate value size
                value_bytes = pickle.dumps(value)
                size_bytes = len(value_bytes)

                # Check if we need to evict entries
                if not self._ensure_space(size_bytes):
                    return False

                # Remove existing entry if present
                if key in self._cache:
                    del self._cache[key]
                    del self._access_times[key]
                    self._stats.total_entries -= 1

                # Add new entry
                self._cache[key] = value
                self._access_times[key] = time.time()
                self._stats.total_entries += 1
                self._stats.total_size_bytes += size_bytes

                return True

            except Exception as e:
                logger.warning(f"Cannot cache value: {e}")
                return False

    def remove(self, key: str) -> bool:
        """Remove entry from cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                del self._access_times[key]
                self._stats.total_entries -= 1
                return True
            return False

    def clear(self):
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self._access_times.clear()
            self._stats.total_entries = 0
            self._stats.total_size_bytes = 0

    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        with self._lock:
            return CacheStats(
                total_entries=self._stats.total_entries,
                total_size_bytes=self._stats.total_size_bytes,
                hit_count=self._stats.hit_count,
                miss_count=self._stats.miss_count,
                hit_rate=self._stats.hit_rate,
                eviction_count=self._stats.eviction_count,
            )

    def _ensure_space(self, required_bytes: int) -> bool:
        """Ensure there's enough space for new entry."""
        if required_bytes > self.max_size_bytes:
            return False

        # Evict entries if necessary
        while (
            self._stats.total_size_bytes + required_bytes > self.max_size_bytes
            and self._cache
        ):
            self._evict_lru_entry()

        return True

    def _evict_lru_entry(self):
        """Evict least recently used entry."""
        if not self._access_times:
            return

        # Find LRU entry
        lru_key = min(self._access_times.keys(), key=lambda k: self._access_times[k])

        del self._cache[lru_key]
        del self._access_times[lru_key]
        self._stats.total_entries -= 1
        self._stats.eviction_count += 1

    def _update_hit_rate(self):
        """Update hit rate statistic."""
        total_requests = self._stats.hit_count + self._stats.miss_count
        if total_requests > 0:
            self._stats.hit_rate = self._stats.hit_count / total_requests


class HybridCache:
    """Simplified hybrid cache that uses only memory caching."""

    def __init__(
        self,
        memory_cache_mb: int = 128,
        persistent_cache_mb: int = 512,
        cache_dir: str = ".cache",
    ):
        self.memory_cache = MemoryCache(max_size_mb=memory_cache_mb)

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        return self.memory_cache.get(key)

    def put(self, key: str, value: Any, ttl_seconds: Optional[float] = None) -> bool:
        """Put value in cache."""
        return self.memory_cache.put(key, value, ttl_seconds)

    def remove(self, key: str) -> bool:
        """Remove entry from cache."""
        return self.memory_cache.remove(key)

    def clear(self):
        """Clear cache."""
        self.memory_cache.clear()

    def get_stats(self) -> Dict[str, CacheStats]:
        """Get statistics for cache."""
        return {
            "memory": self.memory_cache.get_stats(),
            "persistent": CacheStats(0, 0, 0, 0, 0.0, 0),  # Placeholder
        }


class CachedAnalyzer:
    """Analyzer wrapper that adds caching to analysis operations."""

    def __init__(self, cache: Optional[Union[MemoryCache, HybridCache]] = None):
        self.cache = cache or HybridCache()

    def cached_analysis(self, cache_key: str, analysis_func, *args, **kwargs):
        """Perform cached analysis."""
        # Try to get from cache
        result = self.cache.get(cache_key)
        if result is not None:
            logger.debug(f"Cache hit for {cache_key}")
            return result

        # Perform analysis
        logger.debug(f"Cache miss for {cache_key}")
        result = analysis_func(*args, **kwargs)

        # Store in cache
        self.cache.put(cache_key, result)

        return result


# Example usage
if __name__ == "__main__":
    # Test memory cache
    cache = MemoryCache(max_size_mb=10)

    # Test basic operations
    cache.put("test_key", {"data": "test_value", "number": 42})
    result = cache.get("test_key")
    print(f"Cache result: {result}")

    # Test stats
    stats = cache.get_stats()
    print(f"Cache stats: entries={stats.total_entries}, hit_rate={stats.hit_rate:.2f}")

    # Test hybrid cache
    hybrid = HybridCache(memory_cache_mb=5)
    hybrid.put("hybrid_key", {"test": "data"})
    result = hybrid.get("hybrid_key")
    print(f"Hybrid cache result: {result}")
