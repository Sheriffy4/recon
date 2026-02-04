"""
CacheManager for Expensive Operation Caching

Provides a simplified, focused caching interface for expensive operations
like system capability checks, DNS resolutions, and configuration validations.

Requirements: 9.1 - Cache results to avoid repeated expensive operations
"""

import time
import threading
import logging
from typing import Dict, Any, Optional, Callable, TypeVar, Generic
from dataclasses import dataclass
from functools import wraps

T = TypeVar("T")


@dataclass
class CacheEntry(Generic[T]):
    """Cache entry with metadata."""

    value: T
    created_at: float
    last_accessed: float
    access_count: int
    ttl_seconds: Optional[float]

    def is_expired(self) -> bool:
        """Check if the cache entry is expired."""
        if self.ttl_seconds is None:
            return False
        return time.time() - self.created_at > self.ttl_seconds


class CacheManager:
    """
    Simple cache manager for expensive operations.

    Focused on caching system capability checks and configuration validations
    to avoid repeated expensive operations as required by Requirement 9.1.
    """

    def __init__(self, default_ttl_seconds: float = 3600):
        """
        Initialize cache manager.

        Args:
            default_ttl_seconds: Default TTL for cached entries (1 hour)
        """
        self.default_ttl_seconds = default_ttl_seconds
        self.cache: Dict[str, CacheEntry] = {}
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__)

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        with self.lock:
            if key not in self.cache:
                return None

            entry = self.cache[key]

            # Check if expired
            if entry.is_expired():
                del self.cache[key]
                return None

            # Update access stats
            entry.last_accessed = time.time()
            entry.access_count += 1

            return entry.value

    def put(self, key: str, value: Any, ttl_seconds: Optional[float] = None) -> None:
        """
        Put value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl_seconds: TTL in seconds (uses default if None)
        """
        if ttl_seconds is None:
            ttl_seconds = self.default_ttl_seconds

        now = time.time()

        with self.lock:
            entry = CacheEntry(
                value=value,
                created_at=now,
                last_accessed=now,
                access_count=1,
                ttl_seconds=ttl_seconds,
            )

            self.cache[key] = entry

    def invalidate(self, key: str) -> bool:
        """
        Invalidate a cache entry.

        Args:
            key: Cache key to invalidate

        Returns:
            True if entry was found and removed, False otherwise
        """
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()

    def cleanup_expired(self) -> int:
        """
        Remove expired entries.

        Returns:
            Number of entries removed
        """
        with self.lock:
            expired_keys = [key for key, entry in self.cache.items() if entry.is_expired()]

            for key in expired_keys:
                del self.cache[key]

            if expired_keys:
                self.logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")

            return len(expired_keys)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        with self.lock:
            total_accesses = sum(entry.access_count for entry in self.cache.values())

            return {
                "entry_count": len(self.cache),
                "total_accesses": total_accesses,
                "average_accesses": total_accesses / len(self.cache) if self.cache else 0,
            }

    def cached(self, key: Optional[str] = None, ttl_seconds: Optional[float] = None):
        """
        Decorator for caching function results.

        Args:
            key: Cache key (uses function name and args if None)
            ttl_seconds: TTL in seconds (uses default if None)

        Returns:
            Decorated function
        """

        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            @wraps(func)
            def wrapper(*args, **kwargs) -> T:
                # Generate cache key if not provided
                cache_key = key
                if cache_key is None:
                    cache_key = f"{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"

                # Try to get from cache
                cached_result = self.get(cache_key)
                if cached_result is not None:
                    return cached_result

                # Execute function and cache result
                result = func(*args, **kwargs)
                self.put(cache_key, result, ttl_seconds)

                return result

            return wrapper

        return decorator


# Global cache manager instance
_cache_manager: Optional[CacheManager] = None


def get_cache_manager() -> CacheManager:
    """Get global cache manager instance."""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager
