"""
Performance caching components for runtime packet filtering.

This module provides LRU caching, TTL management, and cache statistics
for optimizing domain extraction and pattern matching performance.
"""

import time
import threading
from typing import Any, Dict, Optional, Tuple
from collections import OrderedDict


class LRUCache:
    """
    Thread-safe LRU cache with TTL support and statistics.

    This cache provides:
    - Least Recently Used eviction policy
    - Time-to-live (TTL) expiration
    - Thread-safe operations
    - Cache statistics for monitoring
    """

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 300):
        """
        Initialize LRU Cache.

        Args:
            max_size: Maximum number of items to cache
            ttl_seconds: Time-to-live for cache entries in seconds

        Requirements: 6.3, 6.4
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache = OrderedDict()  # key -> (value, timestamp)
        self._lock = threading.RLock()

        # Statistics
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._expirations = 0

    def get(self, key: Any) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None

            value, timestamp = self._cache[key]

            # Check TTL expiration
            if self._is_expired(timestamp):
                del self._cache[key]
                self._expirations += 1
                self._misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._hits += 1
            return value

    def put(self, key: Any, value: Any) -> None:
        """
        Put value in cache with memory-aware eviction.

        Args:
            key: Cache key
            value: Value to cache
        """
        with self._lock:
            current_time = time.time()

            if key in self._cache:
                # Update existing entry
                self._cache[key] = (value, current_time)
                self._cache.move_to_end(key)
            else:
                # Check if we need to make room
                while len(self._cache) >= self.max_size:
                    self._cache.popitem(last=False)  # Remove oldest
                    self._evictions += 1

                # Add new entry
                self._cache[key] = (value, current_time)

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()

    def cleanup_expired(self) -> int:
        """
        Remove expired entries from cache.

        Returns:
            Number of entries removed
        """
        with self._lock:
            expired_keys = []
            current_time = time.time()

            for key, (value, timestamp) in self._cache.items():
                if self._is_expired(timestamp, current_time):
                    expired_keys.append(key)

            for key in expired_keys:
                del self._cache[key]
                self._expirations += 1

            return len(expired_keys)

    def _is_expired(self, timestamp: float, current_time: Optional[float] = None) -> bool:
        """Check if timestamp is expired based on TTL."""
        if current_time is None:
            current_time = time.time()
        return (current_time - timestamp) > self.ttl_seconds

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests) if total_requests > 0 else 0.0

            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": hit_rate,
                "evictions": self._evictions,
                "expirations": self._expirations,
                "ttl_seconds": self.ttl_seconds,
            }


class PatternCache:
    """
    Cache for compiled regex patterns with lazy compilation.

    This cache provides:
    - Lazy compilation of regex patterns
    - Thread-safe pattern storage
    - Pattern validation and error handling
    """

    def __init__(self):
        """Initialize Pattern Cache."""
        self._patterns = {}  # pattern_string -> compiled_pattern
        self._lock = threading.RLock()
        self._compilation_errors = {}  # pattern_string -> error_message

    def get_compiled_pattern(self, pattern_string: str):
        """
        Get compiled regex pattern, compiling if necessary.

        Args:
            pattern_string: Regex pattern string

        Returns:
            Compiled regex pattern or None if compilation failed
        """
        import re

        with self._lock:
            # Return cached pattern if available
            if pattern_string in self._patterns:
                return self._patterns[pattern_string]

            # Check if compilation previously failed
            if pattern_string in self._compilation_errors:
                return None

            try:
                # Compile pattern
                compiled_pattern = re.compile(pattern_string, re.IGNORECASE)
                self._patterns[pattern_string] = compiled_pattern
                return compiled_pattern

            except re.error as e:
                # Cache compilation error
                self._compilation_errors[pattern_string] = str(e)
                return None

    def clear(self) -> None:
        """Clear all cached patterns."""
        with self._lock:
            self._patterns.clear()
            self._compilation_errors.clear()

    def get_statistics(self) -> Dict[str, Any]:
        """Get pattern cache statistics."""
        with self._lock:
            return {
                "compiled_patterns": len(self._patterns),
                "compilation_errors": len(self._compilation_errors),
            }


class CacheManager:
    """
    Manager for all caching components with cleanup and monitoring.

    This manager provides:
    - Centralized cache management
    - Periodic cleanup of expired entries
    - Unified statistics collection
    """

    def __init__(self):
        """Initialize Cache Manager."""
        self.domain_cache = LRUCache(max_size=1000, ttl_seconds=300)
        self.pattern_cache = PatternCache()
        self._cleanup_interval = 60  # seconds
        self._last_cleanup = time.time()

    def maybe_cleanup(self) -> None:
        """
        Perform cleanup if enough time has passed or cache is full.

        Requirements: 6.4
        """
        current_time = time.time()

        # Check if cleanup is needed due to time or cache size
        time_based_cleanup = (current_time - self._last_cleanup) >= self._cleanup_interval
        size_based_cleanup = len(self.domain_cache._cache) >= (self.domain_cache.max_size * 0.9)

        if time_based_cleanup or size_based_cleanup:
            self.cleanup()
            self._last_cleanup = current_time

    def cleanup(self) -> Dict[str, int]:
        """
        Perform cleanup of all caches.

        Returns:
            Dictionary with cleanup statistics
        """
        expired_count = self.domain_cache.cleanup_expired()

        return {"expired_domains": expired_count, "cleanup_time": time.time()}

    def clear_all(self) -> None:
        """Clear all caches."""
        self.domain_cache.clear()
        self.pattern_cache.clear()

    def get_all_statistics(self) -> Dict[str, Any]:
        """
        Get statistics from all caches.

        Returns:
            Dictionary with all cache statistics
        """
        return {
            "domain_cache": self.domain_cache.get_statistics(),
            "pattern_cache": self.pattern_cache.get_statistics(),
            "last_cleanup": self._last_cleanup,
            "cleanup_interval": self._cleanup_interval,
        }
