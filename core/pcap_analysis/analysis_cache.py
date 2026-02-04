"""
Analysis caching system for PCAP analysis.
Implements intelligent caching to avoid repeated computations and improve performance.
"""

import hashlib
import json
import pickle
import sqlite3
import time
import logging
import os
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path
from functools import wraps
import threading

from .packet_info import PacketInfo
from .comparison_result import ComparisonResult

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Cache entry metadata."""

    key: str
    value_hash: str
    created_at: float
    last_accessed: float
    access_count: int
    size_bytes: int
    ttl_seconds: Optional[float] = None


@dataclass
class CacheStats:
    """Cache statistics."""

    total_entries: int
    total_size_bytes: int
    hit_count: int
    miss_count: int
    hit_rate: float
    eviction_count: int


class CacheKeyGenerator:
    """Generates consistent cache keys for different types of analysis."""

    @staticmethod
    def pcap_file_key(pcap_file: str) -> str:
        """Generate cache key for PCAP file analysis."""
        # Include file path, size, and modification time
        try:
            stat = os.stat(pcap_file)
            key_data = {
                "file_path": os.path.abspath(pcap_file),
                "file_size": stat.st_size,
                "modified_time": stat.st_mtime,
            }
            return hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()
        except OSError:
            # Fallback to just file path if stat fails
            return hashlib.sha256(pcap_file.encode()).hexdigest()

    @staticmethod
    def packet_analysis_key(packets: List[PacketInfo], analysis_type: str) -> str:
        """Generate cache key for packet analysis."""
        # Create a hash based on packet characteristics
        packet_hashes = []
        for packet in packets[:100]:  # Sample first 100 packets for performance
            packet_data = (
                f"{packet.timestamp}_{packet.src_ip}_{packet.dst_ip}_{packet.sequence_num}"
            )
            packet_hashes.append(hashlib.md5(packet_data.encode()).hexdigest()[:8])

        key_data = {
            "analysis_type": analysis_type,
            "packet_count": len(packets),
            "packet_sample_hash": "".join(packet_hashes),
        }
        return hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def comparison_key(recon_pcap: str, zapret_pcap: str, comparison_type: str = "full") -> str:
        """Generate cache key for PCAP comparison."""
        recon_key = CacheKeyGenerator.pcap_file_key(recon_pcap)
        zapret_key = CacheKeyGenerator.pcap_file_key(zapret_pcap)

        key_data = {
            "comparison_type": comparison_type,
            "recon_key": recon_key,
            "zapret_key": zapret_key,
        }
        return hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def strategy_analysis_key(strategy_config: Dict[str, Any]) -> str:
        """Generate cache key for strategy analysis."""
        return hashlib.sha256(json.dumps(strategy_config, sort_keys=True).encode()).hexdigest()


class MemoryCache:
    """In-memory cache with LRU eviction and TTL support."""

    def __init__(self, max_size_mb: int = 256, default_ttl_seconds: Optional[float] = 3600):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.default_ttl_seconds = default_ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._metadata: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        self._stats = CacheStats(0, 0, 0, 0, 0.0, 0)

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self._lock:
            if key not in self._cache:
                self._stats.miss_count += 1
                self._update_hit_rate()
                return None

            # Check TTL
            metadata = self._metadata[key]
            current_time = time.time()

            if (
                metadata.ttl_seconds is not None
                and current_time - metadata.created_at > metadata.ttl_seconds
            ):
                # Entry expired
                self._remove_entry(key)
                self._stats.miss_count += 1
                self._update_hit_rate()
                return None

            # Update access metadata
            metadata.last_accessed = current_time
            metadata.access_count += 1

            self._stats.hit_count += 1
            self._update_hit_rate()

            return self._cache[key]

    def put(self, key: str, value: Any, ttl_seconds: Optional[float] = None) -> bool:
        """Put value in cache."""
        with self._lock:
            # Calculate value size
            try:
                value_bytes = pickle.dumps(value)
                size_bytes = len(value_bytes)
            except Exception as e:
                logger.warning(f"Cannot serialize value for caching: {e}")
                return False

            # Check if we need to evict entries
            if not self._ensure_space(size_bytes):
                logger.warning(f"Cannot cache entry of size {size_bytes} bytes")
                return False

            # Create cache entry
            current_time = time.time()
            ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds

            metadata = CacheEntry(
                key=key,
                value_hash=hashlib.md5(value_bytes).hexdigest(),
                created_at=current_time,
                last_accessed=current_time,
                access_count=1,
                size_bytes=size_bytes,
                ttl_seconds=ttl,
            )

            # Remove existing entry if present
            if key in self._cache:
                self._remove_entry(key)

            # Add new entry
            self._cache[key] = value
            self._metadata[key] = metadata

            self._stats.total_entries += 1
            self._stats.total_size_bytes += size_bytes

            return True

    def remove(self, key: str) -> bool:
        """Remove entry from cache."""
        with self._lock:
            if key in self._cache:
                self._remove_entry(key)
                return True
            return False

    def clear(self):
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self._metadata.clear()
            self._stats = CacheStats(
                0,
                0,
                self._stats.hit_count,
                self._stats.miss_count,
                self._stats.hit_rate,
                self._stats.eviction_count,
            )

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
        while self._stats.total_size_bytes + required_bytes > self.max_size_bytes and self._cache:
            self._evict_lru_entry()

        return True

    def _evict_lru_entry(self):
        """Evict least recently used entry."""
        if not self._metadata:
            return

        # Find LRU entry
        lru_key = min(self._metadata.keys(), key=lambda k: self._metadata[k].last_accessed)

        self._remove_entry(lru_key)
        self._stats.eviction_count += 1

    def _remove_entry(self, key: str):
        """Remove entry and update stats."""
        if key in self._cache:
            metadata = self._metadata[key]
            del self._cache[key]
            del self._metadata[key]
            self._stats.total_entries -= 1
            self._stats.total_size_bytes -= metadata.size_bytes

    def _update_hit_rate(self):
        """Update hit rate statistic."""
        total_requests = self._stats.hit_count + self._stats.miss_count
        if total_requests > 0:
            self._stats.hit_rate = self._stats.hit_count / total_requests


class PersistentCache:
    """Persistent cache using SQLite for storage."""

    def __init__(self, cache_dir: str = ".cache", max_size_mb: int = 1024):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.db_path = self.cache_dir / "analysis_cache.db"
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._lock = threading.RLock()

        self._init_database()

    def _init_database(self):
        """Initialize SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache_entries (
                    key TEXT PRIMARY KEY,
                    value_hash TEXT NOT NULL,
                    data BLOB NOT NULL,
                    created_at REAL NOT NULL,
                    last_accessed REAL NOT NULL,
                    access_count INTEGER NOT NULL DEFAULT 1,
                    size_bytes INTEGER NOT NULL,
                    ttl_seconds REAL
                )
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_last_accessed 
                ON cache_entries(last_accessed)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_created_at 
                ON cache_entries(created_at)
            """
            )

    def get(self, key: str) -> Optional[Any]:
        """Get value from persistent cache."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute(
                        """
                        SELECT data, created_at, ttl_seconds, access_count
                        FROM cache_entries WHERE key = ?
                    """,
                        (key,),
                    )

                    row = cursor.fetchone()
                    if not row:
                        return None

                    data_blob, created_at, ttl_seconds, access_count = row
                    current_time = time.time()

                    # Check TTL
                    if ttl_seconds is not None and current_time - created_at > ttl_seconds:
                        # Entry expired, remove it
                        conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                        return None

                    # Update access metadata
                    conn.execute(
                        """
                        UPDATE cache_entries 
                        SET last_accessed = ?, access_count = access_count + 1
                        WHERE key = ?
                    """,
                        (current_time, key),
                    )

                    # Deserialize and return data
                    return pickle.loads(data_blob)

            except Exception as e:
                logger.error(f"Error reading from persistent cache: {e}")
                return None

    def put(self, key: str, value: Any, ttl_seconds: Optional[float] = None) -> bool:
        """Put value in persistent cache."""
        with self._lock:
            try:
                # Serialize value
                data_blob = pickle.dumps(value)
                size_bytes = len(data_blob)
                value_hash = hashlib.md5(data_blob).hexdigest()
                current_time = time.time()

                # Ensure space
                if not self._ensure_space(size_bytes):
                    return False

                with sqlite3.connect(self.db_path) as conn:
                    # Insert or replace entry
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO cache_entries 
                        (key, value_hash, data, created_at, last_accessed, 
                         access_count, size_bytes, ttl_seconds)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            key,
                            value_hash,
                            data_blob,
                            current_time,
                            current_time,
                            1,
                            size_bytes,
                            ttl_seconds,
                        ),
                    )

                return True

            except Exception as e:
                logger.error(f"Error writing to persistent cache: {e}")
                return False

    def remove(self, key: str) -> bool:
        """Remove entry from persistent cache."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                    return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Error removing from persistent cache: {e}")
                return False

    def clear(self):
        """Clear all cache entries."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("DELETE FROM cache_entries")
            except Exception as e:
                logger.error(f"Error clearing persistent cache: {e}")

    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute(
                        """
                        SELECT 
                            COUNT(*) as total_entries,
                            SUM(size_bytes) as total_size_bytes,
                            SUM(access_count) as total_accesses
                        FROM cache_entries
                    """
                    )

                    row = cursor.fetchone()
                    if row:
                        total_entries, total_size_bytes, total_accesses = row
                        return CacheStats(
                            total_entries=total_entries or 0,
                            total_size_bytes=total_size_bytes or 0,
                            hit_count=0,  # Not tracked in persistent cache
                            miss_count=0,
                            hit_rate=0.0,
                            eviction_count=0,
                        )

            except Exception as e:
                logger.error(f"Error getting cache stats: {e}")

        return CacheStats(0, 0, 0, 0, 0.0, 0)

    def _ensure_space(self, required_bytes: int) -> bool:
        """Ensure there's enough space for new entry."""
        if required_bytes > self.max_size_bytes:
            return False

        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get current size
                cursor = conn.execute("SELECT SUM(size_bytes) FROM cache_entries")
                current_size = cursor.fetchone()[0] or 0

                # Evict entries if necessary
                while current_size + required_bytes > self.max_size_bytes:
                    # Remove oldest entry
                    cursor = conn.execute(
                        """
                        DELETE FROM cache_entries 
                        WHERE key = (
                            SELECT key FROM cache_entries 
                            ORDER BY last_accessed ASC 
                            LIMIT 1
                        )
                    """
                    )

                    if cursor.rowcount == 0:
                        break  # No more entries to remove

                    # Recalculate current size
                    cursor = conn.execute("SELECT SUM(size_bytes) FROM cache_entries")
                    current_size = cursor.fetchone()[0] or 0

            return True

        except Exception as e:
            logger.error(f"Error ensuring cache space: {e}")
            return False


class HybridCache:
    """Hybrid cache that combines memory and persistent caching."""

    def __init__(
        self,
        memory_cache_mb: int = 128,
        persistent_cache_mb: int = 512,
        cache_dir: str = ".cache",
    ):
        self.memory_cache = MemoryCache(max_size_mb=memory_cache_mb)
        self.persistent_cache = PersistentCache(
            cache_dir=cache_dir, max_size_mb=persistent_cache_mb
        )

    def get(self, key: str) -> Optional[Any]:
        """Get value from hybrid cache (memory first, then persistent)."""
        # Try memory cache first
        value = self.memory_cache.get(key)
        if value is not None:
            return value

        # Try persistent cache
        value = self.persistent_cache.get(key)
        if value is not None:
            # Promote to memory cache
            self.memory_cache.put(key, value)
            return value

        return None

    def put(self, key: str, value: Any, ttl_seconds: Optional[float] = None) -> bool:
        """Put value in hybrid cache."""
        # Store in both caches
        memory_success = self.memory_cache.put(key, value, ttl_seconds)
        persistent_success = self.persistent_cache.put(key, value, ttl_seconds)

        return memory_success or persistent_success

    def remove(self, key: str) -> bool:
        """Remove entry from both caches."""
        memory_removed = self.memory_cache.remove(key)
        persistent_removed = self.persistent_cache.remove(key)
        return memory_removed or persistent_removed

    def clear(self):
        """Clear both caches."""
        self.memory_cache.clear()
        self.persistent_cache.clear()

    def get_stats(self) -> Dict[str, CacheStats]:
        """Get statistics for both caches."""
        return {
            "memory": self.memory_cache.get_stats(),
            "persistent": self.persistent_cache.get_stats(),
        }


class CachedAnalyzer:
    """Analyzer wrapper that adds caching to analysis operations."""

    def __init__(self, cache: Optional[Union[MemoryCache, PersistentCache, HybridCache]] = None):
        self.cache = cache or HybridCache()

    def cached_pcap_analysis(
        self,
        pcap_file: str,
        analysis_func: Callable,
        ttl_seconds: Optional[float] = 3600,
    ) -> Any:
        """Perform cached PCAP analysis."""
        # Generate cache key
        cache_key = (
            f"pcap_analysis_{CacheKeyGenerator.pcap_file_key(pcap_file)}_{analysis_func.__name__}"
        )

        # Try to get from cache
        result = self.cache.get(cache_key)
        if result is not None:
            logger.debug(f"Cache hit for PCAP analysis: {pcap_file}")
            return result

        # Perform analysis
        logger.debug(f"Cache miss for PCAP analysis: {pcap_file}")
        result = analysis_func(pcap_file)

        # Store in cache
        self.cache.put(cache_key, result, ttl_seconds)

        return result

    def cached_packet_analysis(
        self,
        packets: List[PacketInfo],
        analysis_func: Callable,
        analysis_type: str,
        ttl_seconds: Optional[float] = 1800,
    ) -> Any:
        """Perform cached packet analysis."""
        # Generate cache key
        cache_key = (
            f"packet_analysis_{CacheKeyGenerator.packet_analysis_key(packets, analysis_type)}"
        )

        # Try to get from cache
        result = self.cache.get(cache_key)
        if result is not None:
            logger.debug(f"Cache hit for packet analysis: {analysis_type}")
            return result

        # Perform analysis
        logger.debug(f"Cache miss for packet analysis: {analysis_type}")
        result = analysis_func(packets)

        # Store in cache
        self.cache.put(cache_key, result, ttl_seconds)

        return result

    def cached_comparison(
        self,
        recon_pcap: str,
        zapret_pcap: str,
        comparison_func: Callable,
        ttl_seconds: Optional[float] = 3600,
    ) -> ComparisonResult:
        """Perform cached PCAP comparison."""
        # Generate cache key
        cache_key = f"comparison_{CacheKeyGenerator.comparison_key(recon_pcap, zapret_pcap)}"

        # Try to get from cache
        result = self.cache.get(cache_key)
        if result is not None:
            logger.debug(f"Cache hit for PCAP comparison: {recon_pcap} vs {zapret_pcap}")
            return result

        # Perform comparison
        logger.debug(f"Cache miss for PCAP comparison: {recon_pcap} vs {zapret_pcap}")
        result = comparison_func(recon_pcap, zapret_pcap)

        # Store in cache
        self.cache.put(cache_key, result, ttl_seconds)

        return result


def cached_analysis(cache_key_func: Callable = None, ttl_seconds: float = 3600):
    """Decorator for caching analysis functions."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get or create cache
            if not hasattr(wrapper, "_cache"):
                wrapper._cache = HybridCache()

            # Generate cache key
            if cache_key_func:
                cache_key = cache_key_func(*args, **kwargs)
            else:
                # Default key generation
                key_data = f"{func.__name__}_{str(args)}_{str(sorted(kwargs.items()))}"
                cache_key = hashlib.sha256(key_data.encode()).hexdigest()

            # Try to get from cache
            result = wrapper._cache.get(cache_key)
            if result is not None:
                logger.debug(f"Cache hit for {func.__name__}")
                return result

            # Execute function
            logger.debug(f"Cache miss for {func.__name__}")
            result = func(*args, **kwargs)

            # Store in cache
            wrapper._cache.put(cache_key, result, ttl_seconds)

            return result

        return wrapper

    return decorator


# Example usage and testing
if __name__ == "__main__":
    # Test memory cache
    memory_cache = MemoryCache(max_size_mb=10)

    # Test basic operations
    memory_cache.put("test_key", {"data": "test_value", "number": 42})
    result = memory_cache.get("test_key")
    print(f"Memory cache result: {result}")

    # Test cache stats
    stats = memory_cache.get_stats()
    print(f"Memory cache stats: {asdict(stats)}")

    # Test persistent cache
    persistent_cache = PersistentCache(cache_dir=".test_cache", max_size_mb=50)

    persistent_cache.put("persistent_key", {"analysis": "result", "timestamp": time.time()})
    result = persistent_cache.get("persistent_key")
    print(f"Persistent cache result: {result}")

    # Test hybrid cache
    hybrid_cache = HybridCache(memory_cache_mb=5, persistent_cache_mb=20)

    hybrid_cache.put("hybrid_key", {"hybrid": "data", "cached_at": time.time()})
    result = hybrid_cache.get("hybrid_key")
    print(f"Hybrid cache result: {result}")

    # Test cached analyzer
    cached_analyzer = CachedAnalyzer(hybrid_cache)

    def sample_analysis_func(data):
        return {"analyzed": data, "timestamp": time.time()}

    # Test cached analysis
    result1 = cached_analyzer.cached_packet_analysis([], sample_analysis_func, "test_analysis")
    result2 = cached_analyzer.cached_packet_analysis([], sample_analysis_func, "test_analysis")

    print(f"First analysis result: {result1}")
    print(f"Second analysis result (cached): {result2}")
    print(f"Results are identical: {result1 == result2}")

    # Clean up test cache
    import shutil

    if os.path.exists(".test_cache"):
        shutil.rmtree(".test_cache")
