#!/usr/bin/env python3
"""
Smart Caching System
Multi-level caching with intelligent invalidation for fingerprints and strategies.
"""

import time
import json
import hashlib
import logging
import threading
from typing import Dict, Any, Optional, List, Tuple, Set
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict
import pickle
import sqlite3
from datetime import datetime, timedelta

@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    key: str
    value: Any
    created_at: float
    last_accessed: float
    access_count: int
    ttl_seconds: Optional[float]
    tags: Set[str]
    size_bytes: int
    
    def is_expired(self) -> bool:
        """Check if the cache entry is expired."""
        if self.ttl_seconds is None:
            return False
        return time.time() - self.created_at > self.ttl_seconds
    
    def is_stale(self, max_age_seconds: float) -> bool:
        """Check if the cache entry is stale."""
        return time.time() - self.created_at > max_age_seconds

@dataclass
class CacheStats:
    """Cache statistics."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size_bytes: int = 0
    entry_count: int = 0
    
    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

class SmartCache:
    """
    Multi-level smart cache with the following features:
    - Domain-based caching
    - CDN-aware caching
    - DPI hash-based caching
    - Intelligent invalidation
    - LRU eviction
    - Persistent storage
    """
    
    def __init__(self, 
                 max_memory_mb: int = 100,
                 max_entries: int = 10000,
                 default_ttl_seconds: float = 3600,  # 1 hour
                 persistent_cache_path: Optional[str] = None):
        
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.max_entries = max_entries
        self.default_ttl_seconds = default_ttl_seconds
        self.persistent_cache_path = persistent_cache_path
        
        self.logger = logging.getLogger(__name__)
        
        # In-memory cache
        self.cache: Dict[str, CacheEntry] = {}
        self.stats = CacheStats()
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Tag-based invalidation
        self.tag_to_keys: Dict[str, Set[str]] = defaultdict(set)
        
        # Persistent cache
        self.db_connection: Optional[sqlite3.Connection] = None
        if persistent_cache_path:
            self._init_persistent_cache()
        
        # Background cleanup
        self._cleanup_thread: Optional[threading.Thread] = None
        self._cleanup_active = False
        self.start_cleanup_thread()
    
    def _init_persistent_cache(self):
        """Initialize persistent cache database."""
        try:
            self.db_connection = sqlite3.connect(
                self.persistent_cache_path, 
                check_same_thread=False
            )
            
            # Create tables
            self.db_connection.execute("""
                CREATE TABLE IF NOT EXISTS cache_entries (
                    key TEXT PRIMARY KEY,
                    value BLOB,
                    created_at REAL,
                    last_accessed REAL,
                    access_count INTEGER,
                    ttl_seconds REAL,
                    tags TEXT,
                    size_bytes INTEGER
                )
            """)
            
            self.db_connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_created_at ON cache_entries(created_at)
            """)
            
            self.db_connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_last_accessed ON cache_entries(last_accessed)
            """)
            
            self.db_connection.commit()
            self.logger.info(f"Persistent cache initialized at {self.persistent_cache_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize persistent cache: {e}")
            self.db_connection = None
    
    def start_cleanup_thread(self):
        """Start background cleanup thread."""
        if self._cleanup_active:
            return
            
        self._cleanup_active = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True
        )
        self._cleanup_thread.start()
    
    def stop_cleanup_thread(self):
        """Stop background cleanup thread."""
        self._cleanup_active = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5.0)
    
    def _cleanup_loop(self):
        """Background cleanup loop."""
        while self._cleanup_active:
            try:
                self._cleanup_expired()
                self._enforce_limits()
                time.sleep(300)  # Cleanup every 5 minutes
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")
                time.sleep(60)
    
    def _cleanup_expired(self):
        """Remove expired entries."""
        with self.lock:
            expired_keys = [
                key for key, entry in self.cache.items()
                if entry.is_expired()
            ]
            
            for key in expired_keys:
                self._remove_entry(key)
                self.stats.evictions += 1
            
            if expired_keys:
                self.logger.debug(f"Cleaned up {len(expired_keys)} expired entries")
    
    def _enforce_limits(self):
        """Enforce memory and entry count limits using LRU eviction."""
        with self.lock:
            # Check if we need to evict
            if (self.stats.size_bytes <= self.max_memory_bytes and 
                self.stats.entry_count <= self.max_entries):
                return
            
            # Sort by last accessed time (LRU)
            entries_by_access = sorted(
                self.cache.items(),
                key=lambda x: x[1].last_accessed
            )
            
            # Evict oldest entries
            evicted = 0
            for key, entry in entries_by_access:
                if (self.stats.size_bytes <= self.max_memory_bytes * 0.8 and
                    self.stats.entry_count <= self.max_entries * 0.8):
                    break
                
                self._remove_entry(key)
                self.stats.evictions += 1
                evicted += 1
            
            if evicted > 0:
                self.logger.debug(f"Evicted {evicted} entries to enforce limits")
    
    def _remove_entry(self, key: str):
        """Remove an entry from cache and update stats."""
        if key not in self.cache:
            return
        
        entry = self.cache[key]
        
        # Update stats
        self.stats.size_bytes -= entry.size_bytes
        self.stats.entry_count -= 1
        
        # Remove from tag mappings
        for tag in entry.tags:
            self.tag_to_keys[tag].discard(key)
            if not self.tag_to_keys[tag]:
                del self.tag_to_keys[tag]
        
        # Remove from cache
        del self.cache[key]
    
    def _calculate_size(self, value: Any) -> int:
        """Calculate approximate size of a value in bytes."""
        try:
            return len(pickle.dumps(value))
        except:
            # Fallback estimation
            if isinstance(value, str):
                return len(value.encode('utf-8'))
            elif isinstance(value, (int, float)):
                return 8
            elif isinstance(value, dict):
                return sum(self._calculate_size(k) + self._calculate_size(v) 
                          for k, v in value.items())
            elif isinstance(value, (list, tuple)):
                return sum(self._calculate_size(item) for item in value)
            else:
                return 1024  # Default estimate
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self.lock:
            if key not in self.cache:
                # Try persistent cache
                value = self._get_from_persistent(key)
                if value is not None:
                    return value
                
                self.stats.misses += 1
                return None
            
            entry = self.cache[key]
            
            # Check if expired
            if entry.is_expired():
                self._remove_entry(key)
                self.stats.misses += 1
                return None
            
            # Update access stats
            entry.last_accessed = time.time()
            entry.access_count += 1
            
            self.stats.hits += 1
            return entry.value
    
    def put(self, key: str, value: Any, ttl_seconds: Optional[float] = None, tags: Optional[Set[str]] = None):
        """Put value in cache."""
        if ttl_seconds is None:
            ttl_seconds = self.default_ttl_seconds
        
        if tags is None:
            tags = set()
        
        size_bytes = self._calculate_size(value)
        now = time.time()
        
        with self.lock:
            # Remove existing entry if present
            if key in self.cache:
                self._remove_entry(key)
            
            # Create new entry
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=now,
                last_accessed=now,
                access_count=1,
                ttl_seconds=ttl_seconds,
                tags=tags,
                size_bytes=size_bytes
            )
            
            # Add to cache
            self.cache[key] = entry
            
            # Update stats
            self.stats.size_bytes += size_bytes
            self.stats.entry_count += 1
            
            # Update tag mappings
            for tag in tags:
                self.tag_to_keys[tag].add(key)
            
            # Store in persistent cache
            self._put_to_persistent(entry)
            
            # Enforce limits
            if (self.stats.size_bytes > self.max_memory_bytes or
                self.stats.entry_count > self.max_entries):
                self._enforce_limits()
    
    def _get_from_persistent(self, key: str) -> Optional[Any]:
        """Get value from persistent cache."""
        if not self.db_connection:
            return None
        
        try:
            cursor = self.db_connection.execute(
                "SELECT value, created_at, ttl_seconds FROM cache_entries WHERE key = ?",
                (key,)
            )
            row = cursor.fetchone()
            
            if not row:
                return None
            
            value_blob, created_at, ttl_seconds = row
            
            # Check if expired
            if ttl_seconds and time.time() - created_at > ttl_seconds:
                self.db_connection.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                self.db_connection.commit()
                return None
            
            # Update access time
            self.db_connection.execute(
                "UPDATE cache_entries SET last_accessed = ?, access_count = access_count + 1 WHERE key = ?",
                (time.time(), key)
            )
            self.db_connection.commit()
            
            return pickle.loads(value_blob)
            
        except Exception as e:
            self.logger.error(f"Error reading from persistent cache: {e}")
            return None
    
    def _put_to_persistent(self, entry: CacheEntry):
        """Store entry in persistent cache."""
        if not self.db_connection:
            return
        
        try:
            value_blob = pickle.dumps(entry.value)
            tags_str = json.dumps(list(entry.tags))
            
            self.db_connection.execute("""
                INSERT OR REPLACE INTO cache_entries 
                (key, value, created_at, last_accessed, access_count, ttl_seconds, tags, size_bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.key, value_blob, entry.created_at, entry.last_accessed,
                entry.access_count, entry.ttl_seconds, tags_str, entry.size_bytes
            ))
            self.db_connection.commit()
            
        except Exception as e:
            self.logger.error(f"Error writing to persistent cache: {e}")
    
    def invalidate_by_tag(self, tag: str):
        """Invalidate all entries with the specified tag."""
        with self.lock:
            if tag not in self.tag_to_keys:
                return
            
            keys_to_remove = list(self.tag_to_keys[tag])
            for key in keys_to_remove:
                self._remove_entry(key)
            
            # Also remove from persistent cache
            if self.db_connection:
                try:
                    self.db_connection.execute(
                        "DELETE FROM cache_entries WHERE tags LIKE ?",
                        (f'%"{tag}"%',)
                    )
                    self.db_connection.commit()
                except Exception as e:
                    self.logger.error(f"Error invalidating persistent cache by tag: {e}")
            
            self.logger.debug(f"Invalidated {len(keys_to_remove)} entries with tag '{tag}'")
    
    def invalidate_by_pattern(self, pattern: str):
        """Invalidate all entries whose keys match the pattern."""
        import fnmatch
        
        with self.lock:
            keys_to_remove = [
                key for key in self.cache.keys()
                if fnmatch.fnmatch(key, pattern)
            ]
            
            for key in keys_to_remove:
                self._remove_entry(key)
            
            self.logger.debug(f"Invalidated {len(keys_to_remove)} entries matching pattern '{pattern}'")
    
    def clear(self):
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            self.tag_to_keys.clear()
            self.stats = CacheStats()
            
            if self.db_connection:
                try:
                    self.db_connection.execute("DELETE FROM cache_entries")
                    self.db_connection.commit()
                except Exception as e:
                    self.logger.error(f"Error clearing persistent cache: {e}")
    
    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        return self.stats
    
    def get_info(self) -> Dict[str, Any]:
        """Get detailed cache information."""
        with self.lock:
            return {
                "stats": asdict(self.stats),
                "memory_usage_mb": self.stats.size_bytes / 1024 / 1024,
                "memory_limit_mb": self.max_memory_bytes / 1024 / 1024,
                "entry_count": self.stats.entry_count,
                "entry_limit": self.max_entries,
                "tag_count": len(self.tag_to_keys),
                "persistent_cache_enabled": self.db_connection is not None
            }

class FingerprintCache(SmartCache):
    """Specialized cache for fingerprinting results."""
    
    def __init__(self, **kwargs):
        super().__init__(default_ttl_seconds=7200, **kwargs)  # 2 hours default TTL
    
    def get_fingerprint(self, domain: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """Get fingerprint for domain:port."""
        key = f"fingerprint:{domain}:{port}"
        return self.get(key)
    
    def put_fingerprint(self, domain: str, port: int, fingerprint: Dict[str, Any], 
                       confidence: float = 1.0):
        """Store fingerprint with appropriate tags and TTL."""
        key = f"fingerprint:{domain}:{port}"
        
        # Create tags for intelligent invalidation
        tags = {
            f"domain:{domain}",
            f"port:{port}",
            "fingerprint"
        }
        
        # Extract CDN info if available
        if "cdn_provider" in fingerprint:
            tags.add(f"cdn:{fingerprint['cdn_provider']}")
        
        # Extract DPI type if available
        if "dpi_type" in fingerprint:
            tags.add(f"dpi_type:{fingerprint['dpi_type']}")
        
        # Adjust TTL based on confidence
        if confidence > 0.8:
            ttl = 7200  # 2 hours for high confidence
        elif confidence > 0.5:
            ttl = 3600  # 1 hour for medium confidence
        else:
            ttl = 1800  # 30 minutes for low confidence
        
        self.put(key, fingerprint, ttl_seconds=ttl, tags=tags)
    
    def invalidate_domain(self, domain: str):
        """Invalidate all fingerprints for a domain."""
        self.invalidate_by_tag(f"domain:{domain}")
    
    def invalidate_cdn(self, cdn_provider: str):
        """Invalidate all fingerprints for a CDN provider."""
        self.invalidate_by_tag(f"cdn:{cdn_provider}")

class StrategyCache(SmartCache):
    """Specialized cache for strategy results."""
    
    def __init__(self, **kwargs):
        super().__init__(default_ttl_seconds=1800, **kwargs)  # 30 minutes default TTL
    
    def get_strategy_result(self, domain: str, strategy_hash: str) -> Optional[Dict[str, Any]]:
        """Get strategy result for domain and strategy."""
        key = f"strategy:{domain}:{strategy_hash}"
        return self.get(key)
    
    def put_strategy_result(self, domain: str, strategy_hash: str, result: Dict[str, Any]):
        """Store strategy result."""
        key = f"strategy:{domain}:{strategy_hash}"
        
        tags = {
            f"domain:{domain}",
            f"strategy:{strategy_hash}",
            "strategy_result"
        }
        
        # Adjust TTL based on success
        success_rate = result.get("success_rate", 0)
        if success_rate > 0.8:
            ttl = 3600  # 1 hour for successful strategies
        elif success_rate > 0.3:
            ttl = 1800  # 30 minutes for partially successful
        else:
            ttl = 600   # 10 minutes for failed strategies
        
        self.put(key, result, ttl_seconds=ttl, tags=tags)

# Global cache instances
_fingerprint_cache: Optional[FingerprintCache] = None
_strategy_cache: Optional[StrategyCache] = None

def get_fingerprint_cache() -> FingerprintCache:
    """Get global fingerprint cache instance."""
    global _fingerprint_cache
    if _fingerprint_cache is None:
        cache_dir = Path("recon/cache")
        cache_dir.mkdir(exist_ok=True)
        _fingerprint_cache = FingerprintCache(
            persistent_cache_path=str(cache_dir / "fingerprints.db")
        )
    return _fingerprint_cache

def get_strategy_cache() -> StrategyCache:
    """Get global strategy cache instance."""
    global _strategy_cache
    if _strategy_cache is None:
        cache_dir = Path("recon/cache")
        cache_dir.mkdir(exist_ok=True)
        _strategy_cache = StrategyCache(
            persistent_cache_path=str(cache_dir / "strategies.db")
        )
    return _strategy_cache