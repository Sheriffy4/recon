# recon/core/fingerprint/cache.py
"""
Persistent Fingerprint Caching System - Task 2 Implementation
TTL-based caching with pickle persistence and thread-safe operations.
"""

import pickle
import time
import threading
import os
from typing import Dict, Optional, Any, List
from dataclasses import dataclass
from pathlib import Path
import logging

from .advanced_models import DPIFingerprint, CacheError

logger = logging.getLogger(__name__)


@dataclass
class CachedFingerprint:
    """Container for cached fingerprint with metadata"""
    fingerprint: DPIFingerprint
    timestamp: float
    ttl: int
    access_count: int = 0
    last_access: float = 0.0
    
    def is_expired(self) -> bool:
        """Check if the cached fingerprint has expired"""
        return time.time() - self.timestamp > self.ttl
    
    def update_access(self):
        """Update access statistics"""
        self.access_count += 1
        self.last_access = time.time()
    
    def time_until_expiry(self) -> float:
        """Get seconds until expiry (negative if already expired)"""
        return (self.timestamp + self.ttl) - time.time()


class FingerprintCache:
    """
    Thread-safe persistent cache for DPI fingerprints with TTL-based expiration.
    Implements requirements 3.1, 3.2, 3.3, 3.4, 3.5 from the specification.
    """
    
    def __init__(self, 
                 cache_file: str = "dpi_fingerprint_cache.pkl", 
                 ttl: int = 3600,
                 max_entries: int = 1000,
                 cleanup_interval: int = 300,
                 auto_save: bool = True):
        """
        Initialize the fingerprint cache.
        
        Args:
            cache_file: Path to the cache file
            ttl: Default TTL in seconds (1 hour)
            max_entries: Maximum number of cache entries
            cleanup_interval: Automatic cleanup interval in seconds (5 minutes)
            auto_save: Whether to automatically save cache on modifications
        """
        self.cache_file = Path(cache_file)
        self.default_ttl = ttl
        self.max_entries = max_entries
        self.cleanup_interval = cleanup_interval
        self.auto_save = auto_save
        
        # Thread-safe cache storage
        self._cache: Dict[str, CachedFingerprint] = {}
        self._lock = threading.RLock()  # Reentrant lock for nested operations
        
        # Statistics
        self._stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'saves': 0,
            'loads': 0,
            'errors': 0
        }
        
        # Background cleanup thread
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()
        
        # Initialize cache
        self._initialize_cache()
    
    def _initialize_cache(self):
        """Initialize cache by loading from disk and starting cleanup thread"""
        try:
            self.load_cache()
            self._start_cleanup_thread()
            logger.info(f"FingerprintCache initialized with {len(self._cache)} entries")
        except Exception as e:
            logger.error(f"Failed to initialize cache: {e}")
            self._stats['errors'] += 1
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        if self.cleanup_interval > 0:
            self._cleanup_thread = threading.Thread(
                target=self._background_cleanup,
                daemon=True,
                name="FingerprintCache-Cleanup"
            )
            self._cleanup_thread.start()
    
    def _background_cleanup(self):
        """Background thread for periodic cache cleanup"""
        while not self._stop_cleanup.wait(self.cleanup_interval):
            try:
                self.cleanup_expired()
            except Exception as e:
                logger.error(f"Background cleanup error: {e}")
                self._stats['errors'] += 1
    
    def get(self, key: str) -> Optional[DPIFingerprint]:
        """
        Get fingerprint from cache.
        
        Args:
            key: Cache key (typically target domain/IP)
            
        Returns:
            DPIFingerprint if found and not expired, None otherwise
        """
        with self._lock:
            try:
                cached_item = self._cache.get(key)
                
                if cached_item is None:
                    self._stats['misses'] += 1
                    logger.debug(f"Cache miss for key: {key}")
                    return None
                
                if cached_item.is_expired():
                    logger.debug(f"Cache entry expired for key: {key}")
                    del self._cache[key]
                    self._stats['misses'] += 1
                    if self.auto_save:
                        self._save_cache_unsafe()
                    return None
                
                # Update access statistics
                cached_item.update_access()
                self._stats['hits'] += 1
                logger.debug(f"Cache hit for key: {key}")
                
                return cached_item.fingerprint
                
            except Exception as e:
                logger.error(f"Error getting cache entry for {key}: {e}")
                self._stats['errors'] += 1
                return None
    
    def set(self, key: str, fingerprint: DPIFingerprint, ttl: Optional[int] = None):
        """
        Store fingerprint in cache.
        
        Args:
            key: Cache key
            fingerprint: DPI fingerprint to cache
            ttl: Time to live in seconds (uses default if None)
        """
        if ttl is None:
            ttl = self.default_ttl
        
        with self._lock:
            try:
                # Check if we need to evict entries
                if len(self._cache) >= self.max_entries and key not in self._cache:
                    self._evict_lru()
                
                cached_item = CachedFingerprint(
                    fingerprint=fingerprint,
                    timestamp=time.time(),
                    ttl=ttl
                )
                
                self._cache[key] = cached_item
                logger.debug(f"Cached fingerprint for key: {key} (TTL: {ttl}s)")
                
                if self.auto_save:
                    self._save_cache_unsafe()
                    
            except Exception as e:
                logger.error(f"Error setting cache entry for {key}: {e}")
                self._stats['errors'] += 1
                raise CacheError(f"Failed to cache fingerprint: {e}")
    
    def invalidate(self, key: Optional[str] = None):
        """
        Invalidate cache entries.
        
        Args:
            key: Specific key to invalidate, or None to clear all
        """
        with self._lock:
            try:
                if key is None:
                    # Clear entire cache
                    count = len(self._cache)
                    self._cache.clear()
                    logger.info(f"Invalidated entire cache ({count} entries)")
                else:
                    # Remove specific key
                    if key in self._cache:
                        del self._cache[key]
                        logger.debug(f"Invalidated cache entry for key: {key}")
                    else:
                        logger.debug(f"Key not found for invalidation: {key}")
                
                if self.auto_save:
                    self._save_cache_unsafe()
                    
            except Exception as e:
                logger.error(f"Error invalidating cache: {e}")
                self._stats['errors'] += 1
                raise CacheError(f"Failed to invalidate cache: {e}")
    
    def cleanup_expired(self) -> int:
        """
        Remove expired entries from cache.
        
        Returns:
            Number of entries removed
        """
        with self._lock:
            try:
                expired_keys = []
                current_time = time.time()
                
                for key, cached_item in self._cache.items():
                    if current_time - cached_item.timestamp > cached_item.ttl:
                        expired_keys.append(key)
                
                for key in expired_keys:
                    del self._cache[key]
                
                if expired_keys:
                    logger.debug(f"Cleaned up {len(expired_keys)} expired entries")
                    if self.auto_save:
                        self._save_cache_unsafe()
                
                return len(expired_keys)
                
            except Exception as e:
                logger.error(f"Error during cleanup: {e}")
                self._stats['errors'] += 1
                return 0
    
    def _evict_lru(self):
        """Evict least recently used entry to make space"""
        if not self._cache:
            return
        
        # Find LRU entry (oldest last_access, fallback to oldest timestamp)
        lru_key = min(
            self._cache.keys(),
            key=lambda k: (
                self._cache[k].last_access or self._cache[k].timestamp,
                self._cache[k].timestamp
            )
        )
        
        del self._cache[lru_key]
        self._stats['evictions'] += 1
        logger.debug(f"Evicted LRU entry: {lru_key}")
    
    def save_cache(self):
        """Manually save cache to disk"""
        with self._lock:
            self._save_cache_unsafe()
    
    def _save_cache_unsafe(self):
        """Save cache to disk (not thread-safe, must be called within lock)"""
        try:
            # Create directory if it doesn't exist
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Create temporary file for atomic write
            temp_file = self.cache_file.with_suffix('.tmp')
            
            with open(temp_file, 'wb') as f:
                pickle.dump(self._cache, f, protocol=pickle.HIGHEST_PROTOCOL)
            
            # Atomic rename
            temp_file.replace(self.cache_file)
            self._stats['saves'] += 1
            logger.debug(f"Cache saved to {self.cache_file}")
            
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
            self._stats['errors'] += 1
            raise CacheError(f"Failed to save cache: {e}")
    
    def load_cache(self):
        """Load cache from disk"""
        with self._lock:
            try:
                if not self.cache_file.exists():
                    logger.debug("Cache file does not exist, starting with empty cache")
                    return
                
                with open(self.cache_file, 'rb') as f:
                    loaded_cache = pickle.load(f)
                
                # Validate loaded data
                if not isinstance(loaded_cache, dict):
                    raise CacheError("Invalid cache file format")
                
                # Filter out expired entries during load
                current_time = time.time()
                valid_entries = {}
                
                for key, cached_item in loaded_cache.items():
                    if isinstance(cached_item, CachedFingerprint):
                        if current_time - cached_item.timestamp <= cached_item.ttl:
                            valid_entries[key] = cached_item
                        else:
                            logger.debug(f"Skipping expired entry during load: {key}")
                    else:
                        logger.warning(f"Invalid cache entry format for key: {key}")
                
                self._cache = valid_entries
                self._stats['loads'] += 1
                logger.info(f"Loaded {len(self._cache)} valid entries from cache")
                
            except FileNotFoundError:
                logger.debug("Cache file not found, starting with empty cache")
            except Exception as e:
                logger.error(f"Failed to load cache: {e}")
                self._stats['errors'] += 1
                # Don't raise exception, just start with empty cache
                self._cache = {}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total_requests = self._stats['hits'] + self._stats['misses']
            hit_rate = (self._stats['hits'] / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'entries': len(self._cache),
                'max_entries': self.max_entries,
                'hits': self._stats['hits'],
                'misses': self._stats['misses'],
                'hit_rate_percent': round(hit_rate, 2),
                'evictions': self._stats['evictions'],
                'saves': self._stats['saves'],
                'loads': self._stats['loads'],
                'errors': self._stats['errors'],
                'cache_file': str(self.cache_file),
                'cache_file_size': self._get_cache_file_size()
            }
    
    def _get_cache_file_size(self) -> int:
        """Get cache file size in bytes"""
        try:
            return self.cache_file.stat().st_size if self.cache_file.exists() else 0
        except Exception:
            return 0
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get detailed cache information"""
        with self._lock:
            entries_info = []
            current_time = time.time()
            
            for key, cached_item in self._cache.items():
                entries_info.append({
                    'key': key,
                    'dpi_type': cached_item.fingerprint.dpi_type.value,
                    'confidence': cached_item.fingerprint.confidence,
                    'age_seconds': current_time - cached_item.timestamp,
                    'ttl_seconds': cached_item.ttl,
                    'time_until_expiry': cached_item.time_until_expiry(),
                    'access_count': cached_item.access_count,
                    'last_access': cached_item.last_access
                })
            
            return {
                'stats': self.get_stats(),
                'entries': entries_info
            }
    
    def contains(self, key: str) -> bool:
        """Check if key exists in cache (without updating access stats)"""
        with self._lock:
            cached_item = self._cache.get(key)
            return cached_item is not None and not cached_item.is_expired()
    
    def keys(self) -> List[str]:
        """Get list of all valid (non-expired) cache keys"""
        with self._lock:
            valid_keys = []
            for key, cached_item in self._cache.items():
                if not cached_item.is_expired():
                    valid_keys.append(key)
            return valid_keys
    
    def update_ttl(self, key: str, new_ttl: int) -> bool:
        """
        Update TTL for existing cache entry.
        
        Args:
            key: Cache key
            new_ttl: New TTL in seconds
            
        Returns:
            True if updated successfully, False if key not found
        """
        with self._lock:
            cached_item = self._cache.get(key)
            if cached_item and not cached_item.is_expired():
                cached_item.ttl = new_ttl
                logger.debug(f"Updated TTL for {key} to {new_ttl}s")
                if self.auto_save:
                    self._save_cache_unsafe()
                return True
            return False
    
    def refresh_entry(self, key: str) -> bool:
        """
        Refresh timestamp for existing cache entry (extend its life).
        
        Args:
            key: Cache key
            
        Returns:
            True if refreshed successfully, False if key not found
        """
        with self._lock:
            cached_item = self._cache.get(key)
            if cached_item and not cached_item.is_expired():
                cached_item.timestamp = time.time()
                logger.debug(f"Refreshed timestamp for {key}")
                if self.auto_save:
                    self._save_cache_unsafe()
                return True
            return False
    
    def close(self):
        """Clean shutdown of cache system"""
        logger.info("Shutting down FingerprintCache")
        
        # Stop cleanup thread
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._stop_cleanup.set()
            self._cleanup_thread.join(timeout=5.0)
        
        # Final save
        try:
            self.save_cache()
        except Exception as e:
            logger.error(f"Error during final cache save: {e}")
        
        logger.info("FingerprintCache shutdown complete")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
    
    def __len__(self) -> int:
        """Get number of cache entries"""
        with self._lock:
            return len(self._cache)
    
    def __contains__(self, key: str) -> bool:
        """Check if key is in cache"""
        return self.contains(key)
    
    def __repr__(self) -> str:
        """String representation of cache"""
        with self._lock:
            return (f"FingerprintCache(entries={len(self._cache)}, "
                   f"max_entries={self.max_entries}, "
                   f"ttl={self.default_ttl}s, "
                   f"file={self.cache_file})")