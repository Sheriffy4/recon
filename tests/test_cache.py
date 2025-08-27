"""
Comprehensive tests for FingerprintCache - Task 2 Implementation
Tests cache operations, TTL logic, persistence, thread safety, and edge cases.
"""
import pytest
import tempfile
import time
import threading
import os
from pathlib import Path
from core.fingerprint.cache import FingerprintCache, CachedFingerprint
from core.fingerprint.advanced_models import DPIFingerprint, DPIType
from core.fingerprint.advanced_models import CacheError

class TestCachedFingerprint:
    """Test CachedFingerprint dataclass functionality"""

    def test_cached_fingerprint_creation(self):
        """Test basic creation and properties"""
        fingerprint = DPIFingerprint(target='example.com')
        cached = CachedFingerprint(fingerprint=fingerprint, timestamp=time.time(), ttl=3600)
        assert cached.fingerprint == fingerprint
        assert cached.access_count == 0
        assert cached.last_access == 0.0
        assert not cached.is_expired()

    def test_expiry_logic(self):
        """Test TTL expiry logic"""
        fingerprint = DPIFingerprint(target='example.com')
        cached = CachedFingerprint(fingerprint=fingerprint, timestamp=time.time(), ttl=3600)
        assert not cached.is_expired()
        cached_expired = CachedFingerprint(fingerprint=fingerprint, timestamp=time.time() - 7200, ttl=3600)
        assert cached_expired.is_expired()

    def test_access_tracking(self):
        """Test access count and timestamp tracking"""
        fingerprint = DPIFingerprint(target='example.com')
        cached = CachedFingerprint(fingerprint=fingerprint, timestamp=time.time(), ttl=3600)
        assert cached.access_count == 0
        assert cached.last_access == 0.0
        cached.update_access()
        assert cached.access_count == 1
        assert cached.last_access > 0
        cached.update_access()
        assert cached.access_count == 2

    def test_time_until_expiry(self):
        """Test time until expiry calculation"""
        fingerprint = DPIFingerprint(target='example.com')
        current_time = time.time()
        cached = CachedFingerprint(fingerprint=fingerprint, timestamp=current_time, ttl=3600)
        time_left = cached.time_until_expiry()
        assert 3590 < time_left <= 3600
        cached_expired = CachedFingerprint(fingerprint=fingerprint, timestamp=current_time - 7200, ttl=3600)
        assert cached_expired.time_until_expiry() < 0

class TestFingerprintCache:
    """Test FingerprintCache functionality"""

    @pytest.fixture
    def temp_cache_file(self):
        """Create temporary cache file"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            yield f.name
        try:
            os.unlink(f.name)
        except FileNotFoundError:
            pass

    @pytest.fixture
    def sample_fingerprint(self):
        """Create sample fingerprint for testing"""
        return DPIFingerprint(target='example.com', dpi_type=DPIType.COMMERCIAL_DPI, confidence=0.85, rst_injection_detected=True, http_header_filtering=True)

    @pytest.fixture
    def cache(self, temp_cache_file):
        """Create cache instance with temporary file"""
        cache = FingerprintCache(cache_file=temp_cache_file, ttl=3600, max_entries=100, cleanup_interval=0, auto_save=True)
        yield cache
        cache.close()

    def test_cache_initialization(self, temp_cache_file):
        """Test cache initialization"""
        cache = FingerprintCache(cache_file=temp_cache_file, ttl=1800, max_entries=500)
        assert cache.default_ttl == 1800
        assert cache.max_entries == 500
        assert len(cache) == 0
        assert cache.cache_file == Path(temp_cache_file)
        cache.close()

    def test_basic_get_set(self, cache, sample_fingerprint):
        """Test basic get/set operations"""
        key = 'test_key'
        assert cache.get(key) is None
        assert key not in cache
        cache.set(key, sample_fingerprint)
        retrieved = cache.get(key)
        assert retrieved is not None
        assert retrieved.target == sample_fingerprint.target
        assert retrieved.dpi_type == sample_fingerprint.dpi_type
        assert key in cache

    def test_ttl_expiration(self, cache, sample_fingerprint):
        """Test TTL-based expiration"""
        key = 'expiring_key'
        cache.set(key, sample_fingerprint, ttl=1)
        assert cache.get(key) is not None
        time.sleep(1.1)
        assert cache.get(key) is None
        assert key not in cache

    def test_cache_invalidation(self, cache, sample_fingerprint):
        """Test cache invalidation"""
        key1, key2 = ('key1', 'key2')
        cache.set(key1, sample_fingerprint)
        cache.set(key2, sample_fingerprint)
        assert len(cache) == 2
        cache.invalidate(key1)
        assert cache.get(key1) is None
        assert cache.get(key2) is not None
        assert len(cache) == 1
        cache.invalidate()
        assert len(cache) == 0
        assert cache.get(key2) is None

    def test_cleanup_expired(self, cache, sample_fingerprint):
        """Test cleanup of expired entries"""
        cache.set('short_ttl', sample_fingerprint, ttl=1)
        cache.set('long_ttl', sample_fingerprint, ttl=3600)
        assert len(cache) == 2
        time.sleep(1.1)
        removed_count = cache.cleanup_expired()
        assert removed_count == 1
        assert len(cache) == 1
        assert cache.get('short_ttl') is None
        assert cache.get('long_ttl') is not None

    def test_lru_eviction(self, temp_cache_file, sample_fingerprint):
        """Test LRU eviction when max_entries is reached"""
        cache = FingerprintCache(cache_file=temp_cache_file, max_entries=3, cleanup_interval=0, auto_save=False)
        cache.set('key1', sample_fingerprint)
        cache.set('key2', sample_fingerprint)
        cache.set('key3', sample_fingerprint)
        assert len(cache) == 3
        cache.get('key1')
        cache.set('key4', sample_fingerprint)
        assert len(cache) == 3
        assert cache.get('key1') is not None
        assert cache.get('key4') is not None
        cache.close()

    def test_persistence_save_load(self, temp_cache_file, sample_fingerprint):
        """Test cache persistence (save/load)"""
        cache1 = FingerprintCache(cache_file=temp_cache_file, cleanup_interval=0, auto_save=False)
        cache1.set('persistent_key', sample_fingerprint)
        cache1.save_cache()
        cache1.close()
        cache2 = FingerprintCache(cache_file=temp_cache_file, cleanup_interval=0)
        retrieved = cache2.get('persistent_key')
        assert retrieved is not None
        assert retrieved.target == sample_fingerprint.target
        cache2.close()

    def test_persistence_expired_filtering(self, temp_cache_file, sample_fingerprint):
        """Test that expired entries are filtered during load"""
        cache1 = FingerprintCache(cache_file=temp_cache_file, cleanup_interval=0, auto_save=False)
        expired_cached = CachedFingerprint(fingerprint=sample_fingerprint, timestamp=time.time() - 7200, ttl=3600)
        cache1._cache['expired_key'] = expired_cached
        cache1.save_cache()
        cache1.close()
        cache2 = FingerprintCache(cache_file=temp_cache_file, cleanup_interval=0)
        assert cache2.get('expired_key') is None
        assert len(cache2) == 0
        cache2.close()

    def test_thread_safety(self, cache, sample_fingerprint):
        """Test thread-safe operations"""
        num_threads = 10
        operations_per_thread = 50
        results = {}
        errors = []

        def worker(thread_id):
            try:
                for i in range(operations_per_thread):
                    key = f'thread_{thread_id}_key_{i}'
                    cache.set(key, sample_fingerprint)
                    retrieved = cache.get(key)
                    if retrieved is None:
                        errors.append(f'Failed to retrieve {key}')
                    if thread_id not in results:
                        results[thread_id] = 0
                    results[thread_id] += 1
            except Exception as e:
                errors.append(f'Thread {thread_id} error: {e}')
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        assert len(errors) == 0, f'Thread safety errors: {errors}'
        assert len(results) == num_threads
        assert sum(results.values()) == num_threads * operations_per_thread

    def test_cache_stats(self, cache, sample_fingerprint):
        """Test cache statistics tracking"""
        stats = cache.get_stats()
        assert stats['entries'] == 0
        assert stats['hits'] == 0
        assert stats['misses'] == 0
        assert stats['hit_rate_percent'] == 0
        cache.set('key1', sample_fingerprint)
        cache.get('key1')
        cache.get('nonexistent')
        stats = cache.get_stats()
        assert stats['entries'] == 1
        assert stats['hits'] == 1
        assert stats['misses'] == 1
        assert stats['hit_rate_percent'] == 50.0

    def test_cache_info(self, cache, sample_fingerprint):
        """Test detailed cache information"""
        cache.set('info_key', sample_fingerprint, ttl=1800)
        info = cache.get_cache_info()
        assert 'stats' in info
        assert 'entries' in info
        assert len(info['entries']) == 1
        entry_info = info['entries'][0]
        assert entry_info['key'] == 'info_key'
        assert entry_info['dpi_type'] == sample_fingerprint.dpi_type.value
        assert entry_info['confidence'] == sample_fingerprint.confidence
        assert entry_info['ttl_seconds'] == 1800
        assert entry_info['time_until_expiry'] > 0

    def test_ttl_update(self, cache, sample_fingerprint):
        """Test TTL update functionality"""
        key = 'ttl_test'
        cache.set(key, sample_fingerprint, ttl=1800)
        assert cache.update_ttl(key, 3600) is True
        info = cache.get_cache_info()
        entry = next((e for e in info['entries'] if e['key'] == key))
        assert entry['ttl_seconds'] == 3600
        assert cache.update_ttl('nonexistent', 1800) is False

    def test_refresh_entry(self, cache, sample_fingerprint):
        """Test entry refresh functionality"""
        key = 'refresh_test'
        cache.set(key, sample_fingerprint)
        initial_info = cache.get_cache_info()
        initial_age = next((e for e in initial_info['entries'] if e['key'] == key))['age_seconds']
        time.sleep(0.1)
        assert cache.refresh_entry(key) is True
        refreshed_info = cache.get_cache_info()
        refreshed_age = next((e for e in refreshed_info['entries'] if e['key'] == key))['age_seconds']
        assert refreshed_age < initial_age
        assert cache.refresh_entry('nonexistent') is False

    def test_contains_and_keys(self, cache, sample_fingerprint):
        """Test contains and keys methods"""
        keys = ['key1', 'key2', 'key3']
        assert cache.keys() == []
        for key in keys:
            assert key not in cache
        for key in keys:
            cache.set(key, sample_fingerprint)
        for key in keys:
            assert key in cache
            assert cache.contains(key) is True
        cache_keys = cache.keys()
        assert len(cache_keys) == len(keys)
        assert set(cache_keys) == set(keys)

    def test_context_manager(self, temp_cache_file, sample_fingerprint):
        """Test context manager functionality"""
        with FingerprintCache(cache_file=temp_cache_file, cleanup_interval=0) as cache:
            cache.set('context_key', sample_fingerprint)
            assert cache.get('context_key') is not None
        with FingerprintCache(cache_file=temp_cache_file, cleanup_interval=0) as cache2:
            assert cache2.get('context_key') is not None

    def test_error_handling(self, cache, sample_fingerprint):
        """Test error handling scenarios"""
        with pytest.raises(CacheError):
            invalid_cache = FingerprintCache(cache_file='/invalid/path/cache.pkl')
            invalid_cache.set('key', sample_fingerprint)

    def test_corrupted_cache_file(self, temp_cache_file, sample_fingerprint):
        """Test handling of corrupted cache file"""
        with open(temp_cache_file, 'w') as f:
            f.write('corrupted data')
        cache = FingerprintCache(cache_file=temp_cache_file, cleanup_interval=0)
        assert len(cache) == 0
        cache.set('new_key', sample_fingerprint)
        assert cache.get('new_key') is not None
        cache.close()

    def test_auto_save_disabled(self, temp_cache_file, sample_fingerprint):
        """Test cache behavior with auto_save disabled"""
        cache = FingerprintCache(cache_file=temp_cache_file, auto_save=False, cleanup_interval=0)
        cache.set('no_auto_save', sample_fingerprint)
        cache.close()
        cache2 = FingerprintCache(cache_file=temp_cache_file, cleanup_interval=0)
        assert cache2.get('no_auto_save') is None
        cache2.close()

    def test_background_cleanup(self, temp_cache_file, sample_fingerprint):
        """Test background cleanup thread"""
        cache = FingerprintCache(cache_file=temp_cache_file, cleanup_interval=1, auto_save=False)
        cache.set('cleanup_test', sample_fingerprint, ttl=1)
        assert len(cache) == 1
        time.sleep(2.5)
        assert len(cache) == 0
        cache.close()

    def test_repr_and_len(self, cache, sample_fingerprint):
        """Test string representation and length"""
        assert len(cache) == 0
        repr_str = repr(cache)
        assert 'FingerprintCache' in repr_str
        assert 'entries=0' in repr_str
        cache.set('repr_test', sample_fingerprint)
        assert len(cache) == 1
        repr_str = repr(cache)
        assert 'entries=1' in repr_str

class TestCacheEdgeCases:
    """Test edge cases and error conditions"""

    def test_very_large_cache(self, temp_cache_file):
        """Test cache with large number of entries"""
        cache = FingerprintCache(cache_file=temp_cache_file, max_entries=10000, cleanup_interval=0, auto_save=False)
        num_entries = 1000
        for i in range(num_entries):
            fingerprint = DPIFingerprint(target=f'site{i}.com')
            cache.set(f'key{i}', fingerprint)
        assert len(cache) == num_entries
        assert cache.get('key500') is not None
        assert cache.get('key999') is not None
        cache.close()

    def test_zero_ttl(self, cache, sample_fingerprint):
        """Test cache behavior with zero TTL"""
        cache.set('zero_ttl', sample_fingerprint, ttl=0)
        assert cache.get('zero_ttl') is None

    def test_negative_ttl(self, cache, sample_fingerprint):
        """Test cache behavior with negative TTL"""
        cache.set('negative_ttl', sample_fingerprint, ttl=-1)
        assert cache.get('negative_ttl') is None

    def test_concurrent_cleanup(self, temp_cache_file, sample_fingerprint):
        """Test concurrent cleanup operations"""
        cache = FingerprintCache(cache_file=temp_cache_file, cleanup_interval=0, auto_save=False)
        for i in range(100):
            cache.set(f'concurrent_{i}', sample_fingerprint, ttl=1)

        def cleanup_worker():
            cache.cleanup_expired()
        time.sleep(1.1)
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=cleanup_worker)
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        assert len(cache) == 0
        cache.close()

    def test_memory_pressure_simulation(self, temp_cache_file):
        """Test cache behavior under memory pressure simulation"""
        cache = FingerprintCache(cache_file=temp_cache_file, max_entries=100, cleanup_interval=0, auto_save=False)
        for round_num in range(3):
            for i in range(150):
                fingerprint = DPIFingerprint(target=f'round{round_num}_site{i}.com', raw_metrics={'large_data': 'x' * 1000})
                cache.set(f'round{round_num}_key{i}', fingerprint)
        assert len(cache) <= cache.max_entries
        cache.close()
if __name__ == '__main__':
    pytest.main([__file__, '-v'])