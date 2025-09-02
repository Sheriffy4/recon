#!/usr/bin/env python3
"""
Integration test for FingerprintCache with the existing system.
Verifies that the cache integrates properly with the fingerprinting workflow.
"""

import sys
import os

# Add the parent directories to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
tests_dir = os.path.dirname(current_dir)
recon_dir = os.path.dirname(tests_dir)
sys.path.insert(0, recon_dir)


sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.fingerprint.cache import FingerprintCache
from core.fingerprint.advanced_models import DPIFingerprint, DPIType
import tempfile
import time


def test_cache_integration():
    """Test cache integration with fingerprinting workflow"""
    print("Testing FingerprintCache integration...")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
        cache_file = f.name

    try:
        # Initialize cache
        cache = FingerprintCache(
            cache_file=cache_file,
            ttl=3600,
            max_entries=1000,
            cleanup_interval=0,  # Disable for testing
            auto_save=True,
        )

        # Simulate fingerprinting workflow
        target = "blocked-site.com"

        # 1. Check cache first (should be empty)
        cached_fingerprint = cache.get(target)
        assert cached_fingerprint is None, "Cache should be empty initially"
        print("✓ Initial cache check passed")

        # 2. Simulate fingerprinting analysis
        fingerprint = DPIFingerprint(
            target=target,
            dpi_type=DPIType.ROSKOMNADZOR_DPI,
            confidence=0.92,
            rst_injection_detected=True,
            http_header_filtering=True,
            dns_hijacking_detected=True,
            analysis_duration=2.5,
            reliability_score=0.88,
        )

        # 3. Store result in cache
        cache.set(target, fingerprint, ttl=1800)  # 30 minutes
        print("✓ Fingerprint cached successfully")

        # 4. Verify cache hit
        cached_result = cache.get(target)
        assert cached_result is not None, "Should retrieve cached fingerprint"
        assert cached_result.target == target
        assert cached_result.dpi_type == DPIType.ROSKOMNADZOR_DPI
        assert cached_result.confidence == 0.92
        assert cached_result.rst_injection_detected is True
        print("✓ Cache retrieval verified")

        # 5. Test cache statistics
        stats = cache.get_stats()
        assert stats["hits"] >= 1
        assert stats["entries"] == 1
        print(
            f"✓ Cache stats: {stats['hits']} hits, {stats['misses']} misses, {stats['hit_rate_percent']}% hit rate"
        )

        # 6. Test cache info
        info = cache.get_cache_info()
        assert len(info["entries"]) == 1
        entry = info["entries"][0]
        assert entry["key"] == target
        assert entry["dpi_type"] == "roskomnadzor_dpi"
        assert entry["confidence"] == 0.92
        print("✓ Cache info verified")

        # 7. Test persistence across instances
        cache.close()

        # Create new cache instance
        cache2 = FingerprintCache(cache_file=cache_file, cleanup_interval=0)
        persistent_result = cache2.get(target)
        assert persistent_result is not None
        assert persistent_result.target == target
        assert persistent_result.dpi_type == DPIType.ROSKOMNADZOR_DPI
        print("✓ Cache persistence verified")

        # 8. Test cache invalidation (simulate DPI behavior change)
        cache2.invalidate(target)
        assert cache2.get(target) is None
        print("✓ Cache invalidation verified")

        cache2.close()

        print("\n🎉 All integration tests passed!")
        return True

    except Exception as e:
        print(f"\n❌ Integration test failed: {e}")
        import traceback

        traceback.print_exc()
        return False

    finally:
        try:
            os.unlink(cache_file)
        except:
            pass


def test_cache_performance():
    """Test cache performance characteristics"""
    print("\nTesting cache performance...")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
        cache_file = f.name

    try:
        cache = FingerprintCache(
            cache_file=cache_file,
            max_entries=1000,
            cleanup_interval=0,
            auto_save=False,  # Disable for performance testing
        )

        # Test bulk operations
        num_entries = 500
        fingerprints = []

        # Create test fingerprints
        for i in range(num_entries):
            fp = DPIFingerprint(
                target=f"site{i}.com",
                dpi_type=DPIType.COMMERCIAL_DPI,
                confidence=0.8 + (i % 20) / 100,  # Vary confidence
                rst_injection_detected=(i % 3 == 0),
                http_header_filtering=(i % 2 == 0),
            )
            fingerprints.append(fp)

        # Measure insertion time
        start_time = time.time()
        for i, fp in enumerate(fingerprints):
            cache.set(f"site{i}.com", fp)
        insert_time = time.time() - start_time

        insert_rate = num_entries / insert_time if insert_time > 0 else float("inf")
        print(
            f"✓ Inserted {num_entries} entries in {insert_time:.3f}s ({insert_rate:.1f} ops/sec)"
        )

        # Measure retrieval time
        start_time = time.time()
        hits = 0
        for i in range(num_entries):
            result = cache.get(f"site{i}.com")
            if result is not None:
                hits += 1
        retrieval_time = time.time() - start_time

        retrieval_rate = hits / retrieval_time if retrieval_time > 0 else float("inf")
        print(
            f"✓ Retrieved {hits} entries in {retrieval_time:.3f}s ({retrieval_rate:.1f} ops/sec)"
        )

        # Test cache efficiency
        stats = cache.get_stats()
        print(f"✓ Cache efficiency: {stats['hit_rate_percent']}% hit rate")

        cache.close()

        print("✓ Performance test completed")
        return True

    except Exception as e:
        print(f"❌ Performance test failed: {e}")
        return False

    finally:
        try:
            os.unlink(cache_file)
        except:
            pass


if __name__ == "__main__":
    print("FingerprintCache Integration Test Suite")
    print("=" * 50)

    success = True
    success &= test_cache_integration()
    success &= test_cache_performance()

    print("\n" + "=" * 50)
    if success:
        print("🎉 All integration tests passed!")
        print("FingerprintCache is ready for production use.")
    else:
        print("❌ Some tests failed. Please check the implementation.")
        sys.exit(1)
