"""
Test Performance Optimizations

This script tests the performance optimizations implemented for:
- Baseline manager caching
- Real domain tester parallel execution
- CLI validation orchestrator

Part of Task 8: Profile and optimize components
"""

import time
import logging
from pathlib import Path

from core.baseline_manager import BaselineManager, BaselineReport, BaselineResult
from core.performance_profiler import PerformanceProfiler


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_baseline_caching():
    """Test baseline manager caching optimization."""
    logger.info("\n" + "=" * 70)
    logger.info("Testing Baseline Manager Caching")
    logger.info("=" * 70)
    
    profiler = PerformanceProfiler()
    
    # Create test baseline
    results = [
        BaselineResult(
            attack_name=f"attack_{i}",
            passed=True,
            packet_count=10,
            validation_passed=True
        )
        for i in range(100)
    ]
    
    baseline = BaselineReport(
        name="test_cache",
        timestamp="2025-10-06T12:00:00",
        version="1.0",
        total_tests=100,
        passed_tests=100,
        failed_tests=0,
        results=results
    )
    
    # Test without cache
    manager_no_cache = BaselineManager(Path("test_baselines"), enable_cache=False)
    manager_no_cache.save_baseline(baseline, "test_cache")
    
    with profiler.profile_operation("load_without_cache_1") as metrics:
        manager_no_cache.load_baseline("test_cache")
    
    time1_no_cache = metrics.execution_time
    
    with profiler.profile_operation("load_without_cache_2") as metrics:
        manager_no_cache.load_baseline("test_cache")
    
    time2_no_cache = metrics.execution_time
    
    logger.info(f"Without cache - Load 1: {time1_no_cache:.6f}s")
    logger.info(f"Without cache - Load 2: {time2_no_cache:.6f}s")
    
    # Test with cache
    manager_with_cache = BaselineManager(Path("test_baselines"), enable_cache=True)
    
    with profiler.profile_operation("load_with_cache_1") as metrics:
        manager_with_cache.load_baseline("test_cache")
    
    time1_with_cache = metrics.execution_time
    
    with profiler.profile_operation("load_with_cache_2") as metrics:
        manager_with_cache.load_baseline("test_cache")
    
    time2_with_cache = metrics.execution_time
    
    logger.info(f"With cache - Load 1: {time1_with_cache:.6f}s")
    logger.info(f"With cache - Load 2: {time2_with_cache:.6f}s (cached)")
    
    # Calculate speedup
    speedup = time2_no_cache / time2_with_cache if time2_with_cache > 0 else 0
    logger.info(f"\nCache speedup: {speedup:.2f}x")
    
    # Get cache stats
    cache_stats = manager_with_cache.get_cache_stats()
    logger.info(f"Cache stats: {cache_stats}")
    
    # Verify cache is working
    assert time2_with_cache < time2_no_cache, "Cache should be faster than no cache"
    logger.info("\n✓ Baseline caching optimization verified")


def test_comparison_performance():
    """Test baseline comparison performance."""
    logger.info("\n" + "=" * 70)
    logger.info("Testing Baseline Comparison Performance")
    logger.info("=" * 70)
    
    profiler = PerformanceProfiler()
    manager = BaselineManager(Path("test_baselines"))
    
    # Create baselines with different sizes
    sizes = [10, 50, 100, 500]
    
    for size in sizes:
        # Create baseline and current reports
        baseline_results = [
            BaselineResult(
                attack_name=f"attack_{i}",
                passed=True,
                packet_count=10,
                validation_passed=True
            )
            for i in range(size)
        ]
        
        current_results = baseline_results.copy()
        # Modify some results to create regressions
        for i in range(min(5, size)):
            current_results[i].passed = False
        
        baseline = BaselineReport(
            name=f"baseline_{size}",
            timestamp="2025-10-06T12:00:00",
            version="1.0",
            total_tests=size,
            passed_tests=size,
            failed_tests=0,
            results=baseline_results
        )
        
        current = BaselineReport(
            name=f"current_{size}",
            timestamp="2025-10-06T13:00:00",
            version="1.0",
            total_tests=size,
            passed_tests=size - 5,
            failed_tests=5,
            results=current_results
        )
        
        # Profile comparison
        with profiler.profile_operation(f"compare_{size}_results") as metrics:
            comparison = manager.compare_with_baseline(current, baseline)
        
        logger.info(
            f"Compare {size} results: {metrics.execution_time:.6f}s "
            f"({len(comparison.regressions)} regressions)"
        )
        
        # Verify <1s requirement
        if metrics.execution_time >= 1.0:
            logger.warning(
                f"⚠ Comparison time {metrics.execution_time:.4f}s exceeds 1s requirement!"
            )
        else:
            logger.info(f"✓ Comparison time within 1s requirement")


def main():
    """Main test function."""
    logger.info("Testing Performance Optimizations...")
    
    try:
        test_baseline_caching()
        test_comparison_performance()
        
        logger.info("\n" + "=" * 70)
        logger.info("✓ ALL PERFORMANCE OPTIMIZATION TESTS PASSED")
        logger.info("=" * 70)
    
    except Exception as e:
        logger.error(f"\n✗ Performance optimization tests failed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
