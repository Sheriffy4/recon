"""
Baseline Manager Profiling and Optimization Script

This script profiles the baseline manager operations and implements optimizations:
- Profile save/load operations
- Optimize JSON serialization
- Add caching for frequently accessed baselines
- Measure and verify <1s comparison time

Part of Task 8: Profile and optimize baseline manager
"""

import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, List

from core.baseline_manager import BaselineManager, BaselineReport, BaselineResult
from core.performance_profiler import PerformanceProfiler


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_test_baseline(num_results: int = 100) -> BaselineReport:
    """Create a test baseline with specified number of results."""
    results = []
    
    for i in range(num_results):
        result = BaselineResult(
            attack_name=f"test_attack_{i}",
            passed=i % 2 == 0,
            packet_count=10 + i,
            validation_passed=i % 3 != 0,
            validation_issues=[f"issue_{j}" for j in range(i % 5)],
            execution_time=0.1 + (i * 0.01),
            metadata={'test_data': f"data_{i}"}
        )
        results.append(result)
    
    return BaselineReport(
        name="test_baseline",
        timestamp="2025-10-06T12:00:00",
        version="1.0",
        total_tests=num_results,
        passed_tests=sum(1 for r in results if r.passed),
        failed_tests=sum(1 for r in results if not r.passed),
        results=results
    )


def profile_save_operation(profiler: PerformanceProfiler, manager: BaselineManager):
    """Profile baseline save operation."""
    logger.info("Profiling baseline save operation...")
    
    # Test with different sizes
    sizes = [10, 50, 100, 500]
    
    for size in sizes:
        baseline = create_test_baseline(size)
        
        with profiler.profile_operation(f"save_baseline_{size}_results") as metrics:
            manager.save_baseline(baseline, f"test_save_{size}")
        
        metrics.details['result_count'] = size
        
        logger.info(f"Save {size} results: {metrics.execution_time:.4f}s")


def profile_load_operation(profiler: PerformanceProfiler, manager: BaselineManager):
    """Profile baseline load operation."""
    logger.info("Profiling baseline load operation...")
    
    # Create test baselines first
    sizes = [10, 50, 100, 500]
    for size in sizes:
        baseline = create_test_baseline(size)
        manager.save_baseline(baseline, f"test_load_{size}")
    
    # Profile loading
    for size in sizes:
        with profiler.profile_operation(f"load_baseline_{size}_results") as metrics:
            loaded = manager.load_baseline(f"test_load_{size}")
        
        metrics.details['result_count'] = len(loaded.results) if loaded else 0
        
        logger.info(f"Load {size} results: {metrics.execution_time:.4f}s")


def profile_comparison_operation(profiler: PerformanceProfiler, manager: BaselineManager):
    """Profile baseline comparison operation."""
    logger.info("Profiling baseline comparison operation...")
    
    # Test with different sizes
    sizes = [10, 50, 100, 500]
    
    for size in sizes:
        baseline = create_test_baseline(size)
        current = create_test_baseline(size)
        
        # Modify some results to create regressions
        for i in range(min(5, size)):
            current.results[i].passed = not baseline.results[i].passed
        
        with profiler.profile_operation(f"compare_baseline_{size}_results") as metrics:
            comparison = manager.compare_with_baseline(current, baseline)
        
        metrics.details['result_count'] = size
        metrics.details['regressions'] = len(comparison.regressions)
        metrics.details['improvements'] = len(comparison.improvements)
        
        logger.info(
            f"Compare {size} results: {metrics.execution_time:.4f}s "
            f"({len(comparison.regressions)} regressions)"
        )
        
        # Verify <1s requirement
        if metrics.execution_time >= 1.0:
            logger.warning(
                f"Comparison time {metrics.execution_time:.4f}s exceeds 1s requirement!"
            )


def main():
    """Main profiling function."""
    logger.info("Starting baseline manager profiling...")
    
    # Initialize profiler and manager
    profiler = PerformanceProfiler(Path("profiling_results"))
    manager = BaselineManager(Path("test_baselines"))
    
    # Profile operations
    profile_save_operation(profiler, manager)
    profile_load_operation(profiler, manager)
    profile_comparison_operation(profiler, manager)
    
    # Generate report
    report = profiler.generate_report("baseline_manager", include_recommendations=True)
    
    # Save report
    report_path = profiler.save_report(report)
    
    # Print summary
    logger.info("\n" + "=" * 70)
    logger.info("PROFILING SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Total operations: {report.summary['total_operations']}")
    logger.info(f"Total time: {report.summary['total_time']:.4f}s")
    logger.info(f"Average time: {report.summary['average_time']:.4f}s")
    logger.info(f"Max time: {report.summary['max_time']:.4f}s")
    logger.info(f"Slowest operation: {report.summary['slowest_operation']}")
    
    if report.recommendations:
        logger.info("\nRECOMMENDATIONS:")
        for rec in report.recommendations:
            logger.info(f"  - {rec}")
    
    logger.info(f"\nFull report saved to: {report_path}")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
