"""
Performance Benchmark Tool for Adaptive Engine Refactoring.

This tool compares the performance of the refactored system against the original
to ensure no performance regressions have been introduced.
"""

import asyncio
import time
import logging
import statistics
import psutil
import gc
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import json
from datetime import datetime
from dataclasses import dataclass, asdict

# Import original adaptive engine
import sys

sys.path.append(str(Path(__file__).parent.parent.parent.parent))
from core.adaptive_engine import AdaptiveEngine as OriginalAdaptiveEngine

# Import refactored components
from ..facade import AdaptiveEngine as RefactoredAdaptiveEngine
from ..config import AdaptiveEngineConfig
from ..container import DIContainer


logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Results from a single benchmark operation."""

    operation: str
    system: str  # 'original' or 'refactored'
    duration_seconds: float
    memory_usage_mb: float
    memory_delta_mb: float
    cpu_usage_percent: float
    success: bool
    error: Optional[str] = None
    metadata: Dict[str, Any] = None


@dataclass
class BenchmarkComparison:
    """Comparison between original and refactored systems."""

    operation: str
    original_result: BenchmarkResult
    refactored_result: BenchmarkResult
    performance_ratio: float  # refactored/original (lower is better)
    memory_ratio: float
    regression_detected: bool
    improvement_percent: float


class PerformanceBenchmark:
    """
    Performance benchmarking tool for comparing original vs refactored systems.

    This tool runs identical operations on both systems and compares:
    - Execution time
    - Memory usage
    - CPU utilization
    - Success rates
    """

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the benchmark tool."""
        self.config_path = config_path
        self.results: List[BenchmarkResult] = []
        self.comparisons: List[BenchmarkComparison] = []

        # Test domains for benchmarking
        self.test_domains = [
            "example.com",
            "google.com",
            "github.com",
            "stackoverflow.com",
            "reddit.com",
        ]

        # Benchmark operations to test
        self.benchmark_operations = [
            "strategy_generation",
            "fingerprint_creation",
            "cache_operations",
            "configuration_loading",
            "metrics_collection",
        ]

        logger.info("Performance benchmark tool initialized")

    async def run_full_benchmark(self, iterations: int = 5) -> Dict[str, Any]:
        """
        Run complete performance benchmark comparing both systems.

        Args:
            iterations: Number of iterations per test for statistical significance

        Returns:
            Comprehensive benchmark results and analysis
        """
        logger.info(f"Starting full performance benchmark with {iterations} iterations")

        benchmark_start = time.time()

        # Initialize both systems
        original_engine = await self._initialize_original_engine()
        refactored_engine = await self._initialize_refactored_engine()

        if not original_engine or not refactored_engine:
            logger.error("Failed to initialize engines for benchmarking")
            return {"error": "Engine initialization failed"}

        # Run benchmarks for each operation
        for operation in self.benchmark_operations:
            logger.info(f"Benchmarking operation: {operation}")

            # Run multiple iterations for statistical significance
            original_results = []
            refactored_results = []

            for i in range(iterations):
                logger.debug(f"Running iteration {i+1}/{iterations} for {operation}")

                # Benchmark original system
                original_result = await self._benchmark_operation(
                    original_engine, operation, "original", i
                )
                if original_result:
                    original_results.append(original_result)
                    self.results.append(original_result)

                # Benchmark refactored system
                refactored_result = await self._benchmark_operation(
                    refactored_engine, operation, "refactored", i
                )
                if refactored_result:
                    refactored_results.append(refactored_result)
                    self.results.append(refactored_result)

                # Small delay between iterations
                await asyncio.sleep(0.1)

            # Compare results for this operation
            if original_results and refactored_results:
                comparison = self._compare_operation_results(
                    operation, original_results, refactored_results
                )
                self.comparisons.append(comparison)

        benchmark_duration = time.time() - benchmark_start

        # Generate comprehensive analysis
        analysis = self._generate_analysis()
        analysis["benchmark_duration_seconds"] = benchmark_duration
        analysis["total_iterations"] = iterations
        analysis["timestamp"] = datetime.now().isoformat()

        logger.info(f"Benchmark completed in {benchmark_duration:.2f} seconds")

        return analysis

    async def _initialize_original_engine(self) -> Optional[OriginalAdaptiveEngine]:
        """Initialize the original adaptive engine."""
        try:
            # Use minimal configuration for benchmarking
            engine = OriginalAdaptiveEngine(
                enable_caching=True, enable_fingerprinting=True, max_trials=5, strategy_timeout=10.0
            )
            logger.info("Original AdaptiveEngine initialized")
            return engine
        except Exception as e:
            logger.error(f"Failed to initialize original engine: {e}")
            return None

    async def _initialize_refactored_engine(self) -> Optional[RefactoredAdaptiveEngine]:
        """Initialize the refactored adaptive engine."""
        try:
            # Create configuration
            config = AdaptiveEngineConfig.create_default()
            config.strategy.max_trials = 5
            config.testing.strategy_timeout = 10.0
            config.caching.enable_caching = True
            config.analytics.enable_profiling = True

            # Initialize DI container and engine
            container = DIContainer(config)
            engine = container.get_adaptive_engine()

            logger.info("Refactored AdaptiveEngine initialized")
            return engine
        except Exception as e:
            logger.error(f"Failed to initialize refactored engine: {e}")
            return None

    async def _benchmark_operation(
        self, engine: Any, operation: str, system: str, iteration: int
    ) -> Optional[BenchmarkResult]:
        """Benchmark a specific operation on an engine."""

        # Get initial system state
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        initial_cpu_time = process.cpu_times()

        # Force garbage collection for consistent measurements
        gc.collect()

        start_time = time.time()
        success = False
        error = None
        metadata = {"iteration": iteration}

        try:
            if operation == "strategy_generation":
                success = await self._benchmark_strategy_generation(engine, metadata)
            elif operation == "fingerprint_creation":
                success = await self._benchmark_fingerprint_creation(engine, metadata)
            elif operation == "cache_operations":
                success = await self._benchmark_cache_operations(engine, metadata)
            elif operation == "configuration_loading":
                success = await self._benchmark_configuration_loading(engine, metadata)
            elif operation == "metrics_collection":
                success = await self._benchmark_metrics_collection(engine, metadata)
            else:
                error = f"Unknown operation: {operation}"

        except Exception as e:
            error = str(e)
            logger.warning(f"Benchmark operation {operation} failed: {e}")

        end_time = time.time()

        # Calculate resource usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        final_cpu_time = process.cpu_times()

        duration = end_time - start_time
        memory_delta = final_memory - initial_memory
        cpu_time_delta = (final_cpu_time.user - initial_cpu_time.user) + (
            final_cpu_time.system - initial_cpu_time.system
        )
        cpu_usage = (cpu_time_delta / duration) * 100 if duration > 0 else 0

        return BenchmarkResult(
            operation=operation,
            system=system,
            duration_seconds=duration,
            memory_usage_mb=final_memory,
            memory_delta_mb=memory_delta,
            cpu_usage_percent=cpu_usage,
            success=success,
            error=error,
            metadata=metadata,
        )

    async def _benchmark_strategy_generation(self, engine: Any, metadata: Dict) -> bool:
        """Benchmark strategy generation performance."""
        try:
            domain = self.test_domains[0]  # Use consistent domain

            if hasattr(engine, "find_best_strategy"):
                # Refactored engine
                result = await engine.find_best_strategy(domain)
                metadata["strategies_generated"] = (
                    len(result.strategies) if hasattr(result, "strategies") else 1
                )
            else:
                # Original engine - simulate strategy generation
                strategies = await engine._generate_strategies_for_domain(domain)
                metadata["strategies_generated"] = len(strategies) if strategies else 0

            return True
        except Exception as e:
            logger.debug(f"Strategy generation benchmark error: {e}")
            return False

    async def _benchmark_fingerprint_creation(self, engine: Any, metadata: Dict) -> bool:
        """Benchmark fingerprint creation performance."""
        try:
            domain = self.test_domains[1]

            if hasattr(engine, "_fingerprint_service"):
                # Refactored engine
                fingerprint = await engine._fingerprint_service.create_fingerprint(domain)
                metadata["fingerprint_created"] = fingerprint is not None
            else:
                # Original engine
                fingerprint = await engine._create_dpi_fingerprint(domain)
                metadata["fingerprint_created"] = fingerprint is not None

            return True
        except Exception as e:
            logger.debug(f"Fingerprint creation benchmark error: {e}")
            return False

    async def _benchmark_cache_operations(self, engine: Any, metadata: Dict) -> bool:
        """Benchmark cache operations performance."""
        try:
            test_key = "benchmark_test_key"
            test_value = {"test": "data", "timestamp": time.time()}

            if hasattr(engine, "_cache_manager"):
                # Refactored engine
                cache_manager = engine._cache_manager
                await cache_manager.set(test_key, test_value, "strategy")
                cached_value = await cache_manager.get(test_key, "strategy")
                await cache_manager.invalidate(test_key, "strategy")
                metadata["cache_operations"] = 3
            else:
                # Original engine - simulate cache operations
                engine._strategy_cache[test_key] = test_value
                cached_value = engine._strategy_cache.get(test_key)
                if test_key in engine._strategy_cache:
                    del engine._strategy_cache[test_key]
                metadata["cache_operations"] = 3

            return cached_value is not None
        except Exception as e:
            logger.debug(f"Cache operations benchmark error: {e}")
            return False

    async def _benchmark_configuration_loading(self, engine: Any, metadata: Dict) -> bool:
        """Benchmark configuration loading performance."""
        try:
            if hasattr(engine, "_config_manager"):
                # Refactored engine
                config = engine._config_manager.get_strategy_config()
                metadata["config_loaded"] = config is not None
            else:
                # Original engine
                config = getattr(engine, "config", None)
                metadata["config_loaded"] = config is not None

            return True
        except Exception as e:
            logger.debug(f"Configuration loading benchmark error: {e}")
            return False

    async def _benchmark_metrics_collection(self, engine: Any, metadata: Dict) -> bool:
        """Benchmark metrics collection performance."""
        try:
            if hasattr(engine, "_analytics_service"):
                # Refactored engine
                metrics = engine._analytics_service.get_performance_metrics()
                metadata["metrics_collected"] = len(metrics) if isinstance(metrics, dict) else 0
            else:
                # Original engine
                stats = engine.get_stats() if hasattr(engine, "get_stats") else {}
                metadata["metrics_collected"] = len(stats)

            return True
        except Exception as e:
            logger.debug(f"Metrics collection benchmark error: {e}")
            return False

    def _compare_operation_results(
        self,
        operation: str,
        original_results: List[BenchmarkResult],
        refactored_results: List[BenchmarkResult],
    ) -> BenchmarkComparison:
        """Compare results between original and refactored systems."""

        # Calculate average metrics for each system
        original_avg = self._calculate_average_result(original_results)
        refactored_avg = self._calculate_average_result(refactored_results)

        # Calculate performance ratios
        performance_ratio = (
            refactored_avg.duration_seconds / original_avg.duration_seconds
            if original_avg.duration_seconds > 0
            else float("inf")
        )

        memory_ratio = (
            refactored_avg.memory_usage_mb / original_avg.memory_usage_mb
            if original_avg.memory_usage_mb > 0
            else float("inf")
        )

        # Detect regression (>10% performance degradation)
        regression_detected = performance_ratio > 1.1

        # Calculate improvement percentage
        improvement_percent = (
            (original_avg.duration_seconds - refactored_avg.duration_seconds)
            / original_avg.duration_seconds
            * 100
            if original_avg.duration_seconds > 0
            else 0
        )

        return BenchmarkComparison(
            operation=operation,
            original_result=original_avg,
            refactored_result=refactored_avg,
            performance_ratio=performance_ratio,
            memory_ratio=memory_ratio,
            regression_detected=regression_detected,
            improvement_percent=improvement_percent,
        )

    def _calculate_average_result(self, results: List[BenchmarkResult]) -> BenchmarkResult:
        """Calculate average metrics from multiple benchmark results."""
        if not results:
            return BenchmarkResult("", "", 0, 0, 0, 0, False)

        successful_results = [r for r in results if r.success]
        if not successful_results:
            return results[0]  # Return first result if none successful

        avg_duration = statistics.mean(r.duration_seconds for r in successful_results)
        avg_memory = statistics.mean(r.memory_usage_mb for r in successful_results)
        avg_memory_delta = statistics.mean(r.memory_delta_mb for r in successful_results)
        avg_cpu = statistics.mean(r.cpu_usage_percent for r in successful_results)

        return BenchmarkResult(
            operation=successful_results[0].operation,
            system=successful_results[0].system,
            duration_seconds=avg_duration,
            memory_usage_mb=avg_memory,
            memory_delta_mb=avg_memory_delta,
            cpu_usage_percent=avg_cpu,
            success=True,
            metadata={"averaged_from": len(successful_results)},
        )

    def _generate_analysis(self) -> Dict[str, Any]:
        """Generate comprehensive analysis of benchmark results."""
        analysis = {
            "summary": {
                "total_operations_tested": len(self.benchmark_operations),
                "total_comparisons": len(self.comparisons),
                "regressions_detected": sum(1 for c in self.comparisons if c.regression_detected),
                "overall_performance_ratio": 0.0,
                "overall_memory_ratio": 0.0,
            },
            "operation_results": [],
            "performance_analysis": {},
            "recommendations": [],
        }

        if not self.comparisons:
            analysis["error"] = "No comparisons available"
            return analysis

        # Calculate overall ratios
        performance_ratios = [
            c.performance_ratio for c in self.comparisons if c.performance_ratio != float("inf")
        ]
        memory_ratios = [c.memory_ratio for c in self.comparisons if c.memory_ratio != float("inf")]

        if performance_ratios:
            analysis["summary"]["overall_performance_ratio"] = statistics.mean(performance_ratios)
        if memory_ratios:
            analysis["summary"]["overall_memory_ratio"] = statistics.mean(memory_ratios)

        # Detailed operation results
        for comparison in self.comparisons:
            operation_analysis = {
                "operation": comparison.operation,
                "performance_ratio": comparison.performance_ratio,
                "memory_ratio": comparison.memory_ratio,
                "improvement_percent": comparison.improvement_percent,
                "regression_detected": comparison.regression_detected,
                "original_duration": comparison.original_result.duration_seconds,
                "refactored_duration": comparison.refactored_result.duration_seconds,
                "original_memory": comparison.original_result.memory_usage_mb,
                "refactored_memory": comparison.refactored_result.memory_usage_mb,
            }
            analysis["operation_results"].append(operation_analysis)

        # Performance analysis
        analysis["performance_analysis"] = {
            "fastest_operation": min(
                self.comparisons, key=lambda c: c.refactored_result.duration_seconds
            ).operation,
            "slowest_operation": max(
                self.comparisons, key=lambda c: c.refactored_result.duration_seconds
            ).operation,
            "most_improved": max(self.comparisons, key=lambda c: c.improvement_percent).operation,
            "most_regressed": (
                max(self.comparisons, key=lambda c: c.performance_ratio).operation
                if any(c.regression_detected for c in self.comparisons)
                else None
            ),
        }

        # Generate recommendations
        analysis["recommendations"] = self._generate_recommendations()

        return analysis

    def _generate_recommendations(self) -> List[str]:
        """Generate performance recommendations based on benchmark results."""
        recommendations = []

        # Check for regressions
        regressions = [c for c in self.comparisons if c.regression_detected]
        if regressions:
            recommendations.append(
                f"Performance regressions detected in {len(regressions)} operations: "
                f"{', '.join(r.operation for r in regressions)}. Consider optimization."
            )

        # Check memory usage
        high_memory_ops = [c for c in self.comparisons if c.memory_ratio > 1.2]
        if high_memory_ops:
            recommendations.append(
                f"Memory usage increased significantly in: "
                f"{', '.join(op.operation for op in high_memory_ops)}. Review memory management."
            )

        # Check for improvements
        improvements = [c for c in self.comparisons if c.improvement_percent > 10]
        if improvements:
            recommendations.append(
                f"Significant performance improvements in: "
                f"{', '.join(imp.operation for imp in improvements)}. Good refactoring results!"
            )

        # Overall assessment
        overall_ratio = statistics.mean(
            c.performance_ratio for c in self.comparisons if c.performance_ratio != float("inf")
        )
        if overall_ratio < 0.9:
            recommendations.append("Overall performance improved after refactoring.")
        elif overall_ratio > 1.1:
            recommendations.append(
                "Overall performance degraded after refactoring. Review implementation."
            )
        else:
            recommendations.append("Overall performance maintained after refactoring.")

        return recommendations

    def save_results(self, output_path: str) -> None:
        """Save benchmark results to JSON file."""
        results_data = {
            "timestamp": datetime.now().isoformat(),
            "results": [asdict(r) for r in self.results],
            "comparisons": [asdict(c) for c in self.comparisons],
            "analysis": self._generate_analysis(),
        }

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w") as f:
            json.dump(results_data, f, indent=2, default=str)

        logger.info(f"Benchmark results saved to {output_path}")

    def print_summary(self) -> None:
        """Print a summary of benchmark results."""
        analysis = self._generate_analysis()

        print("\n" + "=" * 60)
        print("PERFORMANCE BENCHMARK SUMMARY")
        print("=" * 60)

        summary = analysis["summary"]
        print(f"Operations tested: {summary['total_operations_tested']}")
        print(f"Regressions detected: {summary['regressions_detected']}")
        print(f"Overall performance ratio: {summary['overall_performance_ratio']:.3f}")
        print(f"Overall memory ratio: {summary['overall_memory_ratio']:.3f}")

        print("\nOPERATION DETAILS:")
        print("-" * 60)
        for result in analysis["operation_results"]:
            status = "REGRESSION" if result["regression_detected"] else "OK"
            print(f"{result['operation']:20} | {result['improvement_percent']:+6.1f}% | {status}")

        print("\nRECOMMENDATIONS:")
        print("-" * 60)
        for rec in analysis["recommendations"]:
            print(f"• {rec}")

        print("=" * 60)


async def main():
    """Main function to run performance benchmarks."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    benchmark = PerformanceBenchmark()

    print("Starting Adaptive Engine Performance Benchmark...")
    print("This will compare the original and refactored systems.")

    # Run benchmark with 3 iterations for statistical significance
    results = await benchmark.run_full_benchmark(iterations=3)

    # Print summary
    benchmark.print_summary()

    # Save detailed results
    output_path = Path(__file__).parent / "benchmark_results.json"
    benchmark.save_results(str(output_path))

    print(f"\nDetailed results saved to: {output_path}")

    # Return success/failure based on regressions
    regressions = results["summary"]["regressions_detected"]
    if regressions > 0:
        print(f"\n⚠️  WARNING: {regressions} performance regressions detected!")
        return False
    else:
        print("\n✅ No performance regressions detected!")
        return True


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
