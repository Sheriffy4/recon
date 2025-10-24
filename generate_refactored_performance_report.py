#!/usr/bin/env python3
"""
Generate Refactored Performance Report

This script generates a new performance report using the same benchmarks as the baseline
to compare performance after the attack system refactoring.

Part of Task 19.1: Generate new performance report
Requirements: 9.6
"""

import json
import time
import statistics
import psutil
import os
from datetime import datetime
from typing import Dict, Any

from core.bypass.attacks.attack_registry import get_attack_registry
from core.bypass.engine.attack_dispatcher import AttackDispatcher
from core.bypass.techniques.primitives import BypassTechniques


class RefactoredPerformanceBenchmark:
    """Performance benchmark for refactored attack system."""

    def __init__(self):
        """Initialize benchmark with real components."""
        self.registry = get_attack_registry()
        self.techniques = BypassTechniques()
        self.dispatcher = AttackDispatcher(self.techniques, self.registry)

        # Test payloads (same as baseline)
        self.small_payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"  # 34 bytes
        self.medium_payload = (
            b"GET /api/data HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\nContent-Type: application/json\r\n\r\n"
            * 5
        )  # ~350 bytes
        self.large_payload = (
            b"POST /upload HTTP/1.1\r\nHost: bigsite.com\r\nContent-Length: 1000\r\n\r\n"
            + b"A" * 1000
        )  # ~1044 bytes

        # Test iterations (same as baseline)
        self.test_iterations = 50

        # Attack types to test (same as baseline)
        self.attack_types = [
            "fakeddisorder",
            "seqovl",
            "multidisorder",
            "disorder",
            "multisplit",
        ]

    def get_test_params(self, attack_type: str) -> Dict[str, Any]:
        """Get test parameters for each attack type."""
        params_map = {
            "fakeddisorder": {
                "split_pos": 3,
                "ttl": 3,
                "fooling": ["badsum", "badseq"],
            },
            "seqovl": {
                "split_pos": 3,
                "overlap_size": 5,
                "split_seqovl": 5,
                "fake_ttl": 3,
                "fooling": ["badsum"],
            },
            "multidisorder": {"positions": [1, 5, 10], "ttl": 3, "fooling": ["badsum"]},
            "disorder": {"split_pos": 3},
            "multisplit": {"positions": [1, 5, 10]},
        }
        return params_map.get(attack_type, {"split_pos": 3})

    def benchmark_attack_execution(self, attack_type: str) -> Dict[str, Any]:
        """Benchmark execution time for a specific attack type."""
        print(f"  Benchmarking {attack_type}...")

        params = self.get_test_params(attack_type)
        execution_times = []
        successful_tests = 0
        failed_tests = 0

        for i in range(self.test_iterations):
            try:
                start_time = time.perf_counter()

                # Execute attack through dispatcher
                result = self.dispatcher.dispatch_attack(
                    task_type=attack_type,
                    params=params,
                    payload=self.medium_payload,
                    packet_info={},
                )

                end_time = time.perf_counter()
                execution_time = (
                    end_time - start_time
                ) * 1000  # Convert to milliseconds

                # Validate result
                if result and isinstance(result, list) and len(result) > 0:
                    execution_times.append(execution_time)
                    successful_tests += 1
                else:
                    failed_tests += 1
                    print(
                        f"    Warning: Invalid result for {attack_type} iteration {i+1}"
                    )

            except Exception as e:
                failed_tests += 1
                print(f"    Error in {attack_type} iteration {i+1}: {e}")

        if not execution_times:
            return {
                "avg_time_ms": 0,
                "std_dev_ms": 0,
                "min_time_ms": 0,
                "max_time_ms": 0,
                "iterations": 0,
                "success_rate": 0.0,
                "successful_tests": 0,
                "failed_tests": self.test_iterations,
            }

        # Calculate statistics
        avg_time = statistics.mean(execution_times)
        std_dev = statistics.stdev(execution_times) if len(execution_times) > 1 else 0
        min_time = min(execution_times)
        max_time = max(execution_times)
        success_rate = successful_tests / self.test_iterations

        return {
            "avg_time_ms": avg_time,
            "std_dev_ms": std_dev,
            "min_time_ms": min_time,
            "max_time_ms": max_time,
            "iterations": len(execution_times),
            "success_rate": success_rate,
            "successful_tests": successful_tests,
            "failed_tests": failed_tests,
        }

    def benchmark_memory_usage(self) -> Dict[str, Any]:
        """Benchmark memory usage during attack dispatches."""
        print("  Benchmarking memory usage...")

        process = psutil.Process(os.getpid())
        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Perform 100 dispatches
        num_dispatches = 100
        attack_type = "fakeddisorder"
        params = self.get_test_params(attack_type)

        for _ in range(num_dispatches):
            try:
                self.dispatcher.dispatch_attack(
                    task_type=attack_type,
                    params=params,
                    payload=self.medium_payload,
                    packet_info={},
                )
            except Exception as e:
                print(f"    Memory test dispatch error: {e}")

        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - baseline_memory
        memory_per_dispatch = (
            memory_increase * 1024
        ) / num_dispatches  # KB per dispatch

        return {
            "baseline_mb": baseline_memory,
            "after_100_dispatches_mb": final_memory,
            "memory_increase_mb": memory_increase,
            "memory_per_dispatch_kb": memory_per_dispatch,
        }

    def benchmark_throughput(self) -> Dict[str, Any]:
        """Benchmark throughput (dispatches per second)."""
        print("  Benchmarking throughput...")

        attack_type = "fakeddisorder"
        params = self.get_test_params(attack_type)
        num_dispatches = 50

        start_time = time.perf_counter()

        successful_dispatches = 0
        for _ in range(num_dispatches):
            try:
                result = self.dispatcher.dispatch_attack(
                    task_type=attack_type,
                    params=params,
                    payload=self.medium_payload,
                    packet_info={},
                )
                if result:
                    successful_dispatches += 1
            except Exception as e:
                print(f"    Throughput test dispatch error: {e}")

        end_time = time.perf_counter()
        total_time = end_time - start_time

        dispatches_per_second = (
            successful_dispatches / total_time if total_time > 0 else 0
        )

        return {
            "dispatches_per_second": dispatches_per_second,
            "total_time_50_dispatches": total_time,
            "successful_dispatches": successful_dispatches,
            "total_dispatches": num_dispatches,
        }

    def run_full_benchmark(self) -> Dict[str, Any]:
        """Run complete performance benchmark."""
        print("Starting refactored performance benchmark...")
        print(f"Test iterations per attack: {self.test_iterations}")
        print(f"Attack types: {', '.join(self.attack_types)}")

        # System information
        system_info = {
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": psutil.virtual_memory().total / (1024**3),
            "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
            "platform": os.sys.platform,
        }

        # Benchmark execution times
        print("\nBenchmarking attack execution times...")
        execution_times = {}
        success_rates = {}

        for attack_type in self.attack_types:
            result = self.benchmark_attack_execution(attack_type)
            execution_times[attack_type] = {
                "avg_time_ms": result["avg_time_ms"],
                "std_dev_ms": result["std_dev_ms"],
                "min_time_ms": result["min_time_ms"],
                "max_time_ms": result["max_time_ms"],
                "iterations": result["iterations"],
            }
            success_rates[attack_type] = {
                "success_rate": result["success_rate"],
                "total_tests": self.test_iterations,
                "successful_tests": result["successful_tests"],
                "failed_tests": result["failed_tests"],
            }

        # Benchmark memory usage
        print("\nBenchmarking memory usage...")
        memory_usage = self.benchmark_memory_usage()

        # Benchmark throughput
        print("\nBenchmarking throughput...")
        throughput_metrics = self.benchmark_throughput()

        # Calculate performance summary
        valid_times = [
            stats["avg_time_ms"]
            for stats in execution_times.values()
            if stats["avg_time_ms"] > 0
        ]

        if valid_times:
            fastest_attack = min(
                execution_times.keys(), key=lambda k: execution_times[k]["avg_time_ms"]
            )
            slowest_attack = max(
                execution_times.keys(), key=lambda k: execution_times[k]["avg_time_ms"]
            )
            average_execution_time = statistics.mean(valid_times)
        else:
            fastest_attack = "none"
            slowest_attack = "none"
            average_execution_time = 0

        performance_summary = {
            "fastest_attack": fastest_attack,
            "slowest_attack": slowest_attack,
            "total_attacks_tested": len(self.attack_types),
            "average_execution_time_ms": average_execution_time,
        }

        # Payload sizes (same as baseline)
        payload_sizes = {
            "small_bytes": len(self.small_payload),
            "medium_bytes": len(self.medium_payload),
            "large_bytes": len(self.large_payload),
        }

        # Compile full report
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "test_environment": "refactored",
                "system_info": system_info,
                "test_iterations_per_attack": self.test_iterations,
            },
            "execution_times": execution_times,
            "memory_usage": memory_usage,
            "throughput_metrics": throughput_metrics,
            "success_rates": success_rates,
            "payload_sizes": payload_sizes,
            "performance_summary": performance_summary,
        }

        return report


def main():
    """Main function to generate refactored performance report."""
    print("=" * 70)
    print("REFACTORED ATTACK SYSTEM PERFORMANCE BENCHMARK")
    print("=" * 70)

    try:
        # Initialize benchmark
        benchmark = RefactoredPerformanceBenchmark()

        # Run benchmark
        report = benchmark.run_full_benchmark()

        # Save report
        output_file = "refactored_performance.json"
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n✅ Performance report saved to {output_file}")

        # Print summary
        print("\n" + "=" * 70)
        print("PERFORMANCE SUMMARY")
        print("=" * 70)

        execution_times = report["execution_times"]
        for attack_type, stats in execution_times.items():
            if stats["avg_time_ms"] > 0:
                print(
                    f"{attack_type:15} | Avg: {stats['avg_time_ms']:8.3f}ms | "
                    f"Std: {stats['std_dev_ms']:8.3f}ms | "
                    f"Range: {stats['min_time_ms']:6.3f}-{stats['max_time_ms']:8.3f}ms"
                )
            else:
                print(f"{attack_type:15} | FAILED - No successful executions")

        memory = report["memory_usage"]
        throughput = report["throughput_metrics"]

        print("\nMemory Usage:")
        print(f"  Baseline: {memory['baseline_mb']:.1f} MB")
        print(f"  After 100 dispatches: {memory['after_100_dispatches_mb']:.1f} MB")
        print(
            f"  Increase: {memory['memory_increase_mb']:.1f} MB ({memory['memory_per_dispatch_kb']:.2f} KB/dispatch)"
        )

        print("\nThroughput:")
        print(f"  {throughput['dispatches_per_second']:.1f} dispatches/second")
        print(
            f"  Total time for 50 dispatches: {throughput['total_time_50_dispatches']:.3f}s"
        )

        summary = report["performance_summary"]
        print("\nOverall:")
        print(f"  Fastest attack: {summary['fastest_attack']}")
        print(f"  Slowest attack: {summary['slowest_attack']}")
        print(f"  Average execution time: {summary['average_execution_time_ms']:.3f}ms")

        print("\n✅ Refactored performance benchmark completed successfully!")

    except Exception as e:
        print(f"\n❌ Performance benchmark failed: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
