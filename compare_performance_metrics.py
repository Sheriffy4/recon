#!/usr/bin/env python3
"""
Compare Performance Metrics

This script compares the refactored performance report with the baseline
to identify performance improvements and regressions.

Part of Task 19.2: Compare performance metrics
Requirements: 9.6
"""

import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime


class PerformanceComparator:
    """Compare performance metrics between baseline and refactored versions."""

    def __init__(
        self,
        baseline_file: str = "baseline_performance.json",
        refactored_file: str = "refactored_performance.json",
    ):
        """Initialize with baseline and refactored performance files."""
        self.baseline_file = baseline_file
        self.refactored_file = refactored_file
        self.baseline_data = None
        self.refactored_data = None

        # Performance thresholds
        self.regression_threshold = 0.05  # 5% regression threshold
        self.significant_improvement_threshold = 0.10  # 10% improvement threshold

    def load_performance_data(self) -> bool:
        """Load both baseline and refactored performance data."""
        try:
            # Load baseline data
            if not Path(self.baseline_file).exists():
                print(f"❌ Baseline file not found: {self.baseline_file}")
                return False

            with open(self.baseline_file, "r") as f:
                self.baseline_data = json.load(f)
            print(f"✅ Loaded baseline data from {self.baseline_file}")

            # Load refactored data
            if not Path(self.refactored_file).exists():
                print(f"❌ Refactored file not found: {self.refactored_file}")
                return False

            with open(self.refactored_file, "r") as f:
                self.refactored_data = json.load(f)
            print(f"✅ Loaded refactored data from {self.refactored_file}")

            return True

        except Exception as e:
            print(f"❌ Error loading performance data: {e}")
            return False

    def compare_execution_times(self) -> Dict[str, Any]:
        """Compare execution times between baseline and refactored versions."""
        print("\n" + "=" * 70)
        print("EXECUTION TIME COMPARISON")
        print("=" * 70)

        baseline_times = self.baseline_data.get("execution_times", {})
        refactored_times = self.refactored_data.get("execution_times", {})

        comparison_results = {
            "improvements": [],
            "regressions": [],
            "similar": [],
            "missing_attacks": [],
            "new_attacks": [],
        }

        # Find common attacks
        baseline_attacks = set(baseline_times.keys())
        refactored_attacks = set(refactored_times.keys())
        common_attacks = baseline_attacks.intersection(refactored_attacks)

        # Identify missing and new attacks
        comparison_results["missing_attacks"] = list(
            baseline_attacks - refactored_attacks
        )
        comparison_results["new_attacks"] = list(refactored_attacks - baseline_attacks)

        print(f"📊 Comparing {len(common_attacks)} common attacks")
        if comparison_results["missing_attacks"]:
            print(
                f"⚠️ Missing attacks in refactored: {comparison_results['missing_attacks']}"
            )
        if comparison_results["new_attacks"]:
            print(f"✨ New attacks in refactored: {comparison_results['new_attacks']}")

        print(
            f"\n{'Attack':<15} {'Baseline (ms)':<12} {'Refactored (ms)':<14} {'Delta':<8} {'Status'}"
        )
        print("-" * 70)

        for attack in sorted(common_attacks):
            baseline_avg = baseline_times[attack]["avg_time_ms"]
            refactored_avg = refactored_times[attack]["avg_time_ms"]

            # Calculate performance delta
            if baseline_avg > 0:
                delta_ratio = (refactored_avg - baseline_avg) / baseline_avg
                delta_percent = delta_ratio * 100
            else:
                delta_ratio = 0
                delta_percent = 0

            # Determine status
            if abs(delta_ratio) < self.regression_threshold:
                status = "✅ SIMILAR"
                comparison_results["similar"].append(
                    {
                        "attack": attack,
                        "baseline_ms": baseline_avg,
                        "refactored_ms": refactored_avg,
                        "delta_percent": delta_percent,
                    }
                )
            elif delta_ratio > self.regression_threshold:
                status = "❌ REGRESSION"
                comparison_results["regressions"].append(
                    {
                        "attack": attack,
                        "baseline_ms": baseline_avg,
                        "refactored_ms": refactored_avg,
                        "delta_percent": delta_percent,
                    }
                )
            else:
                status = "🚀 IMPROVEMENT"
                comparison_results["improvements"].append(
                    {
                        "attack": attack,
                        "baseline_ms": baseline_avg,
                        "refactored_ms": refactored_avg,
                        "delta_percent": delta_percent,
                    }
                )

            print(
                f"{attack:<15} {baseline_avg:<12.3f} {refactored_avg:<14.3f} {delta_percent:<+7.1f}% {status}"
            )

        return comparison_results

    def compare_memory_usage(self) -> Dict[str, Any]:
        """Compare memory usage between baseline and refactored versions."""
        print("\n" + "=" * 70)
        print("MEMORY USAGE COMPARISON")
        print("=" * 70)

        baseline_memory = self.baseline_data.get("memory_usage", {})
        refactored_memory = self.refactored_data.get("memory_usage", {})

        comparison = {}

        # Compare baseline memory
        baseline_mb = baseline_memory.get("baseline_mb", 0)
        refactored_mb = refactored_memory.get("baseline_mb", 0)
        baseline_delta = refactored_mb - baseline_mb

        print("Baseline Memory:")
        print(f"  Original: {baseline_mb:.1f} MB")
        print(f"  Refactored: {refactored_mb:.1f} MB")
        print(f"  Delta: {baseline_delta:+.1f} MB")

        comparison["baseline_memory_delta_mb"] = baseline_delta

        # Compare memory increase per dispatch
        baseline_per_dispatch = baseline_memory.get("memory_per_dispatch_kb", 0)
        refactored_per_dispatch = refactored_memory.get("memory_per_dispatch_kb", 0)
        per_dispatch_delta = refactored_per_dispatch - baseline_per_dispatch

        print("\nMemory per Dispatch:")
        print(f"  Original: {baseline_per_dispatch:.2f} KB/dispatch")
        print(f"  Refactored: {refactored_per_dispatch:.2f} KB/dispatch")
        print(f"  Delta: {per_dispatch_delta:+.2f} KB/dispatch")

        comparison["per_dispatch_delta_kb"] = per_dispatch_delta

        # Overall memory assessment
        if abs(baseline_delta) < 10 and abs(per_dispatch_delta) < 1:
            memory_status = "✅ SIMILAR"
        elif baseline_delta > 10 or per_dispatch_delta > 1:
            memory_status = "⚠️ INCREASED"
        else:
            memory_status = "🚀 IMPROVED"

        comparison["status"] = memory_status
        print(f"\nMemory Status: {memory_status}")

        return comparison

    def compare_throughput(self) -> Dict[str, Any]:
        """Compare throughput between baseline and refactored versions."""
        print("\n" + "=" * 70)
        print("THROUGHPUT COMPARISON")
        print("=" * 70)

        baseline_throughput = self.baseline_data.get("throughput_metrics", {})
        refactored_throughput = self.refactored_data.get("throughput_metrics", {})

        baseline_dps = baseline_throughput.get("dispatches_per_second", 0)
        refactored_dps = refactored_throughput.get("dispatches_per_second", 0)

        if baseline_dps > 0:
            throughput_delta = (refactored_dps - baseline_dps) / baseline_dps * 100
        else:
            throughput_delta = 0

        print("Dispatches per Second:")
        print(f"  Original: {baseline_dps:.1f} dispatches/sec")
        print(f"  Refactored: {refactored_dps:.1f} dispatches/sec")
        print(f"  Delta: {throughput_delta:+.1f}%")

        # Determine throughput status
        if abs(throughput_delta) < 5:
            throughput_status = "✅ SIMILAR"
        elif throughput_delta < -5:
            throughput_status = "❌ DECREASED"
        else:
            throughput_status = "🚀 IMPROVED"

        print(f"Throughput Status: {throughput_status}")

        return {
            "baseline_dps": baseline_dps,
            "refactored_dps": refactored_dps,
            "delta_percent": throughput_delta,
            "status": throughput_status,
        }

    def compare_success_rates(self) -> Dict[str, Any]:
        """Compare success rates between baseline and refactored versions."""
        print("\n" + "=" * 70)
        print("SUCCESS RATE COMPARISON")
        print("=" * 70)

        baseline_success = self.baseline_data.get("success_rates", {})
        refactored_success = self.refactored_data.get("success_rates", {})

        comparison_results = {
            "improved": [],
            "degraded": [],
            "similar": [],
            "missing": [],
        }

        print(f"{'Attack':<15} {'Baseline':<10} {'Refactored':<12} {'Status'}")
        print("-" * 50)

        for attack in sorted(
            set(baseline_success.keys()).union(set(refactored_success.keys()))
        ):
            baseline_rate = baseline_success.get(attack, {}).get("success_rate", 0)
            refactored_rate = refactored_success.get(attack, {}).get("success_rate", 0)

            if attack not in refactored_success:
                status = "❌ MISSING"
                comparison_results["missing"].append(attack)
            elif baseline_rate == refactored_rate:
                status = "✅ SAME"
                comparison_results["similar"].append(attack)
            elif refactored_rate > baseline_rate:
                status = "🚀 IMPROVED"
                comparison_results["improved"].append(attack)
            else:
                status = "⚠️ DEGRADED"
                comparison_results["degraded"].append(attack)

            print(
                f"{attack:<15} {baseline_rate:<10.1%} {refactored_rate:<12.1%} {status}"
            )

        return comparison_results

    def generate_summary_report(
        self,
        execution_comparison: Dict[str, Any],
        memory_comparison: Dict[str, Any],
        throughput_comparison: Dict[str, Any],
        success_comparison: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate comprehensive summary report."""
        print("\n" + "=" * 70)
        print("PERFORMANCE COMPARISON SUMMARY")
        print("=" * 70)

        # Count improvements and regressions
        num_improvements = len(execution_comparison["improvements"])
        num_regressions = len(execution_comparison["regressions"])
        num_similar = len(execution_comparison["similar"])

        print("📊 Execution Time Analysis:")
        print(f"  🚀 Improvements: {num_improvements}")
        print(f"  ❌ Regressions: {num_regressions}")
        print(f"  ✅ Similar: {num_similar}")

        # Highlight significant changes
        if execution_comparison["regressions"]:
            print("\n⚠️ Performance Regressions:")
            for regression in execution_comparison["regressions"]:
                print(
                    f"  - {regression['attack']}: {regression['delta_percent']:+.1f}% "
                    f"({regression['baseline_ms']:.3f}ms → {regression['refactored_ms']:.3f}ms)"
                )

        if execution_comparison["improvements"]:
            print("\n🚀 Performance Improvements:")
            for improvement in execution_comparison["improvements"]:
                print(
                    f"  - {improvement['attack']}: {improvement['delta_percent']:+.1f}% "
                    f"({improvement['baseline_ms']:.3f}ms → {improvement['refactored_ms']:.3f}ms)"
                )

        # Memory summary
        print(f"\n💾 Memory Usage: {memory_comparison['status']}")
        if abs(memory_comparison["baseline_memory_delta_mb"]) > 1:
            print(
                f"  - Baseline memory change: {memory_comparison['baseline_memory_delta_mb']:+.1f} MB"
            )
        if abs(memory_comparison["per_dispatch_delta_kb"]) > 0.1:
            print(
                f"  - Per-dispatch memory change: {memory_comparison['per_dispatch_delta_kb']:+.2f} KB"
            )

        # Throughput summary
        print(f"\n⚡ Throughput: {throughput_comparison['status']}")
        if abs(throughput_comparison["delta_percent"]) > 1:
            print(
                f"  - Change: {throughput_comparison['delta_percent']:+.1f}% "
                f"({throughput_comparison['baseline_dps']:.1f} → {throughput_comparison['refactored_dps']:.1f} dispatches/sec)"
            )

        # Success rate summary
        if success_comparison["degraded"]:
            print("\n⚠️ Success Rate Issues:")
            for attack in success_comparison["degraded"]:
                print(f"  - {attack}: Success rate decreased")

        # Overall assessment
        print("\n" + "=" * 70)

        critical_regressions = [
            r for r in execution_comparison["regressions"] if r["delta_percent"] > 20
        ]  # >20% regression

        if critical_regressions:
            overall_status = "❌ CRITICAL REGRESSIONS DETECTED"
            print(f"{overall_status}")
            print(f"Critical regressions (>20% slower): {len(critical_regressions)}")
        elif num_regressions > num_improvements:
            overall_status = "⚠️ MORE REGRESSIONS THAN IMPROVEMENTS"
            print(f"{overall_status}")
        elif num_improvements > num_regressions:
            overall_status = "🚀 NET PERFORMANCE IMPROVEMENT"
            print(f"{overall_status}")
        else:
            overall_status = "✅ PERFORMANCE MAINTAINED"
            print(f"{overall_status}")

        # Create summary data
        summary = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": overall_status,
            "execution_times": {
                "improvements": num_improvements,
                "regressions": num_regressions,
                "similar": num_similar,
                "critical_regressions": len(critical_regressions),
            },
            "memory": memory_comparison,
            "throughput": throughput_comparison,
            "success_rates": success_comparison,
            "detailed_execution_comparison": execution_comparison,
        }

        return summary

    def save_comparison_report(
        self, summary: Dict[str, Any], output_file: str = "performance_comparison.json"
    ):
        """Save detailed comparison report to file."""
        try:
            with open(output_file, "w") as f:
                json.dump(summary, f, indent=2)
            print(f"\n💾 Detailed comparison report saved to {output_file}")
        except Exception as e:
            print(f"❌ Failed to save comparison report: {e}")

    def run_full_comparison(self) -> bool:
        """Run complete performance comparison analysis."""
        print("=" * 70)
        print("PERFORMANCE COMPARISON ANALYSIS")
        print("=" * 70)

        # Load data
        if not self.load_performance_data():
            return False

        # Run comparisons
        execution_comparison = self.compare_execution_times()
        memory_comparison = self.compare_memory_usage()
        throughput_comparison = self.compare_throughput()
        success_comparison = self.compare_success_rates()

        # Generate summary
        summary = self.generate_summary_report(
            execution_comparison,
            memory_comparison,
            throughput_comparison,
            success_comparison,
        )

        # Save detailed report
        self.save_comparison_report(summary)

        # Return success status
        critical_regressions = [
            r for r in execution_comparison["regressions"] if r["delta_percent"] > 20
        ]
        return len(critical_regressions) == 0


def main():
    """Main function to run performance comparison."""
    comparator = PerformanceComparator()

    success = comparator.run_full_comparison()

    if success:
        print("\n✅ Performance comparison completed successfully!")
        return 0
    else:
        print("\n❌ Performance comparison completed with critical issues!")
        return 1


if __name__ == "__main__":
    exit(main())
