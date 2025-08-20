#!/usr/bin/env python3
"""
Demonstration of the Comprehensive Reliability Validation System.

This script shows how to use the ReliabilityValidator for:
- Multi-level accessibility checking
- Strategy effectiveness validation
- False positive detection
- Batch validation of multiple strategies
- Comprehensive reliability reporting
"""

import asyncio
import logging

from reliability_validator import (
    ReliabilityValidator,
    validate_domain_accessibility,
    validate_strategy_reliability,
)


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def demo_basic_accessibility_check():
    """Demonstrate basic domain accessibility checking."""
    print("\n" + "=" * 60)
    print("DEMO: Basic Domain Accessibility Check")
    print("=" * 60)

    validator = ReliabilityValidator(timeout=10.0)

    # Test domains with different characteristics
    test_domains = [
        ("httpbin.org", 80),
        ("httpbin.org", 443),
        ("example.com", 80),
        ("example.com", 443),
    ]

    for domain, port in test_domains:
        print(f"\nTesting {domain}:{port}...")

        try:
            result = await validator.multi_level_accessibility_check(domain, port)

            print(f"  Status: {result.status.value}")
            print(f"  Reliability Score: {result.reliability_score:.2f}")
            print(f"  Bypass Effectiveness: {result.bypass_effectiveness:.2f}")
            print(f"  Successful Tests: {result.successful_tests}/{result.total_tests}")
            print(f"  Average Response Time: {result.average_response_time:.2f}s")
            print(f"  False Positive Detected: {result.false_positive_detected}")

            # Show validation method results
            print("  Validation Methods:")
            for val_result in result.validation_results:
                status = "✓" if val_result.success else "✗"
                print(
                    f"    {status} {val_result.method.value}: {val_result.response_time:.2f}s"
                )
                if val_result.error_message:
                    print(f"      Error: {val_result.error_message}")

        except Exception as e:
            print(f"  Error: {e}")

    validator.cleanup()


async def demo_strategy_effectiveness_validation():
    """Demonstrate strategy effectiveness validation."""
    print("\n" + "=" * 60)
    print("DEMO: Strategy Effectiveness Validation")
    print("=" * 60)

    validator = ReliabilityValidator(timeout=8.0)

    # Simulate different bypass strategies
    strategies = [
        ("tcp_fragmentation_v1", "httpbin.org", 80),
        ("http_header_manipulation", "httpbin.org", 443),
        ("tls_handshake_modification", "example.com", 443),
        ("dns_over_https_tunnel", "example.com", 80),
    ]

    for strategy_id, domain, port in strategies:
        print(f"\nValidating strategy '{strategy_id}' for {domain}:{port}...")

        try:
            result = await validator.validate_strategy_effectiveness(
                strategy_id, domain, port, test_iterations=3
            )

            print(f"  Effectiveness Score: {result.effectiveness_score:.2f}")
            print(f"  Reliability Level: {result.reliability_level.value}")
            print(f"  Consistency Score: {result.consistency_score:.2f}")
            print(f"  Performance Score: {result.performance_score:.2f}")
            print(f"  False Positive Rate: {result.false_positive_rate:.2f}")
            print(f"  Recommendation: {result.recommendation}")

            # Show accessibility results summary
            print(f"  Test Iterations: {len(result.accessibility_results)}")
            for i, acc_result in enumerate(result.accessibility_results):
                print(
                    f"    Iteration {i+1}: {acc_result.status.value} "
                    f"(reliability: {acc_result.reliability_score:.2f})"
                )

        except Exception as e:
            print(f"  Error: {e}")

    validator.cleanup()


async def demo_batch_validation():
    """Demonstrate batch validation of multiple strategies."""
    print("\n" + "=" * 60)
    print("DEMO: Batch Strategy Validation")
    print("=" * 60)

    validator = ReliabilityValidator(max_concurrent_tests=3, timeout=6.0)

    # Define multiple strategy-domain combinations
    strategy_combinations = [
        ("fast_tcp_split", "httpbin.org", 443),
        ("http_chunked_encoding", "httpbin.org", 80),
        ("tls_sni_modification", "example.com", 443),
        ("dns_fragmentation", "example.com", 80),
        ("packet_timing_delay", "httpbin.org", 443),
        ("header_case_modification", "example.com", 80),
    ]

    print(f"Validating {len(strategy_combinations)} strategy combinations...")

    try:
        results = await validator.batch_validate_strategies(
            strategy_combinations, test_iterations=2
        )

        print(f"\nCompleted validation of {len(results)} strategies:")

        # Sort by effectiveness score
        sorted_results = sorted(
            results, key=lambda r: r.effectiveness_score, reverse=True
        )

        for i, result in enumerate(sorted_results, 1):
            print(f"\n{i}. {result.strategy_id} ({result.domain}:{result.port})")
            print(f"   Effectiveness: {result.effectiveness_score:.2f}")
            print(f"   Reliability: {result.reliability_level.value}")
            print(f"   Consistency: {result.consistency_score:.2f}")
            print(f"   Performance: {result.performance_score:.2f}")
            print(f"   Recommendation: {result.recommendation}")

        # Generate comprehensive report
        report = validator.generate_reliability_report(results)

        print("\n" + "-" * 40)
        print("RELIABILITY REPORT SUMMARY")
        print("-" * 40)

        summary = report["summary"]
        print(f"Total Strategies Tested: {summary['total_strategies_tested']}")
        print(f"Average Effectiveness: {summary['avg_effectiveness_score']:.2f}")
        print(f"Average Consistency: {summary['avg_consistency_score']:.2f}")
        print(f"Average Performance: {summary['avg_performance_score']:.2f}")
        print(f"Average False Positive Rate: {summary['avg_false_positive_rate']:.2f}")

        print("\nReliability Distribution:")
        for level, count in report["reliability_distribution"].items():
            print(f"  {level}: {count} strategies")

        print("\nTop Recommendations:")
        for rec in report["recommendations"][:3]:
            print(f"  • {rec}")

    except Exception as e:
        print(f"Batch validation error: {e}")

    validator.cleanup()


async def demo_false_positive_detection():
    """Demonstrate false positive detection capabilities."""
    print("\n" + "=" * 60)
    print("DEMO: False Positive Detection")
    print("=" * 60)

    validator = ReliabilityValidator(timeout=5.0)

    # Simulate scenarios with potential false positives
    print("Testing false positive detection scenarios...")

    # Test with a domain that might have inconsistent responses
    test_domain = "httpbin.org"
    test_port = 443

    print(f"\nRunning multiple accessibility checks for {test_domain}:{test_port}...")

    try:
        # Run multiple checks to detect inconsistencies
        results = []
        for i in range(5):
            result = await validator.multi_level_accessibility_check(
                test_domain, test_port
            )
            results.append(result)
            print(
                f"  Check {i+1}: {result.status.value} "
                f"(reliability: {result.reliability_score:.2f}, "
                f"fp_detected: {result.false_positive_detected})"
            )

        # Analyze consistency across multiple runs
        consistency_score = validator._calculate_consistency_score(results)
        print(f"\nOverall Consistency Score: {consistency_score:.2f}")

        # Calculate false positive rate
        baseline_data = {
            "successful_tests": 7,
            "total_tests": 10,
            "reliability_score": 0.7,
        }

        fp_rate = validator._detect_false_positives(results, baseline_data)
        print(f"False Positive Rate: {fp_rate:.2f}")

        if fp_rate > 0.3:
            print("⚠️  High false positive rate detected - results may be unreliable")
        elif fp_rate > 0.1:
            print("⚠️  Moderate false positive rate - additional validation recommended")
        else:
            print("✓ Low false positive rate - results appear reliable")

    except Exception as e:
        print(f"False positive detection error: {e}")

    validator.cleanup()


async def demo_performance_analysis():
    """Demonstrate performance analysis capabilities."""
    print("\n" + "=" * 60)
    print("DEMO: Performance Analysis")
    print("=" * 60)

    validator = ReliabilityValidator(timeout=10.0)

    # Test different scenarios to analyze performance characteristics
    scenarios = [
        ("Fast Response", "httpbin.org", 80),
        ("HTTPS Overhead", "httpbin.org", 443),
        ("DNS Resolution", "example.com", 80),
        ("SSL Handshake", "example.com", 443),
    ]

    performance_data = []

    for scenario_name, domain, port in scenarios:
        print(f"\nAnalyzing performance for {scenario_name} ({domain}:{port})...")

        try:
            # Run multiple iterations to get performance statistics
            iteration_times = []
            reliability_scores = []

            for i in range(3):
                start_time = asyncio.get_event_loop().time()
                result = await validator.multi_level_accessibility_check(domain, port)
                end_time = asyncio.get_event_loop().time()

                total_time = end_time - start_time
                iteration_times.append(total_time)
                reliability_scores.append(result.reliability_score)

                print(
                    f"  Iteration {i+1}: {total_time:.2f}s total, "
                    f"{result.average_response_time:.2f}s avg response, "
                    f"reliability: {result.reliability_score:.2f}"
                )

            # Calculate performance metrics
            avg_total_time = sum(iteration_times) / len(iteration_times)
            avg_reliability = sum(reliability_scores) / len(reliability_scores)

            performance_data.append(
                {
                    "scenario": scenario_name,
                    "domain": domain,
                    "port": port,
                    "avg_total_time": avg_total_time,
                    "avg_reliability": avg_reliability,
                    "consistency": 1.0
                    - (max(iteration_times) - min(iteration_times)) / avg_total_time,
                }
            )

            print(f"  Average Total Time: {avg_total_time:.2f}s")
            print(f"  Average Reliability: {avg_reliability:.2f}")

        except Exception as e:
            print(f"  Error: {e}")

    # Performance summary
    print("\n" + "-" * 40)
    print("PERFORMANCE ANALYSIS SUMMARY")
    print("-" * 40)

    if performance_data:
        fastest = min(performance_data, key=lambda x: x["avg_total_time"])
        most_reliable = max(performance_data, key=lambda x: x["avg_reliability"])
        most_consistent = max(performance_data, key=lambda x: x["consistency"])

        print(
            f"Fastest Scenario: {fastest['scenario']} ({fastest['avg_total_time']:.2f}s)"
        )
        print(
            f"Most Reliable: {most_reliable['scenario']} ({most_reliable['avg_reliability']:.2f})"
        )
        print(
            f"Most Consistent: {most_consistent['scenario']} ({most_consistent['consistency']:.2f})"
        )

    validator.cleanup()


async def demo_convenience_functions():
    """Demonstrate convenience functions."""
    print("\n" + "=" * 60)
    print("DEMO: Convenience Functions")
    print("=" * 60)

    # Test convenience function for domain accessibility
    print("Testing domain accessibility convenience function...")

    try:
        result = await validate_domain_accessibility("httpbin.org", 443)
        print("Domain Accessibility Result:")
        print(f"  Status: {result.status.value}")
        print(f"  Reliability: {result.reliability_score:.2f}")
        print(f"  Response Time: {result.average_response_time:.2f}s")
    except Exception as e:
        print(f"Error: {e}")

    # Test convenience function for strategy reliability
    print("\nTesting strategy reliability convenience function...")

    try:
        result = await validate_strategy_reliability(
            "demo_strategy", "httpbin.org", 80, iterations=2
        )
        print("Strategy Reliability Result:")
        print(f"  Effectiveness: {result.effectiveness_score:.2f}")
        print(f"  Reliability Level: {result.reliability_level.value}")
        print(f"  Recommendation: {result.recommendation}")
    except Exception as e:
        print(f"Error: {e}")


async def main():
    """Run all demonstration scenarios."""
    print("Comprehensive Reliability Validation System Demo")
    print("=" * 60)

    try:
        await demo_basic_accessibility_check()
        await demo_strategy_effectiveness_validation()
        await demo_batch_validation()
        await demo_false_positive_detection()
        await demo_performance_analysis()
        await demo_convenience_functions()

        print("\n" + "=" * 60)
        print("All demonstrations completed successfully!")
        print("=" * 60)

    except Exception as e:
        logger.error(f"Demo error: {e}")
        print(f"\nDemo error: {e}")


if __name__ == "__main__":
    # Run the demonstration
    asyncio.run(main())
