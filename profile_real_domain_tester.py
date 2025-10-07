"""
Real Domain Tester Profiling and Optimization Script

This script profiles the real domain tester operations and implements optimizations:
- Profile DNS resolution and attack execution
- Optimize parallel execution worker pool size
- Add connection pooling for network operations
- Measure throughput and optimize bottlenecks

Part of Task 8.1: Profile and optimize real domain tester
"""

import time
import logging
from pathlib import Path
from typing import List, Dict, Any

from core.real_domain_tester import RealDomainTester
from core.attack_execution_engine import ExecutionConfig
from core.performance_profiler import PerformanceProfiler


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_test_domains(count: int = 10) -> List[str]:
    """Create test domains for profiling."""
    # Use well-known domains that should resolve quickly
    base_domains = [
        "google.com",
        "cloudflare.com",
        "github.com",
        "microsoft.com",
        "amazon.com",
        "facebook.com",
        "twitter.com",
        "linkedin.com",
        "stackoverflow.com",
        "reddit.com"
    ]
    
    # Repeat if needed
    domains = []
    while len(domains) < count:
        domains.extend(base_domains)
    
    return domains[:count]


def profile_dns_resolution(profiler: PerformanceProfiler, tester: RealDomainTester):
    """Profile DNS resolution performance."""
    logger.info("Profiling DNS resolution...")
    
    domains = create_test_domains(20)
    
    # Profile without cache
    tester.clear_dns_cache()
    
    with profiler.profile_operation("dns_resolution_no_cache") as metrics:
        for domain in domains:
            tester.resolve_domain(domain, use_cache=False)
    
    metrics.details['domain_count'] = len(domains)
    metrics.details['avg_time_per_domain'] = metrics.execution_time / len(domains)
    
    logger.info(
        f"DNS resolution (no cache): {metrics.execution_time:.4f}s "
        f"({metrics.details['avg_time_per_domain']:.4f}s per domain)"
    )
    
    # Profile with cache
    tester.clear_dns_cache()
    
    # First pass to populate cache
    for domain in domains:
        tester.resolve_domain(domain, use_cache=True)
    
    # Second pass with cache
    with profiler.profile_operation("dns_resolution_with_cache") as metrics:
        for domain in domains:
            tester.resolve_domain(domain, use_cache=True)
    
    metrics.details['domain_count'] = len(domains)
    metrics.details['avg_time_per_domain'] = metrics.execution_time / len(domains)
    
    logger.info(
        f"DNS resolution (with cache): {metrics.execution_time:.4f}s "
        f"({metrics.details['avg_time_per_domain']:.4f}s per domain)"
    )
    
    # Get cache stats
    cache_stats = tester.get_dns_cache_stats()
    logger.info(f"DNS cache stats: {cache_stats}")


def profile_parallel_execution(profiler: PerformanceProfiler):
    """Profile parallel execution with different worker pool sizes."""
    logger.info("Profiling parallel execution...")
    
    domains = create_test_domains(10)
    attacks = ["fake", "split"]  # Simple attacks for testing
    
    worker_counts = [1, 2, 4, 8]
    
    for workers in worker_counts:
        config = ExecutionConfig(
            capture_pcap=False,  # Disable PCAP for faster testing
            timeout=5.0
        )
        
        tester = RealDomainTester(
            execution_config=config,
            enable_pcap_validation=False,
            max_workers=workers
        )
        
        with profiler.profile_operation(f"parallel_execution_{workers}_workers") as metrics:
            report = tester.test_domains(
                domains=domains[:5],  # Use subset for faster testing
                attacks=attacks,
                parallel=(workers > 1)
            )
        
        metrics.details['worker_count'] = workers
        metrics.details['domain_count'] = len(domains[:5])
        metrics.details['attack_count'] = len(attacks)
        metrics.details['total_tests'] = report.total_tests
        metrics.details['successful_tests'] = report.successful_tests
        metrics.details['throughput'] = report.total_tests / metrics.execution_time if metrics.execution_time > 0 else 0
        
        logger.info(
            f"Parallel execution ({workers} workers): {metrics.execution_time:.4f}s "
            f"({metrics.details['throughput']:.2f} tests/s)"
        )


def profile_attack_execution(profiler: PerformanceProfiler, tester: RealDomainTester):
    """Profile attack execution performance."""
    logger.info("Profiling attack execution...")
    
    domain = "google.com"
    attacks = ["fake", "split", "disorder"]
    
    for attack in attacks:
        with profiler.profile_operation(f"attack_execution_{attack}") as metrics:
            result = tester.test_domain_with_attack(
                domain=domain,
                attack_name=attack,
                attack_params={}
            )
        
        metrics.details['attack'] = attack
        metrics.details['success'] = result.success
        metrics.details['domain'] = domain
        
        logger.info(
            f"Attack execution ({attack}): {metrics.execution_time:.4f}s "
            f"(success={result.success})"
        )


def analyze_bottlenecks(profiler: PerformanceProfiler):
    """Analyze bottlenecks and generate optimization recommendations."""
    logger.info("Analyzing bottlenecks...")
    
    # Find slowest operations
    if not profiler.metrics:
        logger.warning("No metrics collected")
        return
    
    sorted_metrics = sorted(profiler.metrics, key=lambda m: m.execution_time, reverse=True)
    
    logger.info("\nTop 5 slowest operations:")
    for i, metric in enumerate(sorted_metrics[:5], 1):
        logger.info(
            f"  {i}. {metric.operation_name}: {metric.execution_time:.4f}s"
        )
    
    # Analyze DNS resolution
    dns_metrics = [m for m in profiler.metrics if 'dns_resolution' in m.operation_name]
    if dns_metrics:
        logger.info("\nDNS Resolution Analysis:")
        for metric in dns_metrics:
            avg_time = metric.details.get('avg_time_per_domain', 0)
            logger.info(
                f"  {metric.operation_name}: {avg_time:.4f}s per domain"
            )
    
    # Analyze parallel execution
    parallel_metrics = [m for m in profiler.metrics if 'parallel_execution' in m.operation_name]
    if parallel_metrics:
        logger.info("\nParallel Execution Analysis:")
        for metric in parallel_metrics:
            workers = metric.details.get('worker_count', 0)
            throughput = metric.details.get('throughput', 0)
            logger.info(
                f"  {workers} workers: {throughput:.2f} tests/s"
            )
        
        # Find optimal worker count
        if len(parallel_metrics) > 1:
            best_metric = max(parallel_metrics, key=lambda m: m.details.get('throughput', 0))
            logger.info(
                f"\nOptimal worker count: {best_metric.details.get('worker_count')} "
                f"({best_metric.details.get('throughput', 0):.2f} tests/s)"
            )


def main():
    """Main profiling function."""
    logger.info("Starting real domain tester profiling...")
    
    # Initialize profiler
    profiler = PerformanceProfiler(Path("profiling_results"))
    
    # Initialize tester with default config
    config = ExecutionConfig(
        capture_pcap=False,  # Disable PCAP for faster testing
        timeout=5.0
    )
    
    tester = RealDomainTester(
        execution_config=config,
        enable_pcap_validation=False,
        max_workers=4
    )
    
    # Profile operations
    profile_dns_resolution(profiler, tester)
    profile_attack_execution(profiler, tester)
    profile_parallel_execution(profiler)
    
    # Analyze bottlenecks
    analyze_bottlenecks(profiler)
    
    # Generate report
    report = profiler.generate_report("real_domain_tester", include_recommendations=True)
    
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
