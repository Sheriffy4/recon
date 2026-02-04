"""
Load Testing for runtime packet filtering.

This module provides comprehensive load testing including:
- High packet rate processing tests
- Large domain list performance tests
- Memory usage and CPU utilization validation
- Performance requirement verification
"""

import time
import threading
import logging
import random
import string
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil
import os

from .runtime_filter import RuntimePacketFilter
from .config import FilterConfig, FilterMode
from .performance_monitor import PerformanceMonitor
from .resource_manager import ResourceManager, ResourceLimits


logger = logging.getLogger(__name__)


@dataclass
class LoadTestConfig:
    """Configuration for load testing."""

    # Test parameters
    packet_count: int = 10000
    concurrent_threads: int = 4
    test_duration_seconds: float = 60.0

    # Domain list sizes to test
    domain_list_sizes: List[int] = None

    # Performance requirements
    max_latency_ms: float = 10.0
    max_memory_mb: float = 500.0
    max_cpu_percent: float = 80.0
    min_throughput_pps: float = 1000.0  # packets per second

    # Test data generation
    generate_realistic_domains: bool = True
    sni_packet_ratio: float = 0.7  # 70% SNI, 30% Host header

    def __post_init__(self):
        if self.domain_list_sizes is None:
            self.domain_list_sizes = [10, 100, 500, 1000, 5000]


@dataclass
class LoadTestResults:
    """Results from load testing."""

    # Test configuration
    config: LoadTestConfig

    # Performance metrics
    total_packets_processed: int = 0
    test_duration_actual: float = 0.0
    throughput_pps: float = 0.0

    # Latency statistics
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    max_latency_ms: float = 0.0

    # Resource usage
    peak_memory_mb: float = 0.0
    avg_cpu_percent: float = 0.0
    peak_cpu_percent: float = 0.0

    # Success rates
    extraction_success_rate: float = 0.0
    cache_hit_rate: float = 0.0

    # Requirements validation
    latency_requirement_met: bool = False
    memory_requirement_met: bool = False
    cpu_requirement_met: bool = False
    throughput_requirement_met: bool = False

    # Domain list performance
    domain_list_results: Dict[int, Dict[str, float]] = None

    def __post_init__(self):
        if self.domain_list_results is None:
            self.domain_list_results = {}


class LoadTester:
    """
    Comprehensive load tester for runtime packet filtering.

    This class provides:
    - High-throughput packet processing tests
    - Scalability testing with large domain lists
    - Resource usage validation
    - Performance requirement verification
    """

    def __init__(self, config: Optional[LoadTestConfig] = None):
        """
        Initialize Load Tester.

        Args:
            config: Load test configuration

        Requirements: 6.3, 6.4
        """
        self.config = config or LoadTestConfig()
        self.results = LoadTestResults(config=self.config)

        # Test data
        self._test_packets = []
        self._test_domains = []

        # Monitoring
        self._process = psutil.Process(os.getpid())

        logger.info(
            f"LoadTester initialized for {self.config.packet_count} packets, {self.config.concurrent_threads} threads"
        )

    def run_comprehensive_test(self) -> LoadTestResults:
        """
        Run comprehensive load testing suite.

        Returns:
            Complete load test results

        Requirements: 6.3, 6.4
        """
        logger.info("Starting comprehensive load testing suite")

        try:
            # Generate test data
            self._generate_test_data()

            # Test with different domain list sizes
            self._test_domain_list_scalability()

            # Run main throughput test
            self._run_throughput_test()

            # Validate performance requirements
            self._validate_requirements()

            logger.info("Comprehensive load testing completed successfully")

        except Exception as e:
            logger.error(f"Error during load testing: {e}")
            raise

        return self.results

    def _generate_test_data(self) -> None:
        """Generate realistic test packets and domains."""
        logger.info("Generating test data")

        # Generate test domains
        self._test_domains = self._generate_realistic_domains(max(self.config.domain_list_sizes))

        # Generate test packets
        self._test_packets = []
        for i in range(self.config.packet_count):
            if random.random() < self.config.sni_packet_ratio:
                # Generate SNI packet
                packet = self._generate_sni_packet()
            else:
                # Generate HTTP packet with Host header
                packet = self._generate_http_packet()

            self._test_packets.append(packet)

        logger.info(
            f"Generated {len(self._test_packets)} test packets and {len(self._test_domains)} domains"
        )

    def _generate_realistic_domains(self, count: int) -> List[str]:
        """
        Generate realistic domain names for testing.

        Args:
            count: Number of domains to generate

        Returns:
            List of domain names
        """
        domains = []

        # Common TLDs
        tlds = [".com", ".org", ".net", ".edu", ".gov", ".io", ".co", ".uk"]

        # Common domain patterns
        patterns = [
            "www.{name}{tld}",
            "api.{name}{tld}",
            "cdn.{name}{tld}",
            "mail.{name}{tld}",
            "{name}{tld}",
            "app.{name}{tld}",
            "secure.{name}{tld}",
        ]

        for i in range(count):
            # Generate random name
            name_length = random.randint(3, 12)
            name = "".join(random.choices(string.ascii_lowercase, k=name_length))

            # Choose random pattern and TLD
            pattern = random.choice(patterns)
            tld = random.choice(tlds)

            domain = pattern.format(name=name, tld=tld)
            domains.append(domain)

        return domains

    def _generate_sni_packet(self) -> Dict[str, Any]:
        """
        Generate a mock SNI packet for testing.

        Returns:
            Mock packet dictionary
        """
        domain = random.choice(self._test_domains)

        # Create minimal TLS ClientHello with SNI
        sni_bytes = domain.encode("utf-8")
        sni_len = len(sni_bytes)

        # Simplified TLS ClientHello structure
        payload = bytearray()
        payload.extend([0x16, 0x03, 0x01])  # TLS Handshake, TLS 1.0
        payload.extend([0x00, 0x00])  # Length placeholder
        payload.extend([0x01])  # ClientHello
        payload.extend([0x00, 0x00, 0x00])  # Handshake length placeholder
        payload.extend([0x03, 0x03])  # TLS version
        payload.extend([0x00] * 32)  # Random
        payload.extend([0x00])  # Session ID length
        payload.extend([0x00, 0x02, 0x00, 0x35])  # Cipher suites
        payload.extend([0x01, 0x00])  # Compression methods

        # Extensions
        ext_len = 9 + sni_len
        payload.extend([0x00, ext_len])  # Extensions length
        payload.extend([0x00, 0x00])  # SNI extension type
        payload.extend([0x00, ext_len - 4])  # SNI extension length
        payload.extend([0x00, ext_len - 6])  # Server name list length
        payload.extend([0x00])  # Hostname type
        payload.extend([0x00, sni_len])  # Hostname length
        payload.extend(sni_bytes)  # Hostname

        return {
            "payload": bytes(payload),
            "dst_port": 443,
            "src_port": random.randint(1024, 65535),
            "expected_domain": domain,
        }

    def _generate_http_packet(self) -> Dict[str, Any]:
        """
        Generate a mock HTTP packet for testing.

        Returns:
            Mock packet dictionary
        """
        domain = random.choice(self._test_domains)

        # Create HTTP request with Host header
        http_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: LoadTester/1.0\r\n"
            f"Accept: */*\r\n"
            f"\r\n"
        ).encode("utf-8")

        return {
            "payload": http_request,
            "dst_port": 80,
            "src_port": random.randint(1024, 65535),
            "expected_domain": domain,
        }

    def _test_domain_list_scalability(self) -> None:
        """Test performance with different domain list sizes."""
        logger.info("Testing domain list scalability")

        for domain_count in self.config.domain_list_sizes:
            logger.info(f"Testing with {domain_count} domains")

            # Create filter config with subset of domains
            test_domains = set(self._test_domains[:domain_count])
            filter_config = FilterConfig(
                mode=FilterMode.BLACKLIST, domains=test_domains, cache_size=1000, cache_ttl=300
            )

            # Run performance test
            start_time = time.perf_counter()

            # Create filter and process sample packets
            packet_filter = RuntimePacketFilter(filter_config)
            sample_packets = self._test_packets[:1000]  # Use subset for scalability test

            processed_count = 0
            for packet in sample_packets:
                try:
                    packet_filter.should_apply_bypass(packet)
                    processed_count += 1
                except Exception as e:
                    logger.warning(f"Error processing packet: {e}")

            end_time = time.perf_counter()
            duration = end_time - start_time

            # Calculate metrics
            throughput = processed_count / duration if duration > 0 else 0
            avg_latency = (duration / processed_count * 1000) if processed_count > 0 else 0

            # Get filter statistics
            stats = packet_filter.get_statistics()

            self.results.domain_list_results[domain_count] = {
                "throughput_pps": throughput,
                "avg_latency_ms": avg_latency,
                "cache_hit_rate": stats.get("performance_cache_hit_rate", 0),
                "memory_mb": stats.get("current_memory_mb", 0),
            }

            logger.info(
                f"Domain count {domain_count}: {throughput:.1f} pps, {avg_latency:.2f}ms latency"
            )

    def _run_throughput_test(self) -> None:
        """Run main throughput and latency test."""
        logger.info("Running main throughput test")

        # Use largest domain list for main test
        test_domains = set(self._test_domains)
        filter_config = FilterConfig(
            mode=FilterMode.BLACKLIST, domains=test_domains, cache_size=2000, cache_ttl=600
        )

        # Create filter with monitoring
        performance_monitor = PerformanceMonitor(
            max_samples=10000, alert_threshold_ms=self.config.max_latency_ms
        )

        resource_manager = ResourceManager(
            ResourceLimits(
                memory_emergency_mb=self.config.max_memory_mb,
                cpu_emergency_percent=self.config.max_cpu_percent,
            )
        )

        packet_filter = RuntimePacketFilter(
            config=filter_config,
            performance_monitor=performance_monitor,
            resource_manager=resource_manager,
        )

        # Start monitoring
        packet_filter.start_resource_monitoring()

        try:
            # Run concurrent processing test
            start_time = time.perf_counter()
            processed_count = self._run_concurrent_processing(packet_filter)
            end_time = time.perf_counter()

            # Calculate results
            actual_duration = end_time - start_time
            throughput = processed_count / actual_duration if actual_duration > 0 else 0

            # Get performance statistics
            perf_stats = performance_monitor.get_statistics()
            resource_stats = resource_manager.get_statistics()

            # Update results
            self.results.total_packets_processed = processed_count
            self.results.test_duration_actual = actual_duration
            self.results.throughput_pps = throughput

            # Latency statistics
            packet_latency = perf_stats.get("packet_processing_latency", {})
            self.results.avg_latency_ms = packet_latency.get("avg_ms", 0)
            self.results.p95_latency_ms = packet_latency.get("p95_ms", 0)
            self.results.p99_latency_ms = packet_latency.get("p99_ms", 0)
            self.results.max_latency_ms = packet_latency.get("max_ms", 0)

            # Resource usage
            memory_stats = resource_stats.get("memory", {})
            cpu_stats = resource_stats.get("cpu", {})
            self.results.peak_memory_mb = memory_stats.get("max_mb", 0)
            self.results.avg_cpu_percent = cpu_stats.get("avg_percent", 0)
            self.results.peak_cpu_percent = cpu_stats.get("max_percent", 0)

            # Success rates
            self.results.extraction_success_rate = perf_stats.get("sni_success_rate", 0)
            self.results.cache_hit_rate = perf_stats.get("cache_hit_rate", 0)

            logger.info(
                f"Throughput test completed: {throughput:.1f} pps, {self.results.avg_latency_ms:.2f}ms avg latency"
            )

        finally:
            packet_filter.stop_resource_monitoring()

    def _run_concurrent_processing(self, packet_filter: RuntimePacketFilter) -> int:
        """
        Run concurrent packet processing test.

        Args:
            packet_filter: Filter to test

        Returns:
            Number of packets processed
        """
        processed_count = 0

        def process_packet_batch(packets: List[Dict[str, Any]]) -> int:
            """Process a batch of packets."""
            count = 0
            for packet in packets:
                try:
                    packet_filter.should_apply_bypass(packet)
                    count += 1
                except Exception as e:
                    logger.warning(f"Error processing packet: {e}")
            return count

        # Split packets into batches for concurrent processing
        batch_size = len(self._test_packets) // self.config.concurrent_threads
        batches = []

        for i in range(0, len(self._test_packets), batch_size):
            batch = self._test_packets[i : i + batch_size]
            batches.append(batch)

        # Process batches concurrently
        with ThreadPoolExecutor(max_workers=self.config.concurrent_threads) as executor:
            futures = [executor.submit(process_packet_batch, batch) for batch in batches]

            for future in as_completed(futures):
                try:
                    processed_count += future.result()
                except Exception as e:
                    logger.error(f"Error in concurrent processing: {e}")

        return processed_count

    def _validate_requirements(self) -> None:
        """Validate performance requirements."""
        logger.info("Validating performance requirements")

        # Latency requirement
        self.results.latency_requirement_met = (
            self.results.avg_latency_ms <= self.config.max_latency_ms
        )

        # Memory requirement
        self.results.memory_requirement_met = (
            self.results.peak_memory_mb <= self.config.max_memory_mb
        )

        # CPU requirement
        self.results.cpu_requirement_met = (
            self.results.peak_cpu_percent <= self.config.max_cpu_percent
        )

        # Throughput requirement
        self.results.throughput_requirement_met = (
            self.results.throughput_pps >= self.config.min_throughput_pps
        )

        # Log validation results
        requirements_met = [
            (
                "Latency",
                self.results.latency_requirement_met,
                f"{self.results.avg_latency_ms:.2f}ms <= {self.config.max_latency_ms}ms",
            ),
            (
                "Memory",
                self.results.memory_requirement_met,
                f"{self.results.peak_memory_mb:.1f}MB <= {self.config.max_memory_mb}MB",
            ),
            (
                "CPU",
                self.results.cpu_requirement_met,
                f"{self.results.peak_cpu_percent:.1f}% <= {self.config.max_cpu_percent}%",
            ),
            (
                "Throughput",
                self.results.throughput_requirement_met,
                f"{self.results.throughput_pps:.1f}pps >= {self.config.min_throughput_pps}pps",
            ),
        ]

        for name, met, details in requirements_met:
            status = "PASS" if met else "FAIL"
            logger.info(f"{name} requirement: {status} ({details})")

    def generate_report(self) -> str:
        """
        Generate comprehensive test report.

        Returns:
            Formatted test report
        """
        report = []
        report.append("=" * 60)
        report.append("RUNTIME PACKET FILTERING LOAD TEST REPORT")
        report.append("=" * 60)
        report.append("")

        # Test configuration
        report.append("Test Configuration:")
        report.append(f"  Packets processed: {self.results.total_packets_processed:,}")
        report.append(f"  Concurrent threads: {self.config.concurrent_threads}")
        report.append(f"  Test duration: {self.results.test_duration_actual:.2f}s")
        report.append("")

        # Performance results
        report.append("Performance Results:")
        report.append(f"  Throughput: {self.results.throughput_pps:.1f} packets/second")
        report.append(f"  Average latency: {self.results.avg_latency_ms:.2f}ms")
        report.append(f"  95th percentile latency: {self.results.p95_latency_ms:.2f}ms")
        report.append(f"  99th percentile latency: {self.results.p99_latency_ms:.2f}ms")
        report.append(f"  Maximum latency: {self.results.max_latency_ms:.2f}ms")
        report.append("")

        # Resource usage
        report.append("Resource Usage:")
        report.append(f"  Peak memory: {self.results.peak_memory_mb:.1f}MB")
        report.append(f"  Average CPU: {self.results.avg_cpu_percent:.1f}%")
        report.append(f"  Peak CPU: {self.results.peak_cpu_percent:.1f}%")
        report.append("")

        # Success rates
        report.append("Success Rates:")
        report.append(f"  Domain extraction: {self.results.extraction_success_rate:.1f}%")
        report.append(f"  Cache hit rate: {self.results.cache_hit_rate:.1f}%")
        report.append("")

        # Requirements validation
        report.append("Requirements Validation:")
        requirements = [
            ("Latency", self.results.latency_requirement_met),
            ("Memory", self.results.memory_requirement_met),
            ("CPU", self.results.cpu_requirement_met),
            ("Throughput", self.results.throughput_requirement_met),
        ]

        for name, met in requirements:
            status = "PASS" if met else "FAIL"
            report.append(f"  {name}: {status}")

        report.append("")

        # Domain list scalability
        if self.results.domain_list_results:
            report.append("Domain List Scalability:")
            for domain_count, metrics in self.results.domain_list_results.items():
                report.append(
                    f"  {domain_count:,} domains: {metrics['throughput_pps']:.1f} pps, {metrics['avg_latency_ms']:.2f}ms"
                )

        report.append("")
        report.append("=" * 60)

        return "\n".join(report)


def run_load_test(config: Optional[LoadTestConfig] = None) -> LoadTestResults:
    """
    Run load test with specified configuration.

    Args:
        config: Load test configuration

    Returns:
        Load test results

    Requirements: 6.3, 6.4
    """
    tester = LoadTester(config)
    results = tester.run_comprehensive_test()

    # Print report
    report = tester.generate_report()
    print(report)

    return results
