#!/usr/bin/env python3
"""
Comprehensive test demonstrating all metrics collection framework features
Task 3 Implementation - Requirements 2.1, 2.5
"""

import asyncio
import sys
import os
import time
from unittest.mock import patch, AsyncMock, Mock

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.fingerprint.metrics_collector import (
    MetricsCollector,
    TimingMetricsCollector,
    NetworkMetricsCollector,
    ProtocolMetricsCollector,
    ProtocolMetrics,
    ComprehensiveMetrics,
)


async def demonstrate_timing_metrics():
    """Demonstrate timing metrics collection with latency, jitter, and packet timing"""
    print("1. Timing Metrics Collection")
    print("-" * 30)

    collector = TimingMetricsCollector(timeout=2.0, samples=5)

    with patch("asyncio.open_connection") as mock_open_connection:
        # Mock varying response times to demonstrate jitter calculation
        mock_calls = []
        for i in range(5):
            mock_reader = AsyncMock()
            mock_writer = AsyncMock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = Mock()
            mock_writer.wait_closed = AsyncMock()
            mock_reader.read = AsyncMock(return_value=b"H")
            mock_calls.append((mock_reader, mock_writer))

        mock_open_connection.side_effect = mock_calls

        result = await collector.collect_metrics("example.com", 80)

        print(f"  Latency: {result['latency_ms']:.2f} ms")
        print(f"  Jitter: {result['jitter_ms']:.2f} ms")
        print(f"  Packet timing samples: {len(result['packet_timing'])}")
        print(f"  Connection time: {result['connection_time_ms']:.2f} ms")
        print(f"  First byte time: {result['first_byte_time_ms']:.2f} ms")
        print(f"  Success rate: {result['success_rate']:.2f}")
        print(f"  Timeout occurred: {result['timeout_occurred']}")

        # Demonstrate timing trends
        for i in range(3):
            collector.timing_history.append(
                {
                    "timestamp": time.time() + i,
                    "latency_ms": 10.0 + i * 2,
                    "jitter_ms": 1.0 + i * 0.5,
                }
            )

        trends = collector.get_timing_trends()
        if trends:
            print(f"  Latency trend: {trends.get('latency_trend', 'N/A')}")
            print(f"  Jitter trend: {trends.get('jitter_trend', 'N/A')}")
            print(f"  Stability score: {trends.get('stability_score', 0):.2f}")


async def demonstrate_network_metrics():
    """Demonstrate network-level metrics collection"""
    print("\n2. Network Metrics Collection")
    print("-" * 30)

    collector = NetworkMetricsCollector(timeout=2.0)

    with patch("asyncio.open_connection") as mock_open_connection:
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        mock_open_connection.return_value = (mock_reader, mock_writer)

        result = await collector.collect_metrics("example.com", 80)

        print(f"  Packet loss rate: {result['packet_loss_rate']:.2f}")
        print(f"  MTU discovery blocked: {result['mtu_discovery_blocked']}")
        print(f"  TCP window scaling: {result['tcp_window_scaling']}")
        print(f"  TCP options: {result['tcp_options']}")
        print(f"  Fragmented packets: {result['fragmented_packets']}")


async def demonstrate_protocol_metrics():
    """Demonstrate protocol-agnostic metrics collection"""
    print("\n3. Protocol-Agnostic Metrics Collection")
    print("-" * 40)

    collector = ProtocolMetricsCollector(timeout=2.0)

    # Test HTTP metrics
    print("  HTTP Protocol:")
    with patch("asyncio.open_connection") as mock_open_connection:
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        # Mock HTTP response with various status codes
        http_responses = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nConnection: close\r\n\r\n<html>test</html>",
            b"HTTP/1.1 302 Found\r\nLocation: https://example.com\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5678\r\nConnection: close\r\n\r\n<html>test2</html>",
            b"HTTP/1.1 200 OK\r\nContent-Length: 9012\r\nConnection: close\r\n\r\n<html>test3</html>",
        ]

        call_count = 0

        def mock_connection(*args, **kwargs):
            nonlocal call_count
            mock_reader.read = AsyncMock(
                return_value=http_responses[call_count % len(http_responses)]
            )
            call_count += 1
            return (mock_reader, mock_writer)

        mock_open_connection.side_effect = mock_connection

        result = await collector._collect_http_metrics("example.com", 80)

        print(f"    Success rate: {result['success_rate']:.2f}")
        print(f"    Error codes: {result['error_codes']}")
        print(f"    Response sizes: {result['response_sizes']}")
        print(f"    Redirect responses: {result['redirect_responses']}")
        print(f"    Blocked responses: {result['blocked_responses']}")
        print(f"    Avg response time: {result.get('avg_response_time_ms', 0):.2f} ms")

    # Test TCP metrics
    print("  TCP Protocol:")
    with patch("asyncio.open_connection") as mock_open_connection:
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        mock_open_connection.return_value = (mock_reader, mock_writer)

        result = await collector._collect_tcp_metrics("example.com", 80)

        print(f"    Success rate: {result['success_rate']:.2f}")
        print(f"    Connection time: {result['connection_time_ms']:.2f} ms")

    # Test protocol auto-detection
    print("  Auto-detection:")
    protocols = {80: "http", 443: "https", 53: "dns", 8080: "http", 9999: "tcp"}

    for port, expected in protocols.items():
        detected = collector._detect_protocol(port)
        print(f"    Port {port} -> {detected} (expected: {expected})")
        assert detected == expected


async def demonstrate_comprehensive_collection():
    """Demonstrate comprehensive metrics collection with all collectors"""
    print("\n4. Comprehensive Metrics Collection")
    print("-" * 40)

    collector = MetricsCollector(timeout=2.0, max_concurrent=3)

    with patch("asyncio.open_connection") as mock_open_connection:
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n\r\n")

        mock_open_connection.return_value = (mock_reader, mock_writer)

        # Collect comprehensive metrics
        result = await collector.collect_comprehensive_metrics(
            "example.com",
            443,
            protocols=["https", "http"],
            include_timing=True,
            include_network=True,
            include_protocol=True,
        )

        print(f"  Target: {result.target}")
        print(f"  Timestamp: {result.timestamp}")
        print(f"  Reliability score: {result.reliability_score:.2f}")
        print(f"  Collection errors: {len(result.collection_errors)}")

        print("  Timing metrics:")
        print(f"    Latency: {result.timing.latency_ms:.2f} ms")
        print(f"    Jitter: {result.timing.jitter_ms:.2f} ms")
        print(f"    Timeout occurred: {result.timing.timeout_occurred}")

        print("  Network metrics:")
        print(f"    Packet loss rate: {result.network.packet_loss_rate:.2f}")
        print(f"    TCP window scaling: {result.network.tcp_window_scaling}")

        print("  Protocol metrics:")
        for protocol, metrics in result.protocols.items():
            print(f"    {protocol}: success_rate={metrics.success_rate:.2f}")

        print("  Raw data keys:", list(result.raw_data.keys()))


def demonstrate_validation():
    """Demonstrate metrics validation"""
    print("\n5. Metrics Validation")
    print("-" * 25)

    collector = MetricsCollector()

    # Test valid metrics
    valid_metrics = ComprehensiveMetrics(target="example.com")
    valid_metrics.timing.latency_ms = 15.5
    valid_metrics.timing.jitter_ms = 2.3
    valid_metrics.network.packet_loss_rate = 0.1
    valid_metrics.protocols["http"] = ProtocolMetrics(protocol="http", success_rate=0.8)
    valid_metrics.reliability_score = 0.9

    errors = collector.validate_comprehensive_metrics(valid_metrics)
    print(f"  Valid metrics errors: {len(errors)}")

    # Test invalid metrics
    invalid_metrics = ComprehensiveMetrics(target="")  # Empty target
    invalid_metrics.timing.latency_ms = -5.0  # Negative latency
    invalid_metrics.timing.jitter_ms = -1.0  # Negative jitter
    invalid_metrics.network.packet_loss_rate = 1.5  # Invalid packet loss rate
    invalid_metrics.protocols["http"] = ProtocolMetrics(
        protocol="http", success_rate=1.5
    )  # Invalid success rate
    invalid_metrics.reliability_score = -0.1  # Invalid reliability score

    errors = collector.validate_comprehensive_metrics(invalid_metrics)
    print(f"  Invalid metrics errors: {len(errors)}")
    for error in errors[:3]:  # Show first 3 errors
        print(f"    - {error}")
    if len(errors) > 3:
        print(f"    ... and {len(errors) - 3} more")


def demonstrate_aggregation():
    """Demonstrate metrics aggregation"""
    print("\n6. Metrics Aggregation")
    print("-" * 25)

    collector = MetricsCollector()

    # Create multiple metrics to aggregate
    metrics_list = []

    for i in range(3):
        metrics = ComprehensiveMetrics(target="example.com")
        metrics.timing.latency_ms = 10.0 + i * 5.0  # 10, 15, 20
        metrics.timing.jitter_ms = 1.0 + i * 0.5  # 1.0, 1.5, 2.0
        metrics.network.packet_loss_rate = 0.1 + i * 0.05  # 0.1, 0.15, 0.2
        metrics.protocols["http"] = ProtocolMetrics(
            protocol="http", success_rate=0.8 - i * 0.1  # 0.8, 0.7, 0.6
        )
        metrics.reliability_score = 0.9 - i * 0.1  # 0.9, 0.8, 0.7
        metrics_list.append(metrics)

    aggregated = collector.aggregate_metrics(metrics_list)

    print(f"  Aggregated from {len(metrics_list)} metrics collections:")
    print(f"  Average latency: {aggregated.timing.latency_ms:.2f} ms (expected: 15.0)")
    print(f"  Average jitter: {aggregated.timing.jitter_ms:.2f} ms (expected: 1.5)")
    print(
        f"  Max packet loss: {aggregated.network.packet_loss_rate:.2f} (expected: 0.2)"
    )
    print(
        f"  Average HTTP success rate: {aggregated.protocols['http'].success_rate:.2f} (expected: 0.7)"
    )
    print(f"  Recalculated reliability: {aggregated.reliability_score:.2f}")


async def demonstrate_error_handling():
    """Demonstrate error handling in metrics collection"""
    print("\n7. Error Handling")
    print("-" * 20)

    collector = MetricsCollector(timeout=1.0)

    # Test with connection failures
    with patch("asyncio.open_connection") as mock_open_connection:
        mock_open_connection.side_effect = ConnectionRefusedError("Connection refused")

        try:
            result = await collector.collect_comprehensive_metrics(
                "unreachable.example.com", 80
            )
            print(f"  Collection completed with {len(result.collection_errors)} errors")
            print(f"  Reliability score: {result.reliability_score:.2f}")
            for error in result.collection_errors[:2]:
                print(f"    Error: {error}")
        except Exception as e:
            print(f"  Expected error caught: {type(e).__name__}")

    # Test validation errors
    try:
        collector.aggregate_metrics([])  # Empty list should raise ValueError
    except ValueError as e:
        print(f"  Validation error caught: {e}")


async def main():
    """Run comprehensive demonstration of metrics collection framework"""
    print("Metrics Collection Framework Demonstration")
    print("=" * 50)
    print("Task 3 Implementation - Requirements 2.1, 2.5")
    print("=" * 50)

    try:
        await demonstrate_timing_metrics()
        await demonstrate_network_metrics()
        await demonstrate_protocol_metrics()
        await demonstrate_comprehensive_collection()
        demonstrate_validation()
        demonstrate_aggregation()
        await demonstrate_error_handling()

        print("\n" + "=" * 50)
        print("✓ All demonstrations completed successfully!")
        print("\nKey Features Demonstrated:")
        print("- Async metrics collection methods")
        print("- Timing metrics (latency, jitter, packet timing)")
        print("- Protocol-agnostic metric aggregation")
        print("- Comprehensive validation")
        print("- Error handling and graceful degradation")
        print("- Multi-protocol support (HTTP, HTTPS, TCP, DNS)")
        print("- Metrics aggregation and trend analysis")

        return True

    except Exception as e:
        print(f"\nDemonstration failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        success = loop.run_until_complete(main())
        sys.exit(0 if success else 1)
    finally:
        loop.close()
