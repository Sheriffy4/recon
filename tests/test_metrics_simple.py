#!/usr/bin/env python3
"""
Simple test to verify metrics collector functionality
"""

import asyncio
import sys
import os

# Add the parent directories to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
tests_dir = os.path.dirname(current_dir)
recon_dir = os.path.dirname(tests_dir)
sys.path.insert(0, recon_dir)


# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.fingerprint.metrics_collector import (
    MetricsCollector,
    TimingMetricsCollector,
    NetworkMetricsCollector,
    ProtocolMetricsCollector,
    TimingMetrics,
    NetworkMetrics,
    ProtocolMetrics,
    ComprehensiveMetrics,
)


def test_data_structures():
    """Test basic data structure creation"""
    print("Testing data structures...")

    # Test TimingMetrics
    timing = TimingMetrics()
    assert timing.latency_ms == 0.0
    assert timing.jitter_ms == 0.0
    assert timing.packet_timing == []
    print("✓ TimingMetrics creation works")

    # Test NetworkMetrics
    network = NetworkMetrics()
    assert network.packet_loss_rate == 0.0
    assert network.tcp_options == []
    print("✓ NetworkMetrics creation works")

    # Test ProtocolMetrics
    protocol = ProtocolMetrics()
    assert protocol.protocol == "unknown"
    assert protocol.success_rate == 0.0
    print("✓ ProtocolMetrics creation works")

    # Test ComprehensiveMetrics
    comprehensive = ComprehensiveMetrics(target="test.example.com")
    assert comprehensive.target == "test.example.com"
    assert isinstance(comprehensive.timing, TimingMetrics)
    assert isinstance(comprehensive.network, NetworkMetrics)
    print("✓ ComprehensiveMetrics creation works")

    # Test serialization
    data_dict = comprehensive.to_dict()
    assert isinstance(data_dict, dict)
    assert data_dict["target"] == "test.example.com"
    print("✓ ComprehensiveMetrics serialization works")


def test_collector_initialization():
    """Test collector initialization"""
    print("\nTesting collector initialization...")

    # Test TimingMetricsCollector
    timing_collector = TimingMetricsCollector(timeout=5.0, samples=3)
    assert timing_collector.timeout == 5.0
    assert timing_collector.samples == 3
    print("✓ TimingMetricsCollector initialization works")

    # Test NetworkMetricsCollector
    network_collector = NetworkMetricsCollector(timeout=5.0)
    assert network_collector.timeout == 5.0
    print("✓ NetworkMetricsCollector initialization works")

    # Test ProtocolMetricsCollector
    protocol_collector = ProtocolMetricsCollector(timeout=5.0)
    assert protocol_collector.timeout == 5.0
    print("✓ ProtocolMetricsCollector initialization works")

    # Test main MetricsCollector
    main_collector = MetricsCollector(timeout=5.0, max_concurrent=3)
    assert main_collector.timeout == 5.0
    assert main_collector.max_concurrent == 3
    assert isinstance(main_collector.timing_collector, TimingMetricsCollector)
    assert isinstance(main_collector.network_collector, NetworkMetricsCollector)
    assert isinstance(main_collector.protocol_collector, ProtocolMetricsCollector)
    print("✓ MetricsCollector initialization works")


def test_protocol_detection():
    """Test protocol detection"""
    print("\nTesting protocol detection...")

    collector = ProtocolMetricsCollector()

    assert collector._detect_protocol(80) == "http"
    assert collector._detect_protocol(443) == "https"
    assert collector._detect_protocol(53) == "dns"
    assert collector._detect_protocol(8080) == "http"
    assert collector._detect_protocol(9999) == "tcp"

    print("✓ Protocol detection works")


def test_validation():
    """Test metrics validation"""
    print("\nTesting validation...")

    collector = MetricsCollector()

    # Test valid metrics
    valid_metrics = ComprehensiveMetrics(target="test.example.com")
    valid_metrics.timing.latency_ms = 15.5
    valid_metrics.network.packet_loss_rate = 0.1
    valid_metrics.reliability_score = 0.8

    errors = collector.validate_comprehensive_metrics(valid_metrics)
    assert errors == []
    print("✓ Valid metrics validation works")

    # Test invalid metrics
    invalid_metrics = ComprehensiveMetrics(target="")  # Empty target
    invalid_metrics.timing.latency_ms = -5.0  # Negative latency
    invalid_metrics.network.packet_loss_rate = 1.5  # Invalid packet loss rate
    invalid_metrics.reliability_score = -0.1  # Invalid reliability score

    errors = collector.validate_comprehensive_metrics(invalid_metrics)
    assert len(errors) > 0
    print("✓ Invalid metrics validation works")


async def test_mock_collection():
    """Test metrics collection with mocked network calls"""
    print("\nTesting mock collection...")

    from unittest.mock import patch, AsyncMock, Mock

    collector = MetricsCollector(timeout=1.0)

    with patch("asyncio.open_connection") as mock_open_connection:
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n\r\n")

        mock_open_connection.return_value = (mock_reader, mock_writer)

        result = await collector.collect_comprehensive_metrics("test.example.com", 80)

        assert isinstance(result, ComprehensiveMetrics)
        assert result.target == "test.example.com"
        assert 0.0 <= result.reliability_score <= 1.0

        print("✓ Mock collection works")


def test_aggregation():
    """Test metrics aggregation"""
    print("\nTesting aggregation...")

    collector = MetricsCollector()

    # Create test metrics
    metrics1 = ComprehensiveMetrics(target="test.example.com")
    metrics1.timing.latency_ms = 10.0
    metrics1.network.packet_loss_rate = 0.1

    metrics2 = ComprehensiveMetrics(target="test.example.com")
    metrics2.timing.latency_ms = 20.0
    metrics2.network.packet_loss_rate = 0.2

    result = collector.aggregate_metrics([metrics1, metrics2])

    assert result.target == "test.example.com"
    assert result.timing.latency_ms == 15.0  # Average
    assert result.network.packet_loss_rate == 0.2  # Max

    print("✓ Metrics aggregation works")


def main():
    """Run all tests"""
    print("Running Metrics Collector Tests")
    print("=" * 40)

    try:
        test_data_structures()
        test_collector_initialization()
        test_protocol_detection()
        test_validation()
        test_aggregation()

        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(test_mock_collection())
        finally:
            loop.close()

        print("\n" + "=" * 40)
        print("All tests passed! ✓")
        return True

    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
