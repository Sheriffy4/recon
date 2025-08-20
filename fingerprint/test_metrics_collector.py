# recon/core/fingerprint/test_metrics_collector.py
"""
Unit tests for MetricsCollector framework - Task 3 Implementation
Tests async collection methods, timing metrics, protocol-agnostic aggregation and validation.

Requirements: 2.1, 2.5
"""

import unittest
import asyncio
import time
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any

from .metrics_collector import (
    MetricsCollector,
    TimingMetricsCollector,
    NetworkMetricsCollector,
    ProtocolMetricsCollector,
    BaseMetricsCollector,
    TimingMetrics,
    NetworkMetrics,
    ProtocolMetrics,
    ComprehensiveMetrics,
)
from .advanced_models import MetricsCollectionError


class TestTimingMetrics(unittest.TestCase):
    """Test TimingMetrics data structure"""

    def test_timing_metrics_creation(self):
        """Test TimingMetrics creation with default values"""
        metrics = TimingMetrics()

        self.assertEqual(metrics.latency_ms, 0.0)
        self.assertEqual(metrics.jitter_ms, 0.0)
        self.assertEqual(metrics.packet_timing, [])
        self.assertEqual(metrics.connection_time_ms, 0.0)
        self.assertEqual(metrics.first_byte_time_ms, 0.0)
        self.assertEqual(metrics.total_time_ms, 0.0)
        self.assertFalse(metrics.timeout_occurred)
        self.assertEqual(metrics.retransmission_count, 0)

    def test_timing_metrics_with_values(self):
        """Test TimingMetrics creation with specific values"""
        packet_timing = [10.5, 12.3, 11.8]
        metrics = TimingMetrics(
            latency_ms=15.5,
            jitter_ms=2.3,
            packet_timing=packet_timing,
            connection_time_ms=8.2,
            first_byte_time_ms=12.1,
            total_time_ms=25.7,
            timeout_occurred=True,
            retransmission_count=2,
        )

        self.assertEqual(metrics.latency_ms, 15.5)
        self.assertEqual(metrics.jitter_ms, 2.3)
        self.assertEqual(metrics.packet_timing, packet_timing)
        self.assertEqual(metrics.connection_time_ms, 8.2)
        self.assertEqual(metrics.first_byte_time_ms, 12.1)
        self.assertEqual(metrics.total_time_ms, 25.7)
        self.assertTrue(metrics.timeout_occurred)
        self.assertEqual(metrics.retransmission_count, 2)


class TestNetworkMetrics(unittest.TestCase):
    """Test NetworkMetrics data structure"""

    def test_network_metrics_creation(self):
        """Test NetworkMetrics creation with default values"""
        metrics = NetworkMetrics()

        self.assertEqual(metrics.packet_loss_rate, 0.0)
        self.assertEqual(metrics.out_of_order_packets, 0)
        self.assertEqual(metrics.duplicate_packets, 0)
        self.assertEqual(metrics.fragmented_packets, 0)
        self.assertFalse(metrics.mtu_discovery_blocked)
        self.assertEqual(metrics.icmp_responses, [])
        self.assertFalse(metrics.tcp_window_scaling)
        self.assertEqual(metrics.tcp_options, [])


class TestProtocolMetrics(unittest.TestCase):
    """Test ProtocolMetrics data structure"""

    def test_protocol_metrics_creation(self):
        """Test ProtocolMetrics creation with default values"""
        metrics = ProtocolMetrics()

        self.assertEqual(metrics.protocol, "unknown")
        self.assertEqual(metrics.success_rate, 0.0)
        self.assertEqual(metrics.error_codes, [])
        self.assertEqual(metrics.response_sizes, [])
        self.assertEqual(metrics.header_modifications, {})
        self.assertFalse(metrics.content_modifications)
        self.assertEqual(metrics.redirect_responses, 0)
        self.assertEqual(metrics.blocked_responses, 0)


class TestComprehensiveMetrics(unittest.TestCase):
    """Test ComprehensiveMetrics data structure and serialization"""

    def test_comprehensive_metrics_creation(self):
        """Test ComprehensiveMetrics creation"""
        metrics = ComprehensiveMetrics(target="test.example.com")

        self.assertEqual(metrics.target, "test.example.com")
        self.assertIsInstance(metrics.timing, TimingMetrics)
        self.assertIsInstance(metrics.network, NetworkMetrics)
        self.assertIsInstance(metrics.protocols, dict)
        self.assertIsInstance(metrics.raw_data, dict)
        self.assertIsInstance(metrics.collection_errors, list)
        self.assertEqual(metrics.reliability_score, 0.0)

    def test_comprehensive_metrics_to_dict(self):
        """Test ComprehensiveMetrics serialization to dictionary"""
        metrics = ComprehensiveMetrics(target="test.example.com")
        metrics.timing.latency_ms = 15.5
        metrics.network.packet_loss_rate = 0.1
        metrics.protocols["http"] = ProtocolMetrics(protocol="http", success_rate=0.8)

        result = metrics.to_dict()

        self.assertIsInstance(result, dict)
        self.assertEqual(result["target"], "test.example.com")
        self.assertEqual(result["timing"]["latency_ms"], 15.5)
        self.assertEqual(result["network"]["packet_loss_rate"], 0.1)
        self.assertEqual(result["protocols"]["http"]["success_rate"], 0.8)


class TestBaseMetricsCollector(unittest.TestCase):
    """Test BaseMetricsCollector abstract class"""

    def test_base_collector_initialization(self):
        """Test BaseMetricsCollector initialization"""

        # Create a concrete implementation for testing
        class TestCollector(BaseMetricsCollector):
            async def collect_metrics(
                self, target: str, port: int, **kwargs
            ) -> Dict[str, Any]:
                return {"test": True}

        collector = TestCollector(timeout=5.0)
        self.assertEqual(collector.timeout, 5.0)
        self.assertIsNotNone(collector.logger)

    def test_validate_metrics_valid(self):
        """Test metrics validation with valid data"""

        class TestCollector(BaseMetricsCollector):
            async def collect_metrics(
                self, target: str, port: int, **kwargs
            ) -> Dict[str, Any]:
                return {"test": True}

        collector = TestCollector()
        metrics = {
            "latency_ms": 15.5,
            "connection_time_ms": 8.2,
            "total_time_ms": 25.7,
            "success_rate": 0.8,
        }

        errors = collector.validate_metrics(metrics)
        self.assertEqual(errors, [])

    def test_validate_metrics_invalid(self):
        """Test metrics validation with invalid data"""

        class TestCollector(BaseMetricsCollector):
            async def collect_metrics(
                self, target: str, port: int, **kwargs
            ) -> Dict[str, Any]:
                return {"test": True}

        collector = TestCollector()

        # Test non-dict input
        errors = collector.validate_metrics("not a dict")
        self.assertIn("Metrics must be a dictionary", errors)

        # Test negative timing values
        metrics = {"latency_ms": -5.0}
        errors = collector.validate_metrics(metrics)
        self.assertIn("Timing field latency_ms cannot be negative", errors)

        # Test invalid success rate
        metrics = {"success_rate": 1.5}
        errors = collector.validate_metrics(metrics)
        self.assertIn("Success rate must be between 0.0 and 1.0", errors)


class TestTimingMetricsCollector(unittest.TestCase):
    """Test TimingMetricsCollector implementation"""

    def setUp(self):
        self.collector = TimingMetricsCollector(timeout=2.0, samples=3)

    @patch("asyncio.open_connection")
    async def test_collect_metrics_success(self, mock_open_connection):
        """Test successful timing metrics collection"""
        # Mock successful connections
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"H")

        mock_open_connection.return_value = (mock_reader, mock_writer)

        result = await self.collector.collect_metrics("test.example.com", 80)

        self.assertIsInstance(result, dict)
        self.assertIn("latency_ms", result)
        self.assertIn("jitter_ms", result)
        self.assertIn("packet_timing", result)
        self.assertIn("connection_time_ms", result)
        self.assertIn("first_byte_time_ms", result)
        self.assertIn("samples_collected", result)
        self.assertIn("success_rate", result)

        # Verify timing values are reasonable
        self.assertGreaterEqual(result["latency_ms"], 0)
        self.assertGreaterEqual(result["jitter_ms"], 0)
        self.assertGreaterEqual(result["connection_time_ms"], 0)
        self.assertGreaterEqual(result["first_byte_time_ms"], 0)
        self.assertLessEqual(result["success_rate"], 1.0)

        # Verify we attempted the correct number of samples
        self.assertEqual(mock_open_connection.call_count, 3)

    @patch("asyncio.open_connection")
    async def test_collect_metrics_with_timeouts(self, mock_open_connection):
        """Test timing metrics collection with timeouts"""
        # Mock timeout on first attempt, success on others
        mock_open_connection.side_effect = [
            asyncio.TimeoutError(),
            (AsyncMock(), AsyncMock()),
            (AsyncMock(), AsyncMock()),
        ]

        # Configure successful mock connections
        for call in mock_open_connection.side_effect[1:]:
            if isinstance(call, tuple):
                reader, writer = call
                reader.read = AsyncMock(return_value=b"H")
                writer.drain = AsyncMock()
                writer.close = Mock()
                writer.wait_closed = AsyncMock()

        result = await self.collector.collect_metrics("test.example.com", 80)

        self.assertIsInstance(result, dict)
        self.assertTrue(result["timeout_occurred"])
        self.assertGreater(result["samples_collected"], 0)
        self.assertLess(result["success_rate"], 1.0)

    def test_get_timing_trends_insufficient_data(self):
        """Test timing trends with insufficient historical data"""
        trends = self.collector.get_timing_trends()
        self.assertEqual(trends, {})

    def test_get_timing_trends_with_data(self):
        """Test timing trends with sufficient historical data"""
        # Add some historical data
        for i in range(5):
            self.collector.timing_history.append(
                {
                    "timestamp": time.time() + i,
                    "latency_ms": 10.0 + i,
                    "jitter_ms": 1.0 + i * 0.1,
                }
            )

        trends = self.collector.get_timing_trends()

        self.assertIn("latency_trend", trends)
        self.assertIn("jitter_trend", trends)
        self.assertIn("stability_score", trends)
        self.assertIn(trends["latency_trend"], ["increasing", "decreasing"])
        self.assertIn(trends["jitter_trend"], ["increasing", "decreasing"])


class TestNetworkMetricsCollector(unittest.TestCase):
    """Test NetworkMetricsCollector implementation"""

    def setUp(self):
        self.collector = NetworkMetricsCollector(timeout=2.0)

    @patch("asyncio.open_connection")
    async def test_collect_metrics_success(self, mock_open_connection):
        """Test successful network metrics collection"""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        mock_open_connection.return_value = (mock_reader, mock_writer)

        result = await self.collector.collect_metrics("test.example.com", 80)

        self.assertIsInstance(result, dict)
        self.assertIn("packet_loss_rate", result)
        self.assertIn("mtu_discovery_blocked", result)
        self.assertIn("tcp_options", result)
        self.assertIn("tcp_window_scaling", result)

        # Verify values are within expected ranges
        self.assertGreaterEqual(result["packet_loss_rate"], 0.0)
        self.assertLessEqual(result["packet_loss_rate"], 1.0)
        self.assertIsInstance(result["mtu_discovery_blocked"], bool)
        self.assertIsInstance(result["tcp_options"], list)

    @patch("asyncio.open_connection")
    async def test_collect_metrics_connection_failure(self, mock_open_connection):
        """Test network metrics collection with connection failures"""
        mock_open_connection.side_effect = ConnectionRefusedError("Connection refused")

        with self.assertRaises(MetricsCollectionError):
            await self.collector.collect_metrics("test.example.com", 80)


class TestProtocolMetricsCollector(unittest.TestCase):
    """Test ProtocolMetricsCollector implementation"""

    def setUp(self):
        self.collector = ProtocolMetricsCollector(timeout=2.0)

    def test_detect_protocol(self):
        """Test protocol detection based on port"""
        self.assertEqual(self.collector._detect_protocol(80), "http")
        self.assertEqual(self.collector._detect_protocol(443), "https")
        self.assertEqual(self.collector._detect_protocol(53), "dns")
        self.assertEqual(self.collector._detect_protocol(8080), "http")
        self.assertEqual(self.collector._detect_protocol(9999), "tcp")

    @patch("asyncio.open_connection")
    async def test_collect_http_metrics(self, mock_open_connection):
        """Test HTTP metrics collection"""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        # Mock HTTP response
        http_response = b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nConnection: close\r\n\r\n<html>test</html>"
        mock_reader.read = AsyncMock(return_value=http_response)

        mock_open_connection.return_value = (mock_reader, mock_writer)

        result = await self.collector._collect_http_metrics("test.example.com", 80)

        self.assertIsInstance(result, dict)
        self.assertEqual(result["protocol"], "http")
        self.assertGreater(result["success_rate"], 0.0)
        self.assertIn(200, result["error_codes"])
        self.assertIn(1234, result["response_sizes"])
        self.assertEqual(result["redirect_responses"], 0)
        self.assertEqual(result["blocked_responses"], 0)

    @patch("asyncio.open_connection")
    async def test_collect_http_metrics_with_redirects(self, mock_open_connection):
        """Test HTTP metrics collection with redirect responses"""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        # Mock HTTP redirect response
        http_response = b"HTTP/1.1 302 Found\r\nLocation: https://example.com\r\nConnection: close\r\n\r\n"
        mock_reader.read = AsyncMock(return_value=http_response)

        mock_open_connection.return_value = (mock_reader, mock_writer)

        result = await self.collector._collect_http_metrics("test.example.com", 80)

        self.assertEqual(result["protocol"], "http")
        self.assertIn(302, result["error_codes"])
        self.assertGreater(result["redirect_responses"], 0)

    @patch("asyncio.open_connection")
    async def test_collect_tcp_metrics(self, mock_open_connection):
        """Test TCP metrics collection"""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        mock_open_connection.return_value = (mock_reader, mock_writer)

        result = await self.collector._collect_tcp_metrics("test.example.com", 80)

        self.assertIsInstance(result, dict)
        self.assertEqual(result["protocol"], "tcp")
        self.assertEqual(result["success_rate"], 1.0)
        self.assertGreater(result["connection_time_ms"], 0)

    @patch("asyncio.open_connection")
    async def test_collect_metrics_auto_protocol(self, mock_open_connection):
        """Test metrics collection with auto protocol detection"""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n\r\n")

        mock_open_connection.return_value = (mock_reader, mock_writer)

        result = await self.collector.collect_metrics(
            "test.example.com", 80, protocol="auto"
        )

        self.assertEqual(result["protocol"], "http")


class TestMetricsCollector(unittest.TestCase):
    """Test main MetricsCollector class"""

    def setUp(self):
        self.collector = MetricsCollector(timeout=2.0, max_concurrent=3)

    def test_initialization(self):
        """Test MetricsCollector initialization"""
        self.assertEqual(self.collector.timeout, 2.0)
        self.assertEqual(self.collector.max_concurrent, 3)
        self.assertIsInstance(self.collector.timing_collector, TimingMetricsCollector)
        self.assertIsInstance(self.collector.network_collector, NetworkMetricsCollector)
        self.assertIsInstance(
            self.collector.protocol_collector, ProtocolMetricsCollector
        )

    @patch.object(TimingMetricsCollector, "collect_metrics")
    @patch.object(NetworkMetricsCollector, "collect_metrics")
    @patch.object(ProtocolMetricsCollector, "collect_metrics")
    async def test_collect_comprehensive_metrics_success(
        self, mock_protocol, mock_network, mock_timing
    ):
        """Test successful comprehensive metrics collection"""
        # Mock successful collection from all collectors
        mock_timing.return_value = {
            "latency_ms": 15.5,
            "jitter_ms": 2.3,
            "packet_timing": [10, 12, 14],
            "connection_time_ms": 8.2,
            "first_byte_time_ms": 12.1,
            "total_time_ms": 25.7,
            "timeout_occurred": False,
            "retransmission_count": 0,
        }

        mock_network.return_value = {
            "packet_loss_rate": 0.1,
            "out_of_order_packets": 0,
            "duplicate_packets": 0,
            "fragmented_packets": 0,
            "mtu_discovery_blocked": False,
            "icmp_responses": [],
            "tcp_window_scaling": True,
            "tcp_options": ["mss", "wscale"],
        }

        mock_protocol.return_value = {
            "protocol": "https",
            "success_rate": 0.8,
            "error_codes": [200],
            "response_sizes": [1234],
            "header_modifications": {},
            "content_modifications": False,
            "redirect_responses": 0,
            "blocked_responses": 0,
        }

        result = await self.collector.collect_comprehensive_metrics(
            "test.example.com", 443
        )

        self.assertIsInstance(result, ComprehensiveMetrics)
        self.assertEqual(result.target, "test.example.com")
        self.assertEqual(result.timing.latency_ms, 15.5)
        self.assertEqual(result.network.packet_loss_rate, 0.1)
        self.assertIn("https", result.protocols)
        self.assertGreater(result.reliability_score, 0.0)
        self.assertEqual(len(result.collection_errors), 0)

    @patch.object(TimingMetricsCollector, "collect_metrics")
    @patch.object(NetworkMetricsCollector, "collect_metrics")
    @patch.object(ProtocolMetricsCollector, "collect_metrics")
    async def test_collect_comprehensive_metrics_with_errors(
        self, mock_protocol, mock_network, mock_timing
    ):
        """Test comprehensive metrics collection with some collector failures"""
        # Mock timing success, network failure, protocol success
        mock_timing.return_value = {
            "latency_ms": 15.5,
            "jitter_ms": 2.3,
            "packet_timing": [],
        }
        mock_network.side_effect = MetricsCollectionError("Network collection failed")
        mock_protocol.return_value = {"protocol": "https", "success_rate": 0.8}

        result = await self.collector.collect_comprehensive_metrics(
            "test.example.com", 443
        )

        self.assertIsInstance(result, ComprehensiveMetrics)
        self.assertGreater(len(result.collection_errors), 0)
        self.assertLess(result.reliability_score, 1.0)  # Should be penalized for errors

    async def test_collect_comprehensive_metrics_selective_collection(self):
        """Test selective metrics collection"""
        with patch.object(
            self.collector.timing_collector, "collect_metrics"
        ) as mock_timing:
            mock_timing.return_value = {"latency_ms": 15.5}

            result = await self.collector.collect_comprehensive_metrics(
                "test.example.com",
                443,
                include_timing=True,
                include_network=False,
                include_protocol=False,
            )

            self.assertIsInstance(result, ComprehensiveMetrics)
            mock_timing.assert_called_once()

    def test_validate_comprehensive_metrics_valid(self):
        """Test validation of valid comprehensive metrics"""
        metrics = ComprehensiveMetrics(target="test.example.com")
        metrics.timing.latency_ms = 15.5
        metrics.network.packet_loss_rate = 0.1
        metrics.protocols["http"] = ProtocolMetrics(protocol="http", success_rate=0.8)
        metrics.reliability_score = 0.9

        errors = self.collector.validate_comprehensive_metrics(metrics)
        self.assertEqual(errors, [])

    def test_validate_comprehensive_metrics_invalid(self):
        """Test validation of invalid comprehensive metrics"""
        metrics = ComprehensiveMetrics(target="")  # Empty target
        metrics.timing.latency_ms = -5.0  # Negative latency
        metrics.network.packet_loss_rate = 1.5  # Invalid packet loss rate
        metrics.protocols["http"] = ProtocolMetrics(
            protocol="http", success_rate=1.5
        )  # Invalid success rate
        metrics.reliability_score = -0.1  # Invalid reliability score

        errors = self.collector.validate_comprehensive_metrics(metrics)

        self.assertGreater(len(errors), 0)
        self.assertTrue(any("Target cannot be empty" in error for error in errors))
        self.assertTrue(any("Latency cannot be negative" in error for error in errors))
        self.assertTrue(
            any(
                "Packet loss rate must be between 0.0 and 1.0" in error
                for error in errors
            )
        )
        self.assertTrue(
            any(
                "Success rate for http must be between 0.0 and 1.0" in error
                for error in errors
            )
        )
        self.assertTrue(
            any(
                "Reliability score must be between 0.0 and 1.0" in error
                for error in errors
            )
        )

    def test_aggregate_metrics_empty_list(self):
        """Test aggregation with empty metrics list"""
        with self.assertRaises(ValueError):
            self.collector.aggregate_metrics([])

    def test_aggregate_metrics_single_item(self):
        """Test aggregation with single metrics item"""
        metrics = ComprehensiveMetrics(target="test.example.com")
        metrics.timing.latency_ms = 15.5
        metrics.reliability_score = 0.8

        result = self.collector.aggregate_metrics([metrics])

        self.assertEqual(result.target, "test.example.com")
        self.assertEqual(result.timing.latency_ms, 15.5)
        self.assertEqual(result.reliability_score, 0.8)

    def test_aggregate_metrics_multiple_items(self):
        """Test aggregation with multiple metrics items"""
        metrics1 = ComprehensiveMetrics(target="test.example.com")
        metrics1.timing.latency_ms = 10.0
        metrics1.network.packet_loss_rate = 0.1
        metrics1.protocols["http"] = ProtocolMetrics(protocol="http", success_rate=0.8)

        metrics2 = ComprehensiveMetrics(target="test.example.com")
        metrics2.timing.latency_ms = 20.0
        metrics2.network.packet_loss_rate = 0.2
        metrics2.protocols["http"] = ProtocolMetrics(protocol="http", success_rate=0.6)

        result = self.collector.aggregate_metrics([metrics1, metrics2])

        self.assertEqual(result.target, "test.example.com")
        self.assertEqual(result.timing.latency_ms, 15.0)  # Average of 10.0 and 20.0
        self.assertEqual(result.network.packet_loss_rate, 0.2)  # Max of 0.1 and 0.2
        self.assertEqual(
            result.protocols["http"].success_rate, 0.7
        )  # Average of 0.8 and 0.6


class TestMetricsCollectorIntegration(unittest.TestCase):
    """Integration tests for MetricsCollector"""

    def setUp(self):
        self.collector = MetricsCollector(timeout=1.0)

    async def test_end_to_end_collection_mock(self):
        """Test end-to-end metrics collection with mocked network calls"""
        with patch("asyncio.open_connection") as mock_open_connection:
            mock_reader = AsyncMock()
            mock_writer = AsyncMock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = Mock()
            mock_writer.wait_closed = AsyncMock()
            mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n\r\n")

            mock_open_connection.return_value = (mock_reader, mock_writer)

            result = await self.collector.collect_comprehensive_metrics(
                "httpbin.org", 80
            )

            self.assertIsInstance(result, ComprehensiveMetrics)
            self.assertEqual(result.target, "httpbin.org")
            self.assertGreaterEqual(result.reliability_score, 0.0)
            self.assertLessEqual(result.reliability_score, 1.0)


if __name__ == "__main__":
    # Run async tests
    def run_async_test(test_func):
        """Helper to run async test functions"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(test_func())
        finally:
            loop.close()

    # Create test suite
    suite = unittest.TestSuite()

    # Add all test classes
    test_classes = [
        TestTimingMetrics,
        TestNetworkMetrics,
        TestProtocolMetrics,
        TestComprehensiveMetrics,
        TestBaseMetricsCollector,
        TestTimingMetricsCollector,
        TestNetworkMetricsCollector,
        TestProtocolMetricsCollector,
        TestMetricsCollector,
        TestMetricsCollectorIntegration,
    ]

    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
