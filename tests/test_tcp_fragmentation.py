#!/usr/bin/env python3
"""
Comprehensive tests for TCP fragmentation attacks.

Tests all TCP fragmentation attack implementations according to task 5 requirements:
- TCP packet fragmentation techniques
- TCP window manipulation attacks
- TCP sequence number manipulation
- TCP options modification attacks
"""

import unittest
import time

from tcp_fragmentation import (
    SimpleTCPFragmentationAttack,
    FakeDisorderAttack,
    MultiSplitAttack,
    SequenceOverlapAttack,
    WindowManipulationAttack,
    TCPOptionsModificationAttack,
    TCPFragmentationConfig,
)
from base import AttackContext, AttackResult, AttackStatus


class TestTCPFragmentationConfig(unittest.TestCase):
    """Test TCP fragmentation configuration."""

    def test_config_creation(self):
        """Test creating TCP fragmentation configuration."""
        config = TCPFragmentationConfig(
            split_positions=[1, 5, 10], fragment_count=3, fake_ttl=2
        )

        self.assertEqual(config.split_positions, [1, 5, 10])
        self.assertEqual(config.fragment_count, 3)
        self.assertEqual(config.fake_ttl, 2)
        self.assertFalse(config.randomize_order)
        self.assertEqual(config.delay_between_fragments_ms, 1.0)

    def test_config_defaults(self):
        """Test default configuration values."""
        config = TCPFragmentationConfig(split_positions=[5])

        self.assertEqual(config.fragment_count, 3)
        self.assertEqual(config.fake_ttl, 2)
        self.assertFalse(config.randomize_order)
        self.assertEqual(config.delay_between_fragments_ms, 1.0)
        self.assertIsNone(config.window_size_override)
        self.assertFalse(config.bad_checksum)
        self.assertEqual(config.sequence_overlap, 0)
        self.assertEqual(config.tcp_options, b"")


class TestSimpleTCPFragmentationAttack(unittest.TestCase):
    """Test simple TCP fragmentation attack."""

    def setUp(self):
        """Set up test fixtures."""
        self.attack = SimpleTCPFragmentationAttack()
        self.context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            params={"split_pos": 3, "fragment_count": 3},
        )

    def test_attack_name(self):
        """Test attack name property."""
        self.assertEqual(self.attack.name, "simple_fragment")

    def test_execute_success(self):
        """Test successful execution of simple fragmentation."""
        result = self.attack.execute(self.context)

        self.assertIsInstance(result, AttackResult)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.technique_used, "simple_fragment")
        self.assertGreaterEqual(
            result.processing_time_ms, 0
        )  # Allow 0 for very fast execution
        self.assertGreater(result.packets_sent, 0)
        self.assertGreater(result.bytes_sent, 0)

        # Check segments
        self.assertTrue(result.has_segments())
        segments = result.segments
        self.assertIsInstance(segments, list)
        self.assertGreater(len(segments), 1)

        # Verify segment structure
        for segment in segments:
            self.assertIsInstance(segment, tuple)
            self.assertEqual(len(segment), 3)
            payload_data, seq_offset, options = segment
            self.assertIsInstance(payload_data, bytes)
            self.assertIsInstance(seq_offset, int)
            self.assertIsInstance(options, dict)

        # Check metadata
        self.assertEqual(result.get_metadata("fragmentation_type"), "simple")
        self.assertEqual(result.get_metadata("split_position"), 3)
        self.assertIsInstance(result.get_metadata("fragment_count"), int)

    def test_execute_empty_payload(self):
        """Test execution with empty payload."""
        self.context.payload = b""
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.FAILURE)
        self.assertIn("No segments created", result.error_message)

    def test_execute_custom_parameters(self):
        """Test execution with custom parameters."""
        self.context.params = {"split_pos": 10, "fragment_count": 5}
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.get_metadata("split_position"), 10)

    def test_split_payload_calculation(self):
        """Test payload splitting calculation."""
        payload = b"0123456789ABCDEF"
        config = TCPFragmentationConfig(split_positions=[4, 8, 12])

        split_positions = self.attack._calculate_split_positions(payload, config)
        self.assertEqual(split_positions, [4, 8, 12])

        fragments = self.attack._split_payload(payload, split_positions)
        expected_fragments = [b"0123", b"4567", b"89AB", b"CDEF"]
        self.assertEqual(fragments, expected_fragments)

    def test_auto_split_calculation(self):
        """Test automatic split position calculation."""
        payload = b"0123456789ABCDEF"  # 16 bytes
        config = TCPFragmentationConfig(split_positions=[], fragment_count=4)

        split_positions = self.attack._calculate_split_positions(payload, config)
        self.assertEqual(len(split_positions), 3)  # 4 fragments = 3 split positions

        fragments = self.attack._split_payload(payload, split_positions)
        self.assertEqual(len(fragments), 4)

        # Verify all fragments together equal original payload
        reconstructed = b"".join(fragments)
        self.assertEqual(reconstructed, payload)


class TestFakeDisorderAttack(unittest.TestCase):
    """Test fake disorder attack."""

    def setUp(self):
        """Set up test fixtures."""
        self.attack = FakeDisorderAttack()
        self.context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            params={"split_pos": 3, "fake_ttl": 2, "delay_ms": 2.0},
        )

    def test_attack_name(self):
        """Test attack name property."""
        self.assertEqual(self.attack.name, "fake_disorder")

    def test_execute_success(self):
        """Test successful execution of fake disorder."""
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.technique_used, "fake_disorder")
        self.assertTrue(result.has_segments())

        # Check metadata
        self.assertEqual(result.get_metadata("fragmentation_type"), "fake_disorder")
        self.assertEqual(result.get_metadata("fake_ttl"), 2)
        self.assertTrue(result.get_metadata("disorder_applied"))

        # Verify segments have proper options
        segments = result.segments
        self.assertGreater(len(segments), 1)

        # First segment should have low TTL (fake packet)
        first_segment = segments[0]
        self.assertEqual(first_segment[2].get("ttl"), 2)

    def test_disorder_application(self):
        """Test that disorder is properly applied to segments."""
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        segments = result.segments

        # Should have at least 2 segments for disorder to be meaningful
        self.assertGreaterEqual(len(segments), 2)

        # First segment should be fake (low TTL)
        fake_segment = segments[0]
        self.assertEqual(fake_segment[2].get("ttl"), 2)


class TestMultiSplitAttack(unittest.TestCase):
    """Test multi-split attack."""

    def setUp(self):
        """Set up test fixtures."""
        self.attack = MultiSplitAttack()
        self.context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            params={"positions": [1, 3, 10], "randomize": False},
        )

    def test_attack_name(self):
        """Test attack name property."""
        self.assertEqual(self.attack.name, "multisplit")

    def test_execute_success(self):
        """Test successful execution of multi-split."""
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.technique_used, "multisplit")
        self.assertTrue(result.has_segments())

        # Check metadata
        self.assertEqual(result.get_metadata("fragmentation_type"), "multisplit")
        self.assertEqual(result.get_metadata("split_positions"), [1, 3, 10])
        self.assertFalse(result.get_metadata("randomized"))

    def test_execute_with_randomization(self):
        """Test execution with randomization enabled."""
        self.context.params["randomize"] = True
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertTrue(result.get_metadata("randomized"))

    def test_invalid_positions_parameter(self):
        """Test handling of invalid positions parameter."""
        self.context.params["positions"] = "invalid"
        result = self.attack.execute(self.context)

        # Should still succeed with default positions
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.get_metadata("split_positions"), [1, 3, 10])

    def test_empty_positions_parameter(self):
        """Test handling of empty positions parameter."""
        self.context.params["positions"] = []
        result = self.attack.execute(self.context)

        # Should still succeed with default positions
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.get_metadata("split_positions"), [1, 3, 10])


class TestSequenceOverlapAttack(unittest.TestCase):
    """Test sequence overlap attack."""

    def setUp(self):
        """Set up test fixtures."""
        self.attack = SequenceOverlapAttack()
        self.context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            params={"split_pos": 3, "overlap_size": 10, "fake_ttl": 2},
        )

    def test_attack_name(self):
        """Test attack name property."""
        self.assertEqual(self.attack.name, "sequence_overlap")

    def test_execute_success(self):
        """Test successful execution of sequence overlap."""
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.technique_used, "sequence_overlap")
        self.assertTrue(result.has_segments())

        # Check metadata
        self.assertEqual(result.get_metadata("fragmentation_type"), "sequence_overlap")
        self.assertEqual(result.get_metadata("overlap_size"), 10)
        self.assertEqual(result.get_metadata("fake_ttl"), 2)

    def test_sequence_overlap_in_segments(self):
        """Test that sequence overlap is properly applied in segments."""
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        segments = result.segments
        self.assertGreater(len(segments), 1)

        # Check that segments have overlapping sequence numbers
        # (This is verified by the negative sequence offset in overlapping segments)
        for i, segment in enumerate(segments):
            payload_data, seq_offset, options = segment
            if i > 0:  # Not the first segment
                # Should have negative offset due to overlap
                self.assertLessEqual(seq_offset, 0)


class TestWindowManipulationAttack(unittest.TestCase):
    """Test window manipulation attack."""

    def setUp(self):
        """Set up test fixtures."""
        self.attack = WindowManipulationAttack()
        self.context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            params={"window_size": 1, "delay_ms": 50.0, "fragment_count": 5},
        )

    def test_attack_name(self):
        """Test attack name property."""
        self.assertEqual(self.attack.name, "window_manipulation")

    def test_execute_success(self):
        """Test successful execution of window manipulation."""
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.technique_used, "window_manipulation")
        self.assertTrue(result.has_segments())

        # Check metadata
        self.assertEqual(
            result.get_metadata("fragmentation_type"), "window_manipulation"
        )
        self.assertEqual(result.get_metadata("window_size"), 1)
        self.assertEqual(result.get_metadata("delay_ms"), 50.0)

    def test_window_size_in_segments(self):
        """Test that window size is properly set in segments."""
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        segments = result.segments

        # All segments should have window size override
        for segment in segments:
            payload_data, seq_offset, options = segment
            self.assertEqual(options.get("window_size"), 1)

    def test_delay_in_segments(self):
        """Test that delay is properly set in segments."""
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        segments = result.segments

        # Segments after the first should have delay
        for i, segment in enumerate(segments):
            payload_data, seq_offset, options = segment
            if i > 0:  # Not the first segment
                self.assertEqual(options.get("delay_ms"), 50.0)


class TestTCPOptionsModificationAttack(unittest.TestCase):
    """Test TCP options modification attack."""

    def setUp(self):
        """Set up test fixtures."""
        self.attack = TCPOptionsModificationAttack()
        self.context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            params={"split_pos": 5, "options_type": "mss", "bad_checksum": False},
        )

    def test_attack_name(self):
        """Test attack name property."""
        self.assertEqual(self.attack.name, "tcp_options_modification")

    def test_execute_success(self):
        """Test successful execution of TCP options modification."""
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.technique_used, "tcp_options_modification")
        self.assertTrue(result.has_segments())

        # Check metadata
        self.assertEqual(
            result.get_metadata("fragmentation_type"), "tcp_options_modification"
        )
        self.assertEqual(result.get_metadata("options_type"), "mss")
        self.assertFalse(result.get_metadata("bad_checksum"))
        self.assertGreater(result.get_metadata("tcp_options_length"), 0)

    def test_create_mss_options(self):
        """Test creating MSS TCP options."""
        options = self.attack._create_tcp_options("mss")
        self.assertIsInstance(options, bytes)
        self.assertGreater(len(options), 0)
        # MSS option should be 4 bytes: kind(1) + length(1) + value(2)
        self.assertEqual(len(options), 4)

    def test_create_window_scale_options(self):
        """Test creating window scale TCP options."""
        options = self.attack._create_tcp_options("window_scale")
        self.assertIsInstance(options, bytes)
        self.assertEqual(len(options), 3)  # kind(1) + length(1) + scale(1)

    def test_create_timestamp_options(self):
        """Test creating timestamp TCP options."""
        options = self.attack._create_tcp_options("timestamp")
        self.assertIsInstance(options, bytes)
        self.assertEqual(
            len(options), 10
        )  # kind(1) + length(1) + timestamp(4) + echo(4)

    def test_create_sack_permitted_options(self):
        """Test creating SACK permitted TCP options."""
        options = self.attack._create_tcp_options("sack_permitted")
        self.assertIsInstance(options, bytes)
        self.assertEqual(len(options), 2)  # kind(1) + length(1)

    def test_create_md5_signature_options(self):
        """Test creating MD5 signature TCP options."""
        options = self.attack._create_tcp_options("md5_signature")
        self.assertIsInstance(options, bytes)
        self.assertEqual(len(options), 18)  # kind(1) + length(1) + signature(16)

    def test_create_custom_options(self):
        """Test creating custom TCP options."""
        options = self.attack._create_tcp_options("custom")
        self.assertIsInstance(options, bytes)
        self.assertEqual(len(options), 4)  # kind(1) + length(1) + data(2)

    def test_create_default_options(self):
        """Test creating default TCP options."""
        options = self.attack._create_tcp_options("unknown")
        self.assertIsInstance(options, bytes)
        self.assertEqual(len(options), 4)  # 4 NOP bytes

    def test_execute_with_different_options(self):
        """Test execution with different TCP options types."""
        options_types = [
            "mss",
            "window_scale",
            "timestamp",
            "sack_permitted",
            "md5_signature",
            "custom",
        ]

        for options_type in options_types:
            with self.subTest(options_type=options_type):
                self.context.params["options_type"] = options_type
                result = self.attack.execute(self.context)

                self.assertEqual(result.status, AttackStatus.SUCCESS)
                self.assertEqual(result.get_metadata("options_type"), options_type)
                self.assertGreater(result.get_metadata("tcp_options_length"), 0)

    def test_execute_with_bad_checksum(self):
        """Test execution with bad checksum enabled."""
        self.context.params["bad_checksum"] = True
        result = self.attack.execute(self.context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertTrue(result.get_metadata("bad_checksum"))

        # Check that segments have bad_checksum option
        segments = result.segments
        for segment in segments:
            payload_data, seq_offset, options = segment
            self.assertTrue(options.get("bad_checksum", False))


class TestTCPFragmentationRegistration(unittest.TestCase):
    """Test TCP fragmentation attacks registration."""

    def test_register_tcp_fragmentation_attacks(self):
        """Test registration of all TCP fragmentation attacks."""
        # Test that the registration function exists and can be called
        try:
            from tcp_fragmentation import register_tcp_fragmentation_attacks

            # Just test that the function exists and doesn't crash
            # The actual registration is tested in integration tests
            self.assertTrue(callable(register_tcp_fragmentation_attacks))
        except ImportError as e:
            # Skip test if modern_registry is not available
            self.skipTest(f"Modern registry not available: {e}")


class TestTCPFragmentationIntegration(unittest.TestCase):
    """Integration tests for TCP fragmentation attacks."""

    def setUp(self):
        """Set up integration test fixtures."""
        self.test_payload = (
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent\r\n\r\n"
        )
        self.base_context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.test_payload,
        )

    def test_all_attacks_produce_segments(self):
        """Test that all TCP fragmentation attacks produce valid segments."""
        attacks = [
            (SimpleTCPFragmentationAttack(), {"split_pos": 3}),
            (FakeDisorderAttack(), {"split_pos": 3, "fake_ttl": 2}),
            (MultiSplitAttack(), {"positions": [1, 5, 10]}),
            (SequenceOverlapAttack(), {"split_pos": 3, "overlap_size": 5}),
            (WindowManipulationAttack(), {"window_size": 1, "fragment_count": 3}),
            (TCPOptionsModificationAttack(), {"split_pos": 5, "options_type": "mss"}),
        ]

        for attack, params in attacks:
            with self.subTest(attack=attack.name):
                context = AttackContext(
                    dst_ip=self.base_context.dst_ip,
                    dst_port=self.base_context.dst_port,
                    domain=self.base_context.domain,
                    payload=self.base_context.payload,
                    params=params,
                )

                result = attack.execute(context)

                # All attacks should succeed
                self.assertEqual(result.status, AttackStatus.SUCCESS)

                # All attacks should produce segments
                self.assertTrue(result.has_segments())
                segments = result.segments
                self.assertIsInstance(segments, list)
                self.assertGreater(len(segments), 0)

                # Verify segment structure
                total_payload_size = 0
                for segment in segments:
                    self.assertIsInstance(segment, tuple)
                    self.assertEqual(len(segment), 3)

                    payload_data, seq_offset, options = segment
                    self.assertIsInstance(payload_data, bytes)
                    self.assertIsInstance(seq_offset, int)
                    self.assertIsInstance(options, dict)

                    total_payload_size += len(payload_data)

                # Total payload size should match original (allowing for overlaps)
                if "overlap" not in attack.name:
                    self.assertEqual(total_payload_size, len(self.test_payload))

    def test_segment_reconstruction(self):
        """Test that segments can be reconstructed to original payload."""
        attack = SimpleTCPFragmentationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=self.test_payload,
            params={"split_pos": 10, "fragment_count": 3},
        )

        result = attack.execute(context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)

        segments = result.segments

        # Sort segments by sequence offset to reconstruct
        sorted_segments = sorted(segments, key=lambda x: x[1])

        # Reconstruct payload
        reconstructed = b""
        for payload_data, seq_offset, options in sorted_segments:
            reconstructed += payload_data

        self.assertEqual(reconstructed, self.test_payload)

    def test_performance_benchmarks(self):
        """Test performance of TCP fragmentation attacks."""
        attack = SimpleTCPFragmentationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=self.test_payload,
            params={"split_pos": 5},
        )

        # Run multiple times to get average
        execution_times = []
        for _ in range(10):
            start_time = time.time()
            result = attack.execute(context)
            end_time = time.time()

            self.assertEqual(result.status, AttackStatus.SUCCESS)
            execution_times.append((end_time - start_time) * 1000)  # Convert to ms

        avg_time = sum(execution_times) / len(execution_times)

        # Should execute quickly (under 10ms on average)
        self.assertLess(avg_time, 10.0)

        # Processing time should be recorded
        result = attack.execute(context)
        self.assertGreaterEqual(
            result.processing_time_ms, 0
        )  # Allow 0 for very fast execution


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)
