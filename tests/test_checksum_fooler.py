"""
Unit tests for ChecksumFooler component.

Tests badsum functionality, checksum calculation, and conditional application
with various TCP packet scenarios.
"""

import pytest
import struct
import socket
from unittest.mock import patch

from core.bypass.strategies.checksum_fooler import ChecksumFooler, ChecksumResult
from core.bypass.strategies.config_models import FoolingConfig, TCPPacketInfo


class TestChecksumFooler:
    """Test suite for ChecksumFooler component."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = FoolingConfig(badsum=True)
        self.fooler = ChecksumFooler(self.config)

    def test_init_default(self):
        """Test ChecksumFooler initialization with default config."""
        fooler = ChecksumFooler()
        assert fooler is not None
        assert fooler.config is not None
        assert fooler.config.badsum is False  # Default disabled

    def test_init_with_config(self):
        """Test ChecksumFooler initialization with custom config."""
        config = FoolingConfig(badsum=True)
        fooler = ChecksumFooler(config)

        assert fooler.config.badsum is True
        assert hasattr(fooler, "_stats")
        assert hasattr(fooler, "_checksum_cache")

    def test_calculate_bad_checksum_consistency(self):
        """Test that bad checksum calculation is consistent."""
        original_checksum = 0x1234

        bad1 = self.fooler.calculate_bad_checksum(original_checksum)
        bad2 = self.fooler.calculate_bad_checksum(original_checksum)

        assert bad1 == bad2  # Should be consistent
        assert bad1 != original_checksum  # Should be different from original
        assert 0 <= bad1 <= 0xFFFF  # Should be valid 16-bit value

    def test_calculate_bad_checksum_pattern(self):
        """Test that bad checksum follows expected pattern."""
        original_checksum = 0x5678
        expected_bad = original_checksum ^ 0xDEAD

        result = self.fooler.calculate_bad_checksum(original_checksum)

        assert result == expected_bad

    def test_calculate_bad_checksum_edge_cases(self):
        """Test bad checksum calculation with edge cases."""
        test_cases = [
            0x0000,  # Zero checksum
            0xFFFF,  # Max checksum
            0xDEAD,  # Pattern value itself
            0x8000,  # High bit set
        ]

        for original in test_cases:
            bad = self.fooler.calculate_bad_checksum(original)
            assert bad != original
            assert 0 <= bad <= 0xFFFF

    def test_calculate_bad_checksum_error_handling(self):
        """Test bad checksum calculation error handling."""
        # Test with invalid input (should handle gracefully)
        with patch.object(
            self.fooler, "calculate_bad_checksum", side_effect=Exception("Test error")
        ):
            with pytest.raises(Exception):
                self.fooler.calculate_bad_checksum(0x1234)

    def test_should_apply_badsum_enabled(self):
        """Test badsum application decision when enabled."""
        tcp_info = self._create_https_tcp_info()

        result = self.fooler.should_apply_badsum(tcp_info, is_first_part=True)

        assert result is True

    def test_should_apply_badsum_disabled(self):
        """Test badsum application decision when disabled."""
        config = FoolingConfig(badsum=False)
        fooler = ChecksumFooler(config)
        tcp_info = self._create_https_tcp_info()

        result = fooler.should_apply_badsum(tcp_info, is_first_part=True)

        assert result is False

    def test_should_apply_badsum_not_first_part(self):
        """Test badsum application decision for non-first packet part."""
        tcp_info = self._create_https_tcp_info()

        result = self.fooler.should_apply_badsum(tcp_info, is_first_part=False)

        assert result is False

    def test_should_apply_badsum_no_payload(self):
        """Test badsum application decision for packet without payload."""
        tcp_info = self._create_tcp_info_no_payload()

        result = self.fooler.should_apply_badsum(tcp_info, is_first_part=True)

        assert result is False

    def test_should_apply_badsum_not_https(self):
        """Test badsum application decision for non-HTTPS traffic."""
        tcp_info = self._create_http_tcp_info()

        result = self.fooler.should_apply_badsum(tcp_info, is_first_part=True)

        assert result is False

    def test_should_apply_badsum_small_packet(self):
        """Test badsum application decision for small packet."""
        tcp_info = self._create_https_tcp_info()
        # Create TCP info with small payload
        tcp_info.payload = b"small"  # Small payload

        result = self.fooler.should_apply_badsum(tcp_info, is_first_part=True)

        # Should still apply badsum for HTTPS even with small payload
        assert result is True

    def test_apply_badsum_success(self):
        """Test successful badsum application."""
        packet_data = self._create_tcp_packet()
        tcp_info = self._create_https_tcp_info()

        modified_packet, checksum_result = self.fooler.apply_badsum(
            packet_data, tcp_info
        )

        assert len(modified_packet) == len(packet_data)
        assert isinstance(checksum_result, ChecksumResult)
        assert checksum_result.is_badsum_applied is True
        assert checksum_result.original_checksum != checksum_result.modified_checksum

    def test_apply_badsum_checksum_modification(self):
        """Test that badsum actually modifies the checksum in packet."""
        packet_data = self._create_tcp_packet()
        tcp_info = self._create_https_tcp_info()
        original_checksum = self._extract_checksum_from_packet(packet_data)

        modified_packet, checksum_result = self.fooler.apply_badsum(
            packet_data, tcp_info
        )
        modified_checksum = self._extract_checksum_from_packet(modified_packet)

        assert modified_checksum != original_checksum
        assert modified_checksum == checksum_result.modified_checksum

    def test_apply_badsum_error_handling(self):
        """Test badsum application error handling."""
        invalid_packet = b"invalid"  # Too small to be valid TCP packet
        tcp_info = self._create_https_tcp_info()

        with pytest.raises(ChecksumCalculationError):
            self.fooler.apply_badsum(invalid_packet, tcp_info)

    def test_replace_tcp_checksum_valid(self):
        """Test TCP checksum replacement in valid packet."""
        packet_data = self._create_tcp_packet()
        new_checksum = 0xABCD

        modified_packet = self.fooler._replace_tcp_checksum(packet_data, new_checksum)
        extracted_checksum = self._extract_checksum_from_packet(modified_packet)

        assert extracted_checksum == new_checksum
        assert len(modified_packet) == len(packet_data)

    def test_replace_tcp_checksum_invalid_packet(self):
        """Test TCP checksum replacement with invalid packet."""
        invalid_packet = b"too_small"

        with pytest.raises(ChecksumCalculationError):
            self.fooler._replace_tcp_checksum(invalid_packet, 0x1234)

    def test_verify_checksum_modification_valid(self):
        """Test checksum modification verification."""
        original_packet = self._create_tcp_packet()
        tcp_info = self._create_https_tcp_info()
        modified_packet, _ = self.fooler.apply_badsum(original_packet, tcp_info)

        result = self.fooler.verify_checksum_modification(
            original_packet, modified_packet
        )

        assert result is True

    def test_verify_checksum_modification_no_change(self):
        """Test checksum modification verification when no change occurred."""
        packet = self._create_tcp_packet()

        result = self.fooler.verify_checksum_modification(packet, packet)

        assert result is False  # No modification detected

    def test_extract_tcp_checksum_valid(self):
        """Test TCP checksum extraction from valid packet."""
        packet = self._create_tcp_packet_with_checksum(0x5678)

        checksum = self.fooler._extract_tcp_checksum(packet)

        assert checksum == 0x5678

    def test_extract_tcp_checksum_invalid(self):
        """Test TCP checksum extraction from invalid packet."""
        invalid_packet = b"invalid"

        with pytest.raises(ChecksumCalculationError):
            self.fooler._extract_tcp_checksum(invalid_packet)

    def test_packets_equal_except_checksum_true(self):
        """Test packet equality check excluding checksum."""
        packet1 = self._create_tcp_packet_with_checksum(0x1111)
        packet2 = self._create_tcp_packet_with_checksum(0x2222)

        result = self.fooler._packets_equal_except_checksum(packet1, packet2)

        assert result is True

    def test_packets_equal_except_checksum_false(self):
        """Test packet equality check with different content."""
        packet1 = self._create_tcp_packet()
        packet2 = self._create_tcp_packet()
        # Modify payload
        packet2_modified = bytearray(packet2)
        packet2_modified[-1] = 0xFF
        packet2 = bytes(packet2_modified)

        result = self.fooler._packets_equal_except_checksum(packet1, packet2)

        assert result is False

    def test_restore_original_checksum(self):
        """Test restoring original checksum."""
        original_packet = self._create_tcp_packet()
        original_checksum = self._extract_checksum_from_packet(original_packet)

        # Apply badsum
        tcp_info = self._create_https_tcp_info()
        modified_packet, _ = self.fooler.apply_badsum(original_packet, tcp_info)

        # Restore original checksum
        restored_packet = self.fooler.restore_original_checksum(
            modified_packet, original_checksum
        )
        restored_checksum = self._extract_checksum_from_packet(restored_packet)

        assert restored_checksum == original_checksum

    def test_get_stats(self):
        """Test statistics retrieval."""
        stats = self.fooler.get_stats()

        assert "badsum_applied" in stats
        assert "badsum_skipped" in stats
        assert "checksum_errors" in stats
        assert "cache_size" in stats
        assert all(isinstance(v, int) for v in stats.values())

    def test_reset_stats(self):
        """Test statistics reset."""
        # Apply some operations to generate stats
        tcp_info = self._create_https_tcp_info()
        packet = self._create_tcp_packet()
        self.fooler.apply_badsum(packet, tcp_info)

        # Reset stats
        self.fooler.reset_stats()
        stats = self.fooler.get_stats()

        assert stats["badsum_applied"] == 0
        assert stats["badsum_skipped"] == 0
        assert stats["checksum_errors"] == 0

    def test_apply_badsum_to_first_part_only(self):
        """Test applying badsum only to first part of split packets."""
        # Create multiple packet parts
        packet_parts = [
            self._create_tcp_packet(),
            self._create_tcp_packet(),
            self._create_tcp_packet(),
        ]
        tcp_infos = [
            self._create_https_tcp_info(),
            self._create_https_tcp_info(),
            self._create_https_tcp_info(),
        ]

        modified_parts, checksum_results = self.fooler.apply_badsum_to_first_part_only(
            packet_parts, tcp_infos
        )

        assert len(modified_parts) == 3
        assert len(checksum_results) == 3

        # Only first part should have badsum applied
        assert checksum_results[0] is not None
        assert checksum_results[0].is_badsum_applied is True
        assert checksum_results[1] is None  # No badsum for second part
        assert checksum_results[2] is None  # No badsum for third part

    def test_get_badsum_application_summary(self):
        """Test badsum application summary generation."""
        # Create some checksum results
        checksum_results = [
            ChecksumResult(0x1111, 0x2222, True, "test"),
            None,  # No badsum applied
            ChecksumResult(0x3333, 0x4444, True, "test"),
        ]

        summary = self.fooler.get_badsum_application_summary(checksum_results)

        assert summary["total_parts"] == 3
        assert summary["badsum_applied_count"] == 2
        assert summary["badsum_skipped_count"] == 1
        assert summary["application_rate"] == 2 / 3
        assert len(summary["checksum_changes"]) == 2

    def test_validate_checksum_integrity_valid(self):
        """Test checksum integrity validation with valid checksum."""
        packet = self._create_tcp_packet_with_correct_checksum()

        result = self.fooler.validate_checksum_integrity(packet)

        assert result["is_valid"] is True
        assert "current_checksum" in result
        assert "correct_checksum" in result

    def test_validate_checksum_integrity_invalid(self):
        """Test checksum integrity validation with invalid checksum."""
        packet = self._create_tcp_packet_with_checksum(0xFFFF)  # Likely wrong

        result = self.fooler.validate_checksum_integrity(packet)

        assert result["is_valid"] is False
        assert "error_type" in result
        assert result["checksum_diff"] > 0

    def test_is_likely_badsum_pattern_true(self):
        """Test badsum pattern recognition for known patterns."""
        correct_checksum = 0x1234
        badsum_checksum = correct_checksum ^ 0xDEAD

        result = self.fooler._is_likely_badsum_pattern(
            badsum_checksum, correct_checksum
        )

        assert result is True

    def test_is_likely_badsum_pattern_false(self):
        """Test badsum pattern recognition for random corruption."""
        correct_checksum = 0x1234
        random_checksum = 0x5678  # Not a known badsum pattern

        result = self.fooler._is_likely_badsum_pattern(
            random_checksum, correct_checksum
        )

        assert result is False

    def test_classify_checksum_error(self):
        """Test checksum error classification."""
        correct = 0x1234

        # Test different error types
        assert (
            self.fooler._classify_checksum_error(correct ^ 0xDEAD, correct)
            == "intentional_badsum"
        )
        assert (
            self.fooler._classify_checksum_error(correct + 1, correct)
            == "single_bit_error"
        )
        assert self.fooler._classify_checksum_error(0x0000, correct) == "zero_checksum"
        assert (
            self.fooler._classify_checksum_error(0xFFFF, correct) == "all_ones_checksum"
        )

    def test_create_test_packet_with_badsum(self):
        """Test creating test packet with badsum."""
        base_packet = self._create_tcp_packet()

        modified_packet, test_info = self.fooler.create_test_packet_with_badsum(
            base_packet
        )

        assert len(modified_packet) == len(base_packet)
        assert "original_checksum" in test_info
        assert "badsum_checksum" in test_info
        assert "modification_method" in test_info
        assert test_info["original_checksum"] != test_info["badsum_checksum"]

    def test_parse_tcp_info_from_packet(self):
        """Test parsing TCP info from raw packet."""
        packet = self._create_tcp_packet()

        tcp_info = self.fooler._parse_tcp_info_from_packet(packet)

        assert isinstance(tcp_info, TCPPacketInfo)
        assert tcp_info.src_ip is not None
        assert tcp_info.dst_ip is not None
        assert tcp_info.src_port > 0
        assert tcp_info.dst_port > 0

    def test_run_checksum_validation_tests(self):
        """Test running comprehensive checksum validation tests."""
        test_results = self.fooler.run_checksum_validation_tests()

        assert "tests_run" in test_results
        assert "tests_passed" in test_results
        assert "tests_failed" in test_results
        assert "test_details" in test_results
        assert test_results["tests_run"] > 0

    def test_calculate_correct_tcp_checksum(self):
        """Test correct TCP checksum calculation."""
        packet = self._create_tcp_packet_with_checksum(
            0x0000
        )  # Zero checksum for calculation

        correct_checksum = self.fooler._calculate_correct_tcp_checksum(packet)

        assert isinstance(correct_checksum, int)
        assert 0 <= correct_checksum <= 0xFFFF

    def test_calculate_internet_checksum(self):
        """Test Internet checksum calculation (RFC 1071)."""
        test_data = b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c"

        checksum = self.fooler._calculate_internet_checksum(test_data)

        assert isinstance(checksum, int)
        assert 0 <= checksum <= 0xFFFF

    def _create_https_tcp_info(self) -> TCPPacketInfo:
        """Create TCP info for HTTPS traffic."""
        return TCPPacketInfo(
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",  # example.com
            src_port=54321,
            dst_port=443,  # HTTPS
            seq_num=1000,
            ack_num=2000,
            flags=0x18,  # PSH+ACK
            window_size=65535,
            checksum=0x1234,
            payload=b"TLS handshake data",
        )

    def _create_http_tcp_info(self) -> TCPPacketInfo:
        """Create TCP info for HTTP traffic."""
        return TCPPacketInfo(
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            src_port=54321,
            dst_port=80,  # HTTP
            seq_num=1000,
            ack_num=2000,
            flags=0x18,
            window_size=65535,
            checksum=0x1234,
            payload=b"GET / HTTP/1.1\r\n",
        )

    def _create_tcp_info_no_payload(self) -> TCPPacketInfo:
        """Create TCP info without payload."""
        return TCPPacketInfo(
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            src_port=54321,
            dst_port=443,
            seq_num=1000,
            ack_num=2000,
            flags=0x10,  # ACK only
            window_size=65535,
            checksum=0x1234,
            payload=b"",  # No payload
        )

    def _create_tcp_packet(self) -> bytes:
        """Create a basic TCP packet."""
        # IP header (20 bytes)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,  # Version + IHL
            0x00,  # TOS
            0x0040,  # Total length
            0x1234,  # ID
            0x4000,  # Flags + Fragment offset
            0x40,  # TTL
            0x06,  # Protocol (TCP)
            0x0000,  # Checksum (will be calculated)
            socket.inet_aton("192.168.1.100"),  # Source IP
            socket.inet_aton("93.184.216.34"),  # Dest IP
        )

        # TCP header (20 bytes)
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            54321,  # Source port
            443,  # Dest port
            1000,  # Sequence number
            2000,  # Ack number
            0x50,  # Data offset (5 * 4 = 20 bytes)
            0x18,  # Flags (PSH+ACK)
            65535,  # Window size
            0x1234,  # Checksum
            0,  # Urgent pointer
        )

        # Payload
        payload = b"TLS handshake data"

        return ip_header + tcp_header + payload

    def _create_tcp_packet_with_checksum(self, checksum: int) -> bytes:
        """Create TCP packet with specific checksum."""
        packet = bytearray(self._create_tcp_packet())

        # Replace checksum at TCP header offset 16 (IP header is 20 bytes)
        tcp_checksum_offset = 20 + 16
        struct.pack_into("!H", packet, tcp_checksum_offset, checksum)

        return bytes(packet)

    def _create_tcp_packet_with_correct_checksum(self) -> bytes:
        """Create TCP packet with correct checksum."""
        packet = self._create_tcp_packet_with_checksum(0x0000)
        correct_checksum = self.fooler._calculate_correct_tcp_checksum(packet)
        return self._create_tcp_packet_with_checksum(correct_checksum)

    def _extract_checksum_from_packet(self, packet: bytes) -> int:
        """Extract TCP checksum from packet."""
        # TCP checksum is at offset 16 from start of TCP header
        # IP header is 20 bytes, so TCP checksum is at offset 36
        tcp_checksum_offset = 20 + 16
        return struct.unpack(
            "!H", packet[tcp_checksum_offset : tcp_checksum_offset + 2]
        )[0]


@pytest.fixture
def checksum_fooler():
    """Fixture providing a ChecksumFooler instance."""
    config = FoolingConfig(badsum=True)
    return ChecksumFooler(config)


@pytest.fixture
def disabled_checksum_fooler():
    """Fixture providing a ChecksumFooler with badsum disabled."""
    config = FoolingConfig(badsum=False)
    return ChecksumFooler(config)


@pytest.fixture
def sample_tcp_packet():
    """Fixture providing a sample TCP packet."""
    fooler = ChecksumFooler()
    return fooler._create_tcp_packet()


class TestChecksumFoolerIntegration:
    """Integration tests for ChecksumFooler with real-world scenarios."""

    def test_youtube_https_badsum(self, checksum_fooler):
        """Test badsum application to YouTube HTTPS traffic."""
        packet = self._create_youtube_https_packet()
        tcp_info = self._create_youtube_tcp_info()

        modified_packet, result = checksum_fooler.apply_badsum(packet, tcp_info)

        assert result.is_badsum_applied is True
        assert len(modified_packet) == len(packet)

        # Verify checksum was actually changed
        original_checksum = checksum_fooler._extract_tcp_checksum(packet)
        modified_checksum = checksum_fooler._extract_tcp_checksum(modified_packet)
        assert original_checksum != modified_checksum

    def test_multiple_packet_parts_scenario(self, checksum_fooler):
        """Test badsum application to multiple packet parts (split scenario)."""
        # Simulate split packet scenario
        packet_parts = [
            self._create_tls_client_hello_part1(),
            self._create_tls_client_hello_part2(),
            self._create_tls_client_hello_part3(),
        ]

        tcp_infos = [
            self._create_youtube_tcp_info(),
            self._create_youtube_tcp_info(),
            self._create_youtube_tcp_info(),
        ]

        modified_parts, results = checksum_fooler.apply_badsum_to_first_part_only(
            packet_parts, tcp_infos
        )

        # Only first part should have badsum
        assert results[0] is not None and results[0].is_badsum_applied
        assert results[1] is None
        assert results[2] is None

        # Verify first part checksum was modified
        original_checksum = checksum_fooler._extract_tcp_checksum(packet_parts[0])
        modified_checksum = checksum_fooler._extract_tcp_checksum(modified_parts[0])
        assert original_checksum != modified_checksum

    def test_performance_large_volume(self, checksum_fooler):
        """Test performance with large volume of packets."""
        import time

        packets = [self._create_youtube_https_packet() for _ in range(100)]
        tcp_info = self._create_youtube_tcp_info()

        start_time = time.time()

        for packet in packets:
            checksum_fooler.apply_badsum(packet, tcp_info)

        end_time = time.time()
        processing_time = end_time - start_time

        # Should process 100 packets in reasonable time (< 1 second)
        assert processing_time < 1.0

        # Check stats
        stats = checksum_fooler.get_stats()
        assert stats["badsum_applied"] == 100

    def test_error_recovery_malformed_packets(self, checksum_fooler):
        """Test error recovery with malformed packets."""
        malformed_packets = [
            b"",  # Empty packet
            b"too_short",  # Too short
            b"\x00" * 10,  # Wrong format
            b"\xff" * 100,  # Invalid data
        ]

        tcp_info = self._create_youtube_tcp_info()
        error_count = 0

        for packet in malformed_packets:
            try:
                checksum_fooler.apply_badsum(packet, tcp_info)
            except ChecksumCalculationError:
                error_count += 1

        # Should handle most errors gracefully (at least 3 out of 4)
        assert error_count >= len(malformed_packets) - 1

        # Stats should reflect errors
        stats = checksum_fooler.get_stats()
        assert stats["checksum_errors"] > 0

    def _create_youtube_https_packet(self) -> bytes:
        """Create a realistic YouTube HTTPS packet."""
        # IP header for YouTube traffic
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,  # Version + IHL
            0x00,  # TOS
            0x0200,  # Total length (512 bytes)
            0x5678,  # ID
            0x4000,  # Flags + Fragment offset
            0x40,  # TTL
            0x06,  # Protocol (TCP)
            0x0000,  # Checksum
            socket.inet_aton("192.168.1.100"),  # Source IP
            socket.inet_aton("172.217.164.142"),  # YouTube IP
        )

        # TCP header for HTTPS
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            49152,  # Source port
            443,  # HTTPS port
            0x12345678,  # Sequence number
            0x87654321,  # Ack number
            0x50,  # Data offset
            0x18,  # Flags (PSH+ACK)
            65535,  # Window size
            0xABCD,  # Checksum (will be modified)
            0,  # Urgent pointer
        )

        # TLS payload (Client Hello)
        tls_payload = (
            b"\x16\x03\x03\x01\x00"  # TLS record header
            b"\x01\x00\x00\xfc"  # Handshake header
            b"\x03\x03"  # Client Hello version
            + b"\x00" * 32  # Random
            + b"\x00"  # Session ID length
            + b"\x00\x20"  # Cipher suites length
            + b"\x00" * 32  # Cipher suites
            + b"\x01\x00"  # Compression methods
            + b"\x00\x50"  # Extensions length
            + b"\x00\x00\x00\x11"  # SNI extension header
            + b"\x00\x0f\x00\x0d"  # SNI data
            + b"www.youtube.com"  # SNI value
            + b"\x00" * 50  # Additional extensions/padding
        )

        return ip_header + tcp_header + tls_payload

    def _create_youtube_tcp_info(self) -> TCPPacketInfo:
        """Create TCP info for YouTube traffic."""
        return TCPPacketInfo(
            src_ip="192.168.1.100",
            dst_ip="172.217.164.142",  # YouTube IP
            src_port=49152,
            dst_port=443,
            seq_num=0x12345678,
            ack_num=0x87654321,
            flags=0x18,  # PSH+ACK
            window_size=65535,
            checksum=0xABCD,
            payload=b"TLS Client Hello to YouTube",
        )

    def _create_tls_client_hello_part1(self) -> bytes:
        """Create first part of split TLS Client Hello."""
        return self._create_youtube_https_packet()[:50]  # First 50 bytes

    def _create_tls_client_hello_part2(self) -> bytes:
        """Create second part of split TLS Client Hello."""
        full_packet = self._create_youtube_https_packet()
        return full_packet[50:100]  # Middle part

    def _create_tls_client_hello_part3(self) -> bytes:
        """Create third part of split TLS Client Hello."""
        full_packet = self._create_youtube_https_packet()
        return full_packet[100:]  # Remaining part
