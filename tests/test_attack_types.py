"""
Unit tests for individual attack types in the DPI bypass system.

Tests each attack type's core functionality, parameter handling,
and output validation to ensure proper attack execution.
"""

import pytest
from unittest.mock import Mock, patch
from typing import List, Tuple, Dict, Any

from core.bypass.techniques.primitives import BypassTechniques


class TestFakeDisorderAttack:
    """Test suite for fakeddisorder attack type."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.techniques = BypassTechniques()
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    def test_fakeddisorder_basic(self):
        """Test basic fakeddisorder attack execution."""
        result = self.techniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=4,
            fake_ttl=3,
            fooling_methods=["badsum"]
        )
        
        # Should return 3 segments: fake full + real part2 + real part1
        assert len(result) == 3
        
        # First segment should be fake with full payload
        fake_segment = result[0]
        assert fake_segment[0] == self.test_payload  # Full payload
        assert fake_segment[1] == 0  # Offset 0
        assert fake_segment[2]["is_fake"] is True
        assert fake_segment[2]["ttl"] == 3
        
        # Second segment should be real part2
        part2_segment = result[1]
        assert part2_segment[0] == self.test_payload[4:]  # Part after split
        assert part2_segment[1] == 4  # Offset at split position
        assert part2_segment[2]["is_fake"] is False
        
        # Third segment should be real part1
        part1_segment = result[2]
        assert part1_segment[0] == self.test_payload[:4]  # Part before split
        assert part1_segment[1] == 0  # Offset 0
        assert part1_segment[2]["is_fake"] is False
    
    def test_fakeddisorder_split_pos_adjustment(self):
        """Test fakeddisorder with split_pos larger than payload."""
        result = self.techniques.apply_fakeddisorder(
            payload=b"short",
            split_pos=100,  # Much larger than payload
            fake_ttl=3
        )
        
        # Should still work with adjusted split_pos
        assert len(result) == 3
        assert all(isinstance(segment[0], bytes) for segment in result)
    
    def test_fakeddisorder_empty_payload(self):
        """Test fakeddisorder with empty payload."""
        result = self.techniques.apply_fakeddisorder(
            payload=b"",
            split_pos=1,
            fake_ttl=3
        )
        
        # Should return single segment for empty payload
        assert len(result) == 1
        assert result[0][2]["is_fake"] is False
    
    def test_fakeddisorder_fooling_methods(self):
        """Test fakeddisorder with different fooling methods."""
        fooling_methods = ["badsum", "badseq", "md5sig"]
        
        result = self.techniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=4,
            fake_ttl=3,
            fooling_methods=fooling_methods
        )
        
        fake_segment = result[0]
        assert fake_segment[2]["corrupt_tcp_checksum"] is True
        assert fake_segment[2]["add_md5sig_option"] is True
        assert fake_segment[2]["seq_extra"] == -1


class TestSeqovlAttack:
    """Test suite for seqovl (sequence overlap) attack type."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.techniques = BypassTechniques()
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    def test_seqovl_basic(self):
        """Test basic seqovl attack execution."""
        result = self.techniques.apply_seqovl(
            payload=self.test_payload,
            split_pos=8,
            overlap_size=3,
            fake_ttl=3,
            fooling_methods=["badsum"]
        )
        
        # Should return 2 segments: fake overlap + real full
        assert len(result) == 2
        
        # First segment should be fake overlap
        fake_segment = result[0]
        assert fake_segment[2]["is_fake"] is True
        assert fake_segment[2]["ttl"] == 3
        assert fake_segment[1] == 5  # start_offset = max(0, 8-3) = 5
        
        # Second segment should be real full payload
        real_segment = result[1]
        assert real_segment[0] == self.test_payload
        assert real_segment[1] == 0
        assert real_segment[2]["is_fake"] is False
    
    def test_seqovl_overlap_calculation(self):
        """Test seqovl overlap calculation."""
        result = self.techniques.apply_seqovl(
            payload=b"0123456789",
            split_pos=5,
            overlap_size=2,
            fake_ttl=3
        )
        
        fake_segment = result[0]
        # start_offset = max(0, 5-2) = 3
        # overlap_part = payload[3:5] = "34"
        assert fake_segment[0] == b"34"
        assert fake_segment[1] == 3
    
    def test_seqovl_empty_payload(self):
        """Test seqovl with empty payload."""
        result = self.techniques.apply_seqovl(
            payload=b"",
            split_pos=1,
            overlap_size=1,
            fake_ttl=3
        )
        
        # Should return single segment for empty payload
        assert len(result) == 1
        assert result[0][2]["is_fake"] is False


class TestMultidisorderAttack:
    """Test suite for multidisorder attack type."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.techniques = BypassTechniques()
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    def test_multidisorder_basic(self):
        """Test basic multidisorder attack execution."""
        positions = [4, 8, 15]
        
        result = self.techniques.apply_multidisorder(
            payload=self.test_payload,
            positions=positions,
            fooling=["badsum"],
            fake_ttl=1
        )
        
        # Should have fake segment + real fragments in reverse order
        assert len(result) >= 2
        
        # First segment should be fake
        fake_segment = result[0]
        assert fake_segment[2]["is_fake"] is True
        assert fake_segment[2]["ttl"] == 1
        
        # Remaining segments should be real and in reverse order
        real_segments = result[1:]
        for segment in real_segments:
            assert segment[2]["is_fake"] is False
    
    def test_multidisorder_empty_positions(self):
        """Test multidisorder with empty positions list."""
        result = self.techniques.apply_multidisorder(
            payload=self.test_payload,
            positions=[],
            fake_ttl=1
        )
        
        # Should fall back to fakeddisorder
        assert len(result) == 3  # fakeddisorder returns 3 segments
        assert result[0][2]["is_fake"] is True
    
    def test_multidisorder_single_position(self):
        """Test multidisorder with single position."""
        result = self.techniques.apply_multidisorder(
            payload=self.test_payload,
            positions=[10],
            fake_ttl=1
        )
        
        # Should have fake + 2 real fragments in reverse order
        assert len(result) >= 2
        assert result[0][2]["is_fake"] is True
        
        # Check that fragments are in reverse order
        real_segments = result[1:]
        if len(real_segments) >= 2:
            # Later fragment should come first in reverse order
            assert real_segments[0][1] > real_segments[1][1]


class TestDisorderAttack:
    """Test suite for disorder attack type."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.techniques = BypassTechniques()
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    def test_disorder_basic(self):
        """Test basic disorder attack execution."""
        result = self.techniques.apply_disorder(
            payload=self.test_payload,
            split_pos=4,
            ack_first=False
        )
        
        # Should return 2 segments in reverse order
        assert len(result) == 2
        
        # First segment should be part2 (after split)
        part2_segment = result[0]
        assert part2_segment[0] == self.test_payload[4:]
        assert part2_segment[1] == 4
        assert part2_segment[2]["is_fake"] is False
        assert part2_segment[2]["tcp_flags"] == 0x18
        
        # Second segment should be part1 (before split)
        part1_segment = result[1]
        assert part1_segment[0] == self.test_payload[:4]
        assert part1_segment[1] == 0
        assert part1_segment[2]["is_fake"] is False
    
    def test_disorder_ack_first(self):
        """Test disorder with ack_first=True."""
        result = self.techniques.apply_disorder(
            payload=self.test_payload,
            split_pos=4,
            ack_first=True
        )
        
        # First segment should have ACK flag (0x10)
        assert result[0][2]["tcp_flags"] == 0x10
        # Second segment should have PSH+ACK flags (0x18)
        assert result[1][2]["tcp_flags"] == 0x18
    
    def test_disorder_empty_payload(self):
        """Test disorder with empty payload."""
        result = self.techniques.apply_disorder(
            payload=b"",
            split_pos=1,
            ack_first=False
        )
        
        # Should return single segment for empty payload
        assert len(result) == 1
        assert result[0][2]["is_fake"] is False


class TestMultisplitAttack:
    """Test suite for multisplit attack type."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.techniques = BypassTechniques()
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    def test_multisplit_basic(self):
        """Test basic multisplit attack execution."""
        positions = [4, 8, 15]
        
        result = self.techniques.apply_multisplit(
            payload=self.test_payload,
            positions=positions,
            fooling=[]
        )
        
        # Should have multiple segments in order
        assert len(result) >= 3
        
        # All segments should be real
        for segment in result:
            assert segment[2]["is_fake"] is False
        
        # Check that segments are in correct order
        offsets = [segment[1] for segment in result]
        assert offsets == sorted(offsets)
    
    def test_multisplit_with_badsum(self):
        """Test multisplit with badsum fooling."""
        result = self.techniques.apply_multisplit(
            payload=self.test_payload,
            positions=[4, 8],
            fooling=["badsum"]
        )
        
        # First segment should have badsum corruption
        assert result[0][2].get("corrupt_tcp_checksum") is True
        
        # Other segments should not have corruption
        for segment in result[1:]:
            assert segment[2].get("corrupt_tcp_checksum") is not True
    
    def test_multisplit_empty_positions(self):
        """Test multisplit with empty positions."""
        result = self.techniques.apply_multisplit(
            payload=self.test_payload,
            positions=[],
            fooling=[]
        )
        
        # Should return single segment
        assert len(result) == 1
        assert result[0][0] == self.test_payload
        assert result[0][1] == 0
    
    def test_multisplit_delays(self):
        """Test multisplit adds delays between segments."""
        result = self.techniques.apply_multisplit(
            payload=self.test_payload,
            positions=[4, 8],
            fooling=[]
        )
        
        # All segments except last should have delays
        for i, segment in enumerate(result[:-1]):
            assert "delay_ms_after" in segment[2]
            assert segment[2]["delay_ms_after"] >= 5


class TestFakePacketRaceAttack:
    """Test suite for fake packet race attack type."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.techniques = BypassTechniques()
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    def test_fake_packet_race_basic(self):
        """Test basic fake packet race attack execution."""
        result = self.techniques.apply_fake_packet_race(
            payload=self.test_payload,
            ttl=3,
            fooling=["badsum"]
        )
        
        # Should return 2 segments: fake + real
        assert len(result) == 2
        
        # First segment should be fake
        fake_segment = result[0]
        assert fake_segment[0] == self.test_payload
        assert fake_segment[1] == 0
        assert fake_segment[2]["is_fake"] is True
        assert fake_segment[2]["ttl"] == 3
        assert fake_segment[2]["corrupt_tcp_checksum"] is True
        
        # Second segment should be real
        real_segment = result[1]
        assert real_segment[0] == self.test_payload
        assert real_segment[1] == 0
        assert real_segment[2]["is_fake"] is False
    
    def test_fake_packet_race_fooling_methods(self):
        """Test fake packet race with different fooling methods."""
        result = self.techniques.apply_fake_packet_race(
            payload=self.test_payload,
            ttl=5,
            fooling=["md5sig", "fakesni"]
        )
        
        fake_segment = result[0]
        assert fake_segment[2]["add_md5sig_option"] is True
        assert "fooling_sni" in fake_segment[2]
        assert fake_segment[2]["corrupt_tcp_checksum"] is False  # badsum not in fooling
    
    def test_fake_packet_race_default_fooling(self):
        """Test fake packet race with default fooling methods."""
        result = self.techniques.apply_fake_packet_race(
            payload=self.test_payload,
            ttl=3
        )
        
        # Should use default badsum fooling
        fake_segment = result[0]
        assert fake_segment[2]["corrupt_tcp_checksum"] is True


class TestWindowSizeLimitAttack:
    """Test suite for window size limit attack type."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.techniques = BypassTechniques()
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    def test_wssize_limit_basic(self):
        """Test basic window size limit attack execution."""
        result = self.techniques.apply_wssize_limit(
            payload=self.test_payload,
            window_size=5
        )
        
        # Should split payload into chunks of window_size
        expected_chunks = (len(self.test_payload) + 4) // 5  # Ceiling division
        assert len(result) >= expected_chunks
        
        # All segments should be real
        for segment in result:
            assert segment[2]["is_fake"] is False
        
        # Check chunk sizes
        for i, segment in enumerate(result[:-1]):
            assert len(segment[0]) == 5  # All but last should be window_size
        
        # Last chunk might be smaller
        assert len(result[-1][0]) <= 5
    
    def test_wssize_limit_single_byte(self):
        """Test window size limit with single byte chunks."""
        result = self.techniques.apply_wssize_limit(
            payload=b"test",
            window_size=1
        )
        
        # Should have 4 segments, one per byte
        assert len(result) == 4
        
        for i, segment in enumerate(result):
            assert len(segment[0]) == 1
            assert segment[1] == i  # Correct offset
    
    def test_wssize_limit_large_window(self):
        """Test window size limit with window larger than payload."""
        result = self.techniques.apply_wssize_limit(
            payload=b"short",
            window_size=100
        )
        
        # Should return single segment
        assert len(result) == 1
        assert result[0][0] == b"short"
        assert result[0][1] == 0


class TestTLSRecordSplitAttack:
    """Test suite for TLS record split attack type."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.techniques = BypassTechniques()
        # Create a mock TLS record
        self.tls_payload = (
            b'\x16'  # TLS Record Type (Handshake)
            b'\x03\x03'  # TLS Version
            b'\x00\x10'  # Length (16 bytes)
            b'0123456789abcdef'  # 16 bytes of content
        )
    
    def test_tlsrec_split_basic(self):
        """Test basic TLS record split."""
        result = self.techniques.apply_tlsrec_split(
            payload=self.tls_payload,
            split_pos=5
        )
        
        # Should return modified payload with split TLS records
        assert isinstance(result, bytes)
        assert len(result) >= len(self.tls_payload)
        
        # Should start with TLS record type
        assert result[0] == 0x16
    
    def test_tlsrec_split_non_tls(self):
        """Test TLS record split with non-TLS payload."""
        non_tls_payload = b"GET / HTTP/1.1\r\n"
        
        result = self.techniques.apply_tlsrec_split(
            payload=non_tls_payload,
            split_pos=5
        )
        
        # Should return original payload unchanged
        assert result == non_tls_payload
    
    def test_tlsrec_split_empty_payload(self):
        """Test TLS record split with empty payload."""
        result = self.techniques.apply_tlsrec_split(
            payload=b"",
            split_pos=5
        )
        
        # Should return empty payload
        assert result == b""
    
    def test_tlsrec_split_invalid_split_pos(self):
        """Test TLS record split with invalid split position."""
        result = self.techniques.apply_tlsrec_split(
            payload=self.tls_payload,
            split_pos=100  # Larger than content
        )
        
        # Should return original payload
        assert result == self.tls_payload


class TestAttackTypeEdgeCases:
    """Test suite for edge cases across all attack types."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.techniques = BypassTechniques()
    
    def test_all_attacks_handle_empty_payload(self):
        """Test that all attack types handle empty payload gracefully."""
        attacks_to_test = [
            ("apply_fakeddisorder", {"split_pos": 1, "fake_ttl": 3}),
            ("apply_seqovl", {"split_pos": 1, "overlap_size": 1, "fake_ttl": 3}),
            ("apply_multidisorder", {"positions": [1], "fake_ttl": 1}),
            ("apply_disorder", {"split_pos": 1}),
            ("apply_multisplit", {"positions": [1]}),
            ("apply_fake_packet_race", {"ttl": 3}),
        ]
        
        for method_name, params in attacks_to_test:
            method = getattr(self.techniques, method_name)
            result = method(payload=b"", **params)
            
            # Should return valid result structure
            assert isinstance(result, list)
            assert len(result) >= 1
            
            # All segments should have proper structure
            for segment in result:
                assert len(segment) == 3
                assert isinstance(segment[0], bytes)
                assert isinstance(segment[1], int)
                assert isinstance(segment[2], dict)
        
        # Test wssize_limit separately as it correctly returns empty list for empty payload
        result = self.techniques.apply_wssize_limit(payload=b"", window_size=1)
        assert isinstance(result, list)
        assert len(result) == 0  # Empty payload should result in empty segments list
    
    def test_all_attacks_handle_single_byte_payload(self):
        """Test that all attack types handle single byte payload."""
        single_byte = b"A"
        
        attacks_to_test = [
            ("apply_fakeddisorder", {"split_pos": 1, "fake_ttl": 3}),
            ("apply_seqovl", {"split_pos": 1, "overlap_size": 1, "fake_ttl": 3}),
            ("apply_multidisorder", {"positions": [1], "fake_ttl": 1}),
            ("apply_disorder", {"split_pos": 1}),
            ("apply_multisplit", {"positions": [1]}),
            ("apply_fake_packet_race", {"ttl": 3}),
            ("apply_wssize_limit", {"window_size": 1}),
        ]
        
        for method_name, params in attacks_to_test:
            method = getattr(self.techniques, method_name)
            result = method(payload=single_byte, **params)
            
            # Should return valid result
            assert isinstance(result, list)
            assert len(result) >= 1
            
            # Total payload should be preserved (for non-TLS methods)
            if method_name != "apply_tlsrec_split":
                total_payload = b"".join(segment[0] for segment in result if not segment[2].get("is_fake", False))
                assert single_byte in total_payload or len(result) == 1
    
    def test_attack_segment_structure_consistency(self):
        """Test that all attacks return consistent segment structure."""
        test_payload = b"test_payload_for_consistency_check"
        
        attacks_to_test = [
            ("apply_fakeddisorder", {"split_pos": 4, "fake_ttl": 3}),
            ("apply_seqovl", {"split_pos": 4, "overlap_size": 2, "fake_ttl": 3}),
            ("apply_multidisorder", {"positions": [4, 8], "fake_ttl": 1}),
            ("apply_disorder", {"split_pos": 4}),
            ("apply_multisplit", {"positions": [4, 8]}),
            ("apply_fake_packet_race", {"ttl": 3}),
            ("apply_wssize_limit", {"window_size": 5}),
        ]
        
        for method_name, params in attacks_to_test:
            method = getattr(self.techniques, method_name)
            result = method(payload=test_payload, **params)
            
            # Check segment structure consistency
            for i, segment in enumerate(result):
                # Each segment should be a 3-tuple
                assert len(segment) == 3, f"{method_name} segment {i} has wrong length"
                
                payload_part, offset, options = segment
                
                # Payload part should be bytes
                assert isinstance(payload_part, bytes), f"{method_name} segment {i} payload not bytes"
                
                # Offset should be non-negative integer
                assert isinstance(offset, int), f"{method_name} segment {i} offset not int"
                assert offset >= 0, f"{method_name} segment {i} offset negative"
                
                # Options should be dict with required fields
                assert isinstance(options, dict), f"{method_name} segment {i} options not dict"
                assert "is_fake" in options, f"{method_name} segment {i} missing is_fake"
                assert "tcp_flags" in options, f"{method_name} segment {i} missing tcp_flags"
                
                # is_fake should be boolean
                assert isinstance(options["is_fake"], bool), f"{method_name} segment {i} is_fake not bool"
                
                # tcp_flags should be integer
                assert isinstance(options["tcp_flags"], int), f"{method_name} segment {i} tcp_flags not int"
    
    def test_attack_parameter_validation(self):
        """Test that attacks handle invalid parameters gracefully."""
        test_payload = b"test_payload"
        
        # Test with invalid split_pos values
        invalid_split_positions = [-1, 0, 1000]
        
        for split_pos in invalid_split_positions:
            # These methods should handle invalid split_pos gracefully
            result1 = self.techniques.apply_fakeddisorder(test_payload, split_pos, 3)
            result2 = self.techniques.apply_disorder(test_payload, split_pos)
            
            assert isinstance(result1, list) and len(result1) >= 1
            assert isinstance(result2, list) and len(result2) >= 1
        
        # Test with invalid overlap_size
        result = self.techniques.apply_seqovl(test_payload, 4, -5, 3)  # Negative overlap
        assert isinstance(result, list) and len(result) >= 1
        
        # Test with empty positions list
        result = self.techniques.apply_multisplit(test_payload, [])
        assert isinstance(result, list) and len(result) >= 1