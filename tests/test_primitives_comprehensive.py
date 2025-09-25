#!/usr/bin/env python3
"""
Comprehensive unit tests for attack primitives.

This module provides thorough testing of all attack primitives in primitives.py
to ensure correct output segments with proper payload, rel_off, and opts.
"""

import unittest
import sys
from pathlib import Path

# Add the recon directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.bypass.techniques.primitives import BypassTechniques


class TestFakeDisorderAttack(unittest.TestCase):
    """Test cases for fakeddisorder attack primitive."""
    
    def setUp(self):
        self.test_payload = b'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n'
    
    def test_fakeddisorder_no_overlap_basic(self):
        """Test basic fakeddisorder without overlap."""
        segments = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=10,
            overlap_size=0,
            fake_ttl=64,
            fooling_methods=[]
        )
        
        # Should return 2 segments: fake + real
        self.assertEqual(len(segments), 2)
        
        # First segment (fake)
        fake_payload, fake_offset, fake_opts = segments[0]
        self.assertEqual(fake_payload, self.test_payload[:10])
        self.assertEqual(fake_offset, 0)
        self.assertTrue(fake_opts['is_fake'])
        self.assertEqual(fake_opts['ttl'], 64)
        self.assertEqual(fake_opts['tcp_flags'], 0x10)  # ACK
        
        # Second segment (real)
        real_payload, real_offset, real_opts = segments[1]
        self.assertEqual(real_payload, self.test_payload[10:])
        self.assertEqual(real_offset, 10)
        self.assertFalse(real_opts['is_fake'])
        self.assertEqual(real_opts['tcp_flags'], 0x18)  # PSH|ACK
    
    def test_fakeddisorder_with_overlap(self):
        """Test fakeddisorder with overlap."""
        segments = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=20,
            overlap_size=5,
            fake_ttl=1,
            fooling_methods=[]
        )
        
        self.assertEqual(len(segments), 2)
        
        # Fake segment with overlap offset
        fake_payload, fake_offset, fake_opts = segments[0]
        self.assertEqual(fake_payload, self.test_payload[:20])
        self.assertEqual(fake_offset, 15)  # split_pos - overlap_size
        self.assertTrue(fake_opts['is_fake'])
        self.assertEqual(fake_opts['ttl'], 1)
        
        # Real segment at split_pos
        real_payload, real_offset, real_opts = segments[1]
        self.assertEqual(real_payload, self.test_payload[20:])
        self.assertEqual(real_offset, 20)
        self.assertFalse(real_opts['is_fake'])
    
    def test_fakeddisorder_with_fooling_methods(self):
        """Test fakeddisorder with all fooling methods."""
        segments = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=15,
            overlap_size=0,
            fake_ttl=64,
            fooling_methods=['badsum', 'md5sig', 'badseq']
        )
        
        self.assertEqual(len(segments), 2)
        
        # Check fooling options are applied to fake segment
        fake_payload, fake_offset, fake_opts = segments[0]
        self.assertTrue(fake_opts['corrupt_tcp_checksum'])
        self.assertTrue(fake_opts['add_md5sig_option'])
        self.assertTrue(fake_opts['corrupt_sequence'])
    
    def test_fakeddisorder_edge_case_split_pos_too_large(self):
        """Test when split_pos >= payload length."""
        segments = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=len(self.test_payload) + 10,
            overlap_size=0,
            fake_ttl=64
        )
        
        # Should return single real segment
        self.assertEqual(len(segments), 1)
        
        payload, offset, opts = segments[0]
        self.assertEqual(payload, self.test_payload)
        self.assertEqual(offset, 0)
        self.assertFalse(opts['is_fake'])
        self.assertEqual(opts['tcp_flags'], 0x18)
    
    def test_fakeddisorder_edge_case_overlap_clamping(self):
        """Test overlap size clamping."""
        # Test overlap > split_pos (should clamp to split_pos)
        segments = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=10,
            overlap_size=15,  # > split_pos
            fake_ttl=64
        )
        
        self.assertEqual(len(segments), 2)
        
        fake_payload, fake_offset, fake_opts = segments[0]
        self.assertEqual(fake_offset, 0)  # Should be clamped to 0
        
        # Test negative overlap (should clamp to 0)
        segments = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=10,
            overlap_size=-5,
            fake_ttl=64
        )
        
        fake_payload, fake_offset, fake_opts = segments[0]
        self.assertEqual(fake_offset, 0)  # Should be clamped to 0


class TestMultisplitAttack(unittest.TestCase):
    """Test cases for multisplit attack primitive."""
    
    def setUp(self):
        self.test_payload = b'0123456789ABCDEFGHIJ'  # 20 bytes for easy testing
    
    def test_multisplit_basic(self):
        """Test basic multisplit functionality."""
        segments = BypassTechniques.apply_multisplit(self.test_payload, [5, 10, 15])
        
        # Should create 4 segments: [0:5], [5:10], [10:15], [15:]
        self.assertEqual(len(segments), 4)
        
        expected_segments = [
            (b'01234', 0),
            (b'56789', 5),
            (b'ABCDE', 10),
            (b'FGHIJ', 15)
        ]
        
        for i, (expected_payload, expected_offset) in enumerate(expected_segments):
            actual_payload, actual_offset = segments[i]
            self.assertEqual(actual_payload, expected_payload)
            self.assertEqual(actual_offset, expected_offset)
    
    def test_multisplit_empty_positions(self):
        """Test multisplit with empty positions list."""
        segments = BypassTechniques.apply_multisplit(self.test_payload, [])
        
        # Should return single segment with entire payload
        self.assertEqual(len(segments), 1)
        
        payload, offset = segments[0]
        self.assertEqual(payload, self.test_payload)
        self.assertEqual(offset, 0)
    
    def test_multisplit_single_position(self):
        """Test multisplit with single position."""
        segments = BypassTechniques.apply_multisplit(self.test_payload, [10])
        
        self.assertEqual(len(segments), 2)
        
        # First segment: [0:10]
        payload1, offset1 = segments[0]
        self.assertEqual(payload1, self.test_payload[:10])
        self.assertEqual(offset1, 0)
        
        # Second segment: [10:]
        payload2, offset2 = segments[1]
        self.assertEqual(payload2, self.test_payload[10:])
        self.assertEqual(offset2, 10)
    
    def test_multisplit_out_of_bounds_positions(self):
        """Test multisplit with out-of-bounds positions."""
        segments = BypassTechniques.apply_multisplit(
            self.test_payload, 
            [5, len(self.test_payload) + 10, 10]  # One position is out of bounds
        )
        
        # Should ignore out-of-bounds positions
        self.assertEqual(len(segments), 3)  # [0:5], [5:10], [10:]
    
    def test_multisplit_unsorted_positions(self):
        """Test multisplit with unsorted positions."""
        segments = BypassTechniques.apply_multisplit(self.test_payload, [15, 5, 10])
        
        # Should sort positions internally
        self.assertEqual(len(segments), 4)
        
        # Verify segments are in correct order
        payload1, offset1 = segments[0]
        self.assertEqual(offset1, 0)
        
        payload2, offset2 = segments[1]
        self.assertEqual(offset2, 5)
        
        payload3, offset3 = segments[2]
        self.assertEqual(offset3, 10)
        
        payload4, offset4 = segments[3]
        self.assertEqual(offset4, 15)


class TestMultidisorderAttack(unittest.TestCase):
    """Test cases for multidisorder attack primitive."""
    
    def setUp(self):
        self.test_payload = b'0123456789ABCDEFGHIJ'
    
    def test_multidisorder_basic(self):
        """Test basic multidisorder functionality."""
        segments = BypassTechniques.apply_multidisorder(self.test_payload, [5, 10, 15])
        
        # Should be reverse of multisplit
        multisplit_segments = BypassTechniques.apply_multisplit(self.test_payload, [5, 10, 15])
        expected_segments = multisplit_segments[::-1]
        
        self.assertEqual(len(segments), len(expected_segments))
        
        for i, (expected_payload, expected_offset) in enumerate(expected_segments):
            actual_payload, actual_offset = segments[i]
            self.assertEqual(actual_payload, expected_payload)
            self.assertEqual(actual_offset, expected_offset)
    
    def test_multidisorder_single_segment(self):
        """Test multidisorder with single segment (no reversal)."""
        segments = BypassTechniques.apply_multidisorder(self.test_payload, [])
        
        # Single segment should not be reversed
        self.assertEqual(len(segments), 1)
        
        payload, offset = segments[0]
        self.assertEqual(payload, self.test_payload)
        self.assertEqual(offset, 0)


class TestSeqovlAttack(unittest.TestCase):
    """Test cases for seqovl attack primitive."""
    
    def setUp(self):
        self.test_payload = b'0123456789ABCDEFGHIJ'
    
    def test_seqovl_basic(self):
        """Test basic seqovl functionality."""
        segments = BypassTechniques.apply_seqovl(
            self.test_payload, 
            split_pos=10, 
            overlap_size=5
        )
        
        self.assertEqual(len(segments), 2)
        
        # First segment: part2 at split_pos
        part2_payload, part2_offset = segments[0]
        self.assertEqual(part2_payload, self.test_payload[10:])  # 'ABCDEFGHIJ'
        self.assertEqual(part2_offset, 10)
        
        # Second segment: overlap + part1 at negative offset
        part1_payload, part1_offset = segments[1]
        expected_part1 = b'\x00' * 5 + self.test_payload[:10]  # '\x00\x00\x00\x00\x000123456789'
        self.assertEqual(part1_payload, expected_part1)
        self.assertEqual(part1_offset, -5)
    
    def test_seqovl_split_pos_too_large(self):
        """Test seqovl when split_pos >= payload length."""
        segments = BypassTechniques.apply_seqovl(
            self.test_payload,
            split_pos=len(self.test_payload) + 5,
            overlap_size=5
        )
        
        # Should return single segment
        self.assertEqual(len(segments), 1)
        
        payload, offset = segments[0]
        self.assertEqual(payload, self.test_payload)
        self.assertEqual(offset, 0)
    
    def test_seqovl_zero_overlap(self):
        """Test seqovl with zero overlap."""
        segments = BypassTechniques.apply_seqovl(
            self.test_payload,
            split_pos=10,
            overlap_size=0
        )
        
        self.assertEqual(len(segments), 2)
        
        # First segment: part2
        part2_payload, part2_offset = segments[0]
        self.assertEqual(part2_payload, self.test_payload[10:])
        self.assertEqual(part2_offset, 10)
        
        # Second segment: part1 with no overlap
        part1_payload, part1_offset = segments[1]
        self.assertEqual(part1_payload, self.test_payload[:10])
        self.assertEqual(part1_offset, 0)


class TestTlsRecSplitAttack(unittest.TestCase):
    """Test cases for TLS record split attack primitive."""
    
    def setUp(self):
        # Valid TLS ClientHello record
        self.tls_payload = (
            b'\x16\x03\x01\x00\x20'  # TLS Record Header (Handshake, TLS 1.0, Length: 32)
            b'\x01\x00\x00\x1c'      # Handshake Header (Client Hello, Length: 28)
            b'\x03\x03'              # Version: TLS 1.2
            + b'\x00' * 24           # Random + Session ID + Cipher Suites + Compression
        )
        
        self.invalid_payload = b'Not a TLS record'
    
    def test_tlsrec_split_valid_record(self):
        """Test TLS record split with valid TLS record."""
        result = BypassTechniques.apply_tlsrec_split(self.tls_payload, split_pos=10)
        
        # Should return modified payload (different from original)
        self.assertNotEqual(result, self.tls_payload)
        
        # Should still start with TLS record type
        self.assertEqual(result[0], 0x16)
        
        # Should be longer than original (due to split creating two records)
        self.assertGreater(len(result), len(self.tls_payload))
    
    def test_tlsrec_split_invalid_payload(self):
        """Test TLS record split with invalid payload."""
        result = BypassTechniques.apply_tlsrec_split(self.invalid_payload, split_pos=5)
        
        # Should return unchanged
        self.assertEqual(result, self.invalid_payload)
    
    def test_tlsrec_split_empty_payload(self):
        """Test TLS record split with empty payload."""
        result = BypassTechniques.apply_tlsrec_split(b'', split_pos=5)
        
        # Should return unchanged
        self.assertEqual(result, b'')
    
    def test_tlsrec_split_short_payload(self):
        """Test TLS record split with payload shorter than TLS header."""
        short_payload = b'\x16\x03'  # Only 2 bytes
        result = BypassTechniques.apply_tlsrec_split(short_payload, split_pos=1)
        
        # Should return unchanged
        self.assertEqual(result, short_payload)
    
    def test_tlsrec_split_split_pos_out_of_bounds(self):
        """Test TLS record split with split_pos out of bounds."""
        result = BypassTechniques.apply_tlsrec_split(self.tls_payload, split_pos=1000)
        
        # Should return unchanged
        self.assertEqual(result, self.tls_payload)


class TestWssizeLimitAttack(unittest.TestCase):
    """Test cases for window size limit attack primitive."""
    
    def setUp(self):
        self.test_payload = b'0123456789ABCDEFGHIJ'  # 20 bytes
    
    def test_wssize_limit_basic(self):
        """Test basic window size limit functionality."""
        segments = BypassTechniques.apply_wssize_limit(self.test_payload, window_size=5)
        
        # Should create 4 segments of 5 bytes each
        self.assertEqual(len(segments), 4)
        
        expected_segments = [
            (b'01234', 0),
            (b'56789', 5),
            (b'ABCDE', 10),
            (b'FGHIJ', 15)
        ]
        
        for i, (expected_payload, expected_offset) in enumerate(expected_segments):
            actual_payload, actual_offset = segments[i]
            self.assertEqual(actual_payload, expected_payload)
            self.assertEqual(actual_offset, expected_offset)
    
    def test_wssize_limit_window_size_one(self):
        """Test window size limit with window size 1."""
        segments = BypassTechniques.apply_wssize_limit(self.test_payload, window_size=1)
        
        # Should create 20 segments of 1 byte each
        self.assertEqual(len(segments), len(self.test_payload))
        
        for i, (payload, offset) in enumerate(segments):
            self.assertEqual(len(payload), 1)
            self.assertEqual(payload, self.test_payload[i:i+1])
            self.assertEqual(offset, i)
    
    def test_wssize_limit_window_size_larger_than_payload(self):
        """Test window size limit with window size larger than payload."""
        segments = BypassTechniques.apply_wssize_limit(self.test_payload, window_size=100)
        
        # Should create single segment
        self.assertEqual(len(segments), 1)
        
        payload, offset = segments[0]
        self.assertEqual(payload, self.test_payload)
        self.assertEqual(offset, 0)
    
    def test_wssize_limit_uneven_division(self):
        """Test window size limit with uneven division."""
        segments = BypassTechniques.apply_wssize_limit(self.test_payload, window_size=7)
        
        # 20 bytes / 7 = 2 full segments + 1 partial segment
        self.assertEqual(len(segments), 3)
        
        # First segment: 7 bytes
        payload1, offset1 = segments[0]
        self.assertEqual(len(payload1), 7)
        self.assertEqual(offset1, 0)
        
        # Second segment: 7 bytes
        payload2, offset2 = segments[1]
        self.assertEqual(len(payload2), 7)
        self.assertEqual(offset2, 7)
        
        # Third segment: 6 bytes (remainder)
        payload3, offset3 = segments[2]
        self.assertEqual(len(payload3), 6)
        self.assertEqual(offset3, 14)


class TestFoolingMethods(unittest.TestCase):
    """Test cases for fooling methods (badsum, md5sig)."""
    
    def setUp(self):
        # Create a mock TCP packet
        self.mock_packet = bytearray([
            # IP Header (20 bytes)
            0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
            0xc0, 0xa8, 0x01, 0x02,
            # TCP Header (20 bytes)
            0x04, 0xd2, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0x20, 0x00,
            0x00, 0x00, 0x00, 0x00  # Checksum at bytes 36-37
        ])
    
    def test_badsum_fooling(self):
        """Test badsum fooling method."""
        original_packet = self.mock_packet.copy()
        modified_packet = BypassTechniques.apply_badsum_fooling(self.mock_packet)
        
        # Should modify the TCP checksum to 0xDEAD
        import struct
        checksum = struct.unpack('!H', modified_packet[36:38])[0]
        self.assertEqual(checksum, 0xDEAD)
        
        # Should not modify other parts of the packet
        self.assertEqual(modified_packet[:36], original_packet[:36])
        self.assertEqual(modified_packet[38:], original_packet[38:])
    
    def test_md5sig_fooling(self):
        """Test md5sig fooling method."""
        original_packet = self.mock_packet.copy()
        modified_packet = BypassTechniques.apply_md5sig_fooling(self.mock_packet)
        
        # Should modify the TCP checksum to 0xBEEF
        import struct
        checksum = struct.unpack('!H', modified_packet[36:38])[0]
        self.assertEqual(checksum, 0xBEEF)
        
        # Should not modify other parts of the packet
        self.assertEqual(modified_packet[:36], original_packet[:36])
        self.assertEqual(modified_packet[38:], original_packet[38:])
    
    def test_fooling_methods_with_short_packet(self):
        """Test fooling methods with packet too short for TCP checksum."""
        short_packet = bytearray([0x45, 0x00, 0x00, 0x14])  # Only 4 bytes
        
        # Should not crash and return the packet unchanged
        result_badsum = BypassTechniques.apply_badsum_fooling(short_packet.copy())
        result_md5sig = BypassTechniques.apply_md5sig_fooling(short_packet.copy())
        
        self.assertEqual(result_badsum, short_packet)
        self.assertEqual(result_md5sig, short_packet)


if __name__ == '__main__':
    # Run all tests
    unittest.main(verbosity=2)