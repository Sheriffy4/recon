"""
Unit tests for enhanced multidisorder attack implementation.

Tests the packet sequence builder for multidisorder with:
- Correct packet order (fake, part2, part1)
- Badseq fooling application
- Split position usage
- Overlap size handling
"""

import pytest
from core.bypass.techniques.primitives import BypassTechniques


class TestMultidisorderEnhanced:
    """Test suite for enhanced multidisorder attack."""
    
    def test_basic_multidisorder_sequence(self):
        """Test basic multidisorder creates correct packet sequence."""
        payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
        split_pos = 10
        
        segments = BypassTechniques.apply_multidisorder(
            payload,
            positions=[split_pos],
            split_pos=split_pos,
            overlap_size=0,
            fooling=[],
            fake_ttl=1
        )
        
        # Should have 3 segments: fake, part2, part1
        assert len(segments) == 3, f"Expected 3 segments, got {len(segments)}"
        
        # Segment 1: Fake packet
        fake_data, fake_seq, fake_opts = segments[0]
        assert fake_opts["is_fake"] is True, "First segment should be fake"
        assert fake_opts["ttl"] == 1, "Fake packet should have TTL=1"
        assert fake_seq == 0, "Fake packet should start at seq 0"
        
        # Segment 2: Part2 (first real segment)
        part2_data, part2_seq, part2_opts = segments[1]
        assert part2_opts["is_fake"] is False, "Second segment should be real"
        assert part2_seq == split_pos, f"Part2 should start at seq {split_pos}"
        assert part2_data == payload[split_pos:], "Part2 should contain second half of payload"
        
        # Segment 3: Part1 (second real segment, creates disorder)
        part1_data, part1_seq, part1_opts = segments[2]
        assert part1_opts["is_fake"] is False, "Third segment should be real"
        assert part1_seq == 0, "Part1 should start at seq 0"
        assert part1_data == payload[:split_pos], "Part1 should contain first half of payload"
    
    def test_multidisorder_with_badseq(self):
        """Test multidisorder applies badseq fooling correctly."""
        payload = b"Test payload for badseq"
        
        segments = BypassTechniques.apply_multidisorder(
            payload,
            positions=[5],
            split_pos=5,
            overlap_size=0,
            fooling=["badseq"],
            fake_ttl=2
        )
        
        # Check fake packet has badseq offset
        fake_data, fake_seq, fake_opts = segments[0]
        assert fake_opts["seq_offset"] == -10000, "Badseq should set seq_offset to -10000"
    
    def test_multidisorder_with_badsum(self):
        """Test multidisorder applies badsum fooling correctly."""
        payload = b"Test payload for badsum"
        
        segments = BypassTechniques.apply_multidisorder(
            payload,
            positions=[5],
            split_pos=5,
            overlap_size=0,
            fooling=["badsum"],
            fake_ttl=2
        )
        
        # Check fake packet has corrupt checksum flag
        fake_data, fake_seq, fake_opts = segments[0]
        assert fake_opts["corrupt_tcp_checksum"] is True, "Badsum should set corrupt_tcp_checksum"
    
    def test_multidisorder_with_md5sig(self):
        """Test multidisorder applies md5sig fooling correctly."""
        payload = b"Test payload for md5sig"
        
        segments = BypassTechniques.apply_multidisorder(
            payload,
            positions=[5],
            split_pos=5,
            overlap_size=0,
            fooling=["md5sig"],
            fake_ttl=2
        )
        
        # Check fake packet has md5sig flag
        fake_data, fake_seq, fake_opts = segments[0]
        assert fake_opts["add_md5sig"] is True, "Md5sig should set add_md5sig flag"
    
    def test_multidisorder_with_overlap(self):
        """Test multidisorder handles sequence overlap correctly."""
        payload = b"0123456789ABCDEFGHIJ"
        split_pos = 10
        overlap_size = 2
        
        segments = BypassTechniques.apply_multidisorder(
            payload,
            positions=[split_pos],
            split_pos=split_pos,
            overlap_size=overlap_size,
            fooling=[],
            fake_ttl=1
        )
        
        # Part2 should start earlier due to overlap
        part2_data, part2_seq, part2_opts = segments[1]
        expected_seq = split_pos - overlap_size
        assert part2_seq == expected_seq, f"Part2 should start at seq {expected_seq} (split_pos - overlap)"
    
    def test_multidisorder_split_pos_46(self):
        """Test multidisorder with split_pos=46 (x.com strategy)."""
        # Create a payload larger than 46 bytes (typical TLS ClientHello start)
        payload = b"\x16\x03\x01\x00\x00" + b"A" * 50
        split_pos = 46
        
        segments = BypassTechniques.apply_multidisorder(
            payload,
            positions=[split_pos],
            split_pos=split_pos,
            overlap_size=1,
            fooling=["badseq"],
            fake_ttl=2
        )
        
        assert len(segments) == 3, "Should have 3 segments"
        
        # Verify split position is used correctly
        part2_data, part2_seq, part2_opts = segments[1]
        part1_data, part1_seq, part1_opts = segments[2]
        
        assert len(part1_data) == split_pos, f"Part1 should be {split_pos} bytes"
        assert len(part2_data) == len(payload) - split_pos, "Part2 should be remaining bytes"
    
    def test_multidisorder_combined_fooling(self):
        """Test multidisorder with multiple fooling methods."""
        payload = b"Test combined fooling"
        
        segments = BypassTechniques.apply_multidisorder(
            payload,
            positions=[5],
            split_pos=5,
            overlap_size=0,
            fooling=["badseq", "badsum"],
            fake_ttl=3
        )
        
        # Check fake packet has both fooling methods
        fake_data, fake_seq, fake_opts = segments[0]
        assert fake_opts["seq_offset"] == -10000, "Should have badseq offset"
        assert fake_opts["corrupt_tcp_checksum"] is True, "Should have badsum flag"
    
    def test_multidisorder_short_payload(self):
        """Test multidisorder handles short payloads gracefully."""
        payload = b"Hi"
        split_pos = 10  # Larger than payload
        
        segments = BypassTechniques.apply_multidisorder(
            payload,
            positions=[split_pos],
            split_pos=split_pos,
            overlap_size=0,
            fooling=[],
            fake_ttl=1
        )
        
        # Should still create segments, but adjust split position
        assert len(segments) >= 1, "Should create at least fake segment"
    
    def test_multidisorder_tcp_flags(self):
        """Test multidisorder sets correct TCP flags."""
        payload = b"Test TCP flags"
        
        segments = BypassTechniques.apply_multidisorder(
            payload,
            positions=[5],
            split_pos=5,
            overlap_size=0,
            fooling=[],
            fake_ttl=1
        )
        
        # All segments should have PSH+ACK flags (0x18)
        for seg_data, seg_seq, seg_opts in segments:
            assert seg_opts["tcp_flags"] == 0x18, "All segments should have PSH+ACK flags"
    
    def test_multidisorder_real_segments_no_ttl(self):
        """Test real segments don't have TTL set (use OS default)."""
        payload = b"Test real segment TTL"
        
        segments = BypassTechniques.apply_multidisorder(
            payload,
            positions=[5],
            split_pos=5,
            overlap_size=0,
            fooling=[],
            fake_ttl=1
        )
        
        # Fake segment should have TTL
        assert segments[0][2]["ttl"] == 1, "Fake segment should have TTL=1"
        
        # Real segments should have TTL=None (use OS default)
        assert segments[1][2]["ttl"] is None, "Part2 should have TTL=None"
        assert segments[2][2]["ttl"] is None, "Part1 should have TTL=None"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
