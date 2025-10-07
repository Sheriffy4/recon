"""
Test suite for PacketSequenceAnalyzer implementation.

This test suite verifies all the functionality required by task 3:
- Fake packet detection logic
- Split position detection algorithm  
- Overlap size calculation
- Timing analysis between consecutive packets
"""

import pytest
import time
from recon.core.pcap_analysis.packet_sequence_analyzer import (
    PacketSequenceAnalyzer, FakePacketAnalysis, SplitPositionAnalysis,
    OverlapAnalysis, TimingAnalysis, FakeDisorderAnalysis
)
from recon.core.pcap_analysis.packet_info import PacketInfo, TLSInfo


class TestPacketSequenceAnalyzer:
    """Test suite for PacketSequenceAnalyzer."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = PacketSequenceAnalyzer(debug_mode=True)
        self.base_timestamp = time.time()
    
    def create_test_packet(self, **kwargs) -> PacketInfo:
        """Create a test packet with default values."""
        defaults = {
            'timestamp': self.base_timestamp,
            'src_ip': '192.168.1.100',
            'dst_ip': '162.159.140.229',  # x.com IP
            'src_port': 12345,
            'dst_port': 443,
            'sequence_num': 1000,
            'ack_num': 2000,
            'ttl': 64,
            'flags': ['ACK'],
            'payload_length': 0,
            'checksum': 0x1234,
            'checksum_valid': True
        }
        defaults.update(kwargs)
        return PacketInfo(**defaults)
    
    def test_fake_packet_detection_low_ttl(self):
        """Test fake packet detection based on low TTL."""
        # Create fake packet with low TTL
        fake_packet = self.create_test_packet(ttl=3, flags=['PSH', 'ACK'])
        
        analysis = self.analyzer.detect_fake_packet(fake_packet, [fake_packet], 0)
        
        assert analysis.is_fake
        assert analysis.ttl_suspicious
        assert analysis.confidence >= 0.4
        assert "Low TTL: 3" in analysis.indicators
    
    def test_fake_packet_detection_bad_checksum(self):
        """Test fake packet detection based on bad checksum."""
        # Create fake packet with bad checksum
        fake_packet = self.create_test_packet(
            checksum=0x0000, 
            checksum_valid=False,
            flags=['PSH', 'ACK']
        )
        
        analysis = self.analyzer.detect_fake_packet(fake_packet, [fake_packet], 0)
        
        assert analysis.is_fake
        assert analysis.checksum_invalid
        assert analysis.confidence >= 0.3
        assert "Invalid checksum" in analysis.indicators
    
    def test_fake_packet_detection_empty_psh(self):
        """Test fake packet detection based on empty PSH packet."""
        # Create empty PSH packet
        fake_packet = self.create_test_packet(
            payload_length=0,
            flags=['PSH', 'ACK']
        )
        
        analysis = self.analyzer.detect_fake_packet(fake_packet, [fake_packet], 0)
        
        assert analysis.payload_suspicious
        assert "Empty PSH packet" in analysis.indicators
    
    def test_fake_packet_detection_combined_indicators(self):
        """Test fake packet detection with multiple indicators."""
        # Create packet with multiple fake indicators
        fake_packet = self.create_test_packet(
            ttl=3,
            checksum=0x0000,
            checksum_valid=False,
            payload_length=0,
            flags=['PSH', 'ACK']
        )
        
        analysis = self.analyzer.detect_fake_packet(fake_packet, [fake_packet], 0)
        
        assert analysis.is_fake
        assert analysis.confidence >= 0.8  # High confidence with multiple indicators
        assert analysis.ttl_suspicious
        assert analysis.checksum_invalid
        assert analysis.payload_suspicious
    
    def test_real_packet_detection(self):
        """Test that real packets are not flagged as fake."""
        # Create normal packet
        real_packet = self.create_test_packet(
            ttl=64,
            checksum=0x1234,
            checksum_valid=True,
            payload_length=100,
            flags=['PSH', 'ACK']
        )
        
        analysis = self.analyzer.detect_fake_packet(real_packet, [real_packet], 0)
        
        assert not analysis.is_fake
        assert analysis.confidence < 0.5
        assert not analysis.ttl_suspicious
        assert not analysis.checksum_invalid
        assert not analysis.payload_suspicious
    
    def test_split_position_detection_client_hello(self):
        """Test split position detection with ClientHello packet."""
        # Create ClientHello packet
        client_hello = self.create_test_packet(
            payload_length=500,
            is_client_hello=True,
            tls_info=TLSInfo(
                version="3.3",
                handshake_type="ClientHello",
                sni="x.com",
                client_hello_length=500
            )
        )
        
        # Create subsequent small segments (potential splits)
        segment1 = self.create_test_packet(
            timestamp=self.base_timestamp + 0.001,
            sequence_num=1500,
            payload_length=50,
            flags=['PSH', 'ACK']
        )
        
        segment2 = self.create_test_packet(
            timestamp=self.base_timestamp + 0.002,
            sequence_num=1550,
            payload_length=150,
            flags=['PSH', 'ACK']
        )
        
        packets = [client_hello, segment1, segment2]
        analysis = self.analyzer.detect_split_positions(packets)
        
        assert len(analysis.detected_splits) > 0
        assert len(analysis.actual_positions) > 0
        assert analysis.split_method in ["disorder", "fakeddisorder", "multisplit"]
    
    def test_split_position_detection_with_fake_packets(self):
        """Test split position detection with fake packets nearby."""
        # Create ClientHello
        client_hello = self.create_test_packet(
            payload_length=400,
            is_client_hello=True
        )
        
        # Create fake packet
        fake_packet = self.create_test_packet(
            timestamp=self.base_timestamp + 0.001,
            ttl=3,
            checksum_valid=False,
            flags=['PSH', 'ACK']
        )
        
        # Create split segment
        split_segment = self.create_test_packet(
            timestamp=self.base_timestamp + 0.002,
            sequence_num=1400,
            payload_length=100,
            flags=['PSH', 'ACK']
        )
        
        packets = [client_hello, fake_packet, split_segment]
        analysis = self.analyzer.detect_split_positions(packets)
        
        assert analysis.split_method == "fakeddisorder"
        assert analysis.expected_position == 3
    
    def test_overlap_size_calculation(self):
        """Test sequence overlap size calculation."""
        # Create packets with overlapping sequence numbers
        packet1 = self.create_test_packet(
            sequence_num=1000,
            payload_length=100
        )
        
        # Next packet starts before previous ends (overlap)
        packet2 = self.create_test_packet(
            timestamp=self.base_timestamp + 0.001,
            sequence_num=1090,  # Should be 1100, so 10 bytes overlap
            payload_length=50
        )
        
        packets = [packet1, packet2]
        analysis = self.analyzer.calculate_overlap_sizes(packets)
        
        assert len(analysis.overlaps_detected) > 0
        assert analysis.total_overlap_bytes == 10
        overlap = analysis.overlaps_detected[0]
        assert overlap['overlap_bytes'] == 10
        assert overlap['current_seq'] == 1000
        assert overlap['next_seq'] == 1090
        assert overlap['expected_seq'] == 1100
    
    def test_timing_analysis_normal_pattern(self):
        """Test timing analysis with normal packet intervals."""
        packets = []
        for i in range(5):
            packet = self.create_test_packet(
                timestamp=self.base_timestamp + i * 0.05,  # 50ms intervals
                sequence_num=1000 + i * 100
            )
            packets.append(packet)
        
        analysis = self.analyzer.analyze_timing_patterns(packets)
        
        assert analysis.avg_delay == pytest.approx(0.05, rel=1e-3)
        assert analysis.timing_pattern == "normal"
        assert len(analysis.suspicious_delays) == 0
    
    def test_timing_analysis_burst_pattern(self):
        """Test timing analysis with burst pattern (very fast)."""
        packets = []
        for i in range(5):
            packet = self.create_test_packet(
                timestamp=self.base_timestamp + i * 0.001,  # 1ms intervals
                sequence_num=1000 + i * 100
            )
            packets.append(packet)
        
        analysis = self.analyzer.analyze_timing_patterns(packets)
        
        assert analysis.avg_delay == pytest.approx(0.001, rel=1e-3)
        assert analysis.timing_pattern == "burst"
    
    def test_timing_analysis_delayed_pattern(self):
        """Test timing analysis with delayed pattern."""
        packets = []
        for i in range(5):
            packet = self.create_test_packet(
                timestamp=self.base_timestamp + i * 1.0,  # 1 second intervals
                sequence_num=1000 + i * 100
            )
            packets.append(packet)
        
        analysis = self.analyzer.analyze_timing_patterns(packets)
        
        assert analysis.avg_delay == pytest.approx(1.0, rel=1e-3)
        assert analysis.timing_pattern == "delayed"
        assert len(analysis.suspicious_delays) > 0
    
    def test_timing_analysis_suspicious_delays(self):
        """Test detection of suspicious timing delays."""
        # Create packets with one suspicious delay
        packet1 = self.create_test_packet(timestamp=self.base_timestamp)
        packet2 = self.create_test_packet(timestamp=self.base_timestamp + 0.05)  # Normal
        packet3 = self.create_test_packet(timestamp=self.base_timestamp + 2.0)   # Suspicious delay
        
        packets = [packet1, packet2, packet3]
        analysis = self.analyzer.analyze_timing_patterns(packets)
        
        assert len(analysis.suspicious_delays) > 0
        suspicious = analysis.suspicious_delays[0]
        assert suspicious['delay'] > 1.0
        assert 'delay' in suspicious['reason'].lower()
    
    def test_fake_disorder_analysis_complete(self):
        """Test complete fakeddisorder analysis."""
        # Create a realistic fakeddisorder sequence
        packets = []
        
        # 1. Normal SYN
        packets.append(self.create_test_packet(
            timestamp=self.base_timestamp,
            flags=['SYN'],
            sequence_num=1000
        ))
        
        # 2. SYN-ACK response
        packets.append(self.create_test_packet(
            timestamp=self.base_timestamp + 0.01,
            flags=['SYN', 'ACK'],
            sequence_num=2000,
            ack_num=1001
        ))
        
        # 3. ACK
        packets.append(self.create_test_packet(
            timestamp=self.base_timestamp + 0.02,
            flags=['ACK'],
            sequence_num=1001,
            ack_num=2001
        ))
        
        # 4. Fake packet with low TTL
        packets.append(self.create_test_packet(
            timestamp=self.base_timestamp + 0.03,
            flags=['PSH', 'ACK'],
            sequence_num=1001,
            ttl=3,
            checksum_valid=False,
            payload_length=40
        ))
        
        # 5. Real ClientHello first segment
        packets.append(self.create_test_packet(
            timestamp=self.base_timestamp + 0.04,
            flags=['PSH', 'ACK'],
            sequence_num=1001,
            payload_length=3,  # Split at position 3
            is_client_hello=True,
            tls_info=TLSInfo(handshake_type="ClientHello", sni="x.com")
        ))
        
        # 6. ClientHello remaining segment
        packets.append(self.create_test_packet(
            timestamp=self.base_timestamp + 0.05,
            flags=['PSH', 'ACK'],
            sequence_num=1004,
            payload_length=200
        ))
        
        analysis = self.analyzer.analyze_fake_disorder_sequence(packets)
        
        assert analysis.fake_packet_detected
        assert analysis.fake_packet_position == 3  # Fourth packet (0-indexed)
        assert analysis.split_position > 0
        assert len(analysis.real_segments) > 0
        assert len(analysis.ttl_pattern) == len(packets)
        assert 3 in analysis.ttl_pattern  # Low TTL present
        assert analysis.zapret_compliance > 0.5
    
    def test_sequence_comparison(self):
        """Test comparison between recon and zapret sequences."""
        # Create recon sequence (with issues)
        recon_packets = [
            self.create_test_packet(ttl=64, flags=['PSH', 'ACK']),  # Wrong TTL
            self.create_test_packet(
                timestamp=self.base_timestamp + 0.01,
                sequence_num=1100,
                payload_length=5,  # Wrong split position
                is_client_hello=True
            )
        ]
        
        # Create zapret sequence (correct)
        zapret_packets = [
            self.create_test_packet(ttl=3, flags=['PSH', 'ACK']),  # Correct TTL
            self.create_test_packet(
                timestamp=self.base_timestamp + 0.01,
                sequence_num=1100,
                payload_length=3,  # Correct split position
                is_client_hello=True
            )
        ]
        
        comparison = self.analyzer.compare_sequences(recon_packets, zapret_packets)
        
        assert 'recon_analysis' in comparison
        assert 'zapret_analysis' in comparison
        assert len(comparison['differences']) > 0
        assert len(comparison['recommendations']) > 0
        
        # Check for TTL difference
        ttl_diff = next((d for d in comparison['differences'] if d['type'] == 'ttl_pattern'), None)
        assert ttl_diff is not None
        assert ttl_diff['severity'] == 'high'
    
    def test_analysis_summary(self):
        """Test comprehensive analysis summary."""
        # Create test packet sequence
        packets = [
            self.create_test_packet(ttl=3, checksum_valid=False),  # Fake packet
            self.create_test_packet(
                timestamp=self.base_timestamp + 0.01,
                payload_length=3,
                is_client_hello=True
            ),
            self.create_test_packet(
                timestamp=self.base_timestamp + 0.02,
                sequence_num=1003,
                payload_length=200
            )
        ]
        
        summary = self.analyzer.get_analysis_summary(packets)
        
        assert 'packet_count' in summary
        assert summary['packet_count'] == 3
        assert 'fake_disorder' in summary
        assert 'timing' in summary
        assert 'splits' in summary
        assert 'overlaps' in summary
        assert 'quality_score' in summary
        
        # Verify fake disorder analysis
        fake_disorder = summary['fake_disorder']
        assert fake_disorder['fake_detected']
        assert fake_disorder['split_position'] > 0
        assert fake_disorder['real_segments'] > 0
    
    def test_edge_cases(self):
        """Test edge cases and error handling."""
        # Empty packet list
        empty_analysis = self.analyzer.analyze_fake_disorder_sequence([])
        assert not empty_analysis.fake_packet_detected
        assert empty_analysis.split_position == -1
        
        # Single packet
        single_packet = [self.create_test_packet()]
        single_analysis = self.analyzer.analyze_fake_disorder_sequence(single_packet)
        assert len(single_analysis.ttl_pattern) == 1
        assert len(single_analysis.timing_pattern) == 0  # No inter-packet delays
        
        # Timing analysis with single packet
        timing_analysis = self.analyzer.analyze_timing_patterns(single_packet)
        assert len(timing_analysis.inter_packet_delays) == 0
        assert timing_analysis.avg_delay == 0.0


if __name__ == "__main__":
    # Run basic functionality test
    test_suite = TestPacketSequenceAnalyzer()
    test_suite.setup_method()
    
    print("Testing PacketSequenceAnalyzer implementation...")
    
    # Test fake packet detection
    print("✓ Testing fake packet detection...")
    test_suite.test_fake_packet_detection_low_ttl()
    test_suite.test_fake_packet_detection_bad_checksum()
    test_suite.test_fake_packet_detection_combined_indicators()
    test_suite.test_real_packet_detection()
    
    # Test split position detection
    print("✓ Testing split position detection...")
    test_suite.test_split_position_detection_client_hello()
    test_suite.test_split_position_detection_with_fake_packets()
    
    # Test overlap calculation
    print("✓ Testing overlap size calculation...")
    test_suite.test_overlap_size_calculation()
    
    # Test timing analysis
    print("✓ Testing timing analysis...")
    test_suite.test_timing_analysis_normal_pattern()
    test_suite.test_timing_analysis_burst_pattern()
    test_suite.test_timing_analysis_delayed_pattern()
    test_suite.test_timing_analysis_suspicious_delays()
    
    # Test complete analysis
    print("✓ Testing complete fakeddisorder analysis...")
    test_suite.test_fake_disorder_analysis_complete()
    test_suite.test_sequence_comparison()
    test_suite.test_analysis_summary()
    
    # Test edge cases
    print("✓ Testing edge cases...")
    test_suite.test_edge_cases()
    
    print("\n✅ All PacketSequenceAnalyzer tests passed!")
    print("Task 3 implementation is complete and verified.")