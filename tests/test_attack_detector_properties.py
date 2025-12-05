"""
Property-based tests for AttackDetector.

Feature: attack-application-parity
Tests correctness properties for attack detection algorithms.
"""

import struct
import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.validation.attack_detector import AttackDetector, DetectedAttacks


# ============================================================================
# Mock packet creation utilities
# ============================================================================

class MockPacket:
    """Mock packet for testing without Scapy dependency."""
    
    def __init__(self, ip_ttl=64, tcp_seq=1000, tcp_chksum=None, payload=b""):
        self._ip_ttl = ip_ttl
        self._tcp_seq = tcp_seq
        self._tcp_chksum = tcp_chksum
        self._payload = payload
        self._layers = {'IP': True, 'TCP': True, 'Raw': len(payload) > 0}
    
    def haslayer(self, layer):
        """Check if packet has layer."""
        layer_name = layer.__name__ if hasattr(layer, '__name__') else str(layer)
        return self._layers.get(layer_name, False)
    
    def __getitem__(self, layer):
        """Get layer from packet."""
        layer_name = layer.__name__ if hasattr(layer, '__name__') else str(layer)
        if layer_name == 'IP':
            return MockIPLayer(self._ip_ttl)
        elif layer_name == 'TCP':
            return MockTCPLayer(self._tcp_seq, self._tcp_chksum)
        elif layer_name == 'Raw':
            return MockRawLayer(self._payload)
        raise KeyError(f"Layer {layer_name} not found")


class MockIPLayer:
    """Mock IP layer."""
    def __init__(self, ttl):
        self.ttl = ttl


class MockTCPLayer:
    """Mock TCP layer."""
    def __init__(self, seq, chksum):
        self.seq = seq
        self.chksum = chksum


class MockRawLayer:
    """Mock Raw layer."""
    def __init__(self, payload):
        self.load = payload


def create_mock_packet(ttl=64, seq=1000, chksum=None, payload=b""):
    """Create a mock packet for testing."""
    return MockPacket(ip_ttl=ttl, tcp_seq=seq, tcp_chksum=chksum, payload=payload)


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def packet_with_ttl(draw, min_ttl=1, max_ttl=255):
    """Generate packet with specific TTL range."""
    ttl = draw(st.integers(min_value=min_ttl, max_value=max_ttl))
    seq = draw(st.integers(min_value=1000, max_value=100000))
    payload_len = draw(st.integers(min_value=10, max_value=1000))
    payload = draw(st.binary(min_size=payload_len, max_size=payload_len))
    return create_mock_packet(ttl=ttl, seq=seq, payload=payload)


@st.composite
def packet_list_with_sequences(draw, min_packets=1, max_packets=10):
    """Generate list of packets with sequential sequence numbers."""
    num_packets = draw(st.integers(min_value=min_packets, max_value=max_packets))
    base_seq = draw(st.integers(min_value=1000, max_value=10000))
    
    packets = []
    current_seq = base_seq
    for i in range(num_packets):
        payload_len = draw(st.integers(min_value=10, max_value=500))
        payload = draw(st.binary(min_size=payload_len, max_size=payload_len))
        ttl = draw(st.integers(min_value=32, max_value=128))
        
        pkt = create_mock_packet(ttl=ttl, seq=current_seq, payload=payload)
        packets.append(pkt)
        current_seq += payload_len
    
    return packets


@st.composite
def fragmented_packets(draw, min_fragments=2, max_fragments=8):
    """Generate fragmented packets (split attack)."""
    num_fragments = draw(st.integers(min_value=min_fragments, max_value=max_fragments))
    base_seq = draw(st.integers(min_value=1000, max_value=10000))
    
    # Generate total payload
    total_payload_len = draw(st.integers(min_value=100, max_value=2000))
    total_payload = draw(st.binary(min_size=total_payload_len, max_size=total_payload_len))
    
    # Fragment the payload
    fragment_size = total_payload_len // num_fragments
    packets = []
    current_seq = base_seq
    offset = 0
    
    for i in range(num_fragments):
        if i == num_fragments - 1:
            # Last fragment gets remainder
            fragment = total_payload[offset:]
        else:
            fragment = total_payload[offset:offset + fragment_size]
        
        ttl = draw(st.integers(min_value=32, max_value=128))
        pkt = create_mock_packet(ttl=ttl, seq=current_seq, payload=fragment)
        packets.append(pkt)
        
        current_seq += len(fragment)
        offset += len(fragment)
    
    return packets, total_payload


# ============================================================================
# Property Tests for Attack Detection Completeness (Property 9)
# ============================================================================

class TestAttackDetectionCompleteness:
    """
    **Feature: attack-application-parity, Property 9: Attack Detection Completeness**
    **Validates: Requirements 3.2**
    
    Property: For any PCAP file and expected strategy, the Validator should
    detect all attacks specified in the strategy.
    """
    
    @given(ttl=st.integers(min_value=1, max_value=3))
    @settings(max_examples=100)
    def test_detects_fake_attack_with_low_ttl(self, ttl):
        """
        Test that fake attacks are detected when TTL <= 3.
        
        For any packet with TTL <= 3, the detector should identify it
        as a fake attack.
        """
        # Create packet with low TTL
        pkt = create_mock_packet(ttl=ttl, payload=b"fake packet")
        
        # Detect attacks
        detector = AttackDetector()
        attacks = detector.detect_fake([pkt])
        
        # Assert: fake attack should be detected
        assert attacks.fake is True, f"Fake attack should be detected for TTL={ttl}"
        assert attacks.fake_count >= 1, "Fake count should be at least 1"
        assert attacks.fake_ttl <= 3, f"Average TTL should be <= 3, got {attacks.fake_ttl}"
    
    @given(ttl=st.integers(min_value=4, max_value=255))
    @settings(max_examples=100)
    def test_does_not_detect_fake_with_normal_ttl(self, ttl):
        """
        Test that normal TTL packets are not flagged as fake.
        
        For any packet with TTL > 3, the detector should not identify it
        as a fake attack.
        """
        # Create packet with normal TTL
        pkt = create_mock_packet(ttl=ttl, payload=b"normal packet")
        
        # Detect attacks
        detector = AttackDetector()
        attacks = detector.detect_fake([pkt])
        
        # Assert: fake attack should NOT be detected
        assert attacks.fake is False, f"Fake attack should not be detected for TTL={ttl}"
        assert attacks.fake_count == 0, "Fake count should be 0"
    
    @given(packets_and_payload=fragmented_packets(min_fragments=2, max_fragments=8))
    @settings(max_examples=100)
    def test_detects_split_attack_with_multiple_fragments(self, packets_and_payload):
        """
        Test that split attacks are detected when payload is fragmented.
        
        For any payload fragmented into multiple packets, the detector
        should identify it as a split attack.
        """
        packets, total_payload = packets_and_payload
        
        # Detect attacks
        detector = AttackDetector()
        attacks = detector.detect_split(packets)
        
        # Assert: split attack should be detected
        assert attacks.split is True, "Split attack should be detected"
        assert attacks.fragment_count == len(packets), \
            f"Fragment count should be {len(packets)}, got {attacks.fragment_count}"
        assert attacks.fragment_count > 1, "Fragment count should be > 1 for split"
    
    @given(packets_and_payload=fragmented_packets(min_fragments=2, max_fragments=8))
    @settings(max_examples=100)
    def test_split_positions_are_calculated(self, packets_and_payload):
        """
        Test that split positions are correctly calculated.
        
        For any fragmented payload, the detector should calculate the
        cumulative positions where splits occur.
        """
        packets, total_payload = packets_and_payload
        
        # Detect attacks
        detector = AttackDetector()
        attacks = detector.detect_split(packets)
        
        # Assert: split positions should be calculated
        assert len(attacks.split_positions) == len(packets) - 1, \
            f"Should have {len(packets) - 1} split positions, got {len(attacks.split_positions)}"
        
        # Verify positions are cumulative and increasing
        for i in range(len(attacks.split_positions) - 1):
            assert attacks.split_positions[i] < attacks.split_positions[i + 1], \
                "Split positions should be increasing"
    
    @given(
        packets_and_payload=fragmented_packets(min_fragments=2, max_fragments=5),
        sni_offset=st.integers(min_value=50, max_value=150)
    )
    @settings(max_examples=100)
    def test_detects_split_near_sni(self, packets_and_payload, sni_offset):
        """
        Test that split near SNI is detected when split position is close to SNI offset.
        
        For any fragmented payload where a split position is within ±8 bytes
        of the SNI offset, the detector should flag split_near_sni.
        """
        packets, total_payload = packets_and_payload
        
        # Detect attacks
        detector = AttackDetector()
        attacks = detector.detect_split(packets, sni_offset=sni_offset)
        
        # Check if any split position is near SNI
        near_sni = any(abs(pos - sni_offset) <= 8 for pos in attacks.split_positions)
        
        # Assert: split_near_sni should match our calculation
        assert attacks.split_near_sni == near_sni, \
            f"split_near_sni should be {near_sni}, got {attacks.split_near_sni}"
    
    @given(packets=packet_list_with_sequences(min_packets=2, max_packets=8))
    @settings(max_examples=100)
    def test_does_not_detect_disorder_with_ordered_packets(self, packets):
        """
        Test that ordered packets are not flagged as disorder.
        
        For any list of packets with sequential sequence numbers,
        the detector should not identify disorder.
        """
        # Packets are already in order from the strategy
        detector = AttackDetector()
        attacks = detector.detect_disorder(packets)
        
        # Assert: disorder should NOT be detected
        assert attacks.disorder is False, "Disorder should not be detected for ordered packets"
        assert attacks.disorder_type == "", "Disorder type should be empty"
    
    @given(packets=packet_list_with_sequences(min_packets=2, max_packets=8))
    @settings(max_examples=100)
    def test_detects_disorder_with_reversed_packets(self, packets):
        """
        Test that disorder is detected when packets are out of order.
        
        For any list of packets, reversing the order should trigger
        disorder detection.
        """
        assume(len(packets) >= 2)
        
        # Reverse packet order
        reversed_packets = list(reversed(packets))
        
        # Detect attacks
        detector = AttackDetector()
        attacks = detector.detect_disorder(reversed_packets)
        
        # Assert: disorder should be detected
        assert attacks.disorder is True, "Disorder should be detected for reversed packets"
        assert attacks.disorder_type in ["out-of-order", "overlap"], \
            f"Disorder type should be set, got '{attacks.disorder_type}'"
    
    @given(
        num_packets=st.integers(min_value=2, max_value=5),
        low_ttl_count=st.integers(min_value=1, max_value=3)
    )
    @settings(max_examples=100)
    def test_detects_multiple_attack_types(self, num_packets, low_ttl_count):
        """
        Test that multiple attack types can be detected simultaneously.
        
        For any combination of attacks (fake + split), the detector
        should identify all present attacks.
        """
        assume(low_ttl_count < num_packets)
        
        # Create packets with mixed TTLs (some fake, some normal)
        packets = []
        base_seq = 1000
        for i in range(num_packets):
            ttl = 2 if i < low_ttl_count else 64
            payload = f"packet_{i}".encode()
            pkt = create_mock_packet(ttl=ttl, seq=base_seq, payload=payload)
            packets.append(pkt)
            base_seq += len(payload)
        
        # Detect all attacks
        detector = AttackDetector()
        attacks = detector.detect_attacks(packets)
        
        # Assert: both fake and split should be detected
        assert attacks.fake is True, "Fake attack should be detected"
        assert attacks.fake_count == low_ttl_count, \
            f"Fake count should be {low_ttl_count}, got {attacks.fake_count}"
        
        if num_packets > 1:
            assert attacks.split is True, "Split attack should be detected"
            assert attacks.fragment_count == num_packets, \
                f"Fragment count should be {num_packets}, got {attacks.fragment_count}"
    
    @given(packets=packet_list_with_sequences(min_packets=1, max_packets=5))
    @settings(max_examples=100)
    def test_detect_attacks_returns_all_attack_types(self, packets):
        """
        Test that detect_attacks returns a complete DetectedAttacks object.
        
        For any packet list, the detector should return an object with
        all attack type fields populated (even if false).
        """
        detector = AttackDetector()
        attacks = detector.detect_attacks(packets)
        
        # Assert: all fields should be present
        assert hasattr(attacks, 'fake'), "Should have 'fake' field"
        assert hasattr(attacks, 'fake_count'), "Should have 'fake_count' field"
        assert hasattr(attacks, 'fake_ttl'), "Should have 'fake_ttl' field"
        assert hasattr(attacks, 'split'), "Should have 'split' field"
        assert hasattr(attacks, 'fragment_count'), "Should have 'fragment_count' field"
        assert hasattr(attacks, 'split_near_sni'), "Should have 'split_near_sni' field"
        assert hasattr(attacks, 'split_positions'), "Should have 'split_positions' field"
        assert hasattr(attacks, 'disorder'), "Should have 'disorder' field"
        assert hasattr(attacks, 'disorder_type'), "Should have 'disorder_type' field"
        assert hasattr(attacks, 'badsum'), "Should have 'badsum' field"
        assert hasattr(attacks, 'badseq'), "Should have 'badseq' field"
        
        # Assert: types should be correct
        assert isinstance(attacks.fake, bool), "fake should be bool"
        assert isinstance(attacks.fake_count, int), "fake_count should be int"
        assert isinstance(attacks.split, bool), "split should be bool"
        assert isinstance(attacks.fragment_count, int), "fragment_count should be int"
        assert isinstance(attacks.disorder, bool), "disorder should be bool"
        assert isinstance(attacks.badsum, bool), "badsum should be bool"
    
    def test_empty_packet_list_returns_no_attacks(self):
        """
        Test that empty packet list returns DetectedAttacks with all false.
        
        For an empty packet list, no attacks should be detected.
        """
        detector = AttackDetector()
        attacks = detector.detect_attacks([])
        
        # Assert: no attacks should be detected
        assert attacks.fake is False, "No fake attack for empty list"
        assert attacks.split is False, "No split attack for empty list"
        assert attacks.disorder is False, "No disorder attack for empty list"
        assert attacks.badsum is False, "No badsum attack for empty list"
        assert attacks.fake_count == 0, "Fake count should be 0"
        assert attacks.fragment_count == 0, "Fragment count should be 0"
