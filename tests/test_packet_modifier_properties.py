"""
Property-based tests for PacketModifier.

Feature: attack-application-parity
Tests correctness properties for packet modification operations.
"""

import struct
from hypothesis import given, strategies as st, settings, HealthCheck
from hypothesis import assume

from core.packet.modifier import PacketModifier
from core.packet.packet_models import RawPacket, IPHeader, TCPHeader


# Hypothesis strategies for generating test data

@st.composite
def ip_address(draw):
    """Generate valid IP addresses."""
    octets = [draw(st.integers(min_value=1, max_value=254)) for _ in range(4)]
    return '.'.join(map(str, octets))


@st.composite
def tcp_packet(draw):
    """Generate valid TCP packets for testing."""
    # Generate IP header
    ip_header = IPHeader(
        version=4,
        header_length=20,
        ttl=draw(st.integers(min_value=1, max_value=255)),
        protocol=6,  # TCP
        source_ip=draw(ip_address()),
        destination_ip=draw(ip_address())
    )
    
    # Generate TCP header
    tcp_header = TCPHeader(
        source_port=draw(st.integers(min_value=1, max_value=65535)),
        destination_port=draw(st.integers(min_value=1, max_value=65535)),
        sequence_number=draw(st.integers(min_value=0, max_value=0xFFFFFFFF)),
        acknowledgment_number=draw(st.integers(min_value=0, max_value=0xFFFFFFFF)),
        header_length=20,
        flags=draw(st.integers(min_value=0, max_value=0xFF)),
        window_size=draw(st.integers(min_value=0, max_value=65535)),
        checksum=0,  # Will be calculated
        urgent_pointer=0
    )
    
    # Generate payload
    payload = draw(st.binary(min_size=0, max_size=1000))
    
    # Create packet
    packet = RawPacket(
        raw_data=b'',
        ip_header=ip_header,
        tcp_header=tcp_header,
        payload=payload
    )
    
    return packet


class TestBadsumCorruption:
    """
    **Feature: attack-application-parity, Property 14: Badsum Corruption**
    **Validates: Requirements 7.1**
    
    Property: For any fake attack with fooling="badsum", the generated packet
    should have an incorrect TCP checksum.
    """
    
    @given(packet=tcp_packet())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_badsum_creates_incorrect_checksum(self, packet):
        """
        Test that badsum corruption creates an incorrect checksum.
        
        For any TCP packet, applying badsum should result in a checksum
        that differs from the correct checksum.
        """
        modifier = PacketModifier()
        
        # Calculate correct checksum first
        correct_checksum = modifier.calculate_checksum(packet)
        
        # Apply badsum corruption
        corrupted_packet = modifier.corrupt_checksum(packet, method='badsum')
        
        # Get the corrupted checksum
        corrupted_checksum = corrupted_packet.tcp_header.checksum
        
        # Assert: corrupted checksum should differ from correct checksum
        assert corrupted_checksum != correct_checksum, \
            f"Badsum corruption failed: checksum unchanged (0x{corrupted_checksum:04x})"
        
        # Additional check: corrupted checksum should be XOR of correct checksum
        expected_corrupted = correct_checksum ^ 0xFFFF
        assert corrupted_checksum == expected_corrupted, \
            f"Badsum corruption incorrect: expected 0x{expected_corrupted:04x}, got 0x{corrupted_checksum:04x}"
    
    @given(packet=tcp_packet())
    @settings(max_examples=100)
    def test_badsum_is_deterministic(self, packet):
        """
        Test that badsum corruption is deterministic.
        
        For any TCP packet, applying badsum twice should produce the same result.
        """
        modifier = PacketModifier()
        
        # Apply badsum twice
        packet1 = modifier.corrupt_checksum(packet, method='badsum')
        checksum1 = packet1.tcp_header.checksum
        
        # Reset packet and apply again
        packet.tcp_header.checksum = 0
        packet2 = modifier.corrupt_checksum(packet, method='badsum')
        checksum2 = packet2.tcp_header.checksum
        
        # Assert: both checksums should be identical
        assert checksum1 == checksum2, \
            f"Badsum corruption not deterministic: 0x{checksum1:04x} != 0x{checksum2:04x}"
    
    @given(packet=tcp_packet())
    @settings(max_examples=100)
    def test_correct_checksum_calculation(self, packet):
        """
        Test that checksum calculation follows RFC 793.
        
        For any TCP packet, the calculated checksum should be valid according
        to the Internet checksum algorithm.
        """
        modifier = PacketModifier()
        
        # Calculate checksum
        checksum = modifier.calculate_checksum(packet)
        
        # Assert: checksum should be 16-bit value
        assert 0 <= checksum <= 0xFFFF, \
            f"Checksum out of range: 0x{checksum:04x}"
        
        # Set the checksum in the packet
        packet.tcp_header.checksum = checksum
        
        # Verify by recalculating - should get 0 or 0xFFFF when verifying
        # (This is a property of Internet checksum)
        # For now, just verify it's a valid 16-bit value
        assert isinstance(checksum, int), "Checksum should be an integer"
    
    @given(
        packet=tcp_packet(),
        ttl=st.integers(min_value=1, max_value=10)
    )
    @settings(max_examples=100)
    def test_badsum_with_low_ttl(self, packet, ttl):
        """
        Test badsum corruption combined with low TTL (typical fake attack).
        
        For any TCP packet with low TTL and badsum, both modifications
        should be applied correctly.
        """
        modifier = PacketModifier()
        
        # Calculate correct checksum before modifications
        correct_checksum = modifier.calculate_checksum(packet)
        
        # Apply low TTL
        packet = modifier.set_ttl(packet, ttl)
        
        # Apply badsum
        packet = modifier.corrupt_checksum(packet, method='badsum')
        
        # Assert: TTL should be set correctly
        assert packet.ip_header.ttl == ttl, \
            f"TTL not set correctly: expected {ttl}, got {packet.ip_header.ttl}"
        
        # Assert: checksum should be corrupted
        assert packet.tcp_header.checksum != correct_checksum, \
            f"Checksum not corrupted: still 0x{correct_checksum:04x}"
    
    @given(packet=tcp_packet())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_badseq_corruption(self, packet):
        """
        Test that badseq corruption modifies sequence number.
        
        For any TCP packet, applying badseq should result in a different
        sequence number.
        """
        modifier = PacketModifier()
        
        # Get original sequence number
        original_seq = packet.tcp_header.sequence_number
        
        # Apply badseq corruption
        corrupted_packet = modifier.corrupt_checksum(packet, method='badseq')
        
        # Get corrupted sequence number
        corrupted_seq = corrupted_packet.tcp_header.sequence_number
        
        # Assert: sequence number should be different
        assert corrupted_seq != original_seq, \
            f"Badseq corruption failed: sequence unchanged ({original_seq})"
        
        # Assert: corrupted sequence should be original + offset
        expected_seq = (original_seq + 0x10000000) & 0xFFFFFFFF
        assert corrupted_seq == expected_seq, \
            f"Badseq corruption incorrect: expected {expected_seq}, got {corrupted_seq}"
    
    @given(
        packet=tcp_packet(),
        flags_dict=st.dictionaries(
            keys=st.sampled_from(['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG']),
            values=st.booleans(),
            min_size=1,
            max_size=6
        )
    )
    @settings(max_examples=100)
    def test_tcp_flags_setting(self, packet, flags_dict):
        """
        Test that TCP flags are set correctly.
        
        For any TCP packet and flag combination, the flags should be
        set according to the specification.
        """
        modifier = PacketModifier()
        
        # Apply flags
        modified_packet = modifier.set_tcp_flags(packet, flags_dict)
        
        # Map flag names to bit values
        flag_map = {
            'FIN': TCPHeader.FIN,
            'SYN': TCPHeader.SYN,
            'RST': TCPHeader.RST,
            'PSH': TCPHeader.PSH,
            'ACK': TCPHeader.ACK,
            'URG': TCPHeader.URG,
        }
        
        # Calculate expected flags
        expected_flags = 0
        for flag_name, flag_value in flags_dict.items():
            if flag_value and flag_name in flag_map:
                expected_flags |= flag_map[flag_name]
        
        # Assert: flags should match expected
        assert modified_packet.tcp_header.flags == expected_flags, \
            f"Flags not set correctly: expected 0x{expected_flags:02x}, got 0x{modified_packet.tcp_header.flags:02x}"
        
        # Verify individual flags
        for flag_name, flag_value in flags_dict.items():
            if flag_name in flag_map:
                has_flag = bool(modified_packet.tcp_header.flags & flag_map[flag_name])
                assert has_flag == flag_value, \
                    f"Flag {flag_name} not set correctly: expected {flag_value}, got {has_flag}"
    
    @given(
        packet=tcp_packet(),
        ttl1=st.integers(min_value=1, max_value=255),
        ttl2=st.integers(min_value=1, max_value=255)
    )
    @settings(max_examples=100)
    def test_ttl_setting_idempotent(self, packet, ttl1, ttl2):
        """
        Test that TTL setting is idempotent.
        
        For any TCP packet, setting TTL multiple times should result in
        the last value being set.
        """
        modifier = PacketModifier()
        
        # Set TTL twice
        packet = modifier.set_ttl(packet, ttl1)
        packet = modifier.set_ttl(packet, ttl2)
        
        # Assert: final TTL should be ttl2
        assert packet.ip_header.ttl == ttl2, \
            f"TTL not set correctly: expected {ttl2}, got {packet.ip_header.ttl}"
