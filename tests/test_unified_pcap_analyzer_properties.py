"""
Property-based tests for UnifiedPCAPAnalyzer.

Feature: auto-strategy-discovery
Tests correctness properties for PCAP analysis functionality.
"""

import pytest
import struct
import tempfile
from pathlib import Path
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.pcap.unified_analyzer import (
    UnifiedPCAPAnalyzer,
    ClientHelloInfo,
    SplitInfo,
    FakePacketInfo,
    PCAPAnalysisResult
)


# ============================================================================
# Helper functions for generating test PCAP data
# ============================================================================

def create_pcap_header() -> bytes:
    """Create a standard PCAP file header."""
    magic = 0xa1b2c3d4  # Standard PCAP magic number
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    network = 1  # Ethernet
    
    return struct.pack('IHHiIII', magic, version_major, version_minor, 
                      thiszone, sigfigs, snaplen, network)


def create_packet_header(packet_len: int, timestamp: float = 0.0) -> bytes:
    """Create a PCAP packet header."""
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1000000)
    incl_len = packet_len
    orig_len = packet_len
    
    return struct.pack('IIII', ts_sec, ts_usec, incl_len, orig_len)


def create_ip_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int, ttl: int = 64) -> bytes:
    """Create an IP header."""
    version_ihl = 0x45  # IPv4, header length 20 bytes
    tos = 0
    total_length = 20 + payload_len  # IP header + payload
    identification = 0
    flags_fragment = 0
    checksum = 0  # Simplified, not calculating actual checksum
    
    # Convert IP addresses to bytes
    src_ip_bytes = bytes(map(int, src_ip.split('.')))
    dst_ip_bytes = bytes(map(int, dst_ip.split('.')))
    
    header = struct.pack('!BBHHHBBH', version_ihl, tos, total_length, 
                        identification, flags_fragment, ttl, protocol, checksum)
    header += src_ip_bytes + dst_ip_bytes
    
    return header


def create_tcp_header(src_port: int, dst_port: int, seq: int, ack: int = 0, 
                     flags: int = 0x18, payload_len: int = 0, checksum: int = 0) -> bytes:
    """Create a TCP header."""
    data_offset = 5 << 4  # 5 * 4 = 20 bytes, no options
    window = 65535
    urgent_ptr = 0
    
    header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack,
                        data_offset, flags, window, checksum, urgent_ptr)
    
    return header


def create_tls_clienthello(sni: str = "example.com", size: int = 200) -> bytes:
    """Create a minimal TLS ClientHello packet."""
    # TLS record header
    content_type = 0x16  # Handshake
    version = 0x0301  # TLS 1.0
    
    # Handshake header
    handshake_type = 0x01  # ClientHello
    
    # Simplified ClientHello content
    client_version = 0x0303  # TLS 1.2
    random = b'\x00' * 32
    session_id_len = 0
    cipher_suites_len = 4
    cipher_suites = b'\x00\x2f\x00\x35'  # Two cipher suites
    compression_methods_len = 1
    compression_methods = b'\x00'
    
    # SNI extension
    sni_bytes = sni.encode('utf-8')
    sni_len = len(sni_bytes)
    extensions_len = 9 + sni_len  # Extension header + SNI data
    
    # Build handshake message
    handshake_content = struct.pack('!H', client_version)
    handshake_content += random
    handshake_content += struct.pack('!B', session_id_len)
    handshake_content += struct.pack('!H', cipher_suites_len) + cipher_suites
    handshake_content += struct.pack('!B', compression_methods_len) + compression_methods
    handshake_content += struct.pack('!H', extensions_len)
    
    # SNI extension
    handshake_content += struct.pack('!HH', 0x0000, 5 + sni_len)  # Extension type and length
    handshake_content += struct.pack('!H', 3 + sni_len)  # Server name list length
    handshake_content += struct.pack('!B', 0x00)  # Host name type
    handshake_content += struct.pack('!H', sni_len) + sni_bytes
    
    # Pad to desired size
    if len(handshake_content) < size - 9:
        handshake_content += b'\x00' * (size - 9 - len(handshake_content))
    
    handshake_len = len(handshake_content)
    handshake_header = struct.pack('!BI', handshake_type, handshake_len)[:-1]  # 3 bytes for length
    
    record_len = len(handshake_header) + handshake_len
    record_header = struct.pack('!BHH', content_type, version, record_len)
    
    return record_header + handshake_header + handshake_content


def create_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     seq: int, payload: bytes = b'', ttl: int = 64, 
                     tcp_checksum: int = 0) -> bytes:
    """Create a complete TCP packet."""
    tcp_header = create_tcp_header(src_port, dst_port, seq, 0, 0x18, len(payload), tcp_checksum)
    ip_header = create_ip_header(src_ip, dst_ip, 6, len(tcp_header) + len(payload), ttl)
    
    # Ethernet header (simplified)
    eth_header = b'\x00' * 14
    
    return eth_header + ip_header + tcp_header + payload


def create_test_pcap_file(packets: list) -> Path:
    """Create a temporary PCAP file with given packets."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
    
    # Write PCAP header
    temp_file.write(create_pcap_header())
    
    # Write packets
    for i, packet_data in enumerate(packets):
        packet_header = create_packet_header(len(packet_data), float(i))
        temp_file.write(packet_header)
        temp_file.write(packet_data)
    
    temp_file.close()
    return Path(temp_file.name)


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def valid_ip_address(draw):
    """Generate a valid IP address."""
    octets = [draw(st.integers(min_value=1, max_value=254)) for _ in range(4)]
    return '.'.join(map(str, octets))


@st.composite
def valid_port(draw):
    """Generate a valid port number."""
    return draw(st.integers(min_value=1024, max_value=65535))


@st.composite
def valid_domain(draw):
    """Generate a valid domain name."""
    labels = draw(st.lists(
        st.text(alphabet=st.characters(whitelist_categories=('Ll', 'Nd')), 
               min_size=1, max_size=10),
        min_size=2, max_size=3
    ))
    return '.'.join(labels)


# ============================================================================
# Property Tests for ClientHello Detection (Property 7, part 1)
# ============================================================================

class TestClientHelloDetection:
    """
    **Feature: auto-strategy-discovery, Property 7: PCAP analysis correctness**
    **Validates: Requirements 8.1**
    
    Property: For any PCAP file containing TLS traffic, UnifiedPCAPAnalyzer SHALL
    identify ClientHello packets by TLS record header (byte 0 = 0x16, byte 1 = 0x03).
    """
    
    @given(
        src_ip=valid_ip_address(),
        dst_ip=valid_ip_address(),
        src_port=valid_port(),
        dst_port=valid_port(),
        seq=st.integers(min_value=1000, max_value=1000000),
        sni=valid_domain(),
        ch_size=st.integers(min_value=100, max_value=500)
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_clienthello_identified_by_tls_header(self, src_ip, dst_ip, src_port, 
                                                   dst_port, seq, sni, ch_size):
        """
        Test that ClientHello packets are correctly identified by TLS header.
        
        For any packet with TLS record header (0x16 0x03) and handshake type 0x01,
        the analyzer should identify it as a ClientHello.
        """
        # Create ClientHello packet
        clienthello_payload = create_tls_clienthello(sni, ch_size)
        packet = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, clienthello_payload)
        
        # Create PCAP file
        pcap_file = create_test_pcap_file([packet])
        
        try:
            # Analyze
            analyzer = UnifiedPCAPAnalyzer()
            result = analyzer.analyze(pcap_file, sni)
            
            # Verify ClientHello was found
            assert len(result.clienthello_packets) >= 1, \
                f"Should find at least 1 ClientHello, found {len(result.clienthello_packets)}"
            
            # Verify first ClientHello has correct properties
            ch = result.clienthello_packets[0]
            assert ch.seq == seq, f"ClientHello seq should be {seq}, got {ch.seq}"
            assert ch.size > 0, f"ClientHello size should be positive, got {ch.size}"
            assert len(ch.raw_bytes) > 0, "ClientHello raw_bytes should not be empty"
            
            # Verify TLS header in raw bytes
            assert ch.raw_bytes[0] == 0x16, \
                f"First byte should be 0x16 (Handshake), got {hex(ch.raw_bytes[0])}"
            assert ch.raw_bytes[1] == 0x03, \
                f"Second byte should be 0x03 (TLS version), got {hex(ch.raw_bytes[1])}"
        
        finally:
            # Cleanup
            pcap_file.unlink()
    
    @given(
        src_ip=valid_ip_address(),
        dst_ip=valid_ip_address(),
        src_port=valid_port(),
        dst_port=valid_port(),
        seq=st.integers(min_value=1000, max_value=1000000),
        payload=st.binary(min_size=10, max_size=100)
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_non_tls_packets_not_identified_as_clienthello(self, src_ip, dst_ip, 
                                                           src_port, dst_port, seq, payload):
        """
        Test that non-TLS packets are not identified as ClientHello.
        
        For any packet without TLS record header, the analyzer should not
        identify it as a ClientHello.
        """
        # Ensure payload doesn't start with TLS header
        assume(len(payload) < 2 or payload[0] != 0x16 or payload[1] != 0x03)
        
        # Create non-TLS packet
        packet = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, payload)
        
        # Create PCAP file
        pcap_file = create_test_pcap_file([packet])
        
        try:
            # Analyze
            analyzer = UnifiedPCAPAnalyzer()
            result = analyzer.analyze(pcap_file, "example.com")
            
            # Verify no ClientHello was found
            assert len(result.clienthello_packets) == 0, \
                f"Should find 0 ClientHellos in non-TLS packet, found {len(result.clienthello_packets)}"
        
        finally:
            # Cleanup
            pcap_file.unlink()


# ============================================================================
# Property Tests for Split Detection (Property 7, part 2)
# ============================================================================

class TestSplitDetection:
    """
    **Feature: auto-strategy-discovery, Property 7: PCAP analysis correctness**
    **Validates: Requirements 8.2**
    
    Property: For any PCAP file containing TLS traffic, UnifiedPCAPAnalyzer SHALL
    detect split position as the size of the first ClientHello fragment.
    """
    
    @given(
        src_ip=valid_ip_address(),
        dst_ip=valid_ip_address(),
        src_port=valid_port(),
        dst_port=valid_port(),
        seq=st.integers(min_value=1000, max_value=1000000),
        sni=valid_domain(),
        split_pos=st.integers(min_value=10, max_value=100)
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_split_position_detected_as_first_fragment_size(self, src_ip, dst_ip, 
                                                            src_port, dst_port, seq, 
                                                            sni, split_pos):
        """
        Test that split position is correctly detected as first fragment size.
        
        For any ClientHello split into fragments, the split position should be
        equal to the size of the first fragment.
        """
        # Create full ClientHello
        full_clienthello = create_tls_clienthello(sni, 200)
        
        # Split into two fragments
        first_fragment = full_clienthello[:split_pos]
        second_fragment = full_clienthello[split_pos:]
        
        # Create packets
        packet1 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, first_fragment)
        packet2 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq + split_pos, second_fragment)
        
        # Create PCAP file
        pcap_file = create_test_pcap_file([packet1, packet2])
        
        try:
            # Analyze
            analyzer = UnifiedPCAPAnalyzer()
            result = analyzer.analyze(pcap_file, sni)
            
            # Verify split was detected
            assert result.split_info is not None, "Split info should not be None"
            assert result.split_info.detected, "Split should be detected"
            
            # Verify split position matches first fragment size
            assert result.split_info.position == split_pos, \
                f"Split position should be {split_pos}, got {result.split_info.position}"
            
            # Verify fragment count
            assert result.split_info.fragment_count >= 2, \
                f"Should have at least 2 fragments, got {result.split_info.fragment_count}"
        
        finally:
            # Cleanup
            pcap_file.unlink()


# ============================================================================
# Property Tests for Fake Packet Detection (Property 7, part 3)
# ============================================================================

class TestFakePacketDetection:
    """
    **Feature: auto-strategy-discovery, Property 7: PCAP analysis correctness**
    **Validates: Requirements 8.3**
    
    Property: For any PCAP file containing TLS traffic, UnifiedPCAPAnalyzer SHALL
    detect fake packets as packets with TTL < 20.
    """
    
    @given(
        src_ip=valid_ip_address(),
        dst_ip=valid_ip_address(),
        src_port=valid_port(),
        dst_port=valid_port(),
        seq=st.integers(min_value=1000, max_value=1000000),
        ttl=st.integers(min_value=1, max_value=19),
        payload=st.binary(min_size=10, max_size=100)
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_low_ttl_packets_detected_as_fake(self, src_ip, dst_ip, src_port, 
                                              dst_port, seq, ttl, payload):
        """
        Test that packets with TTL < 20 are detected as fake packets.
        
        For any packet with TTL < 20, the analyzer should identify it as a fake packet.
        """
        # Create packet with low TTL
        packet = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, payload, ttl)
        
        # Create PCAP file
        pcap_file = create_test_pcap_file([packet])
        
        try:
            # Analyze
            analyzer = UnifiedPCAPAnalyzer()
            result = analyzer.analyze(pcap_file, "example.com")
            
            # Verify fake packet was detected
            assert len(result.fake_packets) >= 1, \
                f"Should find at least 1 fake packet with TTL={ttl}, found {len(result.fake_packets)}"
            
            # Verify TTL is correct
            fake_pkt = result.fake_packets[0]
            assert fake_pkt.ttl == ttl, f"Fake packet TTL should be {ttl}, got {fake_pkt.ttl}"
            assert fake_pkt.ttl < 20, f"Fake packet TTL should be < 20, got {fake_pkt.ttl}"
        
        finally:
            # Cleanup
            pcap_file.unlink()
    
    @given(
        src_ip=valid_ip_address(),
        dst_ip=valid_ip_address(),
        src_port=valid_port(),
        dst_port=valid_port(),
        seq=st.integers(min_value=1000, max_value=1000000),
        ttl=st.integers(min_value=20, max_value=255),
        payload=st.binary(min_size=10, max_size=100)
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_normal_ttl_packets_not_detected_as_fake(self, src_ip, dst_ip, src_port, 
                                                     dst_port, seq, ttl, payload):
        """
        Test that packets with TTL >= 20 are not detected as fake packets.
        
        For any packet with TTL >= 20, the analyzer should not identify it as a fake packet.
        """
        # Create packet with normal TTL
        packet = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, payload, ttl)
        
        # Create PCAP file
        pcap_file = create_test_pcap_file([packet])
        
        try:
            # Analyze
            analyzer = UnifiedPCAPAnalyzer()
            result = analyzer.analyze(pcap_file, "example.com")
            
            # Verify no fake packet was detected
            assert len(result.fake_packets) == 0, \
                f"Should find 0 fake packets with TTL={ttl}, found {len(result.fake_packets)}"
        
        finally:
            # Cleanup
            pcap_file.unlink()


# ============================================================================
# Property Tests for Disorder Detection (Property 7, part 4)
# ============================================================================

class TestDisorderDetection:
    """
    **Feature: auto-strategy-discovery, Property 7: PCAP analysis correctness**
    **Validates: Requirements 8.4**
    
    Property: For any PCAP file containing TLS traffic, UnifiedPCAPAnalyzer SHALL
    detect disorder when sequence numbers are not monotonically increasing.
    """
    
    @given(
        src_ip=valid_ip_address(),
        dst_ip=valid_ip_address(),
        src_port=valid_port(),
        dst_port=valid_port(),
        seq1=st.integers(min_value=1000, max_value=50000),
        seq2=st.integers(min_value=1000, max_value=50000),
        payload=st.binary(min_size=10, max_size=100)
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_out_of_order_sequences_detected_as_disorder(self, src_ip, dst_ip, 
                                                         src_port, dst_port, 
                                                         seq1, seq2, payload):
        """
        Test that out-of-order sequence numbers are detected as disorder.
        
        For any packets where seq2 < seq1 (not wraparound), the analyzer
        should detect disorder.
        """
        # Ensure seq2 < seq1 and not wraparound
        assume(seq2 < seq1)
        assume(seq1 - seq2 < 2**31)  # Not wraparound
        
        # Create packets with out-of-order sequences
        packet1 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq1, payload)
        packet2 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq2, payload)
        
        # Create PCAP file
        pcap_file = create_test_pcap_file([packet1, packet2])
        
        try:
            # Analyze
            analyzer = UnifiedPCAPAnalyzer()
            result = analyzer.analyze(pcap_file, "example.com")
            
            # Verify disorder was detected
            assert result.disorder_detected, \
                f"Disorder should be detected for seq1={seq1}, seq2={seq2}"
            assert result.disorder_details is not None, \
                "Disorder details should be provided"
        
        finally:
            # Cleanup
            pcap_file.unlink()


# ============================================================================
# Property Tests for Fooling Detection (Property 7, part 5)
# ============================================================================

class TestFoolingDetection:
    """
    **Feature: auto-strategy-discovery, Property 7: PCAP analysis correctness**
    **Validates: Requirements 8.5**
    
    Property: For any PCAP file containing TLS traffic, UnifiedPCAPAnalyzer SHALL
    detect badsum fooling when TCP checksum is invalid (0).
    """
    
    @given(
        src_ip=valid_ip_address(),
        dst_ip=valid_ip_address(),
        src_port=valid_port(),
        dst_port=valid_port(),
        seq=st.integers(min_value=1000, max_value=1000000),
        payload=st.binary(min_size=10, max_size=100)
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_zero_checksum_detected_as_badsum(self, src_ip, dst_ip, src_port, 
                                              dst_port, seq, payload):
        """
        Test that packets with zero checksum are detected as badsum fooling.
        
        For any packet with TCP checksum = 0, the analyzer should detect
        badsum fooling mode.
        """
        # Create packet with zero checksum
        packet = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, 
                                  payload, tcp_checksum=0)
        
        # Create PCAP file
        pcap_file = create_test_pcap_file([packet])
        
        try:
            # Analyze
            analyzer = UnifiedPCAPAnalyzer()
            result = analyzer.analyze(pcap_file, "example.com")
            
            # Verify badsum was detected
            assert "badsum" in result.fooling_modes, \
                f"badsum should be detected, got fooling_modes={result.fooling_modes}"
        
        finally:
            # Cleanup
            pcap_file.unlink()


# ============================================================================
# Integration Tests
# ============================================================================

class TestPCAPAnalysisIntegration:
    """
    Integration tests for complete PCAP analysis workflow.
    """
    
    @given(
        src_ip=valid_ip_address(),
        dst_ip=valid_ip_address(),
        src_port=valid_port(),
        dst_port=valid_port(),
        seq=st.integers(min_value=1000, max_value=1000000),
        sni=valid_domain()
    )
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_complete_analysis_workflow(self, src_ip, dst_ip, src_port, dst_port, seq, sni):
        """
        Test complete PCAP analysis workflow with multiple packet types.
        
        Verify that analyzer correctly processes a PCAP with:
        - ClientHello packets
        - Fake packets (low TTL)
        - Normal packets
        """
        # Create various packets
        clienthello = create_tls_clienthello(sni, 200)
        ch_packet = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, clienthello)
        
        fake_packet = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, 
                                       seq + 1000, b'fake', ttl=5)
        
        normal_packet = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, 
                                         seq + 2000, b'normal data', ttl=64)
        
        # Create PCAP file
        pcap_file = create_test_pcap_file([ch_packet, fake_packet, normal_packet])
        
        try:
            # Analyze
            analyzer = UnifiedPCAPAnalyzer()
            result = analyzer.analyze(pcap_file, sni)
            
            # Verify analysis completed
            assert result.pcap_file == str(pcap_file), "PCAP file path should match"
            assert result.domain == sni, f"Domain should be {sni}, got {result.domain}"
            assert result.total_packets == 3, f"Should have 3 total packets, got {result.total_packets}"
            assert result.tcp_packets == 3, f"Should have 3 TCP packets, got {result.tcp_packets}"
            
            # Verify ClientHello detection
            assert len(result.clienthello_packets) >= 1, \
                f"Should find at least 1 ClientHello, found {len(result.clienthello_packets)}"
            
            # Verify fake packet detection
            assert len(result.fake_packets) >= 1, \
                f"Should find at least 1 fake packet, found {len(result.fake_packets)}"
            
            # Verify no errors
            assert len(result.analysis_errors) == 0, \
                f"Should have no errors, got {result.analysis_errors}"
        
        finally:
            # Cleanup
            pcap_file.unlink()
