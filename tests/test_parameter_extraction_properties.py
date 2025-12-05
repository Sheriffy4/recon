"""
Property-based tests for parameter extraction from PCAP analysis.

Feature: strategy-testing-production-parity, Property 5: Parameters are extracted and logged correctly
Validates: Requirements 3.1, 3.2, 3.3, 3.5
"""

import pytest
from hypothesis import given, strategies as st, settings, assume
from typing import Dict, Any, List
from pathlib import Path
import tempfile
import struct

from core.pcap.analyzer import PCAPAnalyzer


@st.composite
def pcap_with_parameters(draw):
    """
    Generate a synthetic PCAP with known parameters.
    
    Returns tuple of (packets, expected_parameters)
    """
    # Generate random parameters
    ttl = draw(st.integers(min_value=1, max_value=255))
    fake_ttl = draw(st.integers(min_value=1, max_value=5))
    has_bad_checksum = draw(st.booleans())
    
    expected_params = {}
    packets = []
    
    # Create base IP header with specified TTL
    base_ip_header = struct.pack(
        '!BBHHHBBH4s4s',
        0x45,  # Version (4) + IHL (5)
        0,     # TOS
        40,    # Total length
        0,     # ID
        0,     # Flags + Fragment offset
        ttl,   # TTL (parameter to extract)
        6,     # Protocol (TCP)
        0,     # Checksum (will be invalid if has_bad_checksum)
        struct.pack('!I', 0xC0A80101),  # Source IP
        struct.pack('!I', 0xC0A80102),  # Dest IP
    )
    
    base_tcp_header = struct.pack(
        '!HHLLBBHHH',
        12345,  # Source port
        443,    # Dest port
        1000,   # Sequence number
        0,      # Ack number
        0x50,   # Data offset (5) + reserved
        0x02,   # Flags (SYN)
        8192,   # Window
        0,      # Checksum (invalid)
        0,      # Urgent pointer
    )
    
    # Add normal packet with specified TTL
    packet_data = base_ip_header + base_tcp_header + b'DATA'
    packets.append(packet_data)
    expected_params['ttl'] = ttl
    
    # Add fake packet with low TTL if requested
    if fake_ttl < ttl:
        fake_ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            0x45,  # Version (4) + IHL (5)
            0,     # TOS
            40,    # Total length
            0,     # ID
            0,     # Flags + Fragment offset
            fake_ttl,  # Low TTL (fake packet indicator)
            6,     # Protocol (TCP)
            0,     # Checksum
            struct.pack('!I', 0xC0A80101),  # Source IP
            struct.pack('!I', 0xC0A80102),  # Dest IP
        )
        fake_packet = fake_ip_header + base_tcp_header + b'FAKE'
        packets.append(fake_packet)
        expected_params['fake_ttl'] = fake_ttl
    
    # Add fooling modes if bad checksum
    if has_bad_checksum:
        expected_params['fooling'] = ['badsum']
        expected_params['fooling_modes'] = ['badsum']
    
    # Add packet count
    expected_params['packet_count'] = len(packets)
    expected_params['total_bytes'] = sum(len(p) for p in packets)
    
    return packets, expected_params


def create_pcap_file(packets: List[bytes]) -> str:
    """Create a temporary PCAP file with the given packets."""
    fd, pcap_path = tempfile.mkstemp(suffix='.pcap')
    
    try:
        with open(pcap_path, 'wb') as f:
            # Write PCAP global header
            f.write(struct.pack(
                '<IHHIIII',
                0xa1b2c3d4,  # Magic number
                2,           # Major version
                4,           # Minor version
                0,           # Timezone offset
                0,           # Timestamp accuracy
                65535,       # Snaplen
                1,           # Network (Ethernet)
            ))
            
            # Write packets
            for i, packet in enumerate(packets):
                # Write packet header
                timestamp = 1000000 + i
                f.write(struct.pack(
                    '<IIII',
                    timestamp,      # Timestamp seconds
                    0,              # Timestamp microseconds
                    len(packet),    # Captured length
                    len(packet),    # Original length
                ))
                
                # Write packet data
                f.write(packet)
    finally:
        import os
        os.close(fd)
    
    return pcap_path


@given(pcap_data=st.data())
@settings(max_examples=100, deadline=None)
def test_parameters_are_extracted_and_logged_correctly(pcap_data):
    """
    Property 5: Parameters are extracted and logged correctly
    
    For any strategy with extractable parameters, all non-null parameters
    must be extracted from PCAP, logged with actual values, and included
    in saved strategy.
    
    Validates: Requirements 3.1, 3.2, 3.3, 3.5
    """
    # Arrange: Generate PCAP with known parameters
    packets, expected_params = pcap_data.draw(pcap_with_parameters())
    pcap_path = create_pcap_file(packets)
    
    try:
        # Act: Analyze PCAP
        analyzer = PCAPAnalyzer()
        result = analyzer.analyze_strategy_application(pcap_path)
        
        # Assert: All expected parameters should be extracted
        extracted_params = result.parameters
        
        # Check TTL extraction (Task 3.3)
        if 'ttl' in expected_params:
            assert 'ttl' in extracted_params, \
                f"TTL parameter not extracted. Expected: {expected_params['ttl']}"
            assert extracted_params['ttl'] == expected_params['ttl'], \
                f"TTL mismatch: expected {expected_params['ttl']}, got {extracted_params['ttl']}"
        
        # Check fake_ttl extraction if present
        if 'fake_ttl' in expected_params:
            assert 'fake_ttl' in extracted_params, \
                f"fake_ttl parameter not extracted. Expected: {expected_params['fake_ttl']}"
            assert extracted_params['fake_ttl'] == expected_params['fake_ttl'], \
                f"fake_ttl mismatch: expected {expected_params['fake_ttl']}, got {extracted_params['fake_ttl']}"
        
        # Check fooling_modes extraction (Task 3.3)
        if 'fooling' in expected_params:
            assert 'fooling' in extracted_params or 'fooling_modes' in extracted_params, \
                "fooling/fooling_modes parameter not extracted"
            
            extracted_fooling = extracted_params.get('fooling', extracted_params.get('fooling_modes', []))
            expected_fooling = expected_params['fooling']
            
            # Check that expected fooling methods are present
            for method in expected_fooling:
                assert method in extracted_fooling, \
                    f"Expected fooling method '{method}' not found in {extracted_fooling}"
        
        # Check packet_count extraction
        if 'packet_count' in expected_params:
            assert 'packet_count' in extracted_params, \
                "packet_count parameter not extracted"
            assert extracted_params['packet_count'] == expected_params['packet_count'], \
                f"packet_count mismatch: expected {expected_params['packet_count']}, got {extracted_params['packet_count']}"
        
        # Check total_bytes extraction
        if 'total_bytes' in expected_params:
            assert 'total_bytes' in extracted_params, \
                "total_bytes parameter not extracted"
            assert extracted_params['total_bytes'] == expected_params['total_bytes'], \
                f"total_bytes mismatch: expected {expected_params['total_bytes']}, got {extracted_params['total_bytes']}"
        
        # Property: All non-null parameters must be extracted
        # Count how many expected parameters were extracted
        extracted_count = sum(1 for key in expected_params.keys() if key in extracted_params)
        assert extracted_count > 0, \
            f"No parameters were extracted. Expected: {expected_params.keys()}"
        
        # Property: Parameters should have actual values, not None
        for key, value in extracted_params.items():
            if key in expected_params:
                assert value is not None, \
                    f"Parameter '{key}' has None value, expected {expected_params[key]}"
        
    finally:
        # Cleanup
        import os
        if os.path.exists(pcap_path):
            os.unlink(pcap_path)


@given(
    ttl_values=st.lists(st.integers(min_value=1, max_value=255), min_size=1, max_size=10)
)
@settings(max_examples=50, deadline=None)
def test_ttl_extraction_from_multiple_packets(ttl_values: List[int]):
    """
    Property: TTL is correctly extracted from multiple packets.
    
    When multiple packets have different TTL values, the most common
    TTL should be extracted as the primary TTL, and low TTLs should
    be identified as fake_ttl.
    
    Validates: Requirements 3.1, 3.2
    """
    # Arrange: Create packets with specified TTL values
    packets = []
    
    for ttl in ttl_values:
        ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            0x45,  # Version (4) + IHL (5)
            0,     # TOS
            40,    # Total length
            0,     # ID
            0,     # Flags + Fragment offset
            ttl,   # TTL
            6,     # Protocol (TCP)
            0,     # Checksum
            struct.pack('!I', 0xC0A80101),  # Source IP
            struct.pack('!I', 0xC0A80102),  # Dest IP
        )
        
        tcp_header = struct.pack(
            '!HHLLBBHHH',
            12345,  # Source port
            443,    # Dest port
            1000,   # Sequence number
            0,      # Ack number
            0x50,   # Data offset
            0x02,   # Flags (SYN)
            8192,   # Window
            0,      # Checksum
            0,      # Urgent pointer
        )
        
        packet_data = ip_header + tcp_header + b'DATA'
        packets.append(packet_data)
    
    pcap_path = create_pcap_file(packets)
    
    try:
        # Act: Analyze PCAP
        analyzer = PCAPAnalyzer()
        result = analyzer.analyze_strategy_application(pcap_path)
        
        # Assert: TTL should be extracted
        assert 'ttl' in result.parameters, \
            "TTL parameter not extracted from packets"
        
        extracted_ttl = result.parameters['ttl']
        
        # The extracted TTL should be one of the input TTL values
        assert extracted_ttl in ttl_values, \
            f"Extracted TTL {extracted_ttl} not in input TTL values {ttl_values}"
        
        # If there are low TTL values (<=5), fake_ttl should be extracted
        low_ttls = [ttl for ttl in ttl_values if ttl <= 5]
        if low_ttls:
            assert 'fake_ttl' in result.parameters, \
                f"fake_ttl not extracted despite low TTL values: {low_ttls}"
            assert result.parameters['fake_ttl'] in low_ttls, \
                f"Extracted fake_ttl {result.parameters['fake_ttl']} not in low TTL values {low_ttls}"
        
    finally:
        # Cleanup
        import os
        if os.path.exists(pcap_path):
            os.unlink(pcap_path)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
