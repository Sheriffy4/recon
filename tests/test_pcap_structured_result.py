"""
Unit tests for PCAPAnalyzer structured result format.

Task 3.4: Add structured result format
Validates: Requirements 4.3
"""

import pytest
import tempfile
import struct
import os

from core.pcap.analyzer import PCAPAnalyzer
from core.test_result_models import PCAPAnalysisResult


def create_test_pcap() -> str:
    """Create a minimal test PCAP file."""
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
            
            # Write a single packet
            ip_header = struct.pack(
                '!BBHHHBBH4s4s',
                0x45,  # Version (4) + IHL (5)
                0,     # TOS
                40,    # Total length
                0,     # ID
                0,     # Flags + Fragment offset
                64,    # TTL
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
            
            # Write packet header
            f.write(struct.pack(
                '<IIII',
                1000000,        # Timestamp seconds
                0,              # Timestamp microseconds
                len(packet_data),  # Captured length
                len(packet_data),  # Original length
            ))
            
            # Write packet data
            f.write(packet_data)
    finally:
        os.close(fd)
    
    return pcap_path


def test_analyze_pcap_returns_structured_result():
    """
    Test that analyze_pcap returns PCAPAnalysisResult dataclass.
    
    Task 3.4: Add structured result format
    Validates: Requirements 4.3
    """
    # Arrange
    pcap_path = create_test_pcap()
    
    try:
        analyzer = PCAPAnalyzer()
        
        # Act
        result = analyzer.analyze_pcap(pcap_path)
        
        # Assert: Result should be PCAPAnalysisResult instance
        assert isinstance(result, PCAPAnalysisResult), \
            f"Expected PCAPAnalysisResult, got {type(result)}"
        
        # Assert: All required fields should be present
        assert hasattr(result, 'pcap_file'), "Missing pcap_file field"
        assert hasattr(result, 'packet_count'), "Missing packet_count field"
        assert hasattr(result, 'detected_attacks'), "Missing detected_attacks field"
        assert hasattr(result, 'parameters'), "Missing parameters field"
        assert hasattr(result, 'split_positions'), "Missing split_positions field"
        assert hasattr(result, 'fake_packets_detected'), "Missing fake_packets_detected field"
        assert hasattr(result, 'sni_values'), "Missing sni_values field"
        assert hasattr(result, 'analysis_time'), "Missing analysis_time field"
        assert hasattr(result, 'analyzer_version'), "Missing analyzer_version field"
        assert hasattr(result, 'errors'), "Missing errors field"
        assert hasattr(result, 'warnings'), "Missing warnings field"
        
        # Assert: Fields should have correct types
        assert isinstance(result.pcap_file, str), "pcap_file should be str"
        assert isinstance(result.packet_count, int), "packet_count should be int"
        assert isinstance(result.detected_attacks, list), "detected_attacks should be list"
        assert isinstance(result.parameters, dict), "parameters should be dict"
        assert isinstance(result.split_positions, list), "split_positions should be list"
        assert isinstance(result.fake_packets_detected, int), "fake_packets_detected should be int"
        assert isinstance(result.sni_values, list), "sni_values should be list"
        assert isinstance(result.analysis_time, float), "analysis_time should be float"
        assert isinstance(result.analyzer_version, str), "analyzer_version should be str"
        assert isinstance(result.errors, list), "errors should be list"
        assert isinstance(result.warnings, list), "warnings should be list"
        
        # Assert: Basic sanity checks
        assert result.pcap_file == pcap_path, "pcap_file should match input"
        assert result.packet_count >= 0, "packet_count should be non-negative"
        assert result.fake_packets_detected >= 0, "fake_packets_detected should be non-negative"
        assert result.analysis_time >= 0, "analysis_time should be non-negative"
        
    finally:
        # Cleanup
        if os.path.exists(pcap_path):
            os.unlink(pcap_path)


def test_structured_result_includes_all_analysis_data():
    """
    Test that structured result includes all analysis data.
    
    Task 3.4: Verify all required fields are populated
    Validates: Requirements 4.3
    """
    # Arrange: Create PCAP with fake packet (low TTL)
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
            
            # Write fake packet with low TTL
            ip_header = struct.pack(
                '!BBHHHBBH4s4s',
                0x45,  # Version (4) + IHL (5)
                0,     # TOS
                40,    # Total length
                0,     # ID
                0,     # Flags + Fragment offset
                2,     # TTL (low - fake packet)
                6,     # Protocol (TCP)
                0,     # Checksum (invalid)
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
                0,      # Checksum (invalid)
                0,      # Urgent pointer
            )
            
            packet_data = ip_header + tcp_header + b'FAKE'
            
            # Write packet header
            f.write(struct.pack(
                '<IIII',
                1000000,        # Timestamp seconds
                0,              # Timestamp microseconds
                len(packet_data),  # Captured length
                len(packet_data),  # Original length
            ))
            
            # Write packet data
            f.write(packet_data)
        
        os.close(fd)
        
        analyzer = PCAPAnalyzer()
        
        # Act
        result = analyzer.analyze_pcap(pcap_path)
        
        # Assert: Should detect fake packet
        assert result.fake_packets_detected > 0, \
            "Should detect fake packet with low TTL"
        
        # Assert: Should detect fake attack
        assert 'fake' in result.detected_attacks, \
            f"Should detect 'fake' attack, got {result.detected_attacks}"
        
        # Assert: Should extract TTL parameter
        assert 'fake_ttl' in result.parameters or 'ttl' in result.parameters, \
            "Should extract TTL parameter"
        
        # Assert: Should have packet count
        assert result.packet_count == 1, \
            f"Expected 1 packet, got {result.packet_count}"
        
    finally:
        # Cleanup
        if os.path.exists(pcap_path):
            os.unlink(pcap_path)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
