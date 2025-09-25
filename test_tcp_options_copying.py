#!/usr/bin/env python3
"""
Test script to verify TCP options copying functionality.
"""

import sys
import struct
import logging
from pathlib import Path

# Add the recon directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from core.bypass.packet.builder import PacketBuilder
from core.bypass.packet.types import TCPSegmentSpec

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

class MockPacket:
    """Mock packet class for testing"""
    def __init__(self, raw_bytes):
        self.raw = raw_bytes

def create_test_packet_with_options():
    """
    Create a test TCP packet with common TCP options:
    - MSS (Maximum Segment Size)
    - SACK Permitted
    - Timestamps
    - Window Scale
    """
    # IP Header (20 bytes)
    ip_header = bytearray([
        0x45,  # Version (4) + IHL (5)
        0x00,  # Type of Service
        0x00, 0x40,  # Total Length (will be updated)
        0x12, 0x34,  # Identification
        0x40, 0x00,  # Flags + Fragment Offset
        0x40,  # TTL
        0x06,  # Protocol (TCP)
        0x00, 0x00,  # Header Checksum (will be calculated)
        0xC0, 0xA8, 0x01, 0x01,  # Source IP (192.168.1.1)
        0xC0, 0xA8, 0x01, 0x02,  # Destination IP (192.168.1.2)
    ])
    
    # TCP Header (20 bytes base + options)
    tcp_header_base = bytearray([
        0x04, 0xD2,  # Source Port (1234)
        0x00, 0x50,  # Destination Port (80)
        0x12, 0x34, 0x56, 0x78,  # Sequence Number
        0x87, 0x65, 0x43, 0x21,  # Acknowledgment Number
        0x80,  # Data Offset (8 words = 32 bytes) + Reserved
        0x18,  # Flags (PSH + ACK)
        0xFF, 0xFF,  # Window Size
        0x00, 0x00,  # Checksum (will be calculated)
        0x00, 0x00,  # Urgent Pointer
    ])
    
    # TCP Options (12 bytes total, padded to 4-byte boundary)
    tcp_options = bytearray([
        # MSS Option (4 bytes)
        0x02, 0x04, 0x05, 0xB4,  # MSS = 1460
        # SACK Permitted (2 bytes)
        0x04, 0x02,
        # Timestamps (10 bytes)
        0x08, 0x0A, 0x12, 0x34, 0x56, 0x78, 0x87, 0x65, 0x43, 0x21,
        # NOP padding (2 bytes to align to 4-byte boundary)
        0x01, 0x01
    ])
    
    # Update TCP header data offset to account for options
    tcp_header_base[12] = 0x80  # 8 words (32 bytes total)
    
    # Combine headers
    packet = ip_header + tcp_header_base + tcp_options
    
    # Add some payload
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    packet.extend(payload)
    
    # Update IP total length
    total_length = len(packet)
    packet[2:4] = struct.pack("!H", total_length)
    
    return bytes(packet)

def test_tcp_options_extraction():
    """Test that TCP options are correctly extracted and preserved"""
    print("Testing TCP options copying...")
    
    # Create test packet with options
    test_packet_bytes = create_test_packet_with_options()
    test_packet = MockPacket(test_packet_bytes)
    
    # Create packet builder
    builder = PacketBuilder()
    
    # Create a simple segment spec
    spec = TCPSegmentSpec(
        payload=b"Modified payload",
        rel_seq=0,
        flags=0x18,  # PSH + ACK
        ttl=64
    )
    
    # Build new segment
    new_segment = builder.build_tcp_segment(test_packet, spec)
    
    if new_segment is None:
        print("❌ Failed to build TCP segment")
        return False
    
    # Analyze the new segment
    ip_hl = (new_segment[0] & 0x0F) * 4
    tcp_hl = ((new_segment[ip_hl + 12] >> 4) & 0x0F) * 4
    
    print(f"Original packet:")
    print(f"  IP header length: {(test_packet_bytes[0] & 0x0F) * 4} bytes")
    print(f"  TCP header length: {((test_packet_bytes[20 + 12] >> 4) & 0x0F) * 4} bytes")
    
    print(f"New segment:")
    print(f"  IP header length: {ip_hl} bytes")
    print(f"  TCP header length: {tcp_hl} bytes")
    
    # Check if TCP options were preserved
    if tcp_hl > 20:
        tcp_options = new_segment[ip_hl + 20:ip_hl + tcp_hl]
        print(f"  TCP options: {len(tcp_options)} bytes")
        print(f"  Options hex: {tcp_options.hex()}")
        
        # Check for specific options
        options_data = tcp_options
        i = 0
        found_options = []
        
        while i < len(options_data):
            if options_data[i] == 0x00:  # End of options
                break
            elif options_data[i] == 0x01:  # NOP
                found_options.append("NOP")
                i += 1
            elif options_data[i] == 0x02 and i + 1 < len(options_data) and options_data[i + 1] == 0x04:  # MSS
                mss = struct.unpack("!H", options_data[i + 2:i + 4])[0]
                found_options.append(f"MSS={mss}")
                i += 4
            elif options_data[i] == 0x04 and i + 1 < len(options_data) and options_data[i + 1] == 0x02:  # SACK Permitted
                found_options.append("SACK_PERMITTED")
                i += 2
            elif options_data[i] == 0x08 and i + 1 < len(options_data) and options_data[i + 1] == 0x0A:  # Timestamps
                found_options.append("TIMESTAMPS")
                i += 10
            else:
                # Unknown option, skip
                if i + 1 < len(options_data):
                    opt_len = options_data[i + 1]
                    if opt_len > 0:
                        i += opt_len
                    else:
                        i += 1
                else:
                    i += 1
        
        print(f"  Found options: {', '.join(found_options)}")
        
        if len(found_options) > 0:
            print("✅ TCP options successfully copied!")
            return True
        else:
            print("❌ No recognizable TCP options found in new segment")
            return False
    else:
        print("❌ No TCP options found in new segment")
        return False

def test_tcp_options_with_md5sig():
    """Test TCP options copying when MD5SIG option is also added"""
    print("\nTesting TCP options copying with MD5SIG addition...")
    
    # Create test packet with options
    test_packet_bytes = create_test_packet_with_options()
    test_packet = MockPacket(test_packet_bytes)
    
    # Create packet builder
    builder = PacketBuilder()
    
    # Create a segment spec with MD5SIG option
    spec = TCPSegmentSpec(
        payload=b"Modified payload with MD5SIG",
        rel_seq=0,
        flags=0x18,  # PSH + ACK
        ttl=64,
        add_md5sig_option=True
    )
    
    # Build new segment
    new_segment = builder.build_tcp_segment(test_packet, spec)
    
    if new_segment is None:
        print("❌ Failed to build TCP segment with MD5SIG")
        return False
    
    # Analyze the new segment
    ip_hl = (new_segment[0] & 0x0F) * 4
    tcp_hl = ((new_segment[ip_hl + 12] >> 4) & 0x0F) * 4
    
    print(f"New segment with MD5SIG:")
    print(f"  TCP header length: {tcp_hl} bytes")
    
    if tcp_hl > 20:
        tcp_options = new_segment[ip_hl + 20:ip_hl + tcp_hl]
        print(f"  TCP options: {len(tcp_options)} bytes")
        
        # Look for MD5SIG option (0x13, 0x12)
        found_md5sig = False
        for i in range(len(tcp_options) - 1):
            if tcp_options[i] == 0x13 and tcp_options[i + 1] == 0x12:
                found_md5sig = True
                break
        
        if found_md5sig:
            print("✅ MD5SIG option found in addition to original options!")
            return True
        else:
            print("❌ MD5SIG option not found")
            return False
    else:
        print("❌ No TCP options found in new segment")
        return False

if __name__ == "__main__":
    print("TCP Options Copying Test")
    print("=" * 40)
    
    success1 = test_tcp_options_extraction()
    success2 = test_tcp_options_with_md5sig()
    
    print("\n" + "=" * 40)
    if success1 and success2:
        print("✅ All tests passed!")
        sys.exit(0)
    else:
        print("❌ Some tests failed!")
        sys.exit(1)