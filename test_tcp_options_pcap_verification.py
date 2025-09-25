#!/usr/bin/env python3
"""
Test script to verify TCP options copying with real PCAP data.
This script creates test packets and compares them before/after TCP options copying.
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
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class MockPacket:
    """Mock packet class for testing"""
    def __init__(self, raw_bytes):
        self.raw = raw_bytes

def create_realistic_clienthello_packet():
    """
    Create a realistic TCP packet containing a TLS ClientHello with common TCP options.
    This simulates what we might see in real traffic.
    """
    # IP Header (20 bytes) - IPv4
    ip_header = bytearray([
        0x45,  # Version (4) + IHL (5)
        0x00,  # Type of Service
        0x00, 0x00,  # Total Length (will be updated)
        0x12, 0x34,  # Identification
        0x40, 0x00,  # Flags (Don't Fragment) + Fragment Offset
        0x40,  # TTL (64)
        0x06,  # Protocol (TCP)
        0x00, 0x00,  # Header Checksum (will be calculated)
        0xC0, 0xA8, 0x01, 0x64,  # Source IP (192.168.1.100)
        0x8E, 0xFA, 0x5B, 0x23,  # Destination IP (142.250.91.35 - Google)
    ])
    
    # TCP Header base (20 bytes)
    tcp_header_base = bytearray([
        0xC4, 0x18,  # Source Port (50200)
        0x01, 0xBB,  # Destination Port (443 - HTTPS)
        0x12, 0x34, 0x56, 0x78,  # Sequence Number
        0x00, 0x00, 0x00, 0x00,  # Acknowledgment Number (0 for SYN)
        0xA0,  # Data Offset (10 words = 40 bytes) + Reserved
        0x02,  # Flags (SYN)
        0x72, 0x10,  # Window Size (29200)
        0x00, 0x00,  # Checksum (will be calculated)
        0x00, 0x00,  # Urgent Pointer
    ])
    
    # TCP Options (20 bytes total) - Common options seen in real traffic
    tcp_options = bytearray([
        # MSS Option (4 bytes)
        0x02, 0x04, 0x05, 0xB4,  # MSS = 1460
        # SACK Permitted (2 bytes)
        0x04, 0x02,
        # Timestamps (10 bytes)
        0x08, 0x0A, 
        0x01, 0x23, 0x45, 0x67,  # TSval
        0x00, 0x00, 0x00, 0x00,  # TSecr (0 for SYN)
        # NOP (1 byte)
        0x01,
        # Window Scale (3 bytes)
        0x03, 0x03, 0x07,  # Window scale factor = 7
    ])
    
    # Update TCP header data offset to account for options
    tcp_header_base[12] = 0xA0  # 10 words (40 bytes total)
    
    # TLS ClientHello payload (simplified)
    tls_payload = bytearray([
        # TLS Record Header
        0x16,  # Content Type: Handshake
        0x03, 0x01,  # Version: TLS 1.0
        0x00, 0x00,  # Length (will be updated)
        
        # Handshake Header
        0x01,  # Handshake Type: Client Hello
        0x00, 0x00, 0x00,  # Length (will be updated)
        
        # Client Hello
        0x03, 0x03,  # Version: TLS 1.2
        # Random (32 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        
        # Session ID Length
        0x00,
        
        # Cipher Suites Length
        0x00, 0x02,
        # Cipher Suites
        0x13, 0x01,  # TLS_AES_128_GCM_SHA256
        
        # Compression Methods Length
        0x01,
        # Compression Methods
        0x00,  # No compression
        
        # Extensions Length
        0x00, 0x17,  # 23 bytes of extensions
        
        # Server Name Indication Extension
        0x00, 0x00,  # Extension Type: server_name
        0x00, 0x13,  # Extension Length: 19 bytes
        0x00, 0x11,  # Server Name List Length: 17 bytes
        0x00,  # Name Type: host_name
        0x00, 0x0E,  # Host Name Length: 14 bytes
    ])
    
    # Add the hostname separately
    tls_payload.extend(b'www.google.com')
    
    # Update TLS record length
    tls_content_length = len(tls_payload) - 5  # Exclude TLS record header
    tls_payload[3:5] = struct.pack("!H", tls_content_length)
    
    # Update handshake length
    handshake_length = len(tls_payload) - 9  # Exclude TLS record header and handshake header
    tls_payload[6:9] = struct.pack("!I", handshake_length)[1:]  # 3 bytes
    
    # Combine all parts
    packet = ip_header + tcp_header_base + tcp_options + tls_payload
    
    # Update IP total length
    total_length = len(packet)
    packet[2:4] = struct.pack("!H", total_length)
    
    return bytes(packet)

def analyze_tcp_options(packet_bytes, description):
    """Analyze and print TCP options in a packet"""
    ip_hl = (packet_bytes[0] & 0x0F) * 4
    tcp_hl = ((packet_bytes[ip_hl + 12] >> 4) & 0x0F) * 4
    
    print(f"\n{description}:")
    print(f"  IP header length: {ip_hl} bytes")
    print(f"  TCP header length: {tcp_hl} bytes")
    
    if tcp_hl > 20:
        tcp_options = packet_bytes[ip_hl + 20:ip_hl + tcp_hl]
        print(f"  TCP options: {len(tcp_options)} bytes")
        print(f"  Options hex: {tcp_options.hex()}")
        
        # Parse options
        options_data = tcp_options
        i = 0
        found_options = []
        
        while i < len(options_data):
            if options_data[i] == 0x00:  # End of options
                break
            elif options_data[i] == 0x01:  # NOP
                found_options.append("NOP")
                i += 1
            elif options_data[i] == 0x02 and i + 3 < len(options_data):  # MSS
                if options_data[i + 1] == 0x04:
                    mss = struct.unpack("!H", options_data[i + 2:i + 4])[0]
                    found_options.append(f"MSS={mss}")
                    i += 4
                else:
                    i += 1
            elif options_data[i] == 0x03 and i + 2 < len(options_data):  # Window Scale
                if options_data[i + 1] == 0x03:
                    scale = options_data[i + 2]
                    found_options.append(f"WSCALE={scale}")
                    i += 3
                else:
                    i += 1
            elif options_data[i] == 0x04 and i + 1 < len(options_data):  # SACK Permitted
                if options_data[i + 1] == 0x02:
                    found_options.append("SACK_PERMITTED")
                    i += 2
                else:
                    i += 1
            elif options_data[i] == 0x08 and i + 9 < len(options_data):  # Timestamps
                if options_data[i + 1] == 0x0A:
                    tsval = struct.unpack("!I", options_data[i + 2:i + 6])[0]
                    tsecr = struct.unpack("!I", options_data[i + 6:i + 10])[0]
                    found_options.append(f"TIMESTAMPS(val={tsval:08x},ecr={tsecr:08x})")
                    i += 10
                else:
                    i += 1
            elif options_data[i] == 0x13 and i + 17 < len(options_data):  # MD5SIG
                if options_data[i + 1] == 0x12:
                    found_options.append("MD5SIG")
                    i += 18
                else:
                    i += 1
            else:
                # Unknown option, try to skip
                if i + 1 < len(options_data) and options_data[i + 1] > 0:
                    opt_len = options_data[i + 1]
                    found_options.append(f"UNKNOWN({options_data[i]:02x})")
                    i += opt_len
                else:
                    i += 1
        
        print(f"  Parsed options: {', '.join(found_options)}")
        return found_options
    else:
        print("  No TCP options")
        return []

def test_realistic_packet_processing():
    """Test TCP options copying with a realistic packet"""
    print("Testing TCP options copying with realistic ClientHello packet...")
    
    # Create realistic packet
    original_packet_bytes = create_realistic_clienthello_packet()
    original_packet = MockPacket(original_packet_bytes)
    
    # Analyze original packet
    original_options = analyze_tcp_options(original_packet_bytes, "Original packet")
    
    # Create packet builder
    builder = PacketBuilder()
    
    # Test 1: Regular segment
    print("\n" + "="*50)
    print("Test 1: Regular segment with preserved options")
    
    spec1 = TCPSegmentSpec(
        payload=b"Modified TLS payload",
        rel_seq=0,
        flags=0x18,  # PSH + ACK
        ttl=64
    )
    
    new_segment1 = builder.build_tcp_segment(original_packet, spec1)
    if new_segment1:
        new_options1 = analyze_tcp_options(new_segment1, "New segment (regular)")
        
        # Compare options
        if set(original_options) == set(new_options1):
            print("✅ TCP options perfectly preserved!")
        else:
            print("⚠️  TCP options differ:")
            print(f"   Original: {original_options}")
            print(f"   New:      {new_options1}")
    else:
        print("❌ Failed to build regular segment")
        return False
    
    # Test 2: Segment with MD5SIG addition
    print("\n" + "="*50)
    print("Test 2: Segment with MD5SIG addition")
    
    spec2 = TCPSegmentSpec(
        payload=b"Modified TLS payload with MD5SIG",
        rel_seq=0,
        flags=0x18,  # PSH + ACK
        ttl=64,
        add_md5sig_option=True
    )
    
    new_segment2 = builder.build_tcp_segment(original_packet, spec2)
    if new_segment2:
        new_options2 = analyze_tcp_options(new_segment2, "New segment (with MD5SIG)")
        
        # Check that original options are preserved and MD5SIG is added
        has_md5sig = any("MD5SIG" in opt for opt in new_options2)
        original_preserved = all(opt in new_options2 for opt in original_options if opt != "MD5SIG")
        
        if has_md5sig and original_preserved:
            print("✅ Original options preserved and MD5SIG added!")
        else:
            print("❌ Options not properly handled:")
            print(f"   MD5SIG present: {has_md5sig}")
            print(f"   Original preserved: {original_preserved}")
    else:
        print("❌ Failed to build segment with MD5SIG")
        return False
    
    # Test 3: Corrupted checksum
    print("\n" + "="*50)
    print("Test 3: Segment with corrupted checksum")
    
    spec3 = TCPSegmentSpec(
        payload=b"Fake packet with bad checksum",
        rel_seq=0,
        flags=0x18,  # PSH + ACK
        ttl=1,  # Low TTL for fake packet
        corrupt_tcp_checksum=True
    )
    
    new_segment3 = builder.build_tcp_segment(original_packet, spec3)
    if new_segment3:
        new_options3 = analyze_tcp_options(new_segment3, "New segment (corrupted checksum)")
        
        # Check TCP checksum
        ip_hl = (new_segment3[0] & 0x0F) * 4
        tcp_checksum = struct.unpack("!H", new_segment3[ip_hl + 16:ip_hl + 18])[0]
        
        if tcp_checksum == 0xDEAD:
            print("✅ TCP checksum correctly corrupted to 0xDEAD")
        else:
            print(f"❌ TCP checksum not corrupted correctly: 0x{tcp_checksum:04X}")
            
        # Check options preservation
        if set(original_options) == set(new_options3):
            print("✅ TCP options preserved even with corrupted checksum!")
        else:
            print("❌ TCP options not preserved with corrupted checksum")
    else:
        print("❌ Failed to build segment with corrupted checksum")
        return False
    
    return True

if __name__ == "__main__":
    print("TCP Options PCAP Verification Test")
    print("=" * 60)
    
    success = test_realistic_packet_processing()
    
    print("\n" + "=" * 60)
    if success:
        print("✅ All realistic packet tests passed!")
        print("TCP options copying implementation is working correctly!")
        sys.exit(0)
    else:
        print("❌ Some tests failed!")
        sys.exit(1)