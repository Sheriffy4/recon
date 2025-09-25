#!/usr/bin/env python3
"""
Direct test to verify checksum corruption is working correctly.
This bypasses WinDivert to test packet construction in isolation.
"""

import sys
import os
import struct
import logging

# Add recon to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.bypass.packet.builder import PacketBuilder
from core.bypass.packet.types import TCPSegmentSpec

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
)

def create_mock_packet():
    """Create a mock packet for testing"""
    class MockPacket:
        def __init__(self):
            # Create a realistic TCP packet structure
            # IP header (20 bytes) + TCP header (20 bytes) + payload
            ip_header = bytearray([
                0x45, 0x00, 0x00, 0x3c,  # Version, IHL, ToS, Total Length
                0x12, 0x34, 0x40, 0x00,  # ID, Flags, Fragment Offset  
                0x40, 0x06, 0x00, 0x00,  # TTL, Protocol, Checksum
                0x7f, 0x00, 0x00, 0x01,  # Source IP
                0x7f, 0x00, 0x00, 0x01   # Dest IP
            ])
            
            tcp_header = bytearray([
                0x00, 0x50,              # Source Port (80)
                0x01, 0xbb,              # Dest Port (443)
                0x00, 0x00, 0x00, 0x01,  # Sequence Number
                0x00, 0x00, 0x00, 0x02,  # Acknowledgment Number
                0x50, 0x18,              # Data Offset, Flags (PSH|ACK)
                0x20, 0x00,              # Window Size
                0x00, 0x00,              # Checksum (will be calculated)
                0x00, 0x00               # Urgent Pointer
            ])
            
            payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            
            self.raw = bytes(ip_header + tcp_header + payload)
            
    return MockPacket()

def test_checksum_corruption():
    """Test that checksum corruption works correctly"""
    print("🔧 Testing checksum corruption...")
    
    builder = PacketBuilder()
    mock_packet = create_mock_packet()
    
    # Test 1: Normal checksum
    print("\n--- Test 1: Normal Checksum ---")
    spec_normal = TCPSegmentSpec(
        payload=b"Hello World",
        rel_seq=0,
        flags=0x18,
        ttl=64,
        corrupt_tcp_checksum=False
    )
    
    normal_packet = builder.build_tcp_segment(mock_packet, spec_normal)
    if normal_packet:
        # Extract checksum
        ip_len = (normal_packet[0] & 0x0F) * 4
        tcp_checksum_offset = ip_len + 16
        checksum = struct.unpack("!H", normal_packet[tcp_checksum_offset:tcp_checksum_offset+2])[0]
        print(f"Normal packet checksum: 0x{checksum:04X}")
    else:
        print("❌ Failed to build normal packet")
        return False
    
    # Test 2: Corrupted checksum
    print("\n--- Test 2: Corrupted Checksum ---")
    spec_corrupt = TCPSegmentSpec(
        payload=b"Hello World",
        rel_seq=0,
        flags=0x18,
        ttl=64,
        corrupt_tcp_checksum=True
    )
    
    corrupt_packet = builder.build_tcp_segment(mock_packet, spec_corrupt)
    if corrupt_packet:
        # Extract checksum
        ip_len = (corrupt_packet[0] & 0x0F) * 4
        tcp_checksum_offset = ip_len + 16
        checksum = struct.unpack("!H", corrupt_packet[tcp_checksum_offset:tcp_checksum_offset+2])[0]
        print(f"Corrupt packet checksum: 0x{checksum:04X}")
        
        if checksum == 0xDEAD:
            print("✅ Checksum corruption working correctly!")
            return True
        else:
            print(f"❌ Expected 0xDEAD, got 0x{checksum:04X}")
            return False
    else:
        print("❌ Failed to build corrupt packet")
        return False

def test_md5sig_checksum():
    """Test MD5SIG checksum corruption"""
    print("\n🔧 Testing MD5SIG checksum corruption...")
    
    builder = PacketBuilder()
    mock_packet = create_mock_packet()
    
    spec_md5sig = TCPSegmentSpec(
        payload=b"Hello World",
        rel_seq=0,
        flags=0x18,
        ttl=64,
        corrupt_tcp_checksum=True,
        add_md5sig_option=True
    )
    
    md5sig_packet = builder.build_tcp_segment(mock_packet, spec_md5sig)
    if md5sig_packet:
        # Extract checksum
        ip_len = (md5sig_packet[0] & 0x0F) * 4
        tcp_checksum_offset = ip_len + 16
        checksum = struct.unpack("!H", md5sig_packet[tcp_checksum_offset:tcp_checksum_offset+2])[0]
        print(f"MD5SIG packet checksum: 0x{checksum:04X}")
        
        if checksum == 0xBEEF:
            print("✅ MD5SIG checksum corruption working correctly!")
            return True
        else:
            print(f"❌ Expected 0xBEEF, got 0x{checksum:04X}")
            return False
    else:
        print("❌ Failed to build MD5SIG packet")
        return False

def test_packet_structure():
    """Test overall packet structure"""
    print("\n🔧 Testing packet structure...")
    
    builder = PacketBuilder()
    mock_packet = create_mock_packet()
    
    spec = TCPSegmentSpec(
        payload=b"Test payload",
        rel_seq=100,
        flags=0x18,
        ttl=64,
        corrupt_tcp_checksum=True
    )
    
    packet = builder.build_tcp_segment(mock_packet, spec)
    if not packet:
        print("❌ Failed to build packet")
        return False
    
    # Verify packet structure
    print(f"Packet length: {len(packet)} bytes")
    
    # Check IP header
    ip_version = (packet[0] >> 4) & 0xF
    ip_len = (packet[0] & 0x0F) * 4
    ttl = packet[8]
    
    print(f"IP version: {ip_version}")
    print(f"IP header length: {ip_len}")
    print(f"TTL: {ttl}")
    
    # Check TCP header
    tcp_start = ip_len
    src_port = struct.unpack("!H", packet[tcp_start:tcp_start+2])[0]
    dst_port = struct.unpack("!H", packet[tcp_start+2:tcp_start+4])[0]
    seq_num = struct.unpack("!I", packet[tcp_start+4:tcp_start+8])[0]
    flags = packet[tcp_start+13]
    checksum = struct.unpack("!H", packet[tcp_start+16:tcp_start+18])[0]
    
    print(f"Source port: {src_port}")
    print(f"Dest port: {dst_port}")
    print(f"Sequence number: {seq_num}")
    print(f"Flags: 0x{flags:02X}")
    print(f"Checksum: 0x{checksum:04X}")
    
    # Verify expected values
    if ttl == 64 and checksum == 0xDEAD and flags == 0x18:
        print("✅ Packet structure correct!")
        return True
    else:
        print("❌ Packet structure incorrect")
        return False

def main():
    """Main test function"""
    print("🚀 Starting direct checksum verification tests...")
    print("=" * 60)
    
    tests = [
        ("Checksum Corruption", test_checksum_corruption),
        ("MD5SIG Checksum", test_md5sig_checksum),
        ("Packet Structure", test_packet_structure)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*60}")
        print(f"Running: {test_name}")
        print(f"{'='*60}")
        
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
    
    print(f"\n{'='*60}")
    print("FINAL RESULTS")
    print(f"{'='*60}")
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All checksum verification tests passed!")
        print("The packet construction is working correctly.")
        print("The issue may be with WinDivert 'fixing' checksums during transmission.")
        return 0
    else:
        print("⚠️ Some tests failed - packet construction needs fixes.")
        return 1

if __name__ == "__main__":
    sys.exit(main())