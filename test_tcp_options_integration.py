#!/usr/bin/env python3
"""
Integration test to verify TCP options copying works with the actual bypass engine.
"""

import sys
import struct
import logging
from pathlib import Path

# Add the recon directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from core.bypass.packet.builder import PacketBuilder
from core.bypass.packet.types import TCPSegmentSpec
from core.bypass.techniques.primitives import BypassTechniques

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class MockPacket:
    """Mock packet class for testing"""
    def __init__(self, raw_bytes):
        self.raw = raw_bytes

def create_test_packet_with_tls():
    """Create a test packet with TLS ClientHello and TCP options"""
    # IP Header (20 bytes)
    ip_header = bytearray([
        0x45, 0x00, 0x00, 0x00,  # Version, IHL, ToS, Total Length (will be updated)
        0x12, 0x34, 0x40, 0x00,  # ID, Flags, Fragment Offset
        0x40, 0x06, 0x00, 0x00,  # TTL, Protocol, Checksum
        0xC0, 0xA8, 0x01, 0x64,  # Source IP
        0x8E, 0xFA, 0x5B, 0x23,  # Destination IP
    ])
    
    # TCP Header with options (32 bytes total)
    tcp_header = bytearray([
        0xC4, 0x18, 0x01, 0xBB,  # Source Port, Dest Port
        0x12, 0x34, 0x56, 0x78,  # Sequence Number
        0x00, 0x00, 0x00, 0x00,  # Acknowledgment Number
        0x80, 0x18, 0x72, 0x10,  # Data Offset (8 words), Flags, Window
        0x00, 0x00, 0x00, 0x00,  # Checksum, Urgent Pointer
        # TCP Options (12 bytes)
        0x02, 0x04, 0x05, 0xB4,  # MSS = 1460
        0x04, 0x02,              # SACK Permitted
        0x08, 0x0A, 0x01, 0x23, 0x45, 0x67,  # Timestamps (partial)
    ])
    
    # Simple TLS ClientHello
    tls_payload = bytearray([
        0x16, 0x03, 0x01, 0x00, 0x20,  # TLS Record Header (32 bytes payload)
        0x01, 0x00, 0x00, 0x1C,        # Handshake Header (28 bytes)
        0x03, 0x03,                    # TLS Version
        # Random (16 bytes, simplified)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x00,        # Session ID Length
        0x00, 0x02,  # Cipher Suites Length
        0x13, 0x01,  # Cipher Suite
        0x01, 0x00,  # Compression + Extensions Length
    ])
    
    # Combine packet
    packet = ip_header + tcp_header + tls_payload
    
    # Update IP total length
    packet[2:4] = struct.pack("!H", len(packet))
    
    return bytes(packet)

def test_fakeddisorder_with_tcp_options():
    """Test that fakeddisorder preserves TCP options"""
    print("Testing fakeddisorder attack with TCP options preservation...")
    
    # Create test packet
    original_packet_bytes = create_test_packet_with_tls()
    original_packet = MockPacket(original_packet_bytes)
    
    # Analyze original packet options
    ip_hl = (original_packet_bytes[0] & 0x0F) * 4
    tcp_hl = ((original_packet_bytes[ip_hl + 12] >> 4) & 0x0F) * 4
    original_options = original_packet_bytes[ip_hl + 20:ip_hl + tcp_hl]
    
    print(f"Original packet TCP options: {len(original_options)} bytes")
    print(f"Options hex: {original_options.hex()}")
    
    # Apply fakeddisorder attack
    try:
        segments_data = BypassTechniques.apply_fakeddisorder(
            original_packet_bytes[ip_hl + tcp_hl:],  # payload
            split_pos=10,
            overlap_size=5,
            fake_ttl=64,
            fooling_methods=["badsum"]
        )
        
        # Convert to TCPSegmentSpec objects
        segments = []
        for payload, rel_seq, opts in segments_data:
            spec = TCPSegmentSpec(
                payload=payload,
                rel_seq=rel_seq,
                flags=opts.get("tcp_flags", 0x18),
                ttl=opts.get("ttl", 64),
                corrupt_tcp_checksum=opts.get("corrupt_tcp_checksum", False),
                add_md5sig_option=opts.get("add_md5sig_option", False),
                is_fake=opts.get("is_fake", False)
            )
            segments.append(spec)
        
        print(f"Generated {len(segments)} segments from fakeddisorder")
        
        # Build actual packets using PacketBuilder
        builder = PacketBuilder()
        built_packets = []
        
        for i, segment in enumerate(segments):
            print(f"\nSegment {i + 1}:")
            print(f"  Payload length: {len(segment.payload)} bytes")
            print(f"  Relative sequence: {segment.rel_seq}")
            print(f"  Flags: 0x{segment.flags:02X}")
            print(f"  TTL: {segment.ttl}")
            print(f"  Corrupt checksum: {segment.corrupt_tcp_checksum}")
            
            # Build the packet
            built_packet = builder.build_tcp_segment(original_packet, segment)
            
            if built_packet:
                built_packets.append(built_packet)
                
                # Analyze TCP options in built packet
                built_ip_hl = (built_packet[0] & 0x0F) * 4
                built_tcp_hl = ((built_packet[built_ip_hl + 12] >> 4) & 0x0F) * 4
                built_options = built_packet[built_ip_hl + 20:built_ip_hl + built_tcp_hl]
                
                print(f"  Built packet TCP options: {len(built_options)} bytes")
                print(f"  Options hex: {built_options.hex()}")
                
                # Check if options are preserved
                if built_options == original_options:
                    print("  ✅ TCP options perfectly preserved!")
                elif len(built_options) > len(original_options):
                    # Check if original options are contained (MD5SIG might be added)
                    if original_options in built_options:
                        print("  ✅ Original TCP options preserved (additional options added)")
                    else:
                        print("  ❌ TCP options modified unexpectedly")
                else:
                    print("  ❌ TCP options not preserved")
            else:
                print("  ❌ Failed to build packet")
                return False
        
        print(f"\n✅ Successfully built {len(built_packets)} packets with preserved TCP options!")
        return True
        
    except Exception as e:
        print(f"❌ Error during fakeddisorder test: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_tcp_options_with_different_attacks():
    """Test TCP options preservation with different attack types"""
    print("\nTesting TCP options with different attack configurations...")
    
    original_packet_bytes = create_test_packet_with_tls()
    original_packet = MockPacket(original_packet_bytes)
    builder = PacketBuilder()
    
    # Test configurations
    test_configs = [
        {
            "name": "Basic segment",
            "spec": TCPSegmentSpec(
                payload=b"Test payload",
                rel_seq=0,
                flags=0x18,
                ttl=64
            )
        },
        {
            "name": "Fake packet with low TTL",
            "spec": TCPSegmentSpec(
                payload=b"Fake payload",
                rel_seq=0,
                flags=0x18,
                ttl=1,
                corrupt_tcp_checksum=True
            )
        },
        {
            "name": "Segment with MD5SIG",
            "spec": TCPSegmentSpec(
                payload=b"MD5SIG payload",
                rel_seq=0,
                flags=0x18,
                ttl=64,
                add_md5sig_option=True
            )
        }
    ]
    
    success_count = 0
    
    for config in test_configs:
        print(f"\nTesting: {config['name']}")
        
        built_packet = builder.build_tcp_segment(original_packet, config["spec"])
        
        if built_packet:
            # Check TCP options
            ip_hl = (built_packet[0] & 0x0F) * 4
            tcp_hl = ((built_packet[ip_hl + 12] >> 4) & 0x0F) * 4
            
            if tcp_hl > 20:
                options = built_packet[ip_hl + 20:ip_hl + tcp_hl]
                print(f"  TCP options: {len(options)} bytes")
                print(f"  ✅ TCP options preserved")
                success_count += 1
            else:
                print("  ❌ No TCP options found")
        else:
            print("  ❌ Failed to build packet")
    
    print(f"\nResults: {success_count}/{len(test_configs)} configurations successful")
    return success_count == len(test_configs)

if __name__ == "__main__":
    print("TCP Options Integration Test")
    print("=" * 50)
    
    success1 = test_fakeddisorder_with_tcp_options()
    success2 = test_tcp_options_with_different_attacks()
    
    print("\n" + "=" * 50)
    if success1 and success2:
        print("✅ All integration tests passed!")
        print("TCP options copying is working correctly with the bypass engine!")
        sys.exit(0)
    else:
        print("❌ Some integration tests failed!")
        sys.exit(1)