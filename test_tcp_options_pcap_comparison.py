#!/usr/bin/env python3
"""
PCAP comparison test to demonstrate TCP options copying improvement.
This test creates packets with and without TCP options copying to show the difference.
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
logging.basicConfig(level=logging.WARNING)  # Reduce noise for comparison

class MockPacket:
    """Mock packet class for testing"""
    def __init__(self, raw_bytes):
        self.raw = raw_bytes

class LegacyPacketBuilder:
    """
    Simulates the old packet builder behavior without TCP options copying.
    This represents how the system worked before the fix.
    """
    def __init__(self):
        self.logger = logging.getLogger("LegacyPacketBuilder")

    def build_tcp_segment_legacy(self, original_packet, spec: TCPSegmentSpec) -> bytes:
        """Legacy implementation that doesn't preserve TCP options"""
        try:
            raw = bytearray(original_packet.raw)
            ip_hl = (raw[0] & 0x0F) * 4
            
            # OLD BEHAVIOR: Always use 20-byte TCP header (no options)
            tcp_hl = 20
            
            base_seq = struct.unpack("!I", raw[ip_hl+4:ip_hl+8])[0]
            base_ack = struct.unpack("!I", raw[ip_hl+8:ip_hl+12])[0]
            base_win = struct.unpack("!H", raw[ip_hl+14:ip_hl+16])[0]
            
            ip_hdr = bytearray(raw[:ip_hl])
            # OLD BEHAVIOR: Create basic 20-byte TCP header without options
            tcp_hdr = bytearray(raw[ip_hl:ip_hl+20])
            
            seq = (base_seq + spec.rel_seq + spec.seq_extra) & 0xFFFFFFFF
            tcp_hdr[4:8] = struct.pack("!I", seq)
            tcp_hdr[8:12] = struct.pack("!I", base_ack)
            tcp_hdr[13] = spec.flags & 0xFF
            tcp_hdr[14:16] = struct.pack("!H", base_win)
            
            if spec.ttl is not None:
                ip_hdr[8] = spec.ttl
            
            # Build packet
            seg_raw = bytearray(ip_hdr + tcp_hdr + spec.payload)
            seg_raw[2:4] = struct.pack("!H", len(seg_raw))
            
            # IP checksum
            seg_raw[10:12] = b"\x00\x00"
            ip_csum = self._checksum16(seg_raw[:ip_hl])
            seg_raw[10:12] = struct.pack("!H", ip_csum)
            
            # TCP checksum
            if spec.corrupt_tcp_checksum:
                seg_raw[ip_hl+16:ip_hl+18] = struct.pack("!H", 0xDEAD)
            else:
                tcp_csum = self._tcp_checksum(seg_raw[:ip_hl], seg_raw[ip_hl:ip_hl+20], seg_raw[ip_hl+20:])
                seg_raw[ip_hl+16:ip_hl+18] = struct.pack("!H", tcp_csum)
            
            return bytes(seg_raw)
        except Exception as e:
            self.logger.error(f"Failed to build legacy TCP segment: {e}")
            return None

    def _ones_complement_sum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i+1]
            s = (s & 0xFFFF) + (s >> 16)
        return s

    def _checksum16(self, data: bytes) -> int:
        s = self._ones_complement_sum(data)
        return (~s) & 0xFFFF

    def _tcp_checksum(self, ip_hdr: bytes, tcp_hdr: bytes, payload: bytes) -> int:
        src = ip_hdr[12:16]
        dst = ip_hdr[16:20]
        proto = ip_hdr[9]
        tcp_len = len(tcp_hdr) + len(payload)
        pseudo = src + dst + bytes([0, proto]) + tcp_len.to_bytes(2, "big")
        tcp_hdr_wo_csum = bytearray(tcp_hdr)
        tcp_hdr_wo_csum[16:18] = b"\x00\x00"
        s = self._ones_complement_sum(pseudo + bytes(tcp_hdr_wo_csum) + payload)
        return (~s) & 0xFFFF

def create_realistic_packet_with_options():
    """Create a realistic packet with comprehensive TCP options"""
    # IP Header
    ip_header = bytearray([
        0x45, 0x00, 0x00, 0x00,  # Version, IHL, ToS, Total Length
        0x12, 0x34, 0x40, 0x00,  # ID, Flags, Fragment Offset
        0x40, 0x06, 0x00, 0x00,  # TTL, Protocol, Checksum
        0xC0, 0xA8, 0x01, 0x64,  # Source IP
        0x8E, 0xFA, 0x5B, 0x23,  # Destination IP
    ])
    
    # TCP Header with comprehensive options (44 bytes total)
    tcp_header = bytearray([
        0xC4, 0x18, 0x01, 0xBB,  # Source Port, Dest Port
        0x12, 0x34, 0x56, 0x78,  # Sequence Number
        0x87, 0x65, 0x43, 0x21,  # Acknowledgment Number
        0xB0, 0x18, 0x72, 0x10,  # Data Offset (11 words), Flags, Window
        0x00, 0x00, 0x00, 0x00,  # Checksum, Urgent Pointer
        
        # TCP Options (24 bytes)
        0x02, 0x04, 0x05, 0xB4,  # MSS = 1460
        0x04, 0x02,              # SACK Permitted
        0x08, 0x0A,              # Timestamps
        0x12, 0x34, 0x56, 0x78,  # TSval
        0x87, 0x65, 0x43, 0x21,  # TSecr
        0x01,                    # NOP
        0x03, 0x03, 0x07,        # Window Scale = 7
        0x01, 0x01, 0x01, 0x01,  # NOP padding
    ])
    
    # TLS ClientHello payload
    tls_payload = bytearray([
        0x16, 0x03, 0x01, 0x00, 0x30,  # TLS Record Header
        0x01, 0x00, 0x00, 0x2C,        # Handshake Header
        0x03, 0x03,                    # TLS Version
        # Random (32 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x00,        # Session ID Length
        0x00, 0x02,  # Cipher Suites Length
        0x13, 0x01,  # Cipher Suite
        0x01, 0x00,  # Compression + Extensions Length
    ])
    
    # Combine packet
    packet = ip_header + tcp_header + tls_payload
    packet[2:4] = struct.pack("!H", len(packet))
    
    return bytes(packet)

def analyze_packet_options(packet_bytes, description):
    """Analyze and display TCP options in a packet"""
    ip_hl = (packet_bytes[0] & 0x0F) * 4
    tcp_hl = ((packet_bytes[ip_hl + 12] >> 4) & 0x0F) * 4
    
    print(f"\n{description}:")
    print(f"  Total packet size: {len(packet_bytes)} bytes")
    print(f"  IP header length: {ip_hl} bytes")
    print(f"  TCP header length: {tcp_hl} bytes")
    
    if tcp_hl > 20:
        tcp_options = packet_bytes[ip_hl + 20:ip_hl + tcp_hl]
        print(f"  TCP options: {len(tcp_options)} bytes")
        print(f"  Options hex: {tcp_options.hex()}")
        
        # Count recognizable options
        option_count = 0
        i = 0
        while i < len(tcp_options):
            if tcp_options[i] == 0x00:  # End of options
                break
            elif tcp_options[i] == 0x01:  # NOP
                i += 1
            elif tcp_options[i] == 0x02 and i + 3 < len(tcp_options):  # MSS
                option_count += 1
                i += 4
            elif tcp_options[i] == 0x03 and i + 2 < len(tcp_options):  # Window Scale
                option_count += 1
                i += 3
            elif tcp_options[i] == 0x04 and i + 1 < len(tcp_options):  # SACK Permitted
                option_count += 1
                i += 2
            elif tcp_options[i] == 0x08 and i + 9 < len(tcp_options):  # Timestamps
                option_count += 1
                i += 10
            else:
                i += 1
        
        print(f"  Recognized options: {option_count}")
        return option_count
    else:
        print("  TCP options: 0 bytes")
        print("  ❌ NO TCP OPTIONS PRESERVED")
        return 0

def compare_builders():
    """Compare legacy vs new packet builder behavior"""
    print("TCP Options PCAP Comparison Test")
    print("=" * 60)
    print("This test demonstrates the improvement in TCP options handling.")
    
    # Create test packet with comprehensive options
    original_packet_bytes = create_realistic_packet_with_options()
    original_packet = MockPacket(original_packet_bytes)
    
    # Analyze original packet
    original_option_count = analyze_packet_options(original_packet_bytes, "Original packet (with TCP options)")
    
    # Create builders
    legacy_builder = LegacyPacketBuilder()
    new_builder = PacketBuilder()
    
    # Test specification
    test_spec = TCPSegmentSpec(
        payload=b"Test payload for comparison",
        rel_seq=0,
        flags=0x18,  # PSH + ACK
        ttl=64
    )
    
    print("\n" + "="*60)
    print("COMPARISON: Legacy vs New Implementation")
    print("="*60)
    
    # Build with legacy method (no options preservation)
    legacy_packet = legacy_builder.build_tcp_segment_legacy(original_packet, test_spec)
    if legacy_packet:
        legacy_option_count = analyze_packet_options(legacy_packet, "Legacy builder output (OLD BEHAVIOR)")
    else:
        print("❌ Legacy builder failed")
        return False
    
    # Build with new method (with options preservation)
    new_packet = new_builder.build_tcp_segment(original_packet, test_spec)
    if new_packet:
        new_option_count = analyze_packet_options(new_packet, "New builder output (NEW BEHAVIOR)")
    else:
        print("❌ New builder failed")
        return False
    
    # Compare results
    print("\n" + "="*60)
    print("COMPARISON RESULTS:")
    print("="*60)
    
    print(f"Original packet TCP options: {original_option_count}")
    print(f"Legacy builder preserved:    {legacy_option_count} ({'✅' if legacy_option_count > 0 else '❌'})")
    print(f"New builder preserved:       {new_option_count} ({'✅' if new_option_count > 0 else '❌'})")
    
    improvement = new_option_count - legacy_option_count
    if improvement > 0:
        print(f"\n🎉 IMPROVEMENT: +{improvement} TCP options now preserved!")
        print("✅ The new implementation successfully copies TCP options from original packets!")
    elif improvement == 0 and new_option_count > 0:
        print("\n✅ Both implementations preserve TCP options equally well.")
    else:
        print("\n❌ No improvement detected.")
    
    # Test with different scenarios
    print("\n" + "="*60)
    print("TESTING DIFFERENT SCENARIOS:")
    print("="*60)
    
    scenarios = [
        ("Fake packet with corrupted checksum", TCPSegmentSpec(
            payload=b"Fake payload", rel_seq=0, flags=0x18, ttl=1, corrupt_tcp_checksum=True
        )),
        ("Packet with MD5SIG option", TCPSegmentSpec(
            payload=b"MD5SIG payload", rel_seq=0, flags=0x18, ttl=64, add_md5sig_option=True
        )),
        ("Large payload packet", TCPSegmentSpec(
            payload=b"X" * 1000, rel_seq=0, flags=0x18, ttl=64
        ))
    ]
    
    all_scenarios_passed = True
    
    for scenario_name, spec in scenarios:
        print(f"\nScenario: {scenario_name}")
        
        new_packet = new_builder.build_tcp_segment(original_packet, spec)
        if new_packet:
            option_count = analyze_packet_options(new_packet, f"  Result")
            if option_count > 0:
                print(f"  ✅ TCP options preserved in {scenario_name}")
            else:
                print(f"  ❌ TCP options lost in {scenario_name}")
                all_scenarios_passed = False
        else:
            print(f"  ❌ Failed to build packet for {scenario_name}")
            all_scenarios_passed = False
    
    print("\n" + "="*60)
    print("FINAL RESULTS:")
    print("="*60)
    
    if improvement > 0 and all_scenarios_passed:
        print("🎉 SUCCESS: TCP options copying implementation is working perfectly!")
        print("✅ All scenarios preserve TCP options correctly")
        print("✅ Significant improvement over legacy behavior")
        return True
    elif improvement > 0:
        print("⚠️  PARTIAL SUCCESS: TCP options copying works but some scenarios failed")
        return False
    else:
        print("❌ FAILURE: No improvement in TCP options handling")
        return False

if __name__ == "__main__":
    success = compare_builders()
    sys.exit(0 if success else 1)