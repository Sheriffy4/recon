#!/usr/bin/env python3
"""
Example usage of SegmentPacketBuilder for packet construction.
Demonstrates how to build packets from segment tuples with precise control.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bypass.attacks.segment_packet_builder import (
    SegmentPacketBuilder,
    build_segments_batch,
    validate_segments_for_building,
)
from core.bypass.attacks.base import AttackContext
import struct
import socket


def demonstrate_basic_packet_building():
    """Demonstrate basic packet building functionality."""

    print("=== SegmentPacketBuilder Basic Demo ===\n")

    # Create context with TCP session information
    context = AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        src_ip="10.0.0.50",
        src_port=12345,
        domain="target.example.com",
        tcp_seq=1000000,
        tcp_ack=2000000,
        tcp_flags=0x18,  # PSH+ACK
        tcp_window_size=32768,
    )

    # Create packet builder
    builder = SegmentPacketBuilder()

    print("1. Basic Packet Building:")
    payload = b"GET /api/test HTTP/1.1\r\nHost: target.example.com\r\n\r\n"
    seq_offset = 0
    options = {}

    packet_info = builder.build_segment(payload, seq_offset, options, context)

    print(f"   Packet size: {packet_info.packet_size} bytes")
    print(f"   Construction time: {packet_info.construction_time_ms:.3f} ms")
    print(f"   TCP seq: {packet_info.tcp_seq}")
    print(f"   TCP flags: 0x{packet_info.tcp_flags:02x}")
    print(f"   TTL: {packet_info.ttl}")
    print()

    return builder, context


def demonstrate_ttl_manipulation():
    """Demonstrate TTL manipulation in packets."""

    print("2. TTL Manipulation:")

    builder = SegmentPacketBuilder()
    context = AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        src_ip="10.0.0.50",
        src_port=12345,
        tcp_seq=1000000,
        tcp_ack=2000000,
    )

    # Build packets with different TTL values
    ttl_values = [2, 5, 64, 128]

    for ttl in ttl_values:
        payload = f"TTL test packet with TTL={ttl}".encode()
        options = {"ttl": ttl}

        packet_info = builder.build_segment(payload, 0, options, context)

        # Verify TTL in packet
        actual_ttl = packet_info.packet_bytes[8]  # TTL is at offset 8 in IP header

        print(
            f"   TTL {ttl}: packet size {packet_info.packet_size}, actual TTL {actual_ttl}"
        )
        assert actual_ttl == ttl

    print()


def demonstrate_checksum_corruption():
    """Demonstrate TCP checksum corruption."""

    print("3. Checksum Corruption:")

    builder = SegmentPacketBuilder()
    context = AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        src_ip="10.0.0.50",
        src_port=12345,
        tcp_seq=1000000,
        tcp_ack=2000000,
    )

    payload = b"Checksum corruption test"

    # Build packet with good checksum
    good_packet = builder.build_segment(payload, 0, {}, context)
    good_checksum = struct.unpack("!H", good_packet.packet_bytes[36:38])[0]

    # Build packet with corrupted checksum
    bad_packet = builder.build_segment(payload, 0, {"bad_checksum": True}, context)
    bad_checksum = struct.unpack("!H", bad_packet.packet_bytes[36:38])[0]

    print(f"   Good checksum: 0x{good_checksum:04x}")
    print(f"   Bad checksum: 0x{bad_checksum:04x}")
    print(f"   Corruption applied: {bad_packet.checksum_corrupted}")

    assert good_checksum != bad_checksum
    assert bad_checksum == 0xDEAD  # Our corruption marker
    print()


def demonstrate_tcp_flags_manipulation():
    """Demonstrate TCP flags manipulation."""

    print("4. TCP Flags Manipulation:")

    builder = SegmentPacketBuilder()
    context = AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        src_ip="10.0.0.50",
        src_port=12345,
        tcp_seq=1000000,
        tcp_ack=2000000,
    )

    flag_tests = [
        (0x02, "SYN"),
        (0x18, "PSH+ACK"),
        (0x11, "FIN+ACK"),
        (0x04, "RST"),
        (0x20, "URG"),
    ]

    for flags, description in flag_tests:
        payload = f"Flags test: {description}".encode()
        options = {"flags": flags}

        packet_info = builder.build_segment(payload, 0, options, context)

        # Verify flags in packet (TCP flags at offset 33)
        actual_flags = packet_info.packet_bytes[33]

        print(f"   {description}: set 0x{flags:02x}, actual 0x{actual_flags:02x}")
        assert actual_flags == flags

    print()


def demonstrate_sequence_offsets():
    """Demonstrate sequence number offsets."""

    print("5. Sequence Number Offsets:")

    builder = SegmentPacketBuilder()
    context = AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        src_ip="10.0.0.50",
        src_port=12345,
        tcp_seq=1000000,
        tcp_ack=2000000,
    )

    base_payload = b"Sequence test chunk "
    offsets = [0, 20, 40, 60]

    for i, offset in enumerate(offsets):
        payload = base_payload + str(i).encode()

        packet_info = builder.build_segment(payload, offset, {}, context)

        # Verify sequence number in packet (TCP seq at offset 24-27)
        actual_seq = struct.unpack("!I", packet_info.packet_bytes[24:28])[0]
        expected_seq = context.tcp_seq + offset

        print(
            f"   Chunk {i}: offset {offset}, expected seq {expected_seq}, actual seq {actual_seq}"
        )
        assert actual_seq == expected_seq

    print()


def demonstrate_batch_building():
    """Demonstrate batch packet building."""

    print("6. Batch Packet Building:")

    context = AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        src_ip="10.0.0.50",
        src_port=12345,
        tcp_seq=1000000,
        tcp_ack=2000000,
    )

    # Create segments for a FakedDisorder attack
    payload = b"GET /secret HTTP/1.1\r\nHost: target.com\r\nAuthorization: Bearer token123\r\n\r\n"
    split_pos = 20

    segments = [
        # Fake packet with low TTL
        (
            b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
            0,
            {"ttl": 2, "delay_ms": 5},
        ),
        # Second part of real payload (sent first)
        (payload[split_pos:], split_pos, {"delay_ms": 10}),
        # First part of real payload (sent last - creates disorder)
        (payload[:split_pos], 0, {"flags": 0x18}),
    ]

    # Validate segments before building
    is_valid, error_msg = validate_segments_for_building(segments, context)
    print(f"   Segments validation: {'PASS' if is_valid else 'FAIL'}")
    if error_msg:
        print(f"   Error: {error_msg}")

    # Build all segments
    packet_infos = build_segments_batch(segments, context)

    print(f"   Built {len(packet_infos)} packets:")
    for i, info in enumerate(packet_infos):
        print(
            f"     Packet {i+1}: {info.packet_size} bytes, TTL={info.ttl}, "
            f"seq={info.tcp_seq}, flags=0x{info.tcp_flags:02x}"
        )

    print()


def demonstrate_statistics_and_performance():
    """Demonstrate statistics collection and performance monitoring."""

    print("7. Statistics and Performance:")

    builder = SegmentPacketBuilder()
    context = AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        src_ip="10.0.0.50",
        src_port=12345,
        tcp_seq=1000000,
        tcp_ack=2000000,
    )

    # Build multiple packets with different options
    test_cases = [
        (b"packet1", {"ttl": 2}),
        (b"packet2", {"bad_checksum": True}),
        (b"packet3", {"flags": 0x02}),
        (b"packet4", {"ttl": 5, "bad_checksum": True}),
        (b"packet5", {"window_size": 16384}),
    ]

    for payload, options in test_cases:
        builder.build_segment(payload, 0, options, context)

    # Get statistics
    stats = builder.get_stats()

    print(f"   Packets built: {stats['packets_built']}")
    print(f"   Total build time: {stats['total_build_time_ms']:.3f} ms")
    print(f"   Average build time: {stats['avg_build_time_ms']:.3f} ms")
    print(f"   TTL modifications: {stats['ttl_modifications']}")
    print(f"   Checksum corruptions: {stats['checksum_corruptions']}")
    print(f"   Flag modifications: {stats['flag_modifications']}")

    print()


def demonstrate_packet_analysis():
    """Demonstrate packet structure analysis."""

    print("8. Packet Structure Analysis:")

    builder = SegmentPacketBuilder()
    context = AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        src_ip="10.0.0.50",
        src_port=12345,
        tcp_seq=1000000,
        tcp_ack=2000000,
    )

    payload = b"Structure analysis test payload"
    options = {"ttl": 42, "flags": 0x18, "window_size": 8192}

    packet_info = builder.build_segment(payload, 100, options, context)
    packet = packet_info.packet_bytes

    print(f"   Total packet size: {len(packet)} bytes")

    # Analyze IP header
    print("   IP Header:")
    print(f"     Version: {packet[0] >> 4}")
    print(f"     Header Length: {(packet[0] & 0x0F) * 4} bytes")
    print(f"     Total Length: {struct.unpack('!H', packet[2:4])[0]}")
    print(f"     TTL: {packet[8]}")
    print(f"     Protocol: {packet[9]} (TCP)")
    print(f"     Source IP: {socket.inet_ntoa(packet[12:16])}")
    print(f"     Dest IP: {socket.inet_ntoa(packet[16:20])}")

    # Analyze TCP header
    tcp_start = 20
    print("   TCP Header:")
    print(f"     Source Port: {struct.unpack('!H', packet[tcp_start:tcp_start+2])[0]}")
    print(f"     Dest Port: {struct.unpack('!H', packet[tcp_start+2:tcp_start+4])[0]}")
    print(f"     Sequence: {struct.unpack('!I', packet[tcp_start+4:tcp_start+8])[0]}")
    print(
        f"     Acknowledgment: {struct.unpack('!I', packet[tcp_start+8:tcp_start+12])[0]}"
    )
    print(f"     Flags: 0x{packet[tcp_start+13]:02x}")
    print(f"     Window: {struct.unpack('!H', packet[tcp_start+14:tcp_start+16])[0]}")
    print(
        f"     Checksum: 0x{struct.unpack('!H', packet[tcp_start+16:tcp_start+18])[0]:04x}"
    )

    # Analyze payload
    payload_start = 40  # 20 IP + 20 TCP
    actual_payload = packet[payload_start:]
    print(f"   Payload: {len(actual_payload)} bytes")
    print(
        f"     Content: {actual_payload[:50]}{'...' if len(actual_payload) > 50 else ''}"
    )

    print()


def main():
    """Run all demonstrations."""

    print("SegmentPacketBuilder Comprehensive Demo")
    print("=" * 50)
    print()

    try:
        demonstrate_basic_packet_building()
        demonstrate_ttl_manipulation()
        demonstrate_checksum_corruption()
        demonstrate_tcp_flags_manipulation()
        demonstrate_sequence_offsets()
        demonstrate_batch_building()
        demonstrate_statistics_and_performance()
        demonstrate_packet_analysis()

        print("✅ All demonstrations completed successfully!")

    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
