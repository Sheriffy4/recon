"""
Demonstration of PacketSequenceAnalyzer integration with existing PCAP analysis.

This demo shows how the new PacketSequenceAnalyzer works with the existing
PCAPComparator to provide comprehensive packet sequence analysis.
"""

import time
from typing import List
from .packet_sequence_analyzer import PacketSequenceAnalyzer
from .packet_info import PacketInfo, TLSInfo


def demo_sequence_analysis():
    """Demonstrate packet sequence analysis capabilities."""
    print("🔍 PacketSequenceAnalyzer Demo - Task 3 Implementation")
    print("=" * 60)

    # Initialize analyzer
    analyzer = PacketSequenceAnalyzer(debug_mode=True)
    base_time = time.time()

    # Create realistic fakeddisorder packet sequence
    print("\n1. Creating realistic fakeddisorder packet sequence...")
    packets = create_fakeddisorder_sequence(base_time)
    print(f"   Created {len(packets)} packets")

    # Analyze fake packet detection
    print("\n2. Analyzing fake packet detection...")
    fake_count = 0
    for i, packet in enumerate(packets):
        analysis = analyzer.detect_fake_packet(packet, packets, i)
        if analysis.is_fake:
            fake_count += 1
            print(
                f"   Packet {i}: FAKE (confidence: {analysis.confidence:.2f}) - {analysis.indicators}"
            )
        else:
            print(f"   Packet {i}: Real (TTL: {packet.ttl}, flags: {packet.flags})")

    print(f"   Total fake packets detected: {fake_count}")

    # Analyze split positions
    print("\n3. Analyzing split positions...")
    split_analysis = analyzer.detect_split_positions(packets)
    print(f"   Split method: {split_analysis.split_method}")
    print(f"   Detected splits: {split_analysis.detected_splits}")
    print(f"   Actual positions: {split_analysis.actual_positions}")
    print(f"   Expected position: {split_analysis.expected_position}")
    print(f"   Split accuracy: {split_analysis.split_accuracy:.2f}")

    # Analyze overlaps
    print("\n4. Analyzing sequence overlaps...")
    overlap_analysis = analyzer.calculate_overlap_sizes(packets)
    print(f"   Overlaps detected: {len(overlap_analysis.overlaps_detected)}")
    print(f"   Total overlap bytes: {overlap_analysis.total_overlap_bytes}")
    if overlap_analysis.overlaps_detected:
        for i, overlap in enumerate(overlap_analysis.overlaps_detected):
            print(
                f"   Overlap {i+1}: {overlap['overlap_bytes']} bytes at packet {overlap['packet_index']}"
            )

    # Analyze timing patterns
    print("\n5. Analyzing timing patterns...")
    timing_analysis = analyzer.analyze_timing_patterns(packets)
    print(f"   Average delay: {timing_analysis.avg_delay:.6f}s")
    print(f"   Delay variance: {timing_analysis.delay_variance:.6f}")
    print(f"   Timing pattern: {timing_analysis.timing_pattern}")
    print(f"   Suspicious delays: {len(timing_analysis.suspicious_delays)}")

    # Complete fakeddisorder analysis
    print("\n6. Complete fakeddisorder analysis...")
    fake_disorder = analyzer.analyze_fake_disorder_sequence(packets)
    print(f"   Fake packet detected: {fake_disorder.fake_packet_detected}")
    print(f"   Fake packet position: {fake_disorder.fake_packet_position}")
    print(f"   Split position: {fake_disorder.split_position}")
    print(f"   Overlap size: {fake_disorder.overlap_size}")
    print(f"   Real segments: {len(fake_disorder.real_segments)}")
    print(f"   Zapret compliance: {fake_disorder.zapret_compliance:.2f}")
    print(f"   TTL pattern: {fake_disorder.ttl_pattern}")

    # Generate analysis summary
    print("\n7. Analysis summary...")
    summary = analyzer.get_analysis_summary(packets)
    print(f"   Quality score: {summary['quality_score']:.2f}")
    print(f"   Fake disorder compliance: {summary['fake_disorder']['compliance']:.2f}")
    print(f"   Timing pattern: {summary['timing']['pattern']}")
    print(f"   Split method: {summary['splits']['method']}")

    # Compare with "broken" recon sequence
    print("\n8. Comparing with broken recon sequence...")
    broken_packets = create_broken_recon_sequence(base_time)
    comparison = analyzer.compare_sequences(broken_packets, packets)

    print(f"   Differences found: {len(comparison['differences'])}")
    for diff in comparison["differences"]:
        print(f"   - {diff['type']}: {diff['severity']} severity")

    print(f"   Recommendations: {len(comparison['recommendations'])}")
    for rec in comparison["recommendations"]:
        print(f"   - {rec}")

    print("\n✅ Demo completed successfully!")
    print("   Task 3 implementation provides comprehensive packet sequence analysis")
    return summary


def create_fakeddisorder_sequence(base_time: float) -> List[PacketInfo]:
    """Create a realistic fakeddisorder packet sequence."""
    packets = []

    # 1. TCP SYN
    packets.append(
        PacketInfo(
            timestamp=base_time,
            src_ip="192.168.1.100",
            dst_ip="162.159.140.229",  # x.com
            src_port=12345,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=64,
            flags=["SYN"],
            payload_length=0,
            checksum=0x1234,
            checksum_valid=True,
        )
    )

    # 2. TCP SYN-ACK (response)
    packets.append(
        PacketInfo(
            timestamp=base_time + 0.01,
            src_ip="162.159.140.229",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=12345,
            sequence_num=2000,
            ack_num=1001,
            ttl=64,
            flags=["SYN", "ACK"],
            payload_length=0,
            checksum=0x5678,
            checksum_valid=True,
            direction="inbound",
        )
    )

    # 3. TCP ACK
    packets.append(
        PacketInfo(
            timestamp=base_time + 0.02,
            src_ip="192.168.1.100",
            dst_ip="162.159.140.229",
            src_port=12345,
            dst_port=443,
            sequence_num=1001,
            ack_num=2001,
            ttl=64,
            flags=["ACK"],
            payload_length=0,
            checksum=0x9ABC,
            checksum_valid=True,
        )
    )

    # 4. FAKE packet with low TTL (fakeddisorder strategy)
    packets.append(
        PacketInfo(
            timestamp=base_time + 0.025,
            src_ip="192.168.1.100",
            dst_ip="162.159.140.229",
            src_port=12345,
            dst_port=443,
            sequence_num=1001,
            ack_num=2001,
            ttl=3,  # Low TTL - will be dropped by DPI
            flags=["PSH", "ACK"],
            payload_length=40,
            payload=b"\x16\x03\x03\x00\x24" + b"FAKE_TLS_DATA" + b"\x00" * 23,
            checksum=0x0000,  # Bad checksum
            checksum_valid=False,
        )
    )

    # 5. Real ClientHello - first 3 bytes (split_pos=3)
    client_hello_data = (
        b"\x16\x03\x03\x01\x00\x01\x00\x00\xfc\x03\x03"  # TLS header + version
        + b"\x12\x34\x56\x78" * 8  # Random bytes
        + b"\x00\x00\x2e"  # Session ID length + cipher suites length
        + b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f"  # Cipher suites
    )

    packets.append(
        PacketInfo(
            timestamp=base_time + 0.03,
            src_ip="192.168.1.100",
            dst_ip="162.159.140.229",
            src_port=12345,
            dst_port=443,
            sequence_num=1001,
            ack_num=2001,
            ttl=64,
            flags=["PSH", "ACK"],
            payload_length=3,
            payload=client_hello_data[:3],  # First 3 bytes
            checksum=0xDEF0,
            checksum_valid=True,
            is_client_hello=True,
            tls_info=TLSInfo(
                version="3.3",
                handshake_type="ClientHello",
                sni="x.com",
                client_hello_length=len(client_hello_data),
            ),
        )
    )

    # 6. Real ClientHello - remaining bytes with overlap
    packets.append(
        PacketInfo(
            timestamp=base_time + 0.031,
            src_ip="192.168.1.100",
            dst_ip="162.159.140.229",
            src_port=12345,
            dst_port=443,
            sequence_num=1002,  # Overlap of 2 bytes (should be 1004)
            ack_num=2001,
            ttl=64,
            flags=["PSH", "ACK"],
            payload_length=len(client_hello_data) - 1,  # Remaining bytes with overlap
            payload=client_hello_data[2:],  # Overlapping content
            checksum=0x1234,
            checksum_valid=True,
        )
    )

    return packets


def create_broken_recon_sequence(base_time: float) -> List[PacketInfo]:
    """Create a broken recon sequence for comparison."""
    packets = []

    # Same initial handshake
    packets.append(
        PacketInfo(
            timestamp=base_time,
            src_ip="192.168.1.100",
            dst_ip="162.159.140.229",
            src_port=12345,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=64,
            flags=["SYN"],
            payload_length=0,
            checksum=0x1234,
            checksum_valid=True,
        )
    )

    # BROKEN: Fake packet with wrong TTL (should be 3, but using 64)
    packets.append(
        PacketInfo(
            timestamp=base_time + 0.025,
            src_ip="192.168.1.100",
            dst_ip="162.159.140.229",
            src_port=12345,
            dst_port=443,
            sequence_num=1001,
            ack_num=2001,
            ttl=64,  # WRONG: Should be 3
            flags=["PSH", "ACK"],
            payload_length=40,
            checksum=0x1234,  # WRONG: Should be bad checksum
            checksum_valid=True,  # WRONG: Should be invalid
        )
    )

    # BROKEN: Wrong split position (should be 3, but using 5)
    packets.append(
        PacketInfo(
            timestamp=base_time + 0.03,
            src_ip="192.168.1.100",
            dst_ip="162.159.140.229",
            src_port=12345,
            dst_port=443,
            sequence_num=1001,
            ack_num=2001,
            ttl=64,
            flags=["PSH", "ACK"],
            payload_length=5,  # WRONG: Should be 3
            checksum=0xDEF0,
            checksum_valid=True,
            is_client_hello=True,
        )
    )

    return packets


if __name__ == "__main__":
    demo_sequence_analysis()
