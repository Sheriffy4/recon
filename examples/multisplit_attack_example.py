#!/usr/bin/env python3
"""
Example demonstrating MultisplitAttack usage.

This example shows how to use the MultisplitAttack to bypass DPI systems
that rely on contiguous data stream analysis.
"""

import asyncio

from core.bypass.attacks.reference.multisplit_attack import (
    MultisplitAttack,
    MultisplitConfig,
    create_multisplit_attack,
    create_aggressive_multisplit,
    create_subtle_multisplit,
    create_overlap_multisplit,
    create_timing_multisplit,
)
from core.bypass.attacks.base import AttackContext


def demonstrate_basic_usage():
    """Demonstrate basic MultisplitAttack usage."""
    print("=== Basic MultisplitAttack Usage ===")

    # Create test payload
    payload = (
        b"POST /api/restricted-endpoint HTTP/1.1\r\n"
        b"Host: restricted-api.example.com\r\n"
        b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 156\r\n"
        b"\r\n"
        b'{"action": "access_sensitive_data", "user_id": 12345, "query": "SELECT * FROM confidential_records WHERE classification = \'top_secret\'"}'
    )

    # Create attack context
    context = AttackContext(
        dst_ip="203.0.113.50",
        dst_port=443,
        src_ip="192.168.1.100",
        src_port=54321,
        payload=payload,
        tcp_seq=1000,
        tcp_ack=1,
        tcp_flags=0x18,
        tcp_window_size=65535,
        connection_id="demo_connection",
    )

    # Create and execute attack
    attack = MultisplitAttack()
    result = attack.execute(context)

    print(f"Attack Status: {result.status}")
    print(f"Total Segments: {len(result._segments)}")
    print(f"Original Payload Size: {result.metadata['original_payload_size']} bytes")

    # Show segment details
    print("\nSegment Details:")
    for i, (segment_payload, seq_offset, options) in enumerate(result._segments):
        print(f"  Segment {i + 1}:")
        print(f"    Size: {len(segment_payload)} bytes")
        print(f"    Sequence Offset: {seq_offset}")
        print(f"    TTL: {options.get('ttl', 'default')}")
        print(f"    Delay: {options.get('delay_ms', 0):.1f}ms")
        print(f"    Flags: 0x{options.get('flags', 0x18):02x}")
        print(
            f"    Content Preview: {segment_payload[:30]}{'...' if len(segment_payload) > 30 else ''}"
        )
        print()


def demonstrate_custom_configuration():
    """Demonstrate custom configuration options."""
    print("=== Custom Configuration ===")

    # Create custom configuration
    config = MultisplitConfig(
        split_count=8,  # Split into 8 segments
        min_segment_size=15,  # Minimum 15 bytes per segment
        max_segment_size=80,  # Maximum 80 bytes per segment
        overlap_bytes=3,  # 3 bytes overlap between segments
        base_delay_ms=8.0,  # 8ms base delay
        delay_variation_ms=4.0,  # ±4ms random variation
        randomize_order=True,  # Randomize segment order
        vary_ttl=True,  # Vary TTL values
        ttl_range=(58, 64),  # TTL range
        vary_tcp_flags=True,  # Vary TCP flags
        vary_window_size=True,  # Vary window sizes
        window_size_range=(32768, 65535),  # Window size range
        add_padding=True,  # Add padding to segments
        padding_range=(1, 4),  # 1-4 bytes padding
        corrupt_some_checksums=True,  # Corrupt some checksums
        checksum_corruption_probability=0.3,  # 30% corruption probability
        exponential_backoff=True,  # Use exponential backoff
        backoff_multiplier=1.8,  # 1.8x backoff multiplier
    )

    # Create attack with custom config
    attack = MultisplitAttack(name="custom_multisplit", config=config)

    # Test payload
    payload = (
        b"GET /blocked-resource HTTP/1.1\r\nHost: blocked.example.com\r\nUser-Agent: CustomAgent/1.0\r\nAccept: */*\r\n\r\n"
        * 3
    )

    context = AttackContext(
        dst_ip="198.51.100.10",
        dst_port=80,
        payload=payload,
        connection_id="custom_demo",
    )

    result = attack.execute(context)

    print(f"Custom Attack Status: {result.status}")
    print("Configuration Used:")
    for key, value in result.metadata["config"].items():
        print(f"  {key}: {value}")

    # Show attack effectiveness
    effectiveness = attack.estimate_effectiveness(context)
    print(f"\nEstimated Effectiveness: {effectiveness:.1%}")

    # Show required capabilities
    capabilities = attack.get_required_capabilities()
    print(f"Required Capabilities: {', '.join(capabilities)}")

    # Analyze segment characteristics
    segments = result._segments
    delays = [options["delay_ms"] for _, _, options in segments]
    ttls = [options.get("ttl", 64) for _, _, options in segments]
    sizes = [len(payload) for payload, _, _ in segments]

    print("\nSegment Analysis:")
    print(f"  Delay range: {min(delays):.1f}ms - {max(delays):.1f}ms")
    print(f"  TTL range: {min(ttls)} - {max(ttls)}")
    print(f"  Size range: {min(sizes)} - {max(sizes)} bytes")


def demonstrate_attack_variants():
    """Demonstrate different attack variants."""
    print("\n=== Attack Variants ===")

    # Test payload
    payload = (
        b"PUT /admin/config HTTP/1.1\r\n"
        b"Host: admin.restricted-site.com\r\n"
        b"Authorization: Bearer admin-token-xyz789\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 89\r\n"
        b"\r\n"
        b'{"setting": "firewall_rules", "action": "disable", "target": "all", "confirm": true}'
    )

    context = AttackContext(
        dst_ip="203.0.113.20",
        dst_port=443,
        payload=payload,
        connection_id="variants_demo",
    )

    # Test different variants
    variants = [
        ("Standard", create_multisplit_attack()),
        ("Aggressive", create_aggressive_multisplit()),
        ("Subtle", create_subtle_multisplit()),
        ("Overlap", create_overlap_multisplit()),
        ("Timing", create_timing_multisplit()),
    ]

    print(f"Testing {len(variants)} attack variants on {len(payload)}-byte payload:\n")

    for variant_name, attack in variants:
        result = attack.execute(context)
        effectiveness = attack.estimate_effectiveness(context)

        # Calculate segment statistics
        segments = result._segments
        sizes = [len(p) for p, _, _ in segments]
        delays = [opts["delay_ms"] for _, _, opts in segments]

        print(f"{variant_name} Variant:")
        print(f"  Status: {result.status}")
        print(f"  Segments: {len(segments)}")
        print(f"  Segment sizes: {min(sizes)}-{max(sizes)} bytes")
        print(f"  Delay range: {min(delays):.1f}-{max(delays):.1f}ms")
        print(f"  Effectiveness: {effectiveness:.1%}")
        print(f"  Overlap: {result.metadata['config']['overlap_bytes']} bytes")
        print(f"  Randomized: {result.metadata['config']['randomize_order']}")
        print()


def demonstrate_segment_analysis():
    """Demonstrate detailed segment analysis."""
    print("=== Segment Analysis ===")

    payload = b"Sensitive data transmission: " + b"CONFIDENTIAL_INFO_" * 20

    context = AttackContext(
        dst_ip="1.2.3.4", dst_port=443, payload=payload, connection_id="analysis_demo"
    )

    # Use aggressive variant for detailed analysis
    attack = create_aggressive_multisplit()
    result = attack.execute(context)

    print(
        f"Analyzing {len(result._segments)} segments from {len(payload)}-byte payload:"
    )
    print()

    # Analyze segment distribution
    segments = result._segments
    segments_sorted = sorted(segments, key=lambda x: x[1])  # Sort by sequence offset

    print("Segment Distribution:")
    total_bytes = 0
    for i, (segment_payload, seq_offset, options) in enumerate(segments_sorted):
        segment_size = len(segment_payload)
        total_bytes += segment_size

        print(
            f"  Segment {i+1}: offset={seq_offset:3d}, size={segment_size:2d}, "
            f"TTL={options.get('ttl', 64):2d}, delay={options['delay_ms']:5.1f}ms"
        )

        # Show content preview
        preview = segment_payload[:20].decode("utf-8", errors="ignore")
        print(f"    Content: '{preview}{'...' if len(segment_payload) > 20 else ''}'")

    print(f"\nTotal bytes in segments: {total_bytes}")
    print(f"Original payload bytes: {len(payload)}")
    print(
        f"Overhead: {total_bytes - len(payload)} bytes ({((total_bytes - len(payload)) / len(payload) * 100):.1f}%)"
    )

    # Analyze overlap
    overlaps = []
    for i in range(len(segments_sorted) - 1):
        current_end = segments_sorted[i][1] + len(segments_sorted[i][0])
        next_start = segments_sorted[i + 1][1]
        if current_end > next_start:
            overlap = current_end - next_start
            overlaps.append(overlap)

    if overlaps:
        print(f"Overlaps detected: {len(overlaps)} overlapping pairs")
        print(f"Overlap range: {min(overlaps)}-{max(overlaps)} bytes")
    else:
        print("No overlaps detected")


def demonstrate_timing_patterns():
    """Demonstrate timing pattern analysis."""
    print("\n=== Timing Pattern Analysis ===")

    payload = b"Time-sensitive data: " + b"TIMESTAMP_" * 30
    context = AttackContext(
        dst_ip="198.51.100.30",
        dst_port=443,
        payload=payload,
        connection_id="timing_demo",
    )

    # Test different timing configurations
    timing_configs = [
        (
            "Linear",
            MultisplitConfig(
                split_count=6,
                base_delay_ms=5.0,
                delay_variation_ms=2.0,
                exponential_backoff=False,
            ),
        ),
        (
            "Exponential",
            MultisplitConfig(
                split_count=6,
                base_delay_ms=2.0,
                delay_variation_ms=1.0,
                exponential_backoff=True,
                backoff_multiplier=1.5,
            ),
        ),
        (
            "High Variation",
            MultisplitConfig(
                split_count=6,
                base_delay_ms=3.0,
                delay_variation_ms=8.0,
                exponential_backoff=False,
            ),
        ),
        (
            "Aggressive Backoff",
            MultisplitConfig(
                split_count=6,
                base_delay_ms=1.0,
                delay_variation_ms=0.5,
                exponential_backoff=True,
                backoff_multiplier=2.5,
            ),
        ),
    ]

    for config_name, config in timing_configs:
        attack = MultisplitAttack(
            name=f"timing_{config_name.lower().replace(' ', '_')}", config=config
        )
        result = attack.execute(context)

        # Analyze timing pattern
        delays = [options["delay_ms"] for _, _, options in result._segments]
        total_delay = sum(delays)

        print(f"{config_name} Timing Pattern:")
        print(f"  Delays: {[f'{d:.1f}' for d in delays]} ms")
        print(f"  Total delay: {total_delay:.1f}ms")
        print(f"  Average delay: {total_delay/len(delays):.1f}ms")
        print(f"  Delay range: {min(delays):.1f}-{max(delays):.1f}ms")
        print()


def demonstrate_payload_reconstruction():
    """Demonstrate payload reconstruction from segments."""
    print("=== Payload Reconstruction ===")

    original_payload = b"Original message that will be split and then reconstructed to verify integrity."

    context = AttackContext(
        dst_ip="1.2.3.4",
        dst_port=443,
        payload=original_payload,
        connection_id="reconstruction_demo",
    )

    # Test with overlap to make reconstruction more complex
    attack = create_overlap_multisplit()
    result = attack.execute(context)

    print(f"Original payload: {len(original_payload)} bytes")
    print(f"Split into: {len(result._segments)} segments")

    # Sort segments by sequence offset for reconstruction
    segments_sorted = sorted(result._segments, key=lambda x: x[1])

    # Reconstruct payload (handling overlap)
    reconstructed = b""
    last_end = 0

    for i, (segment_payload, seq_offset, options) in enumerate(segments_sorted):
        print(f"Segment {i+1}: offset={seq_offset}, size={len(segment_payload)}")

        if seq_offset >= last_end:
            # No overlap, append entire segment
            reconstructed += segment_payload
            last_end = seq_offset + len(segment_payload)
        else:
            # Handle overlap - only append non-overlapping part
            overlap = last_end - seq_offset
            if overlap < len(segment_payload):
                reconstructed += segment_payload[overlap:]
                last_end = seq_offset + len(segment_payload)

    print(f"\nReconstructed payload: {len(reconstructed)} bytes")
    print(f"Reconstruction successful: {reconstructed == original_payload}")

    if reconstructed != original_payload:
        print("Differences found:")
        print(f"  Original:     '{original_payload[:50]}...'")
        print(f"  Reconstructed: '{reconstructed[:50]}...'")


def demonstrate_effectiveness_analysis():
    """Demonstrate effectiveness analysis for different scenarios."""
    print("\n=== Effectiveness Analysis ===")

    # Test different payload types and sizes
    test_scenarios = [
        ("Small HTTP", b"GET /test HTTP/1.1\r\nHost: test.com\r\n\r\n"),
        (
            "Large HTTP",
            b"POST /api/data HTTP/1.1\r\nHost: api.com\r\n" + b"data=" + b"X" * 1000,
        ),
        ("Binary Data", b"\x01\x02\x03\x04" * 100),
        (
            "JSON API",
            b'{"query": "' + b"SELECT * FROM table WHERE " + b"condition=" * 20 + b'"}',
        ),
        ("XML Data", b"<root>" + b"<item>data</item>" * 50 + b"</root>"),
    ]

    variants = [
        ("Standard", create_multisplit_attack()),
        ("Aggressive", create_aggressive_multisplit()),
        ("Subtle", create_subtle_multisplit()),
    ]

    print("Effectiveness Analysis (Payload Type vs Attack Variant):")
    print("-" * 70)
    print(f"{'Payload Type':<15} {'Standard':<12} {'Aggressive':<12} {'Subtle':<12}")
    print("-" * 70)

    for scenario_name, payload in test_scenarios:
        context = AttackContext(
            dst_ip="1.2.3.4",
            dst_port=443,
            payload=payload,
            connection_id=f"effectiveness_{scenario_name.lower().replace(' ', '_')}",
        )

        effectiveness_scores = []
        for variant_name, attack in variants:
            effectiveness = attack.estimate_effectiveness(context)
            effectiveness_scores.append(f"{effectiveness:.1%}")

        print(
            f"{scenario_name:<15} {effectiveness_scores[0]:<12} {effectiveness_scores[1]:<12} {effectiveness_scores[2]:<12}"
        )

    print("-" * 70)


async def main():
    """Main demonstration function."""
    print("MultisplitAttack Demonstration")
    print("=" * 50)

    # Run all demonstrations
    demonstrate_basic_usage()
    demonstrate_custom_configuration()
    demonstrate_attack_variants()
    demonstrate_segment_analysis()
    demonstrate_timing_patterns()
    demonstrate_payload_reconstruction()
    demonstrate_effectiveness_analysis()

    print("\n" + "=" * 50)
    print("✅ MultisplitAttack demonstration completed!")
    print("\nKey Benefits:")
    print("- Confuses DPI systems that expect contiguous data streams")
    print("- Configurable segment count and overlap for flexibility")
    print("- Variable timing patterns to avoid detection")
    print("- TCP option diversity (TTL, flags, window size)")
    print("- Optional padding and checksum corruption")
    print("- Exponential backoff timing strategies")
    print("- Segment order randomization")
    print("- Effectiveness estimation for different scenarios")
    print("- Comprehensive validation and error handling")


if __name__ == "__main__":
    asyncio.run(main())
