#!/usr/bin/env python3
"""
Example demonstrating FakedDisorderAttack usage.

This example shows how to use the FakedDisorderAttack to bypass DPI systems
that rely on packet order analysis.
"""

import asyncio

from core.bypass.attacks.reference.faked_disorder_attack import (
    FakedDisorderAttack,
    FakedDisorderConfig,
    create_faked_disorder_attack,
    create_aggressive_faked_disorder,
    create_subtle_faked_disorder,
    create_http_optimized_faked_disorder,
)
from core.bypass.attacks.base import AttackContext, AttackStatus


def demonstrate_basic_usage():
    """Demonstrate basic FakedDisorderAttack usage."""
    print("=== Basic FakedDisorderAttack Usage ===")

    # Create HTTP request payload
    http_payload = (
        b"GET /blocked-content HTTP/1.1\r\n"
        b"Host: blocked-site.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
    )

    # Create attack context
    context = AttackContext(
        dst_ip="93.184.216.34",
        dst_port=80,
        src_ip="192.168.1.100",
        src_port=54321,
        payload=http_payload,
        tcp_seq=1000,
        tcp_ack=1,
        tcp_flags=0x18,
        tcp_window_size=65535,
        connection_id="demo_connection",
    )

    # Create and execute attack
    attack = FakedDisorderAttack()
    result = attack.execute(context)

    print(f"Attack Status: {result.status}")
    print(f"Total Segments: {len(result._segments)}")
    print(f"Split Position: {result.metadata['split_position']}")
    print(f"Fake Payload Size: {result.metadata['fake_payload_size']} bytes")
    print(f"Part 1 Size: {result.metadata['part1_size']} bytes")
    print(f"Part 2 Size: {result.metadata['part2_size']} bytes")

    # Show segment details
    print("\nSegment Details:")
    for i, (payload, seq_offset, options) in enumerate(result._segments):
        segment_type = ["Fake Packet", "Part 2 (sent first)", "Part 1 (sent last)"][i]
        print(f"  Segment {i + 1} ({segment_type}):")
        print(f"    Payload Size: {len(payload)} bytes")
        print(f"    Sequence Offset: {seq_offset}")
        print(f"    TTL: {options.get('ttl', 'default')}")
        print(f"    Delay: {options.get('delay_ms', 0)}ms")
        print(f"    Flags: 0x{options.get('flags', 0x18):02x}")
        if options.get("bad_checksum"):
            print("    Checksum: Corrupted")
        print()


def demonstrate_custom_configuration():
    """Demonstrate custom configuration options."""
    print("=== Custom Configuration ===")

    # Create custom configuration
    config = FakedDisorderConfig(
        split_pos=0.3,  # Split at 30% of payload
        fake_ttl=2,  # TTL=2 for fake packet
        fake_delay_ms=25.0,  # 25ms delay after fake packet
        part2_delay_ms=10.0,  # 10ms delay after part 2
        part1_delay_ms=6.0,  # 6ms delay after part 1
        use_different_fake_payload=True,
        corrupt_fake_checksum=True,  # Corrupt fake packet checksum
        randomize_fake_content=True,
    )

    # Create attack with custom config
    attack = FakedDisorderAttack(name="custom_disorder", config=config)

    # Test payload
    payload = b'POST /api/sensitive-data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 50\r\n\r\n{"secret": "confidential_data"}'

    context = AttackContext(
        dst_ip="1.2.3.4", dst_port=443, payload=payload, connection_id="custom_demo"
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
    print(f"Required Capabilities: {', '.join(filter(None, capabilities))}")


def demonstrate_attack_variants():
    """Demonstrate different attack variants."""
    print("\n=== Attack Variants ===")

    # Test payload
    payload = b"GET /restricted-resource HTTP/1.1\r\nHost: restricted.example.com\r\nAuthorization: Bearer secret-token\r\n\r\n"

    context = AttackContext(
        dst_ip="203.0.113.10",
        dst_port=80,
        payload=payload,
        connection_id="variants_demo",
    )

    # Test different variants
    variants = [
        ("Standard", create_faked_disorder_attack()),
        ("Aggressive", create_aggressive_faked_disorder()),
        ("Subtle", create_subtle_faked_disorder()),
        ("HTTP Optimized", create_http_optimized_faked_disorder()),
    ]

    print(f"Testing {len(variants)} attack variants on {len(payload)}-byte payload:\n")

    for variant_name, attack in variants:
        result = attack.execute(context)
        effectiveness = attack.estimate_effectiveness(context)

        print(f"{variant_name} Variant:")
        print(f"  Status: {result.status}")
        print(
            f"  Split Position: {result.metadata['split_position']} ({result.metadata['split_ratio']:.1%})"
        )
        print(f"  Fake Delay: {result.metadata['config']['fake_delay_ms']}ms")
        print(f"  Effectiveness: {effectiveness:.1%}")
        print(
            f"  Checksum Corruption: {result.metadata['config']['corrupt_fake_checksum']}"
        )
        print()


def demonstrate_payload_analysis():
    """Demonstrate payload analysis and fake generation."""
    print("=== Payload Analysis and Fake Generation ===")

    # Test different payload types
    payloads = [
        ("HTTP GET", b"GET /blocked HTTP/1.1\r\nHost: blocked.com\r\n\r\n"),
        (
            "HTTP POST",
            b'POST /api/data HTTP/1.1\r\nHost: api.com\r\nContent-Length: 15\r\n\r\n{"key":"value"}',
        ),
        (
            "TLS Handshake",
            b"\x16\x03\x01\x00\x50\x01\x00\x00\x4c\x03\x03"
            + b"\x00" * 32
            + b"blocked.com",
        ),
        ("Generic Binary", b"\x01\x02\x03\x04\x05" * 20),
    ]

    attack = FakedDisorderAttack()

    for payload_type, payload in payloads:
        print(f"{payload_type} Payload ({len(payload)} bytes):")

        # Generate fake payload
        fake_payload = attack._generate_fake_payload(payload, b"part1", b"part2")

        print(f"  Original: {payload[:50]}{'...' if len(payload) > 50 else ''}")
        print(
            f"  Fake:     {fake_payload[:50]}{'...' if len(fake_payload) > 50 else ''}"
        )
        print(f"  Same?:    {payload == fake_payload}")
        print()


def demonstrate_timing_analysis():
    """Demonstrate timing analysis of attack execution."""
    print("=== Timing Analysis ===")

    import time

    payload = b"GET /timing-test HTTP/1.1\r\nHost: timing.example.com\r\n\r\n"
    context = AttackContext(
        dst_ip="198.51.100.10",
        dst_port=80,
        payload=payload,
        connection_id="timing_demo",
    )

    # Test different timing configurations
    timing_configs = [
        (
            "Fast",
            FakedDisorderConfig(fake_delay_ms=5, part2_delay_ms=2, part1_delay_ms=1),
        ),
        (
            "Medium",
            FakedDisorderConfig(fake_delay_ms=15, part2_delay_ms=8, part1_delay_ms=5),
        ),
        (
            "Slow",
            FakedDisorderConfig(fake_delay_ms=30, part2_delay_ms=15, part1_delay_ms=10),
        ),
    ]

    for config_name, config in timing_configs:
        attack = FakedDisorderAttack(
            name=f"timing_{config_name.lower()}", config=config
        )

        # Measure execution time (note: actual delays would occur during transmission)
        start_time = time.time()
        result = attack.execute(context)
        execution_time = time.time() - start_time

        # Calculate total expected delay
        total_delay = (
            config.fake_delay_ms + config.part2_delay_ms + config.part1_delay_ms
        )

        print(f"{config_name} Timing Configuration:")
        print(f"  Execution Time: {execution_time * 1000:.2f}ms")
        print(f"  Expected Total Delay: {total_delay}ms")
        print(f"  Fake Packet Delay: {config.fake_delay_ms}ms")
        print(f"  Part 2 Delay: {config.part2_delay_ms}ms")
        print(f"  Part 1 Delay: {config.part1_delay_ms}ms")
        print()


def demonstrate_validation_and_error_handling():
    """Demonstrate validation and error handling."""
    print("=== Validation and Error Handling ===")

    # Test various validation scenarios
    test_cases = [
        (
            "Valid Context",
            AttackContext(
                dst_ip="1.2.3.4",
                dst_port=80,
                payload=b"Valid payload for testing",
                connection_id="valid_test",
            ),
        ),
        (
            "Empty Payload",
            AttackContext(
                dst_ip="1.2.3.4", dst_port=80, payload=b"", connection_id="empty_test"
            ),
        ),
        (
            "Short Payload",
            AttackContext(
                dst_ip="1.2.3.4",
                dst_port=80,
                payload=b"short",
                connection_id="short_test",
            ),
        ),
        (
            "Invalid TCP Seq",
            AttackContext(
                dst_ip="1.2.3.4",
                dst_port=80,
                payload=b"Valid payload for testing",
                tcp_seq=-1,
                connection_id="invalid_seq_test",
            ),
        ),
    ]

    attack = FakedDisorderAttack()

    for test_name, context in test_cases:
        print(f"{test_name}:")

        # Validate context
        is_valid, error = attack.validate_context(context)
        print(f"  Validation: {'PASS' if is_valid else 'FAIL'}")
        if error:
            print(f"  Error: {error}")

        # Try execution
        if is_valid:
            result = attack.execute(context)
            print(f"  Execution: {result.status}")
        else:
            result = attack.execute(context)
            print(f"  Execution: {result.status}")
            if result.status == AttackStatus.FAILED:
                print(f"  Error: {result.metadata.get('error', 'Unknown error')}")
        print()


def demonstrate_integration_scenario():
    """Demonstrate realistic integration scenario."""
    print("=== Integration Scenario ===")

    # Simulate a realistic scenario: bypassing DPI for blocked website
    print("Scenario: Accessing blocked news website")
    print("DPI System: Blocks based on Host header and packet order analysis")
    print("Solution: Use FakedDisorderAttack to confuse packet order detection")
    print()

    # Create realistic HTTP request
    blocked_request = (
        b"GET /breaking-news/sensitive-topic HTTP/1.1\r\n"
        b"Host: blocked-news-site.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        b"Accept-Language: en-US,en;q=0.5\r\n"
        b"Accept-Encoding: gzip, deflate\r\n"
        b"DNT: 1\r\n"
        b"Connection: keep-alive\r\n"
        b"Upgrade-Insecure-Requests: 1\r\n"
        b"\r\n"
    )

    context = AttackContext(
        dst_ip="203.0.113.50",  # Blocked news site IP
        dst_port=80,
        src_ip="192.168.1.100",
        src_port=54321,
        payload=blocked_request,
        tcp_seq=1000,
        tcp_ack=1,
        tcp_flags=0x18,
        tcp_window_size=65535,
        connection_id="news_site_bypass",
    )

    # Use HTTP-optimized attack
    attack = create_http_optimized_faked_disorder()
    result = attack.execute(context)

    print(f"Attack Execution: {result.status}")
    print(f"Total Segments Created: {len(result._segments)}")

    # Analyze the attack strategy
    print("\nAttack Strategy Analysis:")
    print("1. Fake Packet (TTL=1, will be dropped by router):")
    fake_payload, fake_seq, fake_opts = result._segments[0]
    print(f"   - Payload: {fake_payload[:50]}...")
    print(f"   - TTL: {fake_opts['ttl']} (will be dropped)")
    print(f"   - Delay: {fake_opts['delay_ms']}ms")

    print("\n2. Part 2 (sent before Part 1 to confuse DPI):")
    part2_payload, part2_seq, part2_opts = result._segments[1]
    print(f"   - Payload: {part2_payload[:30]}...")
    print(f"   - Sequence Offset: {part2_seq}")
    print(f"   - TTL: {part2_opts['ttl']} (normal)")

    print("\n3. Part 1 (sent last, but should be first):")
    part1_payload, part1_seq, part1_opts = result._segments[2]
    print(f"   - Payload: {part1_payload[:30]}...")
    print(f"   - Sequence Offset: {part1_seq}")
    print(f"   - TTL: {part1_opts['ttl']} (normal)")

    print("\nDPI Perspective (what DPI system sees):")
    print("1. Fake packet with innocent content")
    print("2. Part 2 of real request (out of order)")
    print("3. Part 1 of real request (out of order)")
    print("→ DPI gets confused by packet order and fake content")

    print("\nDestination Perspective (what server receives):")
    print("1. Part 1 of real request (fake packet dropped by router)")
    print("2. Part 2 of real request")
    print("→ Server receives complete, valid HTTP request")

    # Show effectiveness
    effectiveness = attack.estimate_effectiveness(context)
    print(f"\nEstimated Bypass Effectiveness: {effectiveness:.1%}")


async def main():
    """Main demonstration function."""
    print("FakedDisorderAttack Demonstration")
    print("=" * 50)

    # Run all demonstrations
    demonstrate_basic_usage()
    demonstrate_custom_configuration()
    demonstrate_attack_variants()
    demonstrate_payload_analysis()
    demonstrate_timing_analysis()
    demonstrate_validation_and_error_handling()
    demonstrate_integration_scenario()

    print("\n" + "=" * 50)
    print("✅ FakedDisorderAttack demonstration completed!")
    print("\nKey Benefits:")
    print("- Confuses DPI systems that rely on packet order analysis")
    print("- Uses fake packets with low TTL to mislead DPI")
    print("- Maintains payload integrity at destination")
    print("- Configurable timing and split strategies")
    print("- Supports various payload types (HTTP, TLS, etc.)")
    print("- Provides effectiveness estimation")
    print("- Comprehensive validation and error handling")


if __name__ == "__main__":
    asyncio.run(main())
