#!/usr/bin/env python3
"""
Showcase of all reference attack implementations.

Demonstrates the usage and capabilities of all reference attacks:
- TCPTimingManipulationAttack
- UrgentPointerManipulationAttack
- WindowScalingAttack
- PayloadObfuscationAttack
"""

import time

from core.bypass.attacks.reference.tcp_timing_manipulation_attack import (
    create_tcp_timing_attack,
    create_burst_timing_attack,
    create_fibonacci_timing_attack,
    create_congestion_simulation_attack,
)
from core.bypass.attacks.reference.urgent_pointer_manipulation_attack import (
    create_urgent_pointer_attack,
    create_aggressive_urgent_attack,
    create_subtle_urgent_attack,
)
from core.bypass.attacks.reference.window_scaling_attack import (
    create_window_scaling_attack,
    create_zero_window_attack,
    create_oscillating_window_attack,
    create_extreme_window_attack,
)
from core.bypass.attacks.reference.payload_obfuscation_attack import (
    ObfuscationMethod,
    create_payload_obfuscation_attack,
    create_base64_obfuscation_attack,
    create_xor_obfuscation_attack,
    create_mixed_obfuscation_attack,
)
from core.bypass.attacks.base import AttackContext


def demonstrate_tcp_timing_attacks():
    """Demonstrate TCP timing manipulation attacks."""
    print("=== TCP Timing Manipulation Attacks ===")

    # Test payload
    payload = b"GET /restricted-api/v1/data HTTP/1.1\r\nHost: restricted.example.com\r\nAuthorization: Bearer secret123\r\n\r\n"

    context = AttackContext(
        dst_ip="203.0.113.10",
        dst_port=443,
        payload=payload,
        connection_id="timing_demo",
    )

    # Test different timing patterns
    timing_variants = [
        ("Standard Random", create_tcp_timing_attack()),
        ("Burst Pattern", create_burst_timing_attack()),
        ("Fibonacci Sequence", create_fibonacci_timing_attack()),
        ("Congestion Simulation", create_congestion_simulation_attack()),
    ]

    for variant_name, attack in timing_variants:
        result = attack.execute(context)
        effectiveness = attack.estimate_effectiveness(context)

        print(f"\n{variant_name}:")
        print(f"  Status: {result.status}")
        print(f"  Segments: {len(result._segments)}")
        print(f"  Timing Pattern: {result.metadata['timing_pattern']}")
        print(f"  Effectiveness: {effectiveness:.1%}")

        # Show timing delays
        delays = [options["delay_ms"] for _, _, options in result._segments]
        print(f"  Delays: {[f'{d:.1f}ms' for d in delays]}")

        # Show segment details
        for i, (segment_payload, seq_offset, options) in enumerate(result._segments):
            print(
                f"    Segment {i+1}: {len(segment_payload)} bytes, offset={seq_offset}, delay={options['delay_ms']:.1f}ms"
            )


def demonstrate_urgent_pointer_attacks():
    """Demonstrate urgent pointer manipulation attacks."""
    print("\n=== Urgent Pointer Manipulation Attacks ===")

    payload = b'POST /admin/critical-action HTTP/1.1\r\nHost: admin.example.com\r\nContent-Type: application/json\r\n\r\n{"action": "delete_all"}'

    context = AttackContext(
        dst_ip="198.51.100.20",
        dst_port=80,
        payload=payload,
        connection_id="urgent_demo",
    )

    urgent_variants = [
        ("Standard Urgent", create_urgent_pointer_attack()),
        ("Aggressive Urgent", create_aggressive_urgent_attack()),
        ("Subtle Urgent", create_subtle_urgent_attack()),
    ]

    for variant_name, attack in urgent_variants:
        result = attack.execute(context)
        effectiveness = attack.estimate_effectiveness(context)

        print(f"\n{variant_name}:")
        print(f"  Status: {result.status}")
        print(f"  Segments: {len(result._segments)}")
        print(f"  Urgent Segments: {result.metadata['urgent_segments']}")
        print(f"  Effectiveness: {effectiveness:.1%}")

        # Show urgent pointer details
        for i, (segment_payload, seq_offset, options) in enumerate(result._segments):
            is_urgent = bool(options["flags"] & 0x20)
            urgent_ptr = options.get("urgent_pointer", 0)

            print(
                f"    Segment {i+1}: {len(segment_payload)} bytes, URG={is_urgent}, ptr={urgent_ptr}"
            )
            if is_urgent:
                print("      Urgent data detected in segment")


def demonstrate_window_scaling_attacks():
    """Demonstrate window scaling attacks."""
    print("\n=== Window Scaling Attacks ===")

    payload = (
        b"PUT /api/config HTTP/1.1\r\nHost: config.example.com\r\nContent-Length: 200\r\n\r\n"
        + b"config_data="
        + b"X" * 180
    )

    context = AttackContext(
        dst_ip="203.0.113.30",
        dst_port=443,
        payload=payload,
        connection_id="window_demo",
    )

    window_variants = [
        ("Standard Random", create_window_scaling_attack()),
        ("Zero Window", create_zero_window_attack()),
        ("Oscillating Window", create_oscillating_window_attack()),
        ("Extreme Values", create_extreme_window_attack()),
    ]

    for variant_name, attack in window_variants:
        result = attack.execute(context)
        effectiveness = attack.estimate_effectiveness(context)

        print(f"\n{variant_name}:")
        print(f"  Status: {result.status}")
        print(f"  Segments: {len(result._segments)}")
        print(f"  Window Pattern: {result.metadata['window_pattern']}")
        print(f"  Effectiveness: {effectiveness:.1%}")

        # Show window sizes
        window_sizes = [options["window_size"] for _, _, options in result._segments]
        print(f"  Window Sizes: {window_sizes}")

        # Analyze window pattern
        zero_windows = sum(1 for ws in window_sizes if ws == 0)
        max_window = max(window_sizes)
        min_window = min(window_sizes)

        print(f"    Zero windows: {zero_windows}/{len(window_sizes)}")
        print(f"    Range: {min_window} - {max_window}")


def demonstrate_payload_obfuscation_attacks():
    """Demonstrate payload obfuscation attacks."""
    print("\n=== Payload Obfuscation Attacks ===")

    payload = b"SELECT * FROM sensitive_table WHERE user_id = 'admin' AND password = 'secret123'"

    context = AttackContext(
        dst_ip="198.51.100.40",
        dst_port=3306,  # MySQL port
        payload=payload,
        connection_id="obfuscation_demo",
    )

    obfuscation_variants = [
        ("Base64 Encoding", create_base64_obfuscation_attack()),
        ("XOR Cipher", create_xor_obfuscation_attack()),
        ("Mixed Obfuscation", create_mixed_obfuscation_attack()),
        (
            "Custom Multi-Method",
            create_payload_obfuscation_attack(
                obfuscation_method=ObfuscationMethod.MIXED_ENCODING,
                per_segment_obfuscation=True,
                add_noise=True,
            ),
        ),
    ]

    print(f"Original payload: {payload[:50]}{'...' if len(payload) > 50 else ''}")
    print(f"Original length: {len(payload)} bytes")

    for variant_name, attack in obfuscation_variants:
        result = attack.execute(context)
        effectiveness = attack.estimate_effectiveness(context)

        print(f"\n{variant_name}:")
        print(f"  Status: {result.status}")
        print(f"  Segments: {len(result._segments)}")
        print(f"  Obfuscation Method: {result.metadata['obfuscation_method']}")
        print(f"  Effectiveness: {effectiveness:.1%}")

        # Show obfuscated segments
        total_obfuscated_size = 0
        for i, (segment_payload, seq_offset, options) in enumerate(result._segments):
            total_obfuscated_size += len(segment_payload)
            preview = (
                segment_payload[:30] if len(segment_payload) > 30 else segment_payload
            )

            print(
                f"    Segment {i+1}: {len(segment_payload)} bytes at offset {seq_offset}"
            )
            print(f"      Preview: {preview}...")

        print(
            f"  Total obfuscated size: {total_obfuscated_size} bytes (vs {len(payload)} original)"
        )


def demonstrate_attack_combinations():
    """Demonstrate combining multiple attacks."""
    print("\n=== Attack Combinations ===")

    payload = b'POST /api/admin/delete-user HTTP/1.1\r\nHost: admin.example.com\r\nAuthorization: Bearer admin_token\r\nContent-Type: application/json\r\n\r\n{"user_id": "target_user"}'

    context = AttackContext(
        dst_ip="203.0.113.50", dst_port=443, payload=payload, connection_id="combo_demo"
    )

    # Create combination scenarios
    combinations = [
        (
            "Timing + Obfuscation",
            [
                create_burst_timing_attack(name="combo_timing"),
                create_xor_obfuscation_attack(name="combo_obfuscation"),
            ],
        ),
        (
            "Window + Urgent",
            [
                create_extreme_window_attack(name="combo_window"),
                create_aggressive_urgent_attack(name="combo_urgent"),
            ],
        ),
        (
            "All Techniques",
            [
                create_fibonacci_timing_attack(name="combo_timing"),
                create_subtle_urgent_attack(name="combo_urgent"),
                create_oscillating_window_attack(name="combo_window"),
                create_mixed_obfuscation_attack(name="combo_obfuscation"),
            ],
        ),
    ]

    for combo_name, attacks in combinations:
        print(f"\n{combo_name}:")

        total_segments = 0
        combined_effectiveness = 1.0

        for attack in attacks:
            result = attack.execute(context)
            effectiveness = attack.estimate_effectiveness(context)

            total_segments += len(result._segments)
            combined_effectiveness *= effectiveness

            print(
                f"  {attack.name}: {len(result._segments)} segments, {effectiveness:.1%} effective"
            )

        print(
            f"  Combined: {total_segments} total segments, {combined_effectiveness:.1%} combined effectiveness"
        )


def demonstrate_real_world_scenarios():
    """Demonstrate attacks against real-world scenarios."""
    print("\n=== Real-World Scenarios ===")

    scenarios = [
        (
            "HTTP API Request",
            AttackContext(
                dst_ip="93.184.216.34",
                dst_port=80,
                payload=b"GET /api/v1/users/sensitive HTTP/1.1\r\nHost: api.blocked.com\r\nAuthorization: Bearer secret\r\n\r\n",
                connection_id="http_api",
            ),
        ),
        (
            "HTTPS Login",
            AttackContext(
                dst_ip="198.51.100.10",
                dst_port=443,
                payload=b'POST /login HTTP/1.1\r\nHost: secure.blocked.com\r\nContent-Type: application/json\r\n\r\n{"username":"admin","password":"secret"}',
                connection_id="https_login",
            ),
        ),
        (
            "Database Query",
            AttackContext(
                dst_ip="203.0.113.100",
                dst_port=3306,
                payload=b"SELECT user_data FROM users WHERE role='admin' AND active=1",
                connection_id="db_query",
            ),
        ),
        (
            "File Transfer",
            AttackContext(
                dst_ip="198.51.100.200",
                dst_port=21,
                payload=b"RETR /confidential/financial_report.pdf",
                connection_id="ftp_transfer",
            ),
        ),
    ]

    # Test each scenario with different attacks
    test_attacks = [
        ("Timing Manipulation", create_congestion_simulation_attack()),
        ("Urgent Pointer", create_aggressive_urgent_attack()),
        ("Window Scaling", create_zero_window_attack()),
        ("Payload Obfuscation", create_mixed_obfuscation_attack()),
    ]

    for scenario_name, context in scenarios:
        print(f"\n{scenario_name} ({context.dst_ip}:{context.dst_port}):")

        best_attack = None
        best_effectiveness = 0.0

        for attack_name, attack in test_attacks:
            try:
                result = attack.execute(context)
                effectiveness = attack.estimate_effectiveness(context)

                print(
                    f"  {attack_name}: {result.status}, {len(result._segments)} segments, {effectiveness:.1%}"
                )

                if effectiveness > best_effectiveness:
                    best_effectiveness = effectiveness
                    best_attack = attack_name

            except Exception as e:
                print(f"  {attack_name}: FAILED - {e}")

        if best_attack:
            print(f"  Best attack: {best_attack} ({best_effectiveness:.1%})")


def demonstrate_performance_analysis():
    """Demonstrate performance analysis of attacks."""
    print("\n=== Performance Analysis ===")

    payload = (
        b"GET /performance-test HTTP/1.1\r\nHost: test.example.com\r\n\r\n"
        + b"X" * 1000
    )

    context = AttackContext(
        dst_ip="203.0.113.200", dst_port=80, payload=payload, connection_id="perf_test"
    )

    # Test attacks with different configurations
    performance_tests = [
        ("Small Segments", create_tcp_timing_attack(segment_count=3)),
        ("Medium Segments", create_tcp_timing_attack(segment_count=8)),
        ("Large Segments", create_tcp_timing_attack(segment_count=15)),
        (
            "Complex Obfuscation",
            create_mixed_obfuscation_attack(per_segment_obfuscation=True),
        ),
        ("Simple Obfuscation", create_base64_obfuscation_attack()),
        ("Aggressive Urgent", create_aggressive_urgent_attack()),
        ("Subtle Urgent", create_subtle_urgent_attack()),
    ]

    for test_name, attack in performance_tests:
        start_time = time.time()

        result = attack.execute(context)

        execution_time = time.time() - start_time

        # Calculate metrics
        total_payload_size = sum(len(payload) for payload, _, _ in result._segments)
        avg_segment_size = (
            total_payload_size / len(result._segments) if result._segments else 0
        )

        print(f"\n{test_name}:")
        print(f"  Execution time: {execution_time*1000:.2f}ms")
        print(f"  Segments: {len(result._segments)}")
        print(f"  Total payload: {total_payload_size} bytes")
        print(f"  Avg segment size: {avg_segment_size:.1f} bytes")
        print(f"  Throughput: {total_payload_size/execution_time:.0f} bytes/sec")


def main():
    """Run all demonstrations."""
    print("Reference Attacks Showcase")
    print("=" * 50)

    try:
        demonstrate_tcp_timing_attacks()
        demonstrate_urgent_pointer_attacks()
        demonstrate_window_scaling_attacks()
        demonstrate_payload_obfuscation_attacks()
        demonstrate_attack_combinations()
        demonstrate_real_world_scenarios()
        demonstrate_performance_analysis()

        print("\n" + "=" * 50)
        print("All demonstrations completed successfully!")

    except Exception as e:
        print(f"\nError during demonstration: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
