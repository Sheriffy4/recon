#!/usr/bin/env python3
"""
Demo script for HTTP manipulation attacks.

Shows how the HTTP manipulation attacks work and what they produce.
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.bypass.attacks.base import AttackContext, AttackResult
from http_manipulation import (
    HeaderModificationAttack,
    MethodManipulationAttack,
    ChunkedEncodingAttack,
    PipelineManipulationAttack,
    HeaderSplittingAttack,
    CaseManipulationAttack,
)


def print_separator(title: str):
    """Print a section separator."""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")


def print_segments(result: AttackResult):
    """Print segments from attack result."""
    if not result.has_segments():
        print("No segments produced")
        return

    segments = result.segments
    print(f"Produced {len(segments)} segments:")

    for i, (payload_data, seq_offset, options) in enumerate(segments):
        print(f"\nSegment {i+1}:")
        print(f"  Sequence offset: {seq_offset}")
        print(f"  Options: {options}")
        print(f"  Payload ({len(payload_data)} bytes):")

        # Try to decode as text for display
        try:
            payload_str = payload_data.decode("utf-8", errors="replace")
            # Show first 200 chars
            if len(payload_str) > 200:
                payload_str = payload_str[:200] + "..."
            print(f"    {repr(payload_str)}")
        except:
            print(f"    Binary data: {payload_data[:50]}...")


def demo_header_modification():
    """Demo header modification attack."""
    print_separator("HTTP Header Modification Attack")

    attack = HeaderModificationAttack()
    context = AttackContext(
        dst_ip="93.184.216.34",
        dst_port=80,
        domain="example.com",
        payload=b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent\r\n\r\n",
        params={
            "custom_headers": {"X-Bypass": "test", "X-Custom": "header"},
            "case_modification": True,
            "order_randomization": True,
            "space_manipulation": True,
        },
    )

    result = attack.execute(context)

    print(f"Status: {result.status}")
    print(f"Technique: {result.technique_used}")
    print(f"Processing time: {result.processing_time_ms:.2f}ms")
    print(f"Headers modified: {result.get_metadata('headers_modified')}")

    print_segments(result)


def demo_method_manipulation():
    """Demo method manipulation attack."""
    print_separator("HTTP Method Manipulation Attack")

    attack = MethodManipulationAttack()
    context = AttackContext(
        dst_ip="93.184.216.34",
        dst_port=80,
        domain="example.com",
        payload=b"GET /api/data HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer token\r\n\r\n",
        params={
            "target_method": "POST",
            "add_override_header": True,
            "fake_headers": {
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "192.168.1.1",
            },
        },
    )

    result = attack.execute(context)

    print(f"Status: {result.status}")
    print(f"Original method: {result.get_metadata('original_method')}")
    print(f"Target method: {result.get_metadata('target_method')}")
    print(f"Override header added: {result.get_metadata('override_header_added')}")

    print_segments(result)


def demo_chunked_encoding():
    """Demo chunked encoding attack."""
    print_separator("HTTP Chunked Encoding Attack")

    attack = ChunkedEncodingAttack()
    context = AttackContext(
        dst_ip="93.184.216.34",
        dst_port=80,
        domain="example.com",
        payload=b'POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{"message": "Hello, World! This is a test message for chunked encoding."}',
        params={"chunk_sizes": [4, 8, 12, 16], "randomize_sizes": True},
    )

    result = attack.execute(context)

    print(f"Status: {result.status}")
    print(f"Chunk sizes: {result.get_metadata('chunk_sizes')}")
    print(f"Randomize sizes: {result.get_metadata('randomize_sizes')}")

    print_segments(result)


def demo_pipeline_manipulation():
    """Demo pipeline manipulation attack."""
    print_separator("HTTP Pipeline Manipulation Attack")

    attack = PipelineManipulationAttack()
    context = AttackContext(
        dst_ip="93.184.216.34",
        dst_port=80,
        domain="example.com",
        payload=b"GET /resource HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n",
        params={
            "pipeline_count": 4,
            "delay_between_requests": 10.0,
            "randomize_headers": True,
        },
    )

    result = attack.execute(context)

    print(f"Status: {result.status}")
    print(f"Pipeline count: {result.get_metadata('pipeline_count')}")
    print(f"Delay between requests: {result.get_metadata('delay_between_requests')}ms")

    print_segments(result)


def demo_header_splitting():
    """Demo header splitting attack."""
    print_separator("HTTP Header Splitting Attack")

    attack = HeaderSplittingAttack()
    context = AttackContext(
        dst_ip="93.184.216.34",
        dst_port=80,
        domain="example.com",
        payload=b"GET /protected HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nAccept-Language: en-US\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n",
        params={
            "headers_per_segment": 2,
            "delay_between_segments": 2.0,
            "randomize_order": True,
        },
    )

    result = attack.execute(context)

    print(f"Status: {result.status}")
    print(f"Headers per segment: {result.get_metadata('headers_per_segment')}")
    print(f"Total segments: {result.get_metadata('total_segments')}")

    print_segments(result)


def demo_case_manipulation():
    """Demo case manipulation attack."""
    print_separator("HTTP Case Manipulation Attack")

    attack = CaseManipulationAttack()
    context = AttackContext(
        dst_ip="93.184.216.34",
        dst_port=80,
        domain="example.com",
        payload=b"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 29\r\n\r\nusername=admin&password=secret",
        params={
            "method_case": "mixed",
            "header_case": "mixed",
            "randomize_each_header": True,
        },
    )

    result = attack.execute(context)

    print(f"Status: {result.status}")
    print(f"Original method: {result.get_metadata('original_method')}")
    print(f"Target method: {result.get_metadata('target_method')}")
    print(f"Method case: {result.get_metadata('method_case')}")

    print_segments(result)


def demo_attack_comparison():
    """Demo comparison of different attacks on the same payload."""
    print_separator("Attack Comparison")

    base_payload = b"GET /blocked-content HTTP/1.1\r\nHost: blocked-site.com\r\nUser-Agent: Browser\r\n\r\n"

    attacks = [
        ("Original", None, {}),
        (
            "Header Modification",
            HeaderModificationAttack(),
            {"case_modification": True},
        ),
        ("Method Manipulation", MethodManipulationAttack(), {"target_method": "POST"}),
        ("Case Manipulation", CaseManipulationAttack(), {"method_case": "mixed"}),
        ("Header Splitting", HeaderSplittingAttack(), {"headers_per_segment": 1}),
    ]

    for name, attack, params in attacks:
        print(f"\n--- {name} ---")

        if attack is None:
            # Show original payload
            print(f"Original payload ({len(base_payload)} bytes):")
            try:
                payload_str = base_payload.decode("utf-8", errors="replace")
                print(f"  {repr(payload_str)}")
            except:
                print(f"  Binary data: {base_payload}")
        else:
            context = AttackContext(
                dst_ip="93.184.216.34",
                dst_port=80,
                domain="blocked-site.com",
                payload=base_payload,
                params=params,
            )

            result = attack.execute(context)
            print(f"Status: {result.status}")
            print(f"Segments: {len(result.segments) if result.has_segments() else 0}")
            print(
                f"Total bytes: {sum(len(seg[0]) for seg in result.segments) if result.has_segments() else 0}"
            )

            if result.has_segments() and len(result.segments) > 0:
                # Show first segment as example
                first_segment = result.segments[0]
                payload_data, seq_offset, options = first_segment
                try:
                    payload_str = payload_data.decode("utf-8", errors="replace")
                    if len(payload_str) > 100:
                        payload_str = payload_str[:100] + "..."
                    print(f"  First segment: {repr(payload_str)}")
                except:
                    print(f"  First segment: Binary data ({len(payload_data)} bytes)")


def main():
    """Run all HTTP attack demos."""
    print("HTTP Manipulation Attacks Demo")
    print("=" * 60)
    print("This demo shows how different HTTP manipulation attacks work")
    print("and what kind of segments they produce for DPI bypass.")

    try:
        demo_header_modification()
        demo_method_manipulation()
        demo_chunked_encoding()
        demo_pipeline_manipulation()
        demo_header_splitting()
        demo_case_manipulation()
        demo_attack_comparison()

        print_separator("Demo Complete")
        print("All HTTP manipulation attacks demonstrated successfully!")
        print("\nKey features implemented:")
        print("✓ HTTP header modification with case changes")
        print("✓ HTTP method manipulation with override headers")
        print("✓ HTTP chunked encoding for body fragmentation")
        print("✓ HTTP pipeline manipulation for multiple requests")
        print("✓ HTTP header splitting across TCP segments")
        print("✓ HTTP case manipulation for evasion")
        print(
            "\nAll attacks produce segments compatible with the modern bypass engine."
        )

    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
