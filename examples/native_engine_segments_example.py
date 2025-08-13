#!/usr/bin/env python3
"""
Example usage of NativePyDivertEngine with segments orchestration.
Demonstrates the integration of segments architecture with the native engine.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bypass.engines.native_pydivert_engine import NativePydivertEngine, EngineConfig
from core.bypass.attacks.base import AttackResult, AttackStatus, AttackContext
from core.bypass.attacks.segment_packet_builder import SegmentPacketBuilder
from unittest.mock import Mock


class MockSegmentAttack:
    """Mock attack that returns segments for demonstration."""
    
    def __init__(self, name: str):
        self.name = name
    
    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute attack and return segments."""
        payload = context.payload
        
        if self.name == "fakeddisorder":
            return self._create_fakeddisorder_segments(payload)
        elif self.name == "multisplit":
            return self._create_multisplit_segments(payload)
        else:
            return AttackResult(status=AttackStatus.FAILED, error_message="Unknown attack")
    
    def _create_fakeddisorder_segments(self, payload: bytes) -> AttackResult:
        """Create FakedDisorder segments."""
        split_pos = min(10, len(payload) // 2)
        
        if split_pos >= len(payload):
            return AttackResult(status=AttackStatus.FAILED, error_message="Payload too small")
        
        # Create fake packet
        fake_payload = b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
        
        # Split real payload
        part1 = payload[:split_pos]
        part2 = payload[split_pos:]
        
        # Create segments
        segments = [
            # Fake packet with low TTL (will be dropped)
            (fake_payload, 0, {"ttl": 2, "delay_ms": 5}),
            
            # Second part first (creates disorder)
            (part2, split_pos, {"delay_ms": 10}),
            
            # First part last
            (part1, 0, {})
        ]
        
        return AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used="fakeddisorder",
            packets_sent=len(segments),
            metadata={"segments": segments}
        )
    
    def _create_multisplit_segments(self, payload: bytes) -> AttackResult:
        """Create Multisplit segments."""
        split_count = 3
        chunk_size = len(payload) // split_count
        
        if chunk_size == 0:
            return AttackResult(status=AttackStatus.FAILED, error_message="Payload too small")
        
        segments = []
        for i in range(split_count):
            start = i * chunk_size
            end = start + chunk_size if i < split_count - 1 else len(payload)
            chunk = payload[start:end]
            
            segments.append((chunk, start, {
                "delay_ms": i * 3,  # Progressive delays
                "window_size": 32768 - (i * 1024)  # Varying window
            }))
        
        return AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used="multisplit",
            packets_sent=len(segments),
            metadata={"segments": segments}
        )


def demonstrate_enhanced_context_creation():
    """Demonstrate enhanced AttackContext creation."""
    
    print("=== Enhanced AttackContext Creation Demo ===\n")
    
    # Create mock engine
    config = EngineConfig(debug=True)
    
    # Mock pydivert to avoid dependency
    import core.bypass.engines.native_pydivert_engine as engine_module
    original_has_pydivert = engine_module.HAS_PYDIVERT
    engine_module.HAS_PYDIVERT = True
    engine_module.pydivert = Mock()
    
    try:
        engine = NativePydivertEngine(config)
        
        # Create mock packet
        mock_packet = Mock()
        mock_packet.dst_addr = "192.168.1.100"
        mock_packet.dst_port = 443
        mock_packet.src_addr = "10.0.0.50"
        mock_packet.src_port = 12345
        
        # Mock TCP info
        mock_packet.tcp = Mock()
        mock_packet.tcp.payload = b"GET /api/data HTTP/1.1\r\nHost: example.com\r\n\r\n"
        mock_packet.tcp.seq_num = 1000000
        mock_packet.tcp.ack_num = 2000000
        mock_packet.tcp.window_size = 32768
        mock_packet.tcp.urg_ptr = 0
        
        # Mock TCP flags
        mock_packet.tcp.fin = False
        mock_packet.tcp.syn = False
        mock_packet.tcp.rst = False
        mock_packet.tcp.psh = True
        mock_packet.tcp.ack = True
        mock_packet.tcp.urg = False
        mock_packet.tcp.ece = False
        mock_packet.tcp.cwr = False
        
        # Create enhanced context
        context = engine._create_enhanced_attack_context(mock_packet)
        
        print("Enhanced AttackContext created:")
        print(f"  Connection: {context.src_ip}:{context.src_port} -> {context.dst_ip}:{context.dst_port}")
        print(f"  TCP Seq: {context.tcp_seq}, ACK: {context.tcp_ack}")
        print(f"  TCP Flags: 0x{context.tcp_flags:02x} ({context.get_tcp_flags_string()})")
        print(f"  Window Size: {context.tcp_window_size}")
        print(f"  Connection ID: {context.connection_id}")
        print(f"  Session Established: {context.session_established}")
        print(f"  Payload Size: {len(context.payload)} bytes")
        print()
        
    finally:
        # Restore original state
        engine_module.HAS_PYDIVERT = original_has_pydivert


def demonstrate_segments_orchestration():
    """Demonstrate segments orchestration functionality."""
    
    print("=== Segments Orchestration Demo ===\n")
    
    # Create segment packet builder
    builder = SegmentPacketBuilder()
    
    # Create test context
    context = AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        src_ip="10.0.0.50",
        src_port=12345,
        tcp_seq=1000000,
        tcp_ack=2000000,
        tcp_flags=0x18,
        tcp_window_size=32768,
        connection_id="test-connection"
    )
    
    # Create mock attack result with segments
    segments = [
        (b"fake packet data", 0, {"ttl": 2, "delay_ms": 5}),
        (b"real data part 2", 15, {"delay_ms": 10}),
        (b"real data part 1", 0, {"bad_checksum": True})
    ]
    
    attack_result = AttackResult(
        status=AttackStatus.SUCCESS,
        technique_used="fakeddisorder",
        packets_sent=len(segments),
        metadata={"segments": segments}
    )
    
    print("Segments to be orchestrated:")
    for i, (payload_data, seq_offset, options) in enumerate(segments):
        print(f"  Segment {i+1}: {len(payload_data)} bytes, offset={seq_offset}, options={options}")
    
    print("\nBuilding packets for segments:")
    
    # Build packets for each segment
    packet_infos = []
    for i, segment in enumerate(segments):
        try:
            packet_info = builder.build_segment(
                segment[0],  # payload_data
                segment[1],  # seq_offset
                segment[2],  # options_dict
                context
            )
            packet_infos.append(packet_info)
            
            print(f"  Packet {i+1}: {packet_info.packet_size} bytes, "
                  f"seq={packet_info.tcp_seq}, ttl={packet_info.ttl}, "
                  f"corrupted={packet_info.checksum_corrupted}")
            
        except Exception as e:
            print(f"  Packet {i+1}: Failed to build - {e}")
    
    # Get builder statistics
    stats = builder.get_stats()
    print(f"\nBuilder Statistics:")
    print(f"  Packets built: {stats['packets_built']}")
    print(f"  Total build time: {stats['total_build_time_ms']:.3f} ms")
    print(f"  TTL modifications: {stats['ttl_modifications']}")
    print(f"  Checksum corruptions: {stats['checksum_corruptions']}")
    print()


def demonstrate_attack_integration():
    """Demonstrate attack integration with segments."""
    
    print("=== Attack Integration Demo ===\n")
    
    # Create mock attacks
    fakeddisorder_attack = MockSegmentAttack("fakeddisorder")
    multisplit_attack = MockSegmentAttack("multisplit")
    
    # Test payload
    test_payload = b"GET /secret/api HTTP/1.1\r\nHost: target.com\r\nAuthorization: Bearer secret123\r\n\r\n"
    
    # Create context
    context = AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        payload=test_payload
    )
    
    print("Testing attacks with segments:")
    print(f"Test payload: {len(test_payload)} bytes")
    print()
    
    # Test FakedDisorder attack
    import asyncio
    
    async def test_attacks():
        print("1. FakedDisorder Attack:")
        result1 = await fakeddisorder_attack.execute(context)
        
        if result1.status == AttackStatus.SUCCESS and result1.has_segments():
            segments = result1.segments
            print(f"   Status: SUCCESS")
            print(f"   Technique: {result1.technique_used}")
            print(f"   Segments: {len(segments)}")
            
            for i, (payload_data, seq_offset, options) in enumerate(segments):
                print(f"     Segment {i+1}: {len(payload_data)} bytes, offset={seq_offset}, {options}")
        else:
            print(f"   Status: {result1.status}")
            print(f"   Error: {result1.error_message}")
        
        print()
        
        # Test Multisplit attack
        print("2. Multisplit Attack:")
        result2 = await multisplit_attack.execute(context)
        
        if result2.status == AttackStatus.SUCCESS and result2.has_segments():
            segments = result2.segments
            print(f"   Status: SUCCESS")
            print(f"   Technique: {result2.technique_used}")
            print(f"   Segments: {len(segments)}")
            
            for i, (payload_data, seq_offset, options) in enumerate(segments):
                print(f"     Segment {i+1}: {len(payload_data)} bytes, offset={seq_offset}, {options}")
        else:
            print(f"   Status: {result2.status}")
            print(f"   Error: {result2.error_message}")
    
    # Run async tests
    asyncio.run(test_attacks())
    print()


def demonstrate_timing_control():
    """Demonstrate precise timing control in segments."""
    
    print("=== Timing Control Demo ===\n")
    
    # Create segments with different timing patterns
    timing_segments = [
        (b"immediate", 0, {}),                    # No delay
        (b"delayed_5ms", 9, {"delay_ms": 5}),    # 5ms delay
        (b"delayed_10ms", 19, {"delay_ms": 10}), # 10ms delay
        (b"delayed_2.5ms", 30, {"delay_ms": 2.5}) # Sub-millisecond delay
    ]
    
    print("Timing patterns in segments:")
    total_delay = 0
    for i, (payload_data, seq_offset, options) in enumerate(timing_segments):
        delay = options.get("delay_ms", 0)
        total_delay += delay
        print(f"  Segment {i+1}: {len(payload_data)} bytes, delay={delay}ms, cumulative={total_delay}ms")
    
    print(f"\nTotal execution time (delays only): {total_delay}ms")
    print("Note: In real execution, packet construction and transmission time would be added.")
    print()


def demonstrate_error_handling():
    """Demonstrate error handling in segments orchestration."""
    
    print("=== Error Handling Demo ===\n")
    
    # Test various error conditions
    error_cases = [
        {
            "name": "Empty segments",
            "segments": [],
            "description": "No segments to process"
        },
        {
            "name": "Invalid segment format",
            "segments": [(b"data", 0)],  # Missing options_dict
            "description": "Segment with wrong tuple length"
        },
        {
            "name": "Invalid payload type",
            "segments": [("not bytes", 0, {})],
            "description": "Payload data is not bytes"
        },
        {
            "name": "Invalid options",
            "segments": [(b"data", 0, {"ttl": 256})],  # TTL out of range
            "description": "Invalid TTL value"
        }
    ]
    
    builder = SegmentPacketBuilder()
    context = AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        tcp_seq=1000000
    )
    
    print("Testing error conditions:")
    
    for case in error_cases:
        print(f"\n{case['name']}:")
        print(f"  Description: {case['description']}")
        
        try:
            # Validate segments
            from core.bypass.attacks.segment_packet_builder import validate_segments_for_building
            is_valid, error_msg = validate_segments_for_building(case['segments'], context)
            
            if is_valid:
                print("  Validation: PASS")
                # Try to build packets
                for segment in case['segments']:
                    packet_info = builder.build_segment(segment[0], segment[1], segment[2], context)
                    print(f"  Build: SUCCESS ({packet_info.packet_size} bytes)")
            else:
                print(f"  Validation: FAIL - {error_msg}")
                
        except Exception as e:
            print(f"  Exception: {type(e).__name__}: {e}")
    
    print()


def main():
    """Run all demonstrations."""
    
    print("NativePyDivertEngine Segments Orchestration Demo")
    print("=" * 60)
    print()
    
    try:
        demonstrate_enhanced_context_creation()
        demonstrate_segments_orchestration()
        demonstrate_attack_integration()
        demonstrate_timing_control()
        demonstrate_error_handling()
        
        print("✅ All demonstrations completed successfully!")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()