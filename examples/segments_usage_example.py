#!/usr/bin/env python3
"""
Example usage of the new segments orchestration system.
Demonstrates how to create attacks that return segment scenarios.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bypass.attacks.base import (
    BaseAttack, 
    AttackContext, 
    AttackResult, 
    AttackResultHelper,
    SegmentTuple
)


class ExampleFakedDisorderAttack(BaseAttack):
    """
    Example implementation of FakedDisorder attack using segments.
    
    This demonstrates the new segments architecture where attacks
    return detailed packet scenarios instead of single payloads.
    """
    
    @property
    def name(self) -> str:
        return "example_fakeddisorder"
    
    @property
    def description(self) -> str:
        return "Example FakedDisorder attack using segments orchestration"
    
    @property
    def category(self) -> str:
        return "tcp"
    
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute FakedDisorder attack using segments.
        
        Strategy:
        1. Send fake packet with low TTL (will be dropped by DPI)
        2. Send second part of real payload first
        3. Send first part of real payload last (creates disorder)
        """
        payload = context.payload
        split_pos = context.params.get("split_pos", 3)
        
        if split_pos >= len(payload):
            return AttackResultHelper.create_failure_result(
                "split_pos exceeds payload length"
            )
        
        # Create fake payload (decoy packet)
        fake_payload = b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
        
        # Split real payload
        part1 = payload[:split_pos]
        part2 = payload[split_pos:]
        
        # Create segment scenario
        segments = [
            # Segment 1: Fake packet with low TTL (will be dropped)
            (fake_payload, 0, {
                "ttl": 2,           # Low TTL - packet will be dropped
                "delay_ms": 5       # Small delay before next packet
            }),
            
            # Segment 2: Second part of real payload (sent first)
            (part2, split_pos, {
                "delay_ms": 10      # Delay to create timing gap
            }),
            
            # Segment 3: First part of real payload (sent last - creates disorder)
            (part1, 0, {
                # No delay - send immediately
            })
        ]
        
        return AttackResultHelper.create_segments_result(
            technique_used="fakeddisorder",
            segments=segments,
            metadata={
                "split_pos": split_pos,
                "fake_payload_size": len(fake_payload),
                "real_payload_size": len(payload)
            }
        )


class ExampleMultisplitAttack(BaseAttack):
    """
    Example implementation of Multisplit attack using segments.
    
    Splits payload into multiple overlapping chunks with timing variations.
    """
    
    @property
    def name(self) -> str:
        return "example_multisplit"
    
    @property
    def description(self) -> str:
        return "Example Multisplit attack using segments orchestration"
    
    @property
    def category(self) -> str:
        return "tcp"
    
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute Multisplit attack using segments.
        
        Strategy:
        1. Split payload into multiple chunks
        2. Add overlap between chunks to confuse DPI
        3. Send chunks with timing variations
        """
        payload = context.payload
        split_count = context.params.get("split_count", 3)
        overlap_size = context.params.get("overlap_size", 5)
        
        if len(payload) < split_count:
            return AttackResultHelper.create_failure_result(
                "payload too small for requested split_count"
            )
        
        # Calculate chunk size
        base_chunk_size = len(payload) // split_count
        segments = []
        
        for i in range(split_count):
            # Calculate chunk boundaries
            start = i * base_chunk_size
            
            if i == split_count - 1:
                # Last chunk - take remaining data
                end = len(payload)
            else:
                # Add overlap to confuse DPI state tracking
                end = min(start + base_chunk_size + overlap_size, len(payload))
            
            chunk = payload[start:end]
            
            # Add timing variation between chunks
            delay = i * 3  # 3ms between chunks
            
            segments.append((chunk, start, {
                "delay_ms": delay,
                "window_size": 32768 - (i * 1024)  # Vary window size
            }))
        
        return AttackResultHelper.create_segments_result(
            technique_used="multisplit",
            segments=segments,
            metadata={
                "split_count": split_count,
                "overlap_size": overlap_size,
                "base_chunk_size": base_chunk_size
            }
        )


class ExampleTimingManipulationAttack(BaseAttack):
    """
    Example attack that uses precise timing control.
    
    Demonstrates advanced timing options in segments.
    """
    
    @property
    def name(self) -> str:
        return "example_timing_manipulation"
    
    @property
    def description(self) -> str:
        return "Example timing manipulation attack using segments"
    
    @property
    def category(self) -> str:
        return "tcp"
    
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute timing manipulation attack.
        
        Strategy:
        1. Send payload in small chunks
        2. Use variable delays to confuse timing-based DPI
        3. Corrupt checksums on some packets
        """
        payload = context.payload
        chunk_size = context.params.get("chunk_size", 8)
        
        segments = []
        offset = 0
        
        while offset < len(payload):
            # Get chunk
            end = min(offset + chunk_size, len(payload))
            chunk = payload[offset:end]
            
            # Calculate variable delay (creates irregular timing pattern)
            delay = (offset % 3) * 2.5  # 0, 2.5, 5.0 ms pattern
            
            # Corrupt checksum on every 3rd packet
            corrupt_checksum = (len(segments) % 3) == 2
            
            # Use low TTL on first packet
            ttl = 2 if offset == 0 else 64
            
            segments.append((chunk, offset, {
                "delay_ms": delay,
                "bad_checksum": corrupt_checksum,
                "ttl": ttl
            }))
            
            offset = end
        
        return AttackResultHelper.create_segments_result(
            technique_used="timing_manipulation",
            segments=segments,
            metadata={
                "chunk_size": chunk_size,
                "total_chunks": len(segments),
                "timing_pattern": "variable"
            }
        )


def demonstrate_segments_usage():
    """Demonstrate how to use the segments system."""
    
    print("=== Segments Orchestration System Demo ===\n")
    
    # Create test context
    context = AttackContext(
        dst_ip="192.168.1.1",
        dst_port=443,
        domain="example.com",
        payload=b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n",
        params={"split_pos": 5}
    )
    
    # Test FakedDisorder attack
    print("1. FakedDisorder Attack:")
    attack1 = ExampleFakedDisorderAttack()
    result1 = attack1.execute(context)
    
    print(f"   Status: {result1.status}")
    print(f"   Technique: {result1.technique_used}")
    print(f"   Segments: {result1.get_segment_count()}")
    
    if result1.has_segments():
        for i, (payload_data, seq_offset, options) in enumerate(result1.segments):
            print(f"   Segment {i+1}: {len(payload_data)} bytes, offset={seq_offset}, options={options}")
    
    print()
    
    # Test Multisplit attack
    print("2. Multisplit Attack:")
    context.params = {"split_count": 4, "overlap_size": 3}
    attack2 = ExampleMultisplitAttack()
    result2 = attack2.execute(context)
    
    print(f"   Status: {result2.status}")
    print(f"   Technique: {result2.technique_used}")
    print(f"   Segments: {result2.get_segment_count()}")
    
    if result2.has_segments():
        for i, (payload_data, seq_offset, options) in enumerate(result2.segments):
            print(f"   Segment {i+1}: {len(payload_data)} bytes, offset={seq_offset}, options={options}")
    
    print()
    
    # Test Timing Manipulation attack
    print("3. Timing Manipulation Attack:")
    context.params = {"chunk_size": 6}
    attack3 = ExampleTimingManipulationAttack()
    result3 = attack3.execute(context)
    
    print(f"   Status: {result3.status}")
    print(f"   Technique: {result3.technique_used}")
    print(f"   Segments: {result3.get_segment_count()}")
    
    if result3.has_segments():
        for i, (payload_data, seq_offset, options) in enumerate(result3.segments):
            print(f"   Segment {i+1}: {len(payload_data)} bytes, offset={seq_offset}, options={options}")
    
    print()
    
    # Demonstrate helper functions
    print("4. Helper Functions Demo:")
    
    # Create segments result using helper
    segments = [
        (b"chunk1", 0, {"ttl": 2}),
        (b"chunk2", 6, {"delay_ms": 5}),
        (b"chunk3", 12, {"bad_checksum": True})
    ]
    
    helper_result = AttackResultHelper.create_segments_result(
        technique_used="helper_demo",
        segments=segments
    )
    
    print(f"   Helper result has segments: {AttackResultHelper.has_segments(helper_result)}")
    print(f"   Segments count: {len(AttackResultHelper.get_segments(helper_result))}")
    print(f"   Segments valid: {AttackResultHelper.validate_segments(segments)}")
    
    # Add segment using helper
    AttackResultHelper.add_segment(helper_result, b"chunk4", 18, {"delay_ms": 10})
    print(f"   After adding segment: {helper_result.get_segment_count()} segments")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demonstrate_segments_usage()