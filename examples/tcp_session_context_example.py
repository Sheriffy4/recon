#!/usr/bin/env python3
"""
Example usage of enhanced AttackContext with TCP session information.
Demonstrates how to use the new TCP session fields for segments orchestration.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bypass.attacks.base import (
    AttackContext, 
    BaseAttack, 
    AttackResult, 
    AttackResultHelper
)


class TCPSessionAwareAttack(BaseAttack):
    """
    Example attack that uses full TCP session information.
    
    Demonstrates how to use the enhanced AttackContext for precise
    TCP session control in segments orchestration.
    """
    
    @property
    def name(self) -> str:
        return "tcp_session_aware"
    
    @property
    def description(self) -> str:
        return "Example attack using full TCP session information"
    
    @property
    def category(self) -> str:
        return "tcp"
    
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute attack using TCP session information.
        
        This example shows how to:
        1. Use current sequence numbers
        2. Calculate proper offsets
        3. Manage TCP flags and window sizes
        4. Track connection state
        """
        payload = context.payload
        
        # Validate TCP session
        if not context.validate_tcp_session():
            return AttackResultHelper.create_failure_result(
                "Invalid TCP session information"
            )
        
        # Create connection ID for tracking
        conn_id = context.create_connection_id()
        
        # Split payload for demonstration
        chunk_size = len(payload) // 3
        if chunk_size == 0:
            chunk_size = len(payload)
        
        segments = []
        current_offset = 0
        
        # Segment 1: First chunk with modified window size
        if len(payload) > 0:
            chunk1_end = min(chunk_size, len(payload))
            chunk1 = payload[current_offset:chunk1_end]
            
            segments.append((chunk1, current_offset, {
                "window_size": context.tcp_window_size // 2,  # Reduce window
                "delay_ms": 5
            }))
            
            current_offset = chunk1_end
        
        # Segment 2: Second chunk with different flags
        if current_offset < len(payload):
            chunk2_end = min(current_offset + chunk_size, len(payload))
            chunk2 = payload[current_offset:chunk2_end]
            
            # Use PSH flag only (no ACK)
            segments.append((chunk2, current_offset, {
                "flags": 0x08,  # PSH only
                "delay_ms": 10
            }))
            
            current_offset = chunk2_end
        
        # Segment 3: Remaining data with urgent pointer
        if current_offset < len(payload):
            chunk3 = payload[current_offset:]
            
            segments.append((chunk3, current_offset, {
                "flags": 0x38,  # PSH+ACK+URG
                "delay_ms": 3
            }))
        
        # Create result with session metadata
        return AttackResultHelper.create_segments_result(
            technique_used="tcp_session_aware",
            segments=segments,
            metadata={
                "connection_id": conn_id,
                "original_seq": context.tcp_seq,
                "original_ack": context.tcp_ack,
                "original_flags": context.get_tcp_flags_string(),
                "original_window": context.tcp_window_size,
                "session_established": context.session_established
            }
        )


class SequenceManipulationAttack(BaseAttack):
    """
    Example attack that demonstrates sequence number manipulation.
    
    Shows how to use sequence tracking methods for complex scenarios.
    """
    
    @property
    def name(self) -> str:
        return "sequence_manipulation"
    
    @property
    def description(self) -> str:
        return "Example attack with sequence number manipulation"
    
    @property
    def category(self) -> str:
        return "tcp"
    
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute attack with sequence number manipulation.
        
        Demonstrates:
        1. Sequence number calculations
        2. Out-of-order segment delivery
        3. Overlapping sequences
        """
        payload = context.payload
        
        if len(payload) < 10:
            return AttackResultHelper.create_failure_result(
                "Payload too small for sequence manipulation"
            )
        
        # Create working copy of context
        work_context = context.copy_tcp_session()
        
        segments = []
        
        # Segment 1: Send middle part first (out of order)
        middle_start = len(payload) // 3
        middle_end = 2 * len(payload) // 3
        middle_chunk = payload[middle_start:middle_end]
        
        segments.append((middle_chunk, middle_start, {
            "delay_ms": 5,
            "ttl": 64
        }))
        
        # Segment 2: Send end part second
        end_chunk = payload[middle_end:]
        
        segments.append((end_chunk, middle_end, {
            "delay_ms": 10,
            "ttl": 64
        }))
        
        # Segment 3: Send beginning part last (creates reordering)
        begin_chunk = payload[:middle_start]
        
        segments.append((begin_chunk, 0, {
            "delay_ms": 15,
            "ttl": 64
        }))
        
        # Segment 4: Overlapping segment for confusion
        overlap_start = middle_start - 5
        overlap_end = middle_start + 5
        overlap_chunk = payload[overlap_start:overlap_end]
        
        segments.append((overlap_chunk, overlap_start, {
            "delay_ms": 20,
            "ttl": 2,  # Low TTL - will be dropped
            "bad_checksum": True
        }))
        
        return AttackResultHelper.create_segments_result(
            technique_used="sequence_manipulation",
            segments=segments,
            metadata={
                "reorder_pattern": "middle->end->begin->overlap",
                "overlap_size": 10,
                "total_payload_size": len(payload)
            }
        )


class ConnectionStateAttack(BaseAttack):
    """
    Example attack that uses connection state tracking.
    
    Demonstrates connection ID and packet ID management.
    """
    
    @property
    def name(self) -> str:
        return "connection_state"
    
    @property
    def description(self) -> str:
        return "Example attack using connection state tracking"
    
    @property
    def category(self) -> str:
        return "tcp"
    
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute attack using connection state tracking.
        
        Shows how to:
        1. Track packet IDs
        2. Use connection identifiers
        3. Manage session state
        """
        payload = context.payload
        
        # Create connection tracking
        conn_id = context.create_connection_id()
        
        segments = []
        chunk_size = max(1, len(payload) // 4)
        
        for i in range(0, len(payload), chunk_size):
            # Get packet ID for this segment
            packet_id = context.increment_packet_id()
            
            # Get chunk
            chunk = payload[i:i + chunk_size]
            
            # Vary behavior based on packet ID
            if packet_id == 1:
                # First packet - establish session
                options = {
                    "flags": 0x18,  # PSH+ACK
                    "window_size": context.tcp_window_size,
                    "delay_ms": 0
                }
            elif packet_id % 2 == 0:
                # Even packets - reduce window
                options = {
                    "window_size": context.tcp_window_size // 2,
                    "delay_ms": packet_id * 2
                }
            else:
                # Odd packets - use urgent pointer
                options = {
                    "flags": 0x38,  # PSH+ACK+URG
                    "delay_ms": packet_id * 3
                }
            
            segments.append((chunk, i, options))
        
        # Mark session as established
        context.session_established = True
        
        return AttackResultHelper.create_segments_result(
            technique_used="connection_state",
            segments=segments,
            metadata={
                "connection_id": conn_id,
                "total_packets": context.packet_id,
                "session_established": context.session_established,
                "chunk_size": chunk_size
            }
        )


def demonstrate_tcp_session_context():
    """Demonstrate enhanced AttackContext usage."""
    
    print("=== Enhanced AttackContext TCP Session Demo ===\n")
    
    # Create enhanced context with full TCP session info
    context = AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        src_ip="10.0.0.50",
        src_port=54321,
        domain="target.example.com",
        payload=b"GET /api/data HTTP/1.1\r\nHost: target.example.com\r\nUser-Agent: TestClient\r\n\r\n",
        
        # TCP session information
        tcp_seq=1000000,
        tcp_ack=2000000,
        tcp_flags=0x18,  # PSH+ACK
        tcp_window_size=32768,
        tcp_urgent_pointer=0,
        
        # Connection state
        initial_seq=1000000,
        session_established=False
    )
    
    print("1. Basic TCP Session Information:")
    print(f"   Connection: {context.src_ip}:{context.src_port} -> {context.dst_ip}:{context.dst_port}")
    print(f"   TCP Seq: {context.tcp_seq}, ACK: {context.tcp_ack}")
    print(f"   Flags: {context.get_tcp_flags_string()}")
    print(f"   Window: {context.tcp_window_size}")
    print(f"   Session Valid: {context.validate_tcp_session()}")
    print()
    
    # Test sequence number operations
    print("2. Sequence Number Operations:")
    print(f"   Current seq: {context.tcp_seq}")
    print(f"   Next seq after 100 bytes: {context.get_next_seq(100)}")
    print(f"   Seq with offset +50: {context.get_seq_with_offset(50)}")
    
    # Advance sequence
    context.advance_seq(100)
    print(f"   After advancing by 100: {context.tcp_seq}")
    print(f"   Sequence offset: {context.current_seq_offset}")
    print()
    
    # Test connection tracking
    print("3. Connection State Tracking:")
    conn_id = context.create_connection_id()
    print(f"   Connection ID: {conn_id}")
    
    for i in range(3):
        packet_id = context.increment_packet_id()
        print(f"   Packet {packet_id} sent")
    print()
    
    # Test TCP flags manipulation
    print("4. TCP Flags Manipulation:")
    context.set_tcp_flags("SYN,ACK")
    print(f"   Set flags to SYN,ACK: {context.get_tcp_flags_string()}")
    
    context.set_tcp_flags(0x11)  # FIN+ACK
    print(f"   Set flags to 0x11: {context.get_tcp_flags_string()}")
    print()
    
    # Test context copying
    print("5. Context Copying:")
    context_copy = context.copy_tcp_session()
    print(f"   Original seq: {context.tcp_seq}")
    print(f"   Copy seq: {context_copy.tcp_seq}")
    print(f"   Same object: {context is context_copy}")
    print()
    
    # Test dictionary conversion
    print("6. Dictionary Conversion:")
    context_dict = context.to_dict()
    print(f"   Connection: {context_dict['connection']}")
    print(f"   TCP Session: {context_dict['tcp_session']}")
    print(f"   State: {context_dict['state']}")
    print()
    
    # Test attacks with enhanced context
    print("7. TCP Session Aware Attack:")
    attack1 = TCPSessionAwareAttack()
    result1 = attack1.execute(context)
    
    print(f"   Status: {result1.status}")
    print(f"   Technique: {result1.technique_used}")
    print(f"   Segments: {result1.get_segment_count()}")
    print(f"   Metadata: {result1.metadata}")
    print()
    
    # Test sequence manipulation attack
    print("8. Sequence Manipulation Attack:")
    attack2 = SequenceManipulationAttack()
    result2 = attack2.execute(context)
    
    print(f"   Status: {result2.status}")
    print(f"   Technique: {result2.technique_used}")
    print(f"   Segments: {result2.get_segment_count()}")
    
    if result2.has_segments():
        for i, (payload_data, seq_offset, options) in enumerate(result2.segments):
            print(f"   Segment {i+1}: {len(payload_data)} bytes at offset {seq_offset}, options: {options}")
    print()
    
    # Test connection state attack
    print("9. Connection State Attack:")
    # Reset context for clean test
    context.reset_sequence_tracking()
    
    attack3 = ConnectionStateAttack()
    result3 = attack3.execute(context)
    
    print(f"   Status: {result3.status}")
    print(f"   Technique: {result3.technique_used}")
    print(f"   Segments: {result3.get_segment_count()}")
    print(f"   Final packet ID: {context.packet_id}")
    print(f"   Session established: {context.session_established}")
    print()
    
    print("=== Demo Complete ===")


if __name__ == "__main__":
    demonstrate_tcp_session_context()