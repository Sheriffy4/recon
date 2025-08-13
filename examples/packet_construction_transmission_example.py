#!/usr/bin/env python3
"""
Example demonstrating packet construction and transmission integration.

Shows how the NativePyDivertEngine integrates with SegmentPacketBuilder
to provide precise packet construction and transmission capabilities.
"""

import asyncio
import logging
import time
from typing import Dict, Any

from core.bypass.engines.native_pydivert_engine import NativePydivertEngine
from core.bypass.engines.base import EngineConfig
from core.bypass.attacks.base import AttackResult, AttackStatus, AttackContext
from core.bypass.attacks.segment_packet_builder import SegmentPacketBuilder
from core.bypass.attacks.timing_controller import get_timing_controller


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PacketConstructionDemo:
    """Demonstration of packet construction and transmission integration."""
    
    def __init__(self):
        """Initialize demo components."""
        self.engine_config = EngineConfig(
            debug=True,
            timeout=30.0,
            packet_buffer_size=65535,
            log_packets=True
        )
        
        # Note: In real usage, engine would be created when needed
        # Here we just demonstrate the configuration
        logger.info("Demo initialized with engine configuration")
    
    def demonstrate_ttl_modification(self):
        """Demonstrate TTL modification in packet construction."""
        logger.info("=== TTL Modification Demo ===")
        
        # Create attack context
        context = AttackContext(
            dst_ip="1.2.3.4",
            dst_port=443,
            src_ip="192.168.1.100",
            src_port=12345,
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            tcp_seq=1000,
            tcp_ack=2000,
            tcp_flags=0x18,  # PSH+ACK
            tcp_window_size=65535
        )
        
        # Create segments with different TTL values
        segments = [
            (b"fake_packet", 0, {"ttl": 1, "delay_ms": 10}),  # Low TTL fake packet
            (b"GET / HTTP/1.1\r\n", 0, {"ttl": 64}),          # Normal TTL real packet
            (b"Host: example.com\r\n\r\n", 17, {"ttl": 64})   # Continuation
        ]
        
        # Demonstrate packet building
        builder = SegmentPacketBuilder()
        
        for i, segment in enumerate(segments):
            payload_data, seq_offset, options = segment
            
            try:
                packet_info = builder.build_segment(payload_data, seq_offset, options, context)
                
                logger.info(f"Segment {i+1} built:")
                logger.info(f"  - Payload: {len(payload_data)} bytes")
                logger.info(f"  - Sequence: {packet_info.tcp_seq} (offset: {seq_offset})")
                logger.info(f"  - TTL: {packet_info.ttl}")
                logger.info(f"  - Packet size: {packet_info.packet_size} bytes")
                logger.info(f"  - Build time: {packet_info.construction_time_ms:.3f}ms")
                
                if options.get("delay_ms"):
                    logger.info(f"  - Delay: {options['delay_ms']}ms")
                
            except Exception as e:
                logger.error(f"Failed to build segment {i+1}: {e}")
        
        logger.info("TTL modification demo completed\n")
    
    def demonstrate_checksum_corruption(self):
        """Demonstrate TCP checksum corruption."""
        logger.info("=== Checksum Corruption Demo ===")
        
        context = AttackContext(
            dst_ip="1.2.3.4",
            dst_port=443,
            src_ip="192.168.1.100",
            src_port=12345,
            payload=b"corrupted_packet_data",
            tcp_seq=1000,
            tcp_ack=2000,
            tcp_flags=0x18,
            tcp_window_size=65535
        )
        
        # Create segments with checksum corruption
        segments = [
            (b"normal_packet", 0, {"bad_checksum": False}),
            (b"corrupted_packet", 13, {"bad_checksum": True}),
        ]
        
        builder = SegmentPacketBuilder()
        
        for i, segment in enumerate(segments):
            payload_data, seq_offset, options = segment
            
            try:
                packet_info = builder.build_segment(payload_data, seq_offset, options, context)
                
                logger.info(f"Segment {i+1} built:")
                logger.info(f"  - Payload: {len(payload_data)} bytes")
                logger.info(f"  - Checksum corrupted: {packet_info.checksum_corrupted}")
                logger.info(f"  - Packet size: {packet_info.packet_size} bytes")
                
            except Exception as e:
                logger.error(f"Failed to build segment {i+1}: {e}")
        
        logger.info("Checksum corruption demo completed\n")
    
    def demonstrate_sequence_adjustment(self):
        """Demonstrate sequence number adjustment."""
        logger.info("=== Sequence Number Adjustment Demo ===")
        
        context = AttackContext(
            dst_ip="1.2.3.4",
            dst_port=443,
            src_ip="192.168.1.100",
            src_port=12345,
            payload=b"multi_segment_payload",
            tcp_seq=5000,  # Base sequence number
            tcp_ack=3000,
            tcp_flags=0x18,
            tcp_window_size=65535
        )
        
        # Create segments with different sequence offsets
        segments = [
            (b"part1", 0, {}),      # seq = 5000 + 0 = 5000
            (b"part2", 5, {}),      # seq = 5000 + 5 = 5005
            (b"part3", 10, {}),     # seq = 5000 + 10 = 5010
            (b"part4", 15, {})      # seq = 5000 + 15 = 5015
        ]
        
        builder = SegmentPacketBuilder()
        
        logger.info(f"Base sequence number: {context.tcp_seq}")
        
        for i, segment in enumerate(segments):
            payload_data, seq_offset, options = segment
            
            try:
                packet_info = builder.build_segment(payload_data, seq_offset, options, context)
                
                expected_seq = context.tcp_seq + seq_offset
                
                logger.info(f"Segment {i+1}:")
                logger.info(f"  - Payload: '{payload_data.decode()}'")
                logger.info(f"  - Sequence offset: {seq_offset}")
                logger.info(f"  - Expected sequence: {expected_seq}")
                logger.info(f"  - Actual sequence: {packet_info.tcp_seq}")
                logger.info(f"  - Match: {packet_info.tcp_seq == expected_seq}")
                
            except Exception as e:
                logger.error(f"Failed to build segment {i+1}: {e}")
        
        logger.info("Sequence adjustment demo completed\n")
    
    def demonstrate_precise_timing(self):
        """Demonstrate precise timing control."""
        logger.info("=== Precise Timing Control Demo ===")
        
        # Get timing controller
        timing_controller = get_timing_controller()
        
        # Test different timing delays
        test_delays = [0.5, 1.0, 2.5, 5.0, 10.0]  # milliseconds
        
        logger.info("Testing timing precision:")
        
        for delay_ms in test_delays:
            start_time = time.time()
            
            # Execute precise delay
            timing_result = timing_controller.delay(delay_ms)
            
            actual_time = (time.time() - start_time) * 1000
            
            logger.info(f"Delay {delay_ms}ms:")
            logger.info(f"  - Requested: {timing_result.requested_delay_ms:.3f}ms")
            logger.info(f"  - Controller actual: {timing_result.actual_delay_ms:.3f}ms")
            logger.info(f"  - Measured actual: {actual_time:.3f}ms")
            logger.info(f"  - Error: {timing_result.accuracy_error_ms:.3f}ms")
            logger.info(f"  - Strategy: {timing_result.strategy_used.value}")
        
        # Get timing statistics
        stats = timing_controller.get_statistics()
        logger.info(f"\nTiming Statistics:")
        logger.info(f"  - Total delays: {stats.get('total_delays', 0)}")
        logger.info(f"  - Average accuracy: {stats.get('average_accuracy_percentage', 0):.1f}%")
        logger.info(f"  - Average error: {stats.get('average_error_ms', 0):.3f}ms")
        
        logger.info("Precise timing demo completed\n")
    
    def demonstrate_comprehensive_integration(self):
        """Demonstrate comprehensive integration of all features."""
        logger.info("=== Comprehensive Integration Demo ===")
        
        context = AttackContext(
            dst_ip="1.2.3.4",
            dst_port=443,
            src_ip="192.168.1.100",
            src_port=12345,
            payload=b"comprehensive_test_payload",
            tcp_seq=10000,
            tcp_ack=20000,
            tcp_flags=0x18,
            tcp_window_size=65535,
            connection_id="192.168.1.100:12345->1.2.3.4:443"
        )
        
        # Create complex segments scenario
        segments = [
            # Fake packet with low TTL and delay
            (b"fake_data", 0, {
                "ttl": 1,
                "delay_ms": 15.5,
                "flags": 0x18
            }),
            
            # Real packet part 1 with checksum corruption
            (b"real_part1", 0, {
                "ttl": 64,
                "bad_checksum": True,
                "delay_ms": 5.2,
                "window_size": 32768
            }),
            
            # Real packet part 2 with normal settings
            (b"real_part2", 10, {
                "ttl": 64,
                "delay_ms": 2.1,
                "flags": 0x10  # ACK only
            })
        ]
        
        builder = SegmentPacketBuilder()
        timing_controller = get_timing_controller()
        
        logger.info(f"Executing comprehensive scenario with {len(segments)} segments")
        logger.info(f"Connection: {context.connection_id}")
        
        total_start_time = time.time()
        
        for i, segment in enumerate(segments):
            payload_data, seq_offset, options = segment
            
            logger.info(f"\n--- Segment {i+1} ---")
            logger.info(f"Payload: {len(payload_data)} bytes")
            logger.info(f"Sequence offset: {seq_offset}")
            logger.info(f"Options: {options}")
            
            try:
                # Build packet
                build_start = time.time()
                packet_info = builder.build_segment(payload_data, seq_offset, options, context)
                build_time = (time.time() - build_start) * 1000
                
                logger.info(f"Packet built in {build_time:.3f}ms:")
                logger.info(f"  - Size: {packet_info.packet_size} bytes")
                logger.info(f"  - Sequence: {packet_info.tcp_seq}")
                logger.info(f"  - TTL: {packet_info.ttl}")
                logger.info(f"  - Checksum corrupted: {packet_info.checksum_corrupted}")
                
                # Apply timing delay
                delay_ms = options.get("delay_ms", 0)
                if delay_ms > 0:
                    timing_result = timing_controller.delay(delay_ms)
                    logger.info(f"Timing delay applied:")
                    logger.info(f"  - Requested: {timing_result.requested_delay_ms:.3f}ms")
                    logger.info(f"  - Actual: {timing_result.actual_delay_ms:.3f}ms")
                    logger.info(f"  - Error: {timing_result.accuracy_error_ms:.3f}ms")
                
                # In real scenario, packet would be sent here
                logger.info("Packet ready for transmission")
                
            except Exception as e:
                logger.error(f"Failed to process segment {i+1}: {e}")
        
        total_time = (time.time() - total_start_time) * 1000
        logger.info(f"\nTotal execution time: {total_time:.3f}ms")
        
        # Get final statistics
        builder_stats = builder.get_stats()
        timing_stats = timing_controller.get_statistics()
        
        logger.info(f"\nFinal Statistics:")
        logger.info(f"Builder - Packets built: {builder_stats['packets_built']}")
        logger.info(f"Builder - Total build time: {builder_stats['total_build_time_ms']:.3f}ms")
        logger.info(f"Builder - TTL modifications: {builder_stats['ttl_modifications']}")
        logger.info(f"Builder - Checksum corruptions: {builder_stats['checksum_corruptions']}")
        logger.info(f"Timing - Total delays: {timing_stats.get('total_delays', 0)}")
        logger.info(f"Timing - Average accuracy: {timing_stats.get('average_accuracy_percentage', 0):.1f}%")
        
        logger.info("Comprehensive integration demo completed\n")
    
    def run_all_demos(self):
        """Run all demonstration scenarios."""
        logger.info("Starting Packet Construction and Transmission Integration Demo")
        logger.info("=" * 70)
        
        try:
            self.demonstrate_ttl_modification()
            self.demonstrate_checksum_corruption()
            self.demonstrate_sequence_adjustment()
            self.demonstrate_precise_timing()
            self.demonstrate_comprehensive_integration()
            
            logger.info("All demonstrations completed successfully!")
            
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            raise


def main():
    """Main demo function."""
    demo = PacketConstructionDemo()
    demo.run_all_demos()


if __name__ == "__main__":
    main()