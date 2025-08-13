#!/usr/bin/env python3
"""
Example demonstrating segment execution diagnostics system.

Shows how to use the comprehensive diagnostic logging and analysis
capabilities for segment-based attack orchestration.
"""

import time
import logging
from typing import Dict, Any

from core.bypass.diagnostics.segment_diagnostics import (
    SegmentDiagnosticLogger, get_segment_diagnostic_logger, configure_segment_diagnostics
)
from core.bypass.attacks.base import AttackContext
from core.bypass.attacks.segment_packet_builder import SegmentPacketInfo
from core.bypass.attacks.timing_controller import TimingMeasurement, TimingStrategy


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SegmentDiagnosticsDemo:
    """Demonstration of segment execution diagnostics."""
    
    def __init__(self):
        """Initialize demo components."""
        self.diagnostic_logger = get_segment_diagnostic_logger()
        
        # Configure diagnostics for detailed logging
        configure_segment_diagnostics(
            detailed_logging=True,
            max_events_per_segment=50,
            max_sessions_history=10
        )
        
        logger.info("Segment diagnostics demo initialized")
    
    def demonstrate_basic_segment_logging(self):
        """Demonstrate basic segment logging capabilities."""
        logger.info("=== Basic Segment Logging Demo ===")
        
        session_id = "demo_session_basic"
        connection_id = "192.168.1.100:12345->1.2.3.4:443"
        
        # Start diagnostic session
        self.diagnostic_logger.start_session(session_id, connection_id)
        
        # Simulate segment execution
        segment_data = self.diagnostic_logger.log_segment_start(
            session_id, 1, 150, 0, {"ttl": 1, "delay_ms": 10}
        )
        
        logger.info(f"Started logging for segment {segment_data.segment_id}")
        
        # Log validation phase
        self.diagnostic_logger.log_validation_phase(segment_data, 1.2, True)
        logger.info("Validation phase logged")
        
        # Create mock packet info
        packet_info = SegmentPacketInfo(
            packet_bytes=b'mock_packet_data_for_demo',
            packet_size=175,
            construction_time_ms=2.8,
            tcp_seq=1000,
            tcp_ack=2000,
            tcp_flags=0x18,
            tcp_window=65535,
            ttl=1,
            checksum_corrupted=False,
            options_applied={"ttl": 1, "delay_ms": 10}
        )
        
        # Log construction phase
        self.diagnostic_logger.log_construction_phase(segment_data, packet_info)
        logger.info("Construction phase logged")
        
        # Create mock timing measurement
        timing_measurement = TimingMeasurement(
            requested_delay_ms=10.0,
            actual_delay_ms=9.8,
            accuracy_error_ms=-0.2,
            strategy_used=TimingStrategy.HIGH_PRECISION
        )
        
        # Log timing phase
        self.diagnostic_logger.log_timing_phase(segment_data, timing_measurement)
        logger.info("Timing phase logged")
        
        # Log transmission phase
        self.diagnostic_logger.log_transmission_phase(segment_data, 0.9, True)
        logger.info("Transmission phase logged")
        
        # End session and get summary
        summary = self.diagnostic_logger.end_session(session_id)
        
        logger.info(f"Session completed with {summary.successful_segments}/{summary.total_segments} successful segments")
        logger.info("Basic segment logging demo completed\n")
    
    def demonstrate_multi_segment_session(self):
        """Demonstrate multi-segment session with various scenarios."""
        logger.info("=== Multi-Segment Session Demo ===")
        
        session_id = "demo_session_multi"
        connection_id = "192.168.1.100:54321->5.6.7.8:443"
        
        # Start session
        self.diagnostic_logger.start_session(session_id, connection_id)
        
        # Define different segment scenarios
        segments_config = [
            {
                "id": 1,
                "payload_size": 100,
                "seq_offset": 0,
                "options": {"ttl": 1, "delay_ms": 15},
                "ttl": 1,
                "checksum_corrupted": False,
                "success": True
            },
            {
                "id": 2,
                "payload_size": 75,
                "seq_offset": 100,
                "options": {"bad_checksum": True, "delay_ms": 5},
                "ttl": 64,
                "checksum_corrupted": True,
                "success": True
            },
            {
                "id": 3,
                "payload_size": 200,
                "seq_offset": 175,
                "options": {"ttl": 2, "delay_ms": 8},
                "ttl": 2,
                "checksum_corrupted": False,
                "success": False  # Simulate transmission failure
            }
        ]
        
        for config in segments_config:
            logger.info(f"Processing segment {config['id']}")
            
            # Start segment logging
            segment_data = self.diagnostic_logger.log_segment_start(
                session_id, config["id"], config["payload_size"], 
                config["seq_offset"], config["options"]
            )
            
            # Log validation (all succeed in this demo)
            self.diagnostic_logger.log_validation_phase(segment_data, 1.0, True)
            
            # Create packet info
            packet_info = SegmentPacketInfo(
                packet_bytes=b'demo_packet_' + str(config["id"]).encode(),
                packet_size=config["payload_size"] + 40,  # Add headers
                construction_time_ms=2.0 + config["id"] * 0.5,
                tcp_seq=1000 + config["seq_offset"],
                tcp_ack=2000,
                tcp_flags=0x18,
                tcp_window=65535,
                ttl=config["ttl"],
                checksum_corrupted=config["checksum_corrupted"],
                options_applied=config["options"]
            )
            
            # Log construction
            self.diagnostic_logger.log_construction_phase(segment_data, packet_info)
            
            # Log timing if delay is specified
            if config["options"].get("delay_ms", 0) > 0:
                timing_measurement = TimingMeasurement(
                    requested_delay_ms=config["options"]["delay_ms"],
                    actual_delay_ms=config["options"]["delay_ms"] - 0.1,
                    accuracy_error_ms=-0.1,
                    strategy_used=TimingStrategy.HIGH_PRECISION
                )
                self.diagnostic_logger.log_timing_phase(segment_data, timing_measurement)
            
            # Log transmission
            error_msg = None if config["success"] else "Simulated transmission failure"
            self.diagnostic_logger.log_transmission_phase(
                segment_data, 1.0, config["success"], error_msg
            )
            
            logger.info(f"Segment {config['id']} {'succeeded' if config['success'] else 'failed'}")
        
        # End session and analyze results
        summary = self.diagnostic_logger.end_session(session_id)
        
        logger.info(f"Multi-segment session completed:")
        logger.info(f"  - Total segments: {summary.total_segments}")
        logger.info(f"  - Successful: {summary.successful_segments}")
        logger.info(f"  - Failed: {summary.failed_segments}")
        logger.info(f"  - TTL modifications: {summary.ttl_modifications}")
        logger.info(f"  - Checksum corruptions: {summary.checksum_corruptions}")
        logger.info(f"  - Timing delays applied: {summary.timing_delays_applied}")
        logger.info("Multi-segment session demo completed\n")
    
    def demonstrate_error_scenarios(self):
        """Demonstrate error handling and logging."""
        logger.info("=== Error Scenarios Demo ===")
        
        session_id = "demo_session_errors"
        connection_id = "test_connection_errors"
        
        self.diagnostic_logger.start_session(session_id, connection_id)
        
        # Scenario 1: Validation error
        logger.info("Testing validation error scenario")
        segment_data1 = self.diagnostic_logger.log_segment_start(
            session_id, 1, 50, 0, {"invalid_option": "bad_value"}
        )
        
        self.diagnostic_logger.log_validation_phase(
            segment_data1, 2.0, False, "Invalid segment options detected"
        )
        
        # Scenario 2: Construction success but transmission failure
        logger.info("Testing transmission error scenario")
        segment_data2 = self.diagnostic_logger.log_segment_start(
            session_id, 2, 100, 50, {"ttl": 1}
        )
        
        self.diagnostic_logger.log_validation_phase(segment_data2, 1.0, True)
        
        packet_info = SegmentPacketInfo(
            packet_bytes=b'failed_transmission_packet',
            packet_size=140,
            construction_time_ms=2.5,
            tcp_seq=1050,
            tcp_ack=2000,
            tcp_flags=0x18,
            tcp_window=65535,
            ttl=1,
            checksum_corrupted=False,
            options_applied={"ttl": 1}
        )
        
        self.diagnostic_logger.log_construction_phase(segment_data2, packet_info)
        self.diagnostic_logger.log_transmission_phase(
            segment_data2, 1.5, False, "Network interface error"
        )
        
        # End session and analyze errors
        summary = self.diagnostic_logger.end_session(session_id)
        
        logger.info(f"Error scenarios completed:")
        logger.info(f"  - Total segments: {summary.total_segments}")
        logger.info(f"  - Failed segments: {summary.failed_segments}")
        logger.info(f"  - Construction errors: {summary.construction_errors}")
        logger.info(f"  - Transmission errors: {summary.transmission_errors}")
        logger.info("Error scenarios demo completed\n")
    
    def demonstrate_performance_analysis(self):
        """Demonstrate performance analysis capabilities."""
        logger.info("=== Performance Analysis Demo ===")
        
        session_id = "demo_session_performance"
        connection_id = "performance_test_connection"
        
        start_time = time.time()
        self.diagnostic_logger.start_session(session_id, connection_id)
        
        # Simulate high-throughput segment processing
        num_segments = 10
        total_bytes = 0
        
        for i in range(num_segments):
            payload_size = 100 + (i * 10)  # Varying payload sizes
            total_bytes += payload_size
            
            segment_data = self.diagnostic_logger.log_segment_start(
                session_id, i + 1, payload_size, i * 50, {"delay_ms": 2}
            )
            
            # Simulate processing time
            time.sleep(0.01)  # 10ms processing time
            
            self.diagnostic_logger.log_validation_phase(segment_data, 0.5, True)
            
            packet_info = SegmentPacketInfo(
                packet_bytes=b'perf_test_packet_' + str(i).encode(),
                packet_size=payload_size + 40,
                construction_time_ms=1.0 + (i * 0.1),
                tcp_seq=1000 + (i * 50),
                tcp_ack=2000,
                tcp_flags=0x18,
                tcp_window=65535,
                ttl=64,
                checksum_corrupted=False,
                options_applied={"delay_ms": 2}
            )
            
            self.diagnostic_logger.log_construction_phase(segment_data, packet_info)
            
            # Simulate timing with varying accuracy
            timing_measurement = TimingMeasurement(
                requested_delay_ms=2.0,
                actual_delay_ms=2.0 + (i * 0.01),  # Gradually decreasing accuracy
                accuracy_error_ms=i * 0.01,
                strategy_used=TimingStrategy.HIGH_PRECISION
            )
            
            self.diagnostic_logger.log_timing_phase(segment_data, timing_measurement)
            self.diagnostic_logger.log_transmission_phase(segment_data, 0.3, True)
        
        # End session and analyze performance
        summary = self.diagnostic_logger.end_session(session_id)
        total_time = time.time() - start_time
        
        logger.info(f"Performance analysis results:")
        logger.info(f"  - Segments processed: {summary.total_segments}")
        logger.info(f"  - Total execution time: {summary.total_execution_time_ms:.1f}ms")
        logger.info(f"  - Average segment time: {summary.average_segment_time_ms:.1f}ms")
        logger.info(f"  - Min/Max segment time: {summary.min_segment_time_ms:.1f}ms / {summary.max_segment_time_ms:.1f}ms")
        logger.info(f"  - Packets per second: {summary.packets_per_second:.1f}")
        logger.info(f"  - Bytes per second: {summary.bytes_per_second:.1f}")
        logger.info(f"  - Timing accuracy: {summary.timing_accuracy_average:.1f}%")
        logger.info(f"  - Actual wall time: {total_time * 1000:.1f}ms")
        logger.info("Performance analysis demo completed\n")
    
    def demonstrate_global_statistics(self):
        """Demonstrate global statistics tracking."""
        logger.info("=== Global Statistics Demo ===")
        
        # Get initial statistics
        initial_stats = self.diagnostic_logger.get_global_statistics()
        logger.info(f"Initial statistics: {initial_stats}")
        
        # Run several quick sessions
        for i in range(3):
            session_id = f"stats_session_{i}"
            self.diagnostic_logger.start_session(session_id, f"connection_{i}")
            
            # Add a simple segment
            segment_data = self.diagnostic_logger.log_segment_start(
                session_id, 1, 50, 0, {}
            )
            
            self.diagnostic_logger.log_validation_phase(segment_data, 1.0, True)
            self.diagnostic_logger.log_transmission_phase(segment_data, 0.5, True)
            
            self.diagnostic_logger.end_session(session_id)
        
        # Get final statistics
        final_stats = self.diagnostic_logger.get_global_statistics()
        
        logger.info(f"Final statistics:")
        logger.info(f"  - Total sessions: {final_stats['total_sessions']}")
        logger.info(f"  - Active sessions: {final_stats['active_sessions']}")
        logger.info(f"  - Total segments processed: {final_stats['total_segments_processed']}")
        logger.info(f"  - Total execution time: {final_stats['total_execution_time_ms']:.1f}ms")
        logger.info(f"  - Average time per session: {final_stats['average_execution_time_per_session_ms']:.1f}ms")
        logger.info(f"  - Sessions in history: {final_stats['sessions_in_history']}")
        
        logger.info("Global statistics demo completed\n")
    
    def run_all_demos(self):
        """Run all demonstration scenarios."""
        logger.info("Starting Segment Execution Diagnostics Demo")
        logger.info("=" * 60)
        
        try:
            self.demonstrate_basic_segment_logging()
            self.demonstrate_multi_segment_session()
            self.demonstrate_error_scenarios()
            self.demonstrate_performance_analysis()
            self.demonstrate_global_statistics()
            
            logger.info("All diagnostics demonstrations completed successfully!")
            
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            raise


def main():
    """Main demo function."""
    demo = SegmentDiagnosticsDemo()
    demo.run_all_demos()


if __name__ == "__main__":
    main()