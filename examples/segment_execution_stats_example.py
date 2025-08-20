#!/usr/bin/env python3
"""
Example demonstrating segment execution statistics and monitoring system.

This example shows how to use the segment execution statistics system
to monitor and analyze the performance of segment-based attacks.
"""

import time
import asyncio

from core.bypass.monitoring.segment_execution_stats import (
    get_segment_stats_collector,
    ExecutionPhase,
    ExecutionStatus,
)


def demonstrate_basic_statistics():
    """Demonstrate basic statistics collection."""
    print("=== Basic Statistics Collection ===")

    # Get the global statistics collector
    stats_collector = get_segment_stats_collector()

    # Start a session
    session_stats = stats_collector.start_session(
        session_id="demo_session_1",
        connection_id="192.168.1.100:54321->93.184.216.34:80",
    )

    print(f"Started session: {session_stats.session_id}")

    # Simulate segment execution
    for i in range(3):
        segment_id = i + 1

        # Start segment tracking
        segment_metrics = stats_collector.start_segment_execution(
            segment_id=segment_id,
            session_id="demo_session_1",
            payload_size=100 + i * 20,
            seq_offset=i * 50,
            options={"ttl": 64, "delay_ms": 5.0 + i},
        )

        print(f"  Started segment {segment_id}")

        # Simulate validation phase
        time.sleep(0.001)  # 1ms
        stats_collector.update_segment_phase(
            segment_metrics, ExecutionPhase.VALIDATION, 1.0
        )

        # Simulate construction phase
        time.sleep(0.002)  # 2ms
        stats_collector.update_segment_phase(
            segment_metrics, ExecutionPhase.CONSTRUCTION, 2.0
        )

        # Simulate timing phase
        time.sleep(0.005)  # 5ms
        stats_collector.update_segment_phase(
            segment_metrics, ExecutionPhase.TIMING, 5.0 + i
        )

        # Simulate transmission phase
        time.sleep(0.001)  # 1ms
        stats_collector.update_segment_phase(
            segment_metrics, ExecutionPhase.TRANSMISSION, 1.0
        )

        # Complete segment execution
        stats_collector.complete_segment_execution(
            segment_metrics,
            status=ExecutionStatus.SUCCESS if i < 2 else ExecutionStatus.FAILED,
            error_message="Transmission failed" if i >= 2 else None,
            packet_size=150 + i * 20,
            ttl_modified=(i == 0),  # First segment has TTL modification
            checksum_corrupted=(i == 1),  # Second segment has checksum corruption
            timing_accuracy_error_ms=0.1 * i,
        )

        print(f"  Completed segment {segment_id}: {'SUCCESS' if i < 2 else 'FAILED'}")

    # Complete session
    completed_session = stats_collector.complete_session("demo_session_1")

    print("\\nSession completed:")
    print(f"  Total segments: {completed_session.total_segments}")
    print(f"  Successful segments: {completed_session.successful_segments}")
    print(f"  Success rate: {completed_session.success_rate_percent:.1f}%")
    print(f"  Average segment time: {completed_session.avg_segment_time_ms:.2f}ms")
    print(
        f"  Throughput: {completed_session.throughput_segments_per_sec:.1f} segments/sec"
    )
    print(f"  TTL modifications: {completed_session.ttl_modifications}")
    print(f"  Checksum corruptions: {completed_session.checksum_corruptions}")


def demonstrate_performance_monitoring():
    """Demonstrate performance monitoring capabilities."""
    print("\\n=== Performance Monitoring ===")

    stats_collector = get_segment_stats_collector()

    # Create multiple sessions to demonstrate monitoring
    for session_num in range(3):
        session_id = f"perf_session_{session_num}"
        connection_id = f"192.168.1.100:5432{session_num}->93.184.216.34:80"

        session_stats = stats_collector.start_session(session_id, connection_id)

        # Simulate different performance characteristics
        segment_count = 5 + session_num * 2
        for i in range(segment_count):
            segment_metrics = stats_collector.start_segment_execution(
                segment_id=i + 1,
                session_id=session_id,
                payload_size=80 + i * 10,
                seq_offset=i * 40,
                options={"ttl": 64, "delay_ms": 2.0 + session_num},
            )

            # Simulate varying performance
            validation_time = 0.5 + session_num * 0.2
            construction_time = 1.0 + session_num * 0.3
            timing_time = 2.0 + session_num + i * 0.1
            transmission_time = 0.8 + session_num * 0.1

            stats_collector.update_segment_phase(
                segment_metrics, ExecutionPhase.VALIDATION, validation_time
            )
            stats_collector.update_segment_phase(
                segment_metrics, ExecutionPhase.CONSTRUCTION, construction_time
            )
            stats_collector.update_segment_phase(
                segment_metrics, ExecutionPhase.TIMING, timing_time
            )
            stats_collector.update_segment_phase(
                segment_metrics, ExecutionPhase.TRANSMISSION, transmission_time
            )

            # Simulate some failures
            success = not (
                i == segment_count - 1 and session_num == 2
            )  # Last segment of last session fails

            stats_collector.complete_segment_execution(
                segment_metrics,
                status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILED,
                error_message=None if success else "Network timeout",
                packet_size=120 + i * 10,
                ttl_modified=(i % 3 == 0),
                checksum_corrupted=(i % 4 == 0),
                timing_accuracy_error_ms=0.05 * i,
            )

        stats_collector.complete_session(session_id)
        print(f"Completed session {session_num + 1}/{3}")

    # Get global statistics
    global_stats = stats_collector.get_global_stats()
    print("\\nGlobal Statistics:")
    print(f"  Total sessions: {global_stats.total_sessions}")
    print(f"  Completed sessions: {global_stats.completed_sessions}")
    print(f"  Total segments processed: {global_stats.total_segments_processed}")
    print(f"  Global success rate: {global_stats.global_success_rate_percent:.1f}%")
    print(
        f"  Global throughput: {global_stats.global_throughput_segments_per_sec:.1f} segments/sec"
    )
    print(
        f"  Average timing accuracy: {global_stats.global_avg_timing_accuracy_percent:.1f}%"
    )
    print(f"  Total TTL modifications: {global_stats.total_ttl_modifications}")
    print(f"  Total checksum corruptions: {global_stats.total_checksum_corruptions}")


def demonstrate_performance_analysis():
    """Demonstrate detailed performance analysis."""
    print("\\n=== Performance Analysis ===")

    stats_collector = get_segment_stats_collector()

    # Get comprehensive performance summary
    performance_summary = stats_collector.get_performance_summary()

    print("Recent Performance:")
    recent_perf = performance_summary.get("recent_performance", {})
    print(f"  Success rate: {recent_perf.get('success_rate_percent', 0):.1f}%")
    print(
        f"  Average execution time: {recent_perf.get('avg_execution_time_ms', 0):.2f}ms"
    )
    print(
        f"  Throughput: {recent_perf.get('throughput_segments_per_sec', 0):.1f} segments/sec"
    )
    print(f"  Active sessions: {recent_perf.get('active_sessions', 0)}")
    print(f"  Active segments: {recent_perf.get('active_segments', 0)}")

    print("\\nTiming Analysis:")
    timing_analysis = performance_summary.get("timing_analysis", {})
    if "construction_time_ms" in timing_analysis:
        construction = timing_analysis["construction_time_ms"]
        print(
            f"  Construction time - Avg: {construction.get('avg', 0):.2f}ms, "
            f"Min: {construction.get('min', 0):.2f}ms, Max: {construction.get('max', 0):.2f}ms"
        )

    if "transmission_time_ms" in timing_analysis:
        transmission = timing_analysis["transmission_time_ms"]
        print(
            f"  Transmission time - Avg: {transmission.get('avg', 0):.2f}ms, "
            f"Min: {transmission.get('min', 0):.2f}ms, Max: {transmission.get('max', 0):.2f}ms"
        )

    if "timing_accuracy_error_ms" in timing_analysis:
        accuracy = timing_analysis["timing_accuracy_error_ms"]
        print(
            f"  Timing accuracy error - Avg: {accuracy.get('avg', 0):.3f}ms, "
            f"Min: {accuracy.get('min', 0):.3f}ms, Max: {accuracy.get('max', 0):.3f}ms"
        )

    print("\\nModification Analysis:")
    mod_analysis = performance_summary.get("modification_analysis", {})
    if "ttl_modifications" in mod_analysis:
        ttl_mods = mod_analysis["ttl_modifications"]
        print(
            f"  TTL modifications: {ttl_mods.get('count', 0)} ({ttl_mods.get('percentage', 0):.1f}%)"
        )

    if "checksum_corruptions" in mod_analysis:
        checksum_corr = mod_analysis["checksum_corruptions"]
        print(
            f"  Checksum corruptions: {checksum_corr.get('count', 0)} ({checksum_corr.get('percentage', 0):.1f}%)"
        )

    print("\\nError Analysis:")
    error_analysis = performance_summary.get("error_analysis", {})
    print(f"  Error rate: {error_analysis.get('error_rate_percent', 0):.1f}%")
    print(f"  Success rate: {error_analysis.get('success_rate_percent', 0):.1f}%")

    status_dist = error_analysis.get("status_distribution", {})
    if status_dist:
        print("  Status distribution:")
        for status, count in status_dist.items():
            print(f"    {status}: {count}")

    error_types = error_analysis.get("error_types", {})
    if error_types:
        print("  Error types:")
        for error_type, count in error_types.items():
            print(f"    {error_type}: {count}")


def demonstrate_recent_sessions_analysis():
    """Demonstrate recent sessions analysis."""
    print("\\n=== Recent Sessions Analysis ===")

    stats_collector = get_segment_stats_collector()

    # Get recent sessions
    recent_sessions = stats_collector.get_recent_sessions(count=5)

    print(f"Recent {len(recent_sessions)} sessions:")
    for i, session in enumerate(recent_sessions):
        print(f"  Session {i + 1}:")
        print(f"    ID: {session.session_id}")
        print(f"    Connection: {session.connection_id}")
        print(
            f"    Segments: {session.total_segments} (Success: {session.successful_segments})"
        )
        print(f"    Success rate: {session.success_rate_percent:.1f}%")
        print(f"    Avg time: {session.avg_segment_time_ms:.2f}ms")
        print(f"    Throughput: {session.throughput_segments_per_sec:.1f} segments/sec")
        print(f"    Timing accuracy: {session.timing_accuracy_percent:.1f}%")
        print()


def demonstrate_engine_integration():
    """Demonstrate integration with NativePyDivertEngine."""
    print("\\n=== Engine Integration ===")

    # Note: This is a demonstration of how the engine would use statistics
    # In practice, the engine automatically integrates with the statistics system

    print("Engine Statistics Integration:")
    print("1. Engine automatically starts session tracking when executing segments")
    print("2. Each segment execution is tracked with detailed metrics")
    print(
        "3. Phase timing is automatically recorded (validation, construction, timing, transmission)"
    )
    print("4. Packet modifications are tracked (TTL, checksum, TCP flags, window size)")
    print("5. Timing accuracy is measured and recorded")
    print("6. Session completion provides comprehensive statistics")
    print("7. Global statistics are continuously updated")

    print("\\nAvailable Engine Methods:")
    print(
        "- engine.get_segment_execution_statistics() - Get detailed segment statistics"
    )
    print("- engine.get_recent_session_stats(count) - Get recent session statistics")
    print("- engine.get_performance_metrics() - Get comprehensive performance metrics")
    print(
        "- engine.get_diagnostic_statistics() - Get diagnostic and segment statistics"
    )

    print("\\nExample Engine Usage:")
    print(
        """
    # Create engine
    engine = NativePyDivertEngine(config)
    
    # Execute attack (statistics are automatically collected)
    result = engine.execute_attack(attack_result, context)
    
    # Get statistics
    segment_stats = engine.get_segment_execution_statistics()
    performance_metrics = engine.get_performance_metrics()
    recent_sessions = engine.get_recent_session_stats(10)
    
    # Analyze performance
    print(f"Success rate: {performance_metrics['reliability']['success_rate_percent']:.1f}%")
    print(f"Throughput: {performance_metrics['throughput']['segments_per_sec']:.1f} segments/sec")
    print(f"Timing accuracy: {performance_metrics['timing']['avg_accuracy_percent']:.1f}%")
    """
    )


def demonstrate_monitoring_dashboard():
    """Demonstrate how to create a monitoring dashboard."""
    print("\\n=== Monitoring Dashboard ===")

    stats_collector = get_segment_stats_collector()

    # Get comprehensive metrics for dashboard
    global_stats = stats_collector.get_global_stats()
    performance_summary = stats_collector.get_performance_summary()
    recent_sessions = stats_collector.get_recent_sessions(5)

    print("📊 SEGMENT EXECUTION MONITORING DASHBOARD")
    print("=" * 50)

    # Overview section
    print("\\n🔍 OVERVIEW")
    print(
        f"  Sessions: {global_stats.active_sessions} active, {global_stats.completed_sessions} completed"
    )
    print(
        f"  Segments: {global_stats.total_segments_processed} processed, {global_stats.total_successful_segments} successful"
    )
    print(f"  Success Rate: {global_stats.global_success_rate_percent:.1f}%")
    print(f"  Error Rate: {global_stats.error_rate_percent:.1f}%")

    # Performance section
    print("\\n⚡ PERFORMANCE")
    recent_perf = performance_summary.get("recent_performance", {})
    print(
        f"  Throughput: {global_stats.global_throughput_segments_per_sec:.1f} segments/sec"
    )
    print(f"  Avg Execution Time: {recent_perf.get('avg_execution_time_ms', 0):.2f}ms")
    print(f"  Timing Accuracy: {global_stats.global_avg_timing_accuracy_percent:.1f}%")

    # Modifications section
    print("\\n🔧 MODIFICATIONS")
    print(f"  TTL Modifications: {global_stats.total_ttl_modifications}")
    print(f"  Checksum Corruptions: {global_stats.total_checksum_corruptions}")
    print(f"  TCP Flags Modifications: {global_stats.total_tcp_flags_modifications}")
    print(
        f"  Window Size Modifications: {global_stats.total_window_size_modifications}"
    )

    # Recent activity section
    print("\\n📈 RECENT ACTIVITY")
    for i, session in enumerate(recent_sessions[-3:]):  # Last 3 sessions
        status_icon = (
            "✅"
            if session.success_rate_percent == 100
            else "⚠️" if session.success_rate_percent > 50 else "❌"
        )
        print(
            f"  {status_icon} {session.session_id}: {session.total_segments} segments, "
            f"{session.success_rate_percent:.1f}% success, {session.avg_segment_time_ms:.1f}ms avg"
        )

    # Alerts section
    print("\\n🚨 ALERTS")
    alerts = []

    if global_stats.global_success_rate_percent < 90:
        alerts.append(
            f"Low success rate: {global_stats.global_success_rate_percent:.1f}%"
        )

    if global_stats.global_avg_timing_accuracy_percent < 85:
        alerts.append(
            f"Poor timing accuracy: {global_stats.global_avg_timing_accuracy_percent:.1f}%"
        )

    if global_stats.global_throughput_segments_per_sec < 10:
        alerts.append(
            f"Low throughput: {global_stats.global_throughput_segments_per_sec:.1f} segments/sec"
        )

    if alerts:
        for alert in alerts:
            print(f"  ⚠️  {alert}")
    else:
        print("  ✅ All systems operating normally")

    print("\\n" + "=" * 50)


async def main():
    """Main demonstration function."""
    print("Segment Execution Statistics and Monitoring System Demo")
    print("=" * 60)

    # Reset statistics for clean demo
    from core.bypass.monitoring.segment_execution_stats import reset_global_stats

    reset_global_stats()

    # Run demonstrations
    demonstrate_basic_statistics()
    demonstrate_performance_monitoring()
    demonstrate_performance_analysis()
    demonstrate_recent_sessions_analysis()
    demonstrate_engine_integration()
    demonstrate_monitoring_dashboard()

    print("\\n✅ Demo completed successfully!")
    print("\\nThe segment execution statistics system provides:")
    print("- Real-time performance monitoring")
    print("- Detailed timing analysis")
    print("- Modification tracking")
    print("- Error analysis and reporting")
    print("- Historical data and trends")
    print("- Integration with engine diagnostics")


if __name__ == "__main__":
    asyncio.run(main())
