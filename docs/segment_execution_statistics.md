# Segment Execution Statistics and Monitoring

## Overview

The Segment Execution Statistics and Monitoring system provides comprehensive tracking, analysis, and reporting of segment-based attack execution performance. This system enables real-time monitoring, historical analysis, and performance optimization of the Native Attack Orchestration system.

## Architecture

### Core Components

#### 1. SegmentExecutionMetrics
Tracks metrics for individual segment execution:

```python
@dataclass
class SegmentExecutionMetrics:
    segment_id: int
    session_id: str
    payload_size: int
    seq_offset: int
    options: Dict[str, Any]
    
    # Timing metrics
    start_time: float
    end_time: Optional[float] = None
    phase_times: Dict[ExecutionPhase, float] = field(default_factory=dict)
    
    # Execution metrics
    status: ExecutionStatus = ExecutionStatus.SUCCESS
    error_message: Optional[str] = None
    
    # Performance metrics
    construction_time_ms: float = 0.0
    timing_accuracy_error_ms: float = 0.0
    transmission_time_ms: float = 0.0
    
    # Packet metrics
    packet_size: int = 0
    ttl_modified: bool = False
    checksum_corrupted: bool = False
    tcp_flags_modified: bool = False
    window_size_modified: bool = False
```

#### 2. SessionExecutionStats
Aggregates statistics for complete session execution:

```python
@dataclass
class SessionExecutionStats:
    session_id: str
    connection_id: str
    start_time: float
    end_time: Optional[float] = None
    
    # Segment metrics
    total_segments: int = 0
    successful_segments: int = 0
    failed_segments: int = 0
    
    # Timing metrics
    total_execution_time_ms: float = 0.0
    avg_segment_time_ms: float = 0.0
    min_segment_time_ms: float = float('inf')
    max_segment_time_ms: float = 0.0
    
    # Performance metrics
    total_payload_bytes: int = 0
    total_packet_bytes: int = 0
    throughput_segments_per_sec: float = 0.0
    throughput_bytes_per_sec: float = 0.0
    
    # Modification statistics
    ttl_modifications: int = 0
    checksum_corruptions: int = 0
    tcp_flags_modifications: int = 0
    window_size_modifications: int = 0
    
    # Timing accuracy
    avg_timing_accuracy_error_ms: float = 0.0
    timing_accuracy_percent: float = 100.0
```

#### 3. GlobalExecutionStats
Provides system-wide statistics across all sessions:

```python
@dataclass
class GlobalExecutionStats:
    # Session metrics
    total_sessions: int = 0
    active_sessions: int = 0
    completed_sessions: int = 0
    failed_sessions: int = 0
    
    # Segment metrics
    total_segments_processed: int = 0
    total_successful_segments: int = 0
    total_failed_segments: int = 0
    
    # Performance metrics
    avg_session_duration_ms: float = 0.0
    avg_segments_per_session: float = 0.0
    global_throughput_segments_per_sec: float = 0.0
    global_throughput_bytes_per_sec: float = 0.0
    
    # Timing metrics
    global_avg_timing_accuracy_percent: float = 100.0
    global_avg_construction_time_ms: float = 0.0
    global_avg_transmission_time_ms: float = 0.0
    
    # Modification statistics
    total_ttl_modifications: int = 0
    total_checksum_corruptions: int = 0
    total_tcp_flags_modifications: int = 0
    total_window_size_modifications: int = 0
    
    # Error statistics
    error_rate_percent: float = 0.0
    common_errors: Dict[str, int] = field(default_factory=dict)
```

#### 4. SegmentExecutionStatsCollector
Central collector that manages all statistics:

```python
class SegmentExecutionStatsCollector:
    def start_segment_execution(self, segment_id, session_id, payload_size, seq_offset, options)
    def update_segment_phase(self, metrics, phase, duration_ms)
    def complete_segment_execution(self, metrics, status, error_message, ...)
    def start_session(self, session_id, connection_id)
    def complete_session(self, session_id)
    def get_global_stats(self)
    def get_performance_summary(self)
    def get_recent_sessions(self, count)
    def get_recent_segments(self, count)
```

## Execution Phases

The system tracks five distinct phases of segment execution:

### 1. Validation Phase
- Validates segment parameters
- Checks payload format and options
- Verifies context compatibility

### 2. Construction Phase
- Builds packet from segment data
- Applies packet modifications
- Calculates checksums and headers

### 3. Timing Phase
- Executes requested delays
- Measures timing accuracy
- Tracks timing strategy used

### 4. Transmission Phase
- Sends packet via PyDivert
- Measures transmission time
- Records transmission success/failure

### 5. Complete Phase
- Finalizes segment metrics
- Updates session statistics
- Records final status

## Execution Status

Each segment execution can have one of four statuses:

- **SUCCESS**: Segment executed successfully
- **FAILED**: Segment execution failed (recoverable)
- **TIMEOUT**: Segment execution timed out
- **ERROR**: Unrecoverable error occurred

## Integration with NativePyDivertEngine

The statistics system is automatically integrated with the NativePyDivertEngine:

```python
def _execute_segments_with_timing(self, segments: list, context: AttackContext) -> bool:
    # Get controllers
    timing_controller = get_timing_controller()
    diagnostic_logger = get_segment_diagnostic_logger()
    stats_collector = get_segment_stats_collector()  # Statistics integration
    
    # Start statistics session
    session_stats = stats_collector.start_session(session_id, context.connection_id)
    
    for i, segment in enumerate(segments):
        # Start segment statistics tracking
        segment_metrics = stats_collector.start_segment_execution(
            i + 1, session_id, len(payload_data), seq_offset, options_dict
        )
        
        # Track each phase
        stats_collector.update_segment_phase(segment_metrics, ExecutionPhase.VALIDATION, validation_time)
        stats_collector.update_segment_phase(segment_metrics, ExecutionPhase.CONSTRUCTION, construction_time)
        stats_collector.update_segment_phase(segment_metrics, ExecutionPhase.TIMING, timing_phase_time)
        stats_collector.update_segment_phase(segment_metrics, ExecutionPhase.TRANSMISSION, transmission_time)
        
        # Complete segment with detailed metrics
        stats_collector.complete_segment_execution(
            segment_metrics, status, error_message, packet_size,
            ttl_modified, checksum_corrupted, tcp_flags_modified, 
            window_size_modified, timing_accuracy_error_ms
        )
    
    # Complete session
    session_stats = stats_collector.complete_session(session_id)
```

## Usage Examples

### Basic Statistics Collection

```python
from core.bypass.monitoring.segment_execution_stats import get_segment_stats_collector

# Get global collector
stats_collector = get_segment_stats_collector()

# Start session
session_stats = stats_collector.start_session("attack_session", "connection_id")

# Track segment execution
segment_metrics = stats_collector.start_segment_execution(
    segment_id=1,
    session_id="attack_session",
    payload_size=100,
    seq_offset=0,
    options={"ttl": 64, "delay_ms": 5}
)

# Update phases
stats_collector.update_segment_phase(segment_metrics, ExecutionPhase.VALIDATION, 1.0)
stats_collector.update_segment_phase(segment_metrics, ExecutionPhase.CONSTRUCTION, 2.0)
stats_collector.update_segment_phase(segment_metrics, ExecutionPhase.TIMING, 5.2)
stats_collector.update_segment_phase(segment_metrics, ExecutionPhase.TRANSMISSION, 0.8)

# Complete segment
stats_collector.complete_segment_execution(
    segment_metrics,
    ExecutionStatus.SUCCESS,
    packet_size=150,
    ttl_modified=True,
    timing_accuracy_error_ms=0.2
)

# Complete session
completed_session = stats_collector.complete_session("attack_session")
```

### Engine Integration

```python
from core.bypass.engines.native_pydivert_engine import NativePyDivertEngine

# Create engine (statistics automatically integrated)
engine = NativePyDivertEngine(config)

# Execute attack (statistics collected automatically)
result = engine.execute_attack(attack_result, context)

# Get statistics
segment_stats = engine.get_segment_execution_statistics()
performance_metrics = engine.get_performance_metrics()
recent_sessions = engine.get_recent_session_stats(10)

# Analyze performance
print(f"Success rate: {performance_metrics['reliability']['success_rate_percent']:.1f}%")
print(f"Throughput: {performance_metrics['throughput']['segments_per_sec']:.1f} segments/sec")
print(f"Timing accuracy: {performance_metrics['timing']['avg_accuracy_percent']:.1f}%")
```

### Performance Analysis

```python
# Get comprehensive performance summary
performance_summary = stats_collector.get_performance_summary()

# Analyze timing performance
timing_analysis = performance_summary["timing_analysis"]
print(f"Construction time: {timing_analysis['construction_time_ms']['avg']:.2f}ms avg")
print(f"Transmission time: {timing_analysis['transmission_time_ms']['avg']:.2f}ms avg")
print(f"Timing accuracy error: {timing_analysis['timing_accuracy_error_ms']['avg']:.3f}ms avg")

# Analyze modifications
mod_analysis = performance_summary["modification_analysis"]
print(f"TTL modifications: {mod_analysis['ttl_modifications']['percentage']:.1f}%")
print(f"Checksum corruptions: {mod_analysis['checksum_corruptions']['percentage']:.1f}%")

# Analyze errors
error_analysis = performance_summary["error_analysis"]
print(f"Error rate: {error_analysis['error_rate_percent']:.1f}%")
for error_type, count in error_analysis["error_types"].items():
    print(f"  {error_type}: {count}")
```

## Monitoring and Alerting

### Real-time Monitoring

```python
def monitor_performance():
    stats_collector = get_segment_stats_collector()
    
    while True:
        global_stats = stats_collector.get_global_stats()
        
        # Check performance thresholds
        if global_stats.global_success_rate_percent < 90:
            alert("Low success rate", global_stats.global_success_rate_percent)
        
        if global_stats.global_throughput_segments_per_sec < 10:
            alert("Low throughput", global_stats.global_throughput_segments_per_sec)
        
        if global_stats.global_avg_timing_accuracy_percent < 85:
            alert("Poor timing accuracy", global_stats.global_avg_timing_accuracy_percent)
        
        time.sleep(10)  # Check every 10 seconds
```

### Dashboard Creation

```python
def create_dashboard():
    stats_collector = get_segment_stats_collector()
    global_stats = stats_collector.get_global_stats()
    performance_summary = stats_collector.get_performance_summary()
    
    dashboard = {
        "overview": {
            "active_sessions": global_stats.active_sessions,
            "total_segments": global_stats.total_segments_processed,
            "success_rate": global_stats.global_success_rate_percent,
            "error_rate": global_stats.error_rate_percent
        },
        "performance": {
            "throughput": global_stats.global_throughput_segments_per_sec,
            "timing_accuracy": global_stats.global_avg_timing_accuracy_percent,
            "avg_construction_time": global_stats.global_avg_construction_time_ms,
            "avg_transmission_time": global_stats.global_avg_transmission_time_ms
        },
        "modifications": {
            "ttl_modifications": global_stats.total_ttl_modifications,
            "checksum_corruptions": global_stats.total_checksum_corruptions,
            "tcp_flags_modifications": global_stats.total_tcp_flags_modifications,
            "window_size_modifications": global_stats.total_window_size_modifications
        },
        "recent_activity": stats_collector.get_recent_sessions(5),
        "timing_analysis": performance_summary.get("timing_analysis", {}),
        "error_analysis": performance_summary.get("error_analysis", {})
    }
    
    return dashboard
```

## Performance Metrics

### Throughput Metrics
- **Segments per second**: Rate of segment processing
- **Bytes per second**: Data throughput rate
- **Sessions per minute**: Session completion rate

### Timing Metrics
- **Construction time**: Time to build packets
- **Transmission time**: Time to send packets
- **Timing accuracy**: Precision of delay implementation
- **Total execution time**: End-to-end segment processing time

### Reliability Metrics
- **Success rate**: Percentage of successful segments
- **Error rate**: Percentage of failed segments
- **Session completion rate**: Percentage of completed sessions

### Modification Metrics
- **TTL modifications**: Count and percentage of TTL changes
- **Checksum corruptions**: Count and percentage of checksum modifications
- **TCP flags modifications**: Count and percentage of flag changes
- **Window size modifications**: Count and percentage of window changes

## Configuration

### Statistics Collection Settings

```python
# Create collector with custom settings
collector = SegmentExecutionStatsCollector(
    max_history_size=1000  # Maximum number of historical records
)

# Global collector configuration
from core.bypass.monitoring.segment_execution_stats import reset_global_stats
reset_global_stats()  # Reset all statistics
```

### Performance Thresholds

```python
# Define performance thresholds for monitoring
PERFORMANCE_THRESHOLDS = {
    "min_success_rate_percent": 90.0,
    "min_throughput_segments_per_sec": 10.0,
    "min_timing_accuracy_percent": 85.0,
    "max_avg_construction_time_ms": 5.0,
    "max_avg_transmission_time_ms": 2.0,
    "max_error_rate_percent": 10.0
}
```

## Thread Safety

The statistics system is fully thread-safe:

- Uses `threading.RLock()` for all operations
- Supports concurrent segment execution tracking
- Safe for multi-threaded engine operations
- Atomic updates to global statistics

## Memory Management

- Configurable history size limits
- Automatic cleanup of old records
- Efficient data structures (deque for O(1) operations)
- Minimal memory overhead per segment

## Integration Points

### Engine Integration
- Automatic statistics collection during segment execution
- Integration with diagnostic system
- Performance metrics in engine reports

### Diagnostic System Integration
- Correlates with diagnostic logging
- Provides performance context for diagnostics
- Shared session tracking

### Timing Controller Integration
- Tracks timing accuracy from timing controller
- Correlates requested vs actual delays
- Performance analysis of timing strategies

## Best Practices

### 1. Regular Monitoring
```python
# Monitor key metrics regularly
def check_system_health():
    stats = get_segment_stats_collector().get_global_stats()
    
    if stats.global_success_rate_percent < 95:
        logger.warning(f"Success rate below threshold: {stats.global_success_rate_percent:.1f}%")
    
    if stats.global_throughput_segments_per_sec < 50:
        logger.warning(f"Throughput below threshold: {stats.global_throughput_segments_per_sec:.1f} segments/sec")
```

### 2. Performance Analysis
```python
# Analyze performance trends
def analyze_performance_trends():
    collector = get_segment_stats_collector()
    recent_sessions = collector.get_recent_sessions(20)
    
    # Calculate trend metrics
    success_rates = [s.success_rate_percent for s in recent_sessions]
    avg_times = [s.avg_segment_time_ms for s in recent_sessions]
    
    # Detect performance degradation
    if len(success_rates) >= 10:
        recent_avg = sum(success_rates[-5:]) / 5
        older_avg = sum(success_rates[-10:-5]) / 5
        
        if recent_avg < older_avg - 5:  # 5% degradation
            logger.warning("Performance degradation detected")
```

### 3. Resource Optimization
```python
# Optimize based on statistics
def optimize_based_on_stats():
    summary = get_segment_stats_collector().get_performance_summary()
    timing_analysis = summary.get("timing_analysis", {})
    
    # Optimize construction if it's slow
    construction_time = timing_analysis.get("construction_time_ms", {})
    if construction_time.get("avg", 0) > 3.0:
        logger.info("Consider optimizing packet construction")
    
    # Optimize timing if accuracy is poor
    timing_error = timing_analysis.get("timing_accuracy_error_ms", {})
    if timing_error.get("avg", 0) > 1.0:
        logger.info("Consider adjusting timing strategy")
```

## Troubleshooting

### Common Issues

#### 1. High Memory Usage
```python
# Reduce history size
collector = SegmentExecutionStatsCollector(max_history_size=500)

# Regular cleanup
collector.reset_statistics()
```

#### 2. Performance Impact
```python
# Minimize statistics collection overhead
# - Use appropriate history sizes
# - Avoid frequent global stats queries
# - Batch statistics updates when possible
```

#### 3. Thread Contention
```python
# Reduce lock contention
# - Minimize time in critical sections
# - Use local variables before updating shared state
# - Batch updates when possible
```

## Future Enhancements

### Planned Features
- Historical trend analysis
- Predictive performance modeling
- Automated performance optimization
- Integration with external monitoring systems
- Real-time alerting and notifications
- Performance regression detection
- Comparative analysis between attack types

### API Extensions
- REST API for external monitoring
- WebSocket for real-time updates
- Export capabilities (JSON, CSV, metrics format)
- Integration with Prometheus/Grafana
- Custom metric definitions

## Conclusion

The Segment Execution Statistics and Monitoring system provides comprehensive visibility into the performance and behavior of the Native Attack Orchestration system. It enables:

- **Real-time monitoring** of segment execution performance
- **Historical analysis** of system behavior and trends
- **Performance optimization** through detailed metrics
- **Reliability monitoring** with success/failure tracking
- **Resource utilization** analysis and optimization
- **Integration** with existing diagnostic and monitoring systems

This system is essential for maintaining high performance, reliability, and effectiveness of segment-based attacks in production environments.