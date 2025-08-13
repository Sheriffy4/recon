# Segment Execution Diagnostics System

This document describes the comprehensive diagnostic logging and analysis system for segment-based attack orchestration in the Native Attack Orchestration system.

## Overview

The Segment Execution Diagnostics System provides detailed monitoring, logging, and analysis capabilities for segment-based attacks. It tracks every phase of segment execution, from validation through transmission, providing comprehensive insights into performance, accuracy, and effectiveness.

## Key Features

- **Comprehensive Phase Tracking**: Monitors validation, construction, timing, and transmission phases
- **Detailed Event Logging**: Records all events with timestamps and metadata
- **Performance Analysis**: Calculates throughput, timing accuracy, and execution metrics
- **Error Tracking**: Detailed error logging and categorization
- **Session Management**: Groups segments into sessions for analysis
- **Global Statistics**: Tracks system-wide diagnostic metrics

## Architecture

### Core Components

1. **SegmentDiagnosticLogger**: Main diagnostic logging class
2. **SegmentDiagnosticData**: Individual segment diagnostic information
3. **SegmentExecutionSummary**: Session-level analysis and reporting
4. **SegmentExecutionEvent**: Individual events during execution
5. **SegmentExecutionPhase**: Execution phase enumeration

### Data Flow

```
Session Start → Segment Start → Validation → Construction → Timing → Transmission → Session End → Summary
```

## Usage

### Basic Usage

```python
from core.bypass.diagnostics.segment_diagnostics import get_segment_diagnostic_logger

# Get diagnostic logger
diagnostic_logger = get_segment_diagnostic_logger()

# Start session
session_id = "attack_session_001"
connection_id = "192.168.1.100:12345->1.2.3.4:443"
diagnostic_logger.start_session(session_id, connection_id)

# Log segment execution
segment_data = diagnostic_logger.log_segment_start(
    session_id, 1, 150, 0, {"ttl": 1, "delay_ms": 10}
)

# Log each phase
diagnostic_logger.log_validation_phase(segment_data, 1.2, True)
diagnostic_logger.log_construction_phase(segment_data, packet_info)
diagnostic_logger.log_timing_phase(segment_data, timing_measurement)
diagnostic_logger.log_transmission_phase(segment_data, 0.9, True)

# End session and get summary
summary = diagnostic_logger.end_session(session_id)
```

### Integration with Engine

The diagnostic system is automatically integrated with `NativePyDivertEngine`:

```python
# Diagnostics are automatically enabled in segment execution
engine._execute_segments_with_timing(segments, context)
# This automatically creates diagnostic sessions and logs all phases
```

## Diagnostic Data Structure

### SegmentDiagnosticData

Contains comprehensive information about a single segment:

```python
@dataclass
class SegmentDiagnosticData:
    segment_id: int
    payload_size: int
    seq_offset: int
    options: Dict[str, Any]
    
    # Phase timings
    validation_time_ms: Optional[float]
    construction_time_ms: Optional[float]
    timing_delay_ms: Optional[float]
    transmission_time_ms: Optional[float]
    total_execution_time_ms: Optional[float]
    
    # Results
    packet_info: Optional[SegmentPacketInfo]
    timing_measurement: Optional[TimingMeasurement]
    success: bool
    error_message: Optional[str]
    
    # Event log
    events: List[SegmentExecutionEvent]
```

### SegmentExecutionSummary

Provides session-level analysis:

```python
@dataclass
class SegmentExecutionSummary:
    session_id: str
    connection_id: str
    total_segments: int
    successful_segments: int
    failed_segments: int
    
    # Timing analysis
    total_execution_time_ms: float
    average_segment_time_ms: float
    min_segment_time_ms: float
    max_segment_time_ms: float
    
    # Packet analysis
    total_packets_built: int
    total_bytes_transmitted: int
    ttl_modifications: int
    checksum_corruptions: int
    timing_delays_applied: int
    
    # Accuracy analysis
    timing_accuracy_average: float
    timing_errors: int
    construction_errors: int
    transmission_errors: int
    
    # Performance metrics
    packets_per_second: float
    bytes_per_second: float
```

## Execution Phases

### 1. Validation Phase

Validates segment format and options:

```python
diagnostic_logger.log_validation_phase(
    segment_data, 
    validation_time_ms=1.2, 
    success=True, 
    error_message=None
)
```

**Tracked Metrics:**
- Validation time
- Success/failure status
- Error messages
- Validation rules applied

### 2. Construction Phase

Logs packet construction details:

```python
diagnostic_logger.log_construction_phase(segment_data, packet_info)
```

**Tracked Metrics:**
- Construction time
- Packet size
- TCP sequence/acknowledgment numbers
- TTL modifications
- Checksum corruption
- Applied options

### 3. Timing Phase

Records timing delay execution:

```python
diagnostic_logger.log_timing_phase(segment_data, timing_measurement)
```

**Tracked Metrics:**
- Requested vs actual delay
- Timing accuracy
- Strategy used
- Error measurements

### 4. Transmission Phase

Logs packet transmission:

```python
diagnostic_logger.log_transmission_phase(
    segment_data, 
    transmission_time_ms=0.9, 
    success=True, 
    error_message=None
)
```

**Tracked Metrics:**
- Transmission time
- Success/failure status
- Error messages
- Total execution time

## Analysis and Reporting

### Session Summary

Each session generates a comprehensive summary:

```python
summary = diagnostic_logger.end_session(session_id)

print(f"Success rate: {summary.successful_segments}/{summary.total_segments}")
print(f"Average timing accuracy: {summary.timing_accuracy_average:.1f}%")
print(f"Throughput: {summary.packets_per_second:.1f} packets/sec")
```

### Detailed Logging

The system provides detailed logging output:

```
2024-01-15 10:30:15 - SegmentDiagnostics - INFO - Started diagnostic session demo_session_001 for connection 192.168.1.100:12345->1.2.3.4:443
2024-01-15 10:30:15 - SegmentDiagnostics - DEBUG - Session demo_session_001: Started segment 1 (payload: 150 bytes, offset: 0)
2024-01-15 10:30:15 - SegmentDiagnostics - DEBUG - Segment 1 validation succeeded (1.200ms)
2024-01-15 10:30:15 - SegmentDiagnostics - DEBUG - Segment 1 packet constructed: 175 bytes, seq=1000 (TTL=1) (2.800ms)
2024-01-15 10:30:15 - SegmentDiagnostics - DEBUG - Segment 1 timing delay: requested=10.000ms, actual=9.800ms, error=0.200ms, strategy=high_precision
2024-01-15 10:30:15 - SegmentDiagnostics - DEBUG - Segment 1 transmission succeeded (0.900ms)
2024-01-15 10:30:15 - SegmentDiagnostics - INFO - Segment 1 completed successfully (total: 15.200ms)
```

### Comprehensive Summary Report

```
============================================================
SEGMENT EXECUTION SUMMARY - Session demo_session_001
============================================================
Connection: 192.168.1.100:12345->1.2.3.4:443
Segments: 3/3 successful (100.0%)
Total execution time: 45.2ms
Average segment time: 15.1ms
Segment time range: 12.5ms - 18.3ms

Packet Analysis:
  - Packets built: 3
  - Bytes transmitted: 525
  - TTL modifications: 2
  - Checksum corruptions: 1
  - Timing delays applied: 3

Accuracy Analysis:
  - Timing accuracy: 98.5%
  - Timing errors: 0
  - Construction errors: 0
  - Transmission errors: 0

Performance Metrics:
  - Packets/second: 66.4
  - Bytes/second: 11,615.0
============================================================
```

## Configuration

### Basic Configuration

```python
from core.bypass.diagnostics.segment_diagnostics import configure_segment_diagnostics

configure_segment_diagnostics(
    detailed_logging=True,
    max_events_per_segment=100,
    max_sessions_history=50
)
```

### Engine Integration Configuration

```python
# Diagnostics are automatically configured in NativePyDivertEngine
# Additional configuration can be done through the diagnostic logger
diagnostic_logger = get_segment_diagnostic_logger()
diagnostic_logger.configure(detailed_logging=False)
```

## Performance Metrics

### Timing Analysis

- **Timing Accuracy**: Percentage accuracy of timing delays
- **Timing Errors**: Count of delays with >1ms error
- **Average Delay Error**: Mean timing error across all segments

### Throughput Analysis

- **Packets per Second**: Segment processing rate
- **Bytes per Second**: Data transmission rate
- **Average Segment Time**: Mean execution time per segment

### Modification Tracking

- **TTL Modifications**: Count of packets with modified TTL
- **Checksum Corruptions**: Count of packets with corrupted checksums
- **Timing Delays Applied**: Count of segments with timing delays

## Error Tracking

### Error Categories

1. **Validation Errors**: Invalid segment format or options
2. **Construction Errors**: Packet building failures
3. **Transmission Errors**: Network transmission failures
4. **Timing Errors**: Precision timing failures

### Error Analysis

```python
summary = diagnostic_logger.end_session(session_id)

print(f"Validation errors: {summary.failed_segments - summary.transmission_errors}")
print(f"Construction errors: {summary.construction_errors}")
print(f"Transmission errors: {summary.transmission_errors}")
print(f"Timing errors: {summary.timing_errors}")
```

## Global Statistics

### System-Wide Metrics

```python
stats = diagnostic_logger.get_global_statistics()

print(f"Total sessions: {stats['total_sessions']}")
print(f"Total segments processed: {stats['total_segments_processed']}")
print(f"Average execution time per session: {stats['average_execution_time_per_session_ms']:.1f}ms")
```

### Historical Data

The system maintains limited historical data:

- **Session History**: Last 50 sessions (configurable)
- **Event History**: Last 100 events per segment (configurable)
- **Global Counters**: Persistent across system lifetime

## Integration Examples

### Manual Integration

```python
# Create diagnostic logger
diagnostic_logger = SegmentDiagnosticLogger("CustomDiagnostics")

# Use in custom segment execution
session_id = "custom_session"
diagnostic_logger.start_session(session_id, "custom_connection")

for segment in segments:
    segment_data = diagnostic_logger.log_segment_start(
        session_id, segment.id, len(segment.payload), 
        segment.seq_offset, segment.options
    )
    
    # Execute segment with logging
    # ... segment execution code ...
    
    diagnostic_logger.log_transmission_phase(segment_data, time_ms, success)

summary = diagnostic_logger.end_session(session_id)
```

### Engine Integration

```python
# Automatic integration in NativePyDivertEngine
engine = NativePyDivertEngine(config)

# Diagnostics are automatically enabled
result = engine._execute_segments_orchestration(attack_result, context)

# Get diagnostic statistics
diag_stats = engine.get_diagnostic_statistics()
```

## Best Practices

### Performance Considerations

1. **Detailed Logging**: Enable only when needed for debugging
2. **History Limits**: Configure appropriate limits for memory usage
3. **Event Filtering**: Use appropriate logging levels

### Analysis Workflow

1. **Enable Diagnostics**: Configure detailed logging for analysis
2. **Execute Segments**: Run segment-based attacks
3. **Analyze Results**: Review session summaries and statistics
4. **Optimize Performance**: Use metrics to improve timing and throughput

### Troubleshooting

1. **Check Session Status**: Verify sessions are properly started/ended
2. **Review Event Logs**: Examine detailed event sequences
3. **Analyze Error Patterns**: Look for common failure modes
4. **Monitor Performance**: Track timing accuracy and throughput

## Future Enhancements

### Planned Features

1. **Real-time Monitoring**: Live diagnostic dashboards
2. **Advanced Analytics**: Machine learning-based analysis
3. **Export Capabilities**: JSON/CSV export for external analysis
4. **Alerting System**: Automatic alerts for performance issues

### Integration Improvements

1. **Database Storage**: Persistent diagnostic data storage
2. **Web Interface**: Browser-based diagnostic viewing
3. **API Endpoints**: REST API for diagnostic data access
4. **Visualization**: Charts and graphs for performance analysis

## Conclusion

The Segment Execution Diagnostics System provides comprehensive monitoring and analysis capabilities for segment-based attack orchestration. It enables detailed performance analysis, error tracking, and optimization of segment execution, making it an essential tool for developing and debugging advanced DPI evasion techniques.