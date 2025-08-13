# NativePyDivertEngine Segments Integration

## Overview

The NativePyDivertEngine has been enhanced with segments orchestration capabilities, enabling precise control over TCP session manipulation. This integration allows attacks to return detailed packet scenarios instead of simple payload modifications, achieving zapret-level effectiveness.

## Architecture Integration

```
┌─────────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│   PyDivert Packet   │───▶│ NativePyDivertEngine │───▶│   AttackAdapter     │
│   (Intercepted)     │    │                      │    │                     │
└─────────────────────┘    └──────────────────────┘    └─────────────────────┘
                                      │                           │
                                      ▼                           ▼
                           ┌──────────────────────┐    ┌─────────────────────┐
                           │ Enhanced Context     │    │   Attack Result     │
                           │ (TCP Session Info)   │    │   (with Segments)   │
                           └──────────────────────┘    └─────────────────────┘
                                      │                           │
                                      ▼                           ▼
                           ┌──────────────────────┐    ┌─────────────────────┐
                           │ SegmentPacketBuilder │    │ Segments Execution  │
                           │ (Packet Construction)│    │ (Timing Control)    │
                           └──────────────────────┘    └─────────────────────┘
```

## Key Enhancements

### 1. Enhanced AttackContext Creation

The engine now creates comprehensive AttackContext objects with complete TCP session information:

```python
def _create_enhanced_attack_context(self, packet: pydivert.Packet) -> Optional[AttackContext]:
    """Create enhanced AttackContext with complete TCP session information."""
    
    context = AttackContext(
        # Basic packet info
        dst_ip=packet.dst_addr,
        dst_port=packet.dst_port,
        src_ip=packet.src_addr,
        src_port=packet.src_port,
        payload=packet.tcp.payload,
        
        # Enhanced TCP session information
        tcp_seq=packet.tcp.seq_num,
        tcp_ack=packet.tcp.ack_num,
        tcp_flags=self._get_tcp_flags_int(packet),
        tcp_window_size=packet.tcp.window_size,
        
        # Connection state
        connection_id=f"{packet.src_addr}:{packet.src_port}->{packet.dst_addr}:{packet.dst_port}",
        session_established=True
    )
    
    return context
```

### 2. Segments Orchestration Engine

The core orchestration logic handles segment execution with precise timing:

```python
def _execute_segments_orchestration(self, attack_result: AttackResult, context: AttackContext) -> bool:
    """Execute segments orchestration with precise timing and control."""
    
    segments = attack_result.segments
    
    for i, segment in enumerate(segments):
        # Build packet using SegmentPacketBuilder
        packet_info = self.segment_builder.build_segment(
            segment[0],  # payload_data
            segment[1],  # seq_offset
            segment[2],  # options_dict
            context
        )
        
        # Apply pre-send delay
        delay_ms = segment[2].get("delay_ms", 0)
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        
        # Send packet via PyDivert
        packet_obj = pydivert.Packet(packet_info.packet_bytes)
        self.windivert_handle.send(packet_obj)
```

### 3. Backward Compatibility

Legacy attacks using `modified_payload` continue to work:

```python
if attack_result.has_segments():
    # New segments orchestration
    return self._execute_segments_orchestration(attack_result, context)
elif attack_result.modified_payload:
    # Legacy modified payload support
    return self._send_modified_packet(packet, attack_result.modified_payload)
```

## Usage Examples

### Basic Segments Attack

```python
class ExampleSegmentsAttack(BaseAttack):
    def execute(self, context: AttackContext) -> AttackResult:
        payload = context.payload
        
        # Create segments scenario
        segments = [
            # Fake packet with low TTL
            (b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n", 0, {
                "ttl": 2,
                "delay_ms": 5
            }),
            
            # Real payload with timing
            (payload, 0, {
                "delay_ms": 10,
                "bad_checksum": True
            })
        ]
        
        return AttackResultHelper.create_segments_result(
            technique_used="example_segments",
            segments=segments
        )
```

### Engine Integration

```python
# Initialize engine with segments support
config = EngineConfig(debug=True)
engine = NativePyDivertEngine(config)

# The engine automatically detects and handles segments
# No additional configuration needed
```

## Packet Processing Flow

### 1. Packet Interception

```python
def _process_packet_with_attack(self, packet: pydivert.Packet) -> bool:
    """Enhanced packet processing with segments orchestration support."""
    
    # Create enhanced context
    context = self._create_enhanced_attack_context(packet)
    
    # Execute attack
    attack_result = await self.attack_adapter.execute_attack_by_name(attack_name, context)
    
    # Handle result based on type
    if attack_result.has_segments():
        return self._execute_segments_orchestration(attack_result, context)
    elif attack_result.modified_payload:
        return self._send_modified_packet(packet, attack_result.modified_payload)
    else:
        return False  # Send original packet
```

### 2. TCP Flags Conversion

```python
def _get_tcp_flags_int(self, packet: pydivert.Packet) -> int:
    """Convert PyDivert TCP flags to integer representation."""
    
    flags = 0
    if packet.tcp.fin: flags |= 0x01
    if packet.tcp.syn: flags |= 0x02
    if packet.tcp.rst: flags |= 0x04
    if packet.tcp.psh: flags |= 0x08
    if packet.tcp.ack: flags |= 0x10
    if packet.tcp.urg: flags |= 0x20
    if packet.tcp.ece: flags |= 0x40
    if packet.tcp.cwr: flags |= 0x80
    
    return flags
```

### 3. Segment Execution

```python
# For each segment in the attack result:
for i, segment in enumerate(segments):
    # Build packet with precise control
    packet_info = self.segment_builder.build_segment(
        payload_data=segment[0],
        seq_offset=segment[1], 
        options=segment[2],
        context=context
    )
    
    # Apply timing delay
    delay_ms = segment[2].get("delay_ms", 0)
    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)
    
    # Send via PyDivert
    packet_obj = pydivert.Packet(packet_info.packet_bytes)
    self.windivert_handle.send(packet_obj)
    
    # Update statistics
    self.stats.packets_sent += 1
    self.stats.modified_packets += 1
```

## Advanced Features

### Timing Precision

The engine supports microsecond-level timing control:

```python
# Sub-millisecond delays
segments = [
    (payload1, 0, {"delay_ms": 2.5}),    # 2.5ms delay
    (payload2, 10, {"delay_ms": 0.1}),   # 0.1ms delay
    (payload3, 20, {})                   # No delay
]
```

### TTL Manipulation

Precise TTL control for packet dropping techniques:

```python
segments = [
    (fake_payload, 0, {"ttl": 2}),       # Will be dropped by DPI
    (real_payload, 0, {"ttl": 64})       # Normal TTL
]
```

### Checksum Corruption

Intentional checksum corruption for DPI confusion:

```python
segments = [
    (payload, 0, {"bad_checksum": True})  # Corrupted checksum
]
```

### TCP Flags Manipulation

Complete control over TCP flags:

```python
segments = [
    (payload1, 0, {"flags": 0x02}),      # SYN
    (payload2, 10, {"flags": 0x18}),     # PSH+ACK
    (payload3, 20, {"flags": 0x11})      # FIN+ACK
]
```

## Statistics and Monitoring

### Enhanced Statistics

The engine collects comprehensive statistics including segment builder metrics:

```python
stats = engine.get_stats()

# Standard engine stats
print(f"Packets processed: {stats.packets_processed}")
print(f"Packets modified: {stats.packets_modified}")

# Segment builder stats (if available)
if hasattr(stats, 'metadata'):
    print(f"Segment packets built: {stats.metadata.get('segment_packets_built', 0)}")
    print(f"TTL modifications: {stats.metadata.get('segment_ttl_modifications', 0)}")
    print(f"Checksum corruptions: {stats.metadata.get('segment_checksum_corruptions', 0)}")
```

### Performance Monitoring

```python
# Segment builder performance
segment_stats = engine.segment_builder.get_stats()
print(f"Average build time: {segment_stats['avg_build_time_ms']:.3f} ms")
print(f"Total packets built: {segment_stats['packets_built']}")
```

## Error Handling

### Segment Validation

```python
# Automatic validation during orchestration
try:
    result = engine._execute_segments_orchestration(attack_result, context)
except Exception as e:
    logger.error(f"Segments orchestration failed: {e}")
    return False
```

### Graceful Degradation

```python
# If segment building fails, continue with remaining segments
for i, segment in enumerate(segments):
    try:
        packet_info = self.segment_builder.build_segment(...)
        # Send packet
    except Exception as e:
        logger.error(f"Failed to send segment {i + 1}: {e}")
        continue  # Continue with next segment
```

## Integration Benefits

### Zapret-Level Effectiveness

- **Precise Timing**: Microsecond-level control over packet transmission
- **TTL Manipulation**: Exact TTL values for packet dropping techniques
- **Checksum Corruption**: Intentional corruption for DPI confusion
- **TCP Session Control**: Complete control over sequence numbers and flags

### Performance Optimization

- **Efficient Packet Building**: Optimized raw packet construction
- **Minimal Overhead**: Direct PyDivert integration without unnecessary layers
- **Statistics Collection**: Comprehensive performance monitoring
- **Memory Efficiency**: Optimized segment processing

### Flexibility and Extensibility

- **Backward Compatibility**: Legacy attacks continue to work
- **Easy Migration**: Simple upgrade path for existing attacks
- **Rich Options**: Comprehensive segment option support
- **Debugging Support**: Detailed logging and statistics

## Migration Guide

### For Attack Developers

1. **Keep existing attacks** - they work with `modified_payload`
2. **For new attacks** - use segments architecture:

```python
# Old way
return AttackResult(
    status=AttackStatus.SUCCESS,
    modified_payload=modified_data
)

# New way
segments = [(modified_data, 0, {"delay_ms": 5})]
return AttackResultHelper.create_segments_result(
    technique_used="my_attack",
    segments=segments
)
```

### For Engine Users

No changes required - the engine automatically handles both legacy and segments-based attacks.

## Best Practices

1. **Use Segments for Complex Attacks**: Multi-packet scenarios benefit from segments
2. **Validate Segments**: Use validation functions before execution
3. **Monitor Performance**: Track segment builder statistics
4. **Handle Errors Gracefully**: Implement proper error handling
5. **Test Timing**: Verify timing precision in your environment

This integration provides the foundation for implementing sophisticated DPI bypass techniques with the precision and control needed to match zapret's effectiveness while maintaining the flexibility and extensibility of the Python-based system.