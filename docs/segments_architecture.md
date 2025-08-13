# Segments Orchestration Architecture

## Overview

The segments orchestration system is a revolutionary enhancement to our native attack architecture that enables full TCP session control. Instead of modifying single packets, attacks can now return detailed scenarios for the engine to execute with precise timing, TTL manipulation, and checksum corruption.

## Key Concepts

### Segment Tuple Format

Each segment is defined as a tuple: `(payload_data, seq_offset, options_dict)`

```python
SegmentTuple = Tuple[bytes, int, Dict[str, Any]]
```

- **payload_data**: Raw bytes to send
- **seq_offset**: TCP sequence number offset from original packet
- **options_dict**: Transmission options

### Supported Options

The options dictionary supports the following keys:

- `"ttl": int` - IP Time To Live value (for packet dropping)
- `"bad_checksum": bool` - Corrupt TCP checksum
- `"delay_ms": float` - Delay before sending (milliseconds)
- `"window_size": int` - TCP window size override
- `"flags": int` - TCP flags override

## AttackResult Enhancement

### New Properties

```python
@property
def segments(self) -> Optional[List[SegmentTuple]]:
    """Get/set segments list for orchestration"""

def has_segments(self) -> bool:
    """Check if result contains segments"""

def get_segment_count(self) -> int:
    """Get number of segments"""

def add_segment(self, payload_data: bytes, seq_offset: int = 0, options: Optional[Dict[str, Any]] = None):
    """Add a segment to the result"""
```

### Backward Compatibility

The `modified_payload` field is maintained for backward compatibility. When both `segments` and `modified_payload` are present, the engine prioritizes `segments`.

## Helper Functions

### AttackResultHelper Enhancements

```python
# Create result with segments
AttackResultHelper.create_segments_result(
    technique_used="fakeddisorder",
    segments=segments_list
)

# Validate segments format
AttackResultHelper.validate_segments(segments_list)

# Safe operations
AttackResultHelper.has_segments(result)
AttackResultHelper.get_segments(result)
AttackResultHelper.add_segment(result, payload, offset, options)
```

## Usage Examples

### FakedDisorder Attack

```python
def execute(self, context: AttackContext) -> AttackResult:
    payload = context.payload
    split_pos = context.params.get("split_pos", 3)
    
    # Create fake packet
    fake_payload = b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
    
    # Split real payload
    part1 = payload[:split_pos]
    part2 = payload[split_pos:]
    
    # Create segment scenario
    segments = [
        # Fake packet with low TTL (dropped by DPI)
        (fake_payload, 0, {"ttl": 2, "delay_ms": 5}),
        
        # Second part first (creates disorder)
        (part2, split_pos, {"delay_ms": 10}),
        
        # First part last
        (part1, 0, {})
    ]
    
    return AttackResultHelper.create_segments_result(
        technique_used="fakeddisorder",
        segments=segments
    )
```

### Multisplit Attack

```python
def execute(self, context: AttackContext) -> AttackResult:
    payload = context.payload
    split_count = context.params.get("split_count", 3)
    
    segments = []
    chunk_size = len(payload) // split_count
    
    for i in range(split_count):
        start = i * chunk_size
        end = start + chunk_size if i < split_count - 1 else len(payload)
        chunk = payload[start:end]
        
        segments.append((chunk, start, {
            "delay_ms": i * 5,  # Progressive delays
            "window_size": 32768 - (i * 1024)  # Varying window
        }))
    
    return AttackResultHelper.create_segments_result(
        technique_used="multisplit",
        segments=segments
    )
```

## Engine Integration

The native engine will process segments as follows:

1. **Intercept original packet**
2. **Execute attack** via AttackAdapter
3. **Check for segments** in AttackResult
4. **If segments present**:
   - Don't send original packet
   - Iterate through segments
   - Apply timing delays
   - Construct packets with options
   - Send via PyDivert
5. **If no segments**: Use legacy modified_payload or send original

## Benefits

### Precision Control
- Microsecond-level timing control
- Exact TTL and checksum manipulation
- Complete TCP session orchestration

### Zapret-Level Effectiveness
- Replicates zapret's sophisticated techniques
- Multi-packet scenarios with precise timing
- Advanced state confusion attacks

### Flexibility
- Any number of segments per attack
- Rich options for each segment
- Easy composition of complex scenarios

### Maintainability
- Clean separation of concerns
- Backward compatibility preserved
- Comprehensive validation and error handling

## Migration Guide

### For Attack Developers

1. **Keep existing attacks** - they continue to work
2. **For new attacks** - use segments architecture
3. **Migration pattern**:
   ```python
   # Old way
   return AttackResult(
       status=AttackStatus.SUCCESS,
       modified_payload=modified_data
   )
   
   # New way
   segments = [(modified_data, 0, {})]
   return AttackResultHelper.create_segments_result(
       technique_used="my_attack",
       segments=segments
   )
   ```

### For Engine Developers

1. **Check for segments first**:
   ```python
   if result.has_segments():
       await self._execute_segments(result.segments, context)
   elif result.modified_payload:
       await self._send_modified_packet(result.modified_payload, context)
   else:
       return False  # Send original
   ```

2. **Implement segment execution loop**
3. **Add timing control with asyncio.sleep()**
4. **Use PacketBuilder for construction**

## Testing

Comprehensive test suite covers:
- Segment validation
- Helper functions
- Backward compatibility
- Error handling
- Performance characteristics

Run tests with:
```bash
python -m pytest tests/test_attack_result_segments.py -v
```

## Performance Considerations

- Minimal overhead for segment processing
- Efficient packet construction with PacketBuilder
- Optimized timing control
- Memory-efficient segment storage

## Future Enhancements

- Advanced timing patterns
- Conditional segment execution
- Dynamic segment generation
- Integration with ML optimization

This architecture provides the foundation for achieving zapret-level effectiveness while maintaining the flexibility and extensibility of our Python-based system.