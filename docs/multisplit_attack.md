# MultisplitAttack Documentation

## Overview

The `MultisplitAttack` is an advanced DPI bypass technique that fragments payloads into multiple configurable segments with optional overlap, timing variations, and TCP option diversity. This attack is particularly effective against DPI systems that rely on contiguous data stream analysis and expect packets to arrive in predictable patterns.

## Attack Strategy

The MultisplitAttack implements a flexible segmentation strategy:

1. **Payload Fragmentation**: Splits payload into N configurable segments
2. **Optional Overlap**: Adds redundant bytes between segments for confusion
3. **Timing Variation**: Uses configurable delays with optional randomization
4. **TCP Diversity**: Varies TTL, flags, and window sizes across segments
5. **Order Randomization**: Optionally randomizes segment transmission order
6. **Padding and Corruption**: Adds padding and selectively corrupts checksums

### Key Advantages

- **Flexible Segmentation**: 2-20 configurable segments
- **Overlap Support**: Redundant data between segments
- **Timing Control**: Linear or exponential backoff patterns
- **TCP Diversity**: Varies multiple TCP parameters
- **Order Confusion**: Optional segment order randomization
- **Adaptive Configuration**: Multiple predefined variants

## Architecture

### Core Components

#### MultisplitConfig
Comprehensive configuration dataclass:

```python
@dataclass
class MultisplitConfig:
    # Segmentation
    split_count: int = 5                    # Number of segments (2-20)
    min_segment_size: int = 10              # Minimum segment size
    max_segment_size: int = 0               # Maximum segment size (0=no limit)
    overlap_bytes: int = 0                  # Overlap between segments
    
    # Timing
    base_delay_ms: float = 5.0              # Base delay between segments
    delay_variation_ms: float = 3.0         # Random delay variation (±ms)
    exponential_backoff: bool = False       # Use exponential backoff
    backoff_multiplier: float = 1.5         # Backoff multiplier
    
    # Randomization
    randomize_order: bool = False           # Randomize segment order
    
    # TCP Variations
    vary_ttl: bool = False                  # Vary TTL values
    ttl_range: Tuple[int, int] = (60, 64)   # TTL range
    vary_tcp_flags: bool = False            # Vary TCP flags
    vary_window_size: bool = False          # Vary window sizes
    window_size_range: Tuple[int, int] = (32768, 65535)
    
    # Advanced Options
    add_padding: bool = False               # Add padding to segments
    padding_range: Tuple[int, int] = (1, 5) # Padding size range
    corrupt_some_checksums: bool = False    # Corrupt some checksums
    checksum_corruption_probability: float = 0.2  # Corruption probability
```

#### MultisplitAttack
Main attack class with comprehensive functionality:

```python
class MultisplitAttack(BaseAttack):
    def execute(self, context: AttackContext) -> AttackResult
    def estimate_effectiveness(self, context: AttackContext) -> float
    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]
    def get_required_capabilities(self) -> List[str]
    def get_attack_info(self) -> Dict[str, Any]
```

## Usage Examples

### Basic Usage

```python
from core.bypass.attacks.reference.multisplit_attack import MultisplitAttack
from core.bypass.attacks.base import AttackContext

# Create attack
attack = MultisplitAttack()

# Create context
context = AttackContext(
    dst_ip="203.0.113.10",
    dst_port=443,
    payload=b"POST /api/data HTTP/1.1\r\nHost: api.com\r\nContent-Length: 50\r\n\r\n{\"data\": \"sensitive_information\"}",
    connection_id="demo"
)

# Execute attack
result = attack.execute(context)

# Check result
if result.status == AttackStatus.SUCCESS:
    print(f"Created {len(result._segments)} segments")
    for i, (payload, seq_offset, options) in enumerate(result._segments):
        print(f"Segment {i+1}: {len(payload)} bytes at offset {seq_offset}, delay={options['delay_ms']}ms")
```

### Custom Configuration

```python
from core.bypass.attacks.reference.multisplit_attack import (
    MultisplitAttack, MultisplitConfig
)

# Create custom configuration
config = MultisplitConfig(
    split_count=8,                    # 8 segments
    min_segment_size=15,              # Minimum 15 bytes
    overlap_bytes=3,                  # 3 bytes overlap
    base_delay_ms=10.0,               # 10ms base delay
    delay_variation_ms=5.0,           # ±5ms variation
    randomize_order=True,             # Randomize order
    vary_ttl=True,                    # Vary TTL
    ttl_range=(55, 64),              # TTL range
    vary_tcp_flags=True,              # Vary TCP flags
    corrupt_some_checksums=True,      # Corrupt some checksums
    checksum_corruption_probability=0.3,  # 30% corruption rate
    exponential_backoff=True,         # Exponential delays
    backoff_multiplier=1.8            # 1.8x multiplier
)

# Create attack with config
attack = MultisplitAttack(name="custom_multisplit", config=config)
```

### Factory Functions

```python
from core.bypass.attacks.reference.multisplit_attack import (
    create_multisplit_attack,
    create_aggressive_multisplit,
    create_subtle_multisplit,
    create_overlap_multisplit,
    create_timing_multisplit
)

# Standard attack
standard = create_multisplit_attack(split_count=6, base_delay_ms=8.0)

# Aggressive variant (maximum fragmentation)
aggressive = create_aggressive_multisplit()

# Subtle variant (minimal fragmentation)
subtle = create_subtle_multisplit()

# Overlap-optimized variant
overlap = create_overlap_multisplit()

# Timing-optimized variant
timing = create_timing_multisplit()
```

## Configuration Parameters

### Segmentation Parameters

#### Split Count (`split_count`)
- **Range**: 2 to 20
- **Default**: 5
- **Description**: Number of segments to create
- **Impact**: More segments = more confusion but higher overhead

#### Segment Size Constraints
- **`min_segment_size`**: Minimum bytes per segment (default: 10)
- **`max_segment_size`**: Maximum bytes per segment (0 = no limit)
- **Impact**: Controls segment size distribution

#### Overlap (`overlap_bytes`)
- **Range**: 0 to payload_size/2
- **Default**: 0
- **Description**: Redundant bytes between segments
- **Impact**: Increases confusion but adds overhead

### Timing Parameters

#### Base Delay (`base_delay_ms`)
- **Range**: 0.0+
- **Default**: 5.0ms
- **Description**: Base delay between segments
- **Impact**: Higher delays increase stealth but add latency

#### Delay Variation (`delay_variation_ms`)
- **Range**: 0.0+
- **Default**: 3.0ms
- **Description**: Random variation in delays (±ms)
- **Impact**: Prevents timing pattern detection

#### Exponential Backoff
- **`exponential_backoff`**: Enable exponential delay increase (default: False)
- **`backoff_multiplier`**: Multiplier for exponential delays (default: 1.5)
- **Impact**: Creates increasing delay pattern

### Randomization Parameters

#### Order Randomization (`randomize_order`)
- **Default**: False
- **Description**: Randomize segment transmission order
- **Impact**: Confuses order-dependent DPI analysis

### TCP Variation Parameters

#### TTL Variation
- **`vary_ttl`**: Enable TTL variation (default: False)
- **`ttl_range`**: TTL value range (default: 60-64)
- **Impact**: Varies packet routing behavior

#### TCP Flags Variation (`vary_tcp_flags`)
- **Default**: False
- **Description**: Vary TCP flags across segments
- **Options**: PSH+ACK (0x18), ACK (0x10), PSH (0x08)
- **Impact**: Confuses flag-based DPI analysis

#### Window Size Variation
- **`vary_window_size`**: Enable window size variation (default: False)
- **`window_size_range`**: Window size range (default: 32768-65535)
- **Impact**: Varies TCP flow control parameters

### Advanced Parameters

#### Padding
- **`add_padding`**: Add padding to segments (default: False)
- **`padding_range`**: Padding size range (default: 1-5 bytes)
- **Impact**: Obscures actual segment boundaries

#### Checksum Corruption
- **`corrupt_some_checksums`**: Enable selective corruption (default: False)
- **`checksum_corruption_probability`**: Corruption probability (default: 0.2)
- **Impact**: Forces retransmission, confuses analysis

## Segmentation Strategies

### Count-Based Segmentation
When `max_segment_size` is 0 (default):

```python
# Divides payload into equal segments based on split_count
base_size = payload_length // split_count
remainder = payload_length % split_count
# First 'remainder' segments get +1 byte
```

### Size-Based Segmentation
When `max_segment_size` > 0:

```python
# Creates segments up to max_segment_size
# Number of segments varies based on payload size
# Includes size randomization if delay_variation_ms > 0
```

### Overlap Handling
When `overlap_bytes` > 0:

```python
# Extends segment boundaries to create overlap
# Previous segment extends forward
# Next segment extends backward
# Maintains payload integrity at destination
```

## Timing Strategies

### Linear Timing
```python
config = MultisplitConfig(
    base_delay_ms=5.0,
    delay_variation_ms=2.0,
    exponential_backoff=False
)
# Delays: ~5ms ±2ms for each segment
```

### Exponential Backoff
```python
config = MultisplitConfig(
    base_delay_ms=2.0,
    exponential_backoff=True,
    backoff_multiplier=1.5
)
# Delays: 2ms, 3ms, 4.5ms, 6.75ms, 10.125ms...
```

### High Variation
```python
config = MultisplitConfig(
    base_delay_ms=3.0,
    delay_variation_ms=8.0
)
# Delays: 3ms ±8ms (wide random variation)
```

## Attack Variants

### Standard Variant
- Balanced configuration for general use
- 5 segments with moderate delays
- No advanced features enabled

```python
attack = create_multisplit_attack()
```

### Aggressive Variant
- Maximum fragmentation and confusion
- 10 segments with overlap
- All variation features enabled
- Exponential backoff timing

```python
attack = create_aggressive_multisplit()
# Configuration:
# - split_count=10
# - overlap_bytes=3
# - randomize_order=True
# - vary_ttl=True
# - vary_tcp_flags=True
# - vary_window_size=True
# - add_padding=True
# - corrupt_some_checksums=True
# - exponential_backoff=True
```

### Subtle Variant
- Minimal fragmentation for stealth
- 3 segments with short delays
- No variation features
- Low detection risk

```python
attack = create_subtle_multisplit()
# Configuration:
# - split_count=3
# - overlap_bytes=0
# - base_delay_ms=2.0
# - All variation features disabled
```

### Overlap Variant
- Optimized for overlap-based confusion
- 6 segments with 5-byte overlap
- TTL variation and checksum corruption
- Order randomization

```python
attack = create_overlap_multisplit()
```

### Timing Variant
- Optimized for timing-based confusion
- 7 segments with high delay variation
- Exponential backoff
- TCP flag and window size variation

```python
attack = create_timing_multisplit()
```

## Effectiveness Estimation

The attack provides dynamic effectiveness estimation:

```python
effectiveness = attack.estimate_effectiveness(context)
print(f"Estimated effectiveness: {effectiveness:.1%}")
```

### Effectiveness Factors

#### Base Effectiveness: 60%

#### Payload Size Bonuses:
- **>500 bytes**: +10%
- **>1000 bytes**: +10% (additional)

#### Configuration Bonuses:
- **≥7 segments**: +10%
- **Overlap enabled**: +5%
- **Order randomization**: +5%
- **TCP variations**: +5%
- **Checksum corruption**: +5%
- **Exponential backoff**: +5%

#### Maximum Effectiveness: 100%

### Example Effectiveness Scores:
- **Small payload, basic config**: ~60-70%
- **Large payload, aggressive config**: ~90-100%
- **Medium payload, overlap config**: ~75-85%

## Integration with Native Attack Orchestration

### Segments Architecture
```python
# Attack creates N segments based on configuration
segments = result._segments
# [(segment1_payload, offset1, options1),
#  (segment2_payload, offset2, options2),
#  ...]
```

### Engine Integration
```python
from core.bypass.engines.native_pydivert_engine import NativePyDivertEngine

engine = NativePyDivertEngine(config)
result = engine.execute_attack(attack_result, context)

# Engine automatically handles:
# - Segment timing control (including exponential backoff)
# - TTL modifications
# - TCP flag variations
# - Window size modifications
# - Checksum corruption
# - Order randomization
# - Statistics collection
# - Diagnostic logging
```

## Performance Characteristics

### Execution Speed
- Fast segment creation (< 5ms for typical payloads)
- Efficient boundary calculation algorithms
- Minimal CPU overhead per segment

### Memory Usage
- Linear memory usage with segment count
- Efficient overlap handling
- Minimal memory overhead per segment

### Network Impact
- **Packet Overhead**: N packets instead of 1 (N×100% overhead)
- **Byte Overhead**: Overlap bytes + padding (configurable)
- **Timing Overhead**: Sum of all segment delays
- **Bandwidth Efficiency**: High (minimal redundant data)

### Scalability
- Handles large payloads efficiently (tested up to 10KB)
- Supports up to 20 segments
- Concurrent execution support
- Thread-safe implementation

## Security Considerations

### Overlap Security
- Overlap data is identical to original payload
- No sensitive information leakage
- Destination receives complete, valid payload

### Timing Security
- Randomized delays prevent timing fingerprinting
- Exponential backoff appears natural
- No predictable timing signatures

### Order Security
- Randomization uses cryptographically secure random
- Sequence offsets maintain payload integrity
- No information leakage through ordering

## Troubleshooting

### Common Issues

#### "Payload too small for N segments"
```python
# Solution: Reduce segment count or increase payload size
config = MultisplitConfig(split_count=3)  # Fewer segments
# OR ensure payload >= split_count * min_segment_size
```

#### Poor Effectiveness Estimation
```python
# Check payload size and configuration
if len(payload) < 500:
    # Use fewer segments for small payloads
    config.split_count = 3
    
# Enable more features for higher effectiveness
config.overlap_bytes = 2
config.randomize_order = True
config.vary_ttl = True
```

#### High Memory Usage
```python
# Reduce segment count and overlap
config = MultisplitConfig(
    split_count=5,      # Instead of 10+
    overlap_bytes=1     # Instead of 5+
)
```

#### Timing Issues
```python
# Reduce delays for time-sensitive applications
config = MultisplitConfig(
    base_delay_ms=1.0,
    delay_variation_ms=0.5,
    exponential_backoff=False
)
```

### Performance Issues

#### Slow Execution
```python
# Disable expensive features
config = MultisplitConfig(
    randomize_order=False,
    add_padding=False,
    vary_ttl=False
)
```

#### High Network Latency
```python
# Minimize delays
config = MultisplitConfig(
    base_delay_ms=0.5,
    delay_variation_ms=0.2
)
```

## Best Practices

### Configuration Selection

#### For HTTP Traffic
```python
# Moderate segmentation with overlap
config = MultisplitConfig(
    split_count=6,
    overlap_bytes=3,
    base_delay_ms=5.0,
    vary_tcp_flags=True
)
```

#### For Binary Data
```python
# High segmentation with randomization
config = MultisplitConfig(
    split_count=8,
    randomize_order=True,
    vary_ttl=True,
    corrupt_some_checksums=True
)
```

#### For Time-Sensitive Applications
```python
# Minimal delays, fewer segments
config = MultisplitConfig(
    split_count=3,
    base_delay_ms=1.0,
    delay_variation_ms=0.5
)
```

#### For Maximum Stealth
```python
# Subtle configuration
attack = create_subtle_multisplit()
```

#### For Maximum Confusion
```python
# Aggressive configuration
attack = create_aggressive_multisplit()
```

### Payload Size Optimization
```python
def optimize_for_payload_size(payload_size: int) -> MultisplitConfig:
    if payload_size < 100:
        return MultisplitConfig(split_count=2, min_segment_size=5)
    elif payload_size < 500:
        return MultisplitConfig(split_count=4, overlap_bytes=1)
    elif payload_size < 2000:
        return MultisplitConfig(split_count=7, overlap_bytes=3)
    else:
        return MultisplitConfig(split_count=10, overlap_bytes=5)
```

### Effectiveness Monitoring
```python
# Monitor effectiveness over time
effectiveness_history = []
for result in attack_results:
    eff = attack.estimate_effectiveness(context)
    effectiveness_history.append(eff)

avg_effectiveness = sum(effectiveness_history) / len(effectiveness_history)
if avg_effectiveness < 0.7:
    # Consider more aggressive configuration
    attack = create_aggressive_multisplit()
```

## Advanced Usage

### Custom Segment Boundary Calculation
```python
class CustomMultisplitAttack(MultisplitAttack):
    def _calculate_segment_boundaries(self, payload_len: int) -> List[Tuple[int, int]]:
        # Custom boundary calculation logic
        # Example: Split at specific content boundaries
        boundaries = []
        # ... custom logic ...
        return boundaries
```

### Dynamic Configuration
```python
def create_adaptive_multisplit(context: AttackContext) -> MultisplitAttack:
    config = MultisplitConfig()
    
    # Adapt based on payload size
    payload_len = len(context.payload)
    if payload_len > 1000:
        config.split_count = 8
        config.overlap_bytes = 4
    elif payload_len > 500:
        config.split_count = 6
        config.overlap_bytes = 2
    else:
        config.split_count = 4
        config.overlap_bytes = 1
    
    # Adapt based on destination port
    if context.dst_port == 443:  # HTTPS
        config.vary_ttl = True
        config.corrupt_some_checksums = True
    elif context.dst_port == 80:  # HTTP
        config.vary_tcp_flags = True
        config.randomize_order = True
    
    return MultisplitAttack(config=config)
```

### Integration with Other Attacks
```python
# Chain with other attacks
def create_multi_layer_attack():
    attacks = [
        create_multisplit_attack(split_count=4),
        create_other_attack(),  # Additional attack
    ]
    return attacks

# Conditional attack selection
def select_attack_based_on_payload(payload: bytes):
    if len(payload) > 1000:
        return create_aggressive_multisplit()
    elif b'HTTP/' in payload:
        return create_overlap_multisplit()
    else:
        return create_subtle_multisplit()
```

## Testing and Validation

### Unit Testing
```python
def test_multisplit_execution():
    attack = MultisplitAttack()
    context = create_test_context()
    result = attack.execute(context)
    
    assert result.status == AttackStatus.SUCCESS
    assert len(result._segments) == attack.config.split_count
    
    # Verify payload reconstruction
    segments_sorted = sorted(result._segments, key=lambda x: x[1])
    reconstructed = b"".join(payload for payload, _, _ in segments_sorted)
    assert reconstructed == context.payload
```

### Integration Testing
```python
def test_engine_integration():
    engine = NativePyDivertEngine(config)
    attack = create_aggressive_multisplit()
    result = attack.execute(context)
    
    success = engine._execute_segments_orchestration(result, context)
    assert success
    
    # Verify all segments were processed
    stats = engine.get_stats()
    assert stats.packets_sent == len(result._segments)
```

### Performance Testing
```python
def test_performance_with_large_payload():
    large_payload = b"X" * 10000  # 10KB
    context = AttackContext(payload=large_payload, ...)
    
    attack = create_multisplit_attack(split_count=15)
    
    start_time = time.time()
    result = attack.execute(context)
    execution_time = time.time() - start_time
    
    assert result.status == AttackStatus.SUCCESS
    assert execution_time < 0.1  # Should be fast
    assert len(result._segments) == 15
```

## Conclusion

The MultisplitAttack provides a highly configurable and effective approach to bypassing DPI systems that rely on contiguous data stream analysis. Key benefits include:

- **High Flexibility**: Extensive configuration options for different scenarios
- **Proven Effectiveness**: Particularly effective against stream-based DPI
- **Performance**: Efficient execution with minimal overhead
- **Integration**: Seamless integration with Native Attack Orchestration
- **Variants**: Multiple predefined variants for common use cases
- **Security**: Safe overlap and timing handling
- **Scalability**: Handles payloads from small to very large

The attack is suitable for various use cases, from subtle bypassing to aggressive DPI confusion, making it a versatile tool in the DPI bypass arsenal.