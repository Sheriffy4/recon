# FakedDisorderAttack Documentation

## Overview

The `FakedDisorderAttack` is a sophisticated DPI bypass technique that uses packet disorder and fake packets to confuse Deep Packet Inspection (DPI) systems. This attack is particularly effective against DPI systems that rely on packet order analysis and sequential content inspection.

## Attack Strategy

The FakedDisorderAttack implements a three-segment strategy:

1. **Fake Packet**: Sends a deceptive packet with low TTL (Time To Live) that will be dropped by intermediate routers
2. **Part 2**: Sends the second part of the real payload first
3. **Part 1**: Sends the first part of the real payload last

### What Each System Sees

- **DPI System**: `[fake_packet] → [part2] → [part1]` (confused by disorder and fake content)
- **Destination Server**: `[part1] → [part2]` (fake packet is dropped, receives complete payload)

## Architecture

### Core Components

#### FakedDisorderConfig
Configuration dataclass that controls attack behavior:

```python
@dataclass
class FakedDisorderConfig:
    split_pos: float = 0.5              # Where to split payload (0.0-1.0)
    fake_ttl: int = 1                   # TTL for fake packet
    fake_delay_ms: float = 20.0         # Delay after fake packet
    part2_delay_ms: float = 8.0         # Delay after part 2
    part1_delay_ms: float = 5.0         # Delay after part 1
    use_different_fake_payload: bool = True
    custom_fake_payload: Optional[bytes] = None
    corrupt_fake_checksum: bool = False
    fake_tcp_flags: Optional[int] = None
    randomize_fake_content: bool = True
```

#### FakedDisorderAttack
Main attack class implementing the BaseAttack interface:

```python
class FakedDisorderAttack(BaseAttack):
    def execute(self, context: AttackContext) -> AttackResult
    def estimate_effectiveness(self, context: AttackContext) -> float
    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]
    def get_required_capabilities(self) -> List[str]
```

## Usage Examples

### Basic Usage

```python
from core.bypass.attacks.reference.faked_disorder_attack import FakedDisorderAttack
from core.bypass.attacks.base import AttackContext

# Create attack
attack = FakedDisorderAttack()

# Create context
context = AttackContext(
    dst_ip="93.184.216.34",
    dst_port=80,
    payload=b"GET /blocked HTTP/1.1\r\nHost: blocked.com\r\n\r\n",
    connection_id="demo"
)

# Execute attack
result = attack.execute(context)

# Check result
if result.status == AttackStatus.SUCCESS:
    print(f"Created {len(result._segments)} segments")
    for i, (payload, seq_offset, options) in enumerate(result._segments):
        print(f"Segment {i+1}: {len(payload)} bytes, TTL={options['ttl']}")
```

### Custom Configuration

```python
from core.bypass.attacks.reference.faked_disorder_attack import (
    FakedDisorderAttack, FakedDisorderConfig
)

# Create custom configuration
config = FakedDisorderConfig(
    split_pos=0.3,                    # Split at 30%
    fake_ttl=2,                       # TTL=2 for fake packet
    fake_delay_ms=25.0,               # 25ms delay
    corrupt_fake_checksum=True,       # Corrupt fake checksum
    randomize_fake_content=True       # Randomize fake content
)

# Create attack with config
attack = FakedDisorderAttack(name="custom_disorder", config=config)
```

### Factory Functions

```python
from core.bypass.attacks.reference.faked_disorder_attack import (
    create_faked_disorder_attack,
    create_aggressive_faked_disorder,
    create_subtle_faked_disorder,
    create_http_optimized_faked_disorder
)

# Standard attack
standard = create_faked_disorder_attack()

# Aggressive variant (maximum confusion)
aggressive = create_aggressive_faked_disorder()

# Subtle variant (minimal delays)
subtle = create_subtle_faked_disorder()

# HTTP-optimized variant
http_optimized = create_http_optimized_faked_disorder()
```

## Configuration Parameters

### Split Position (`split_pos`)
- **Range**: 0.0 to 1.0
- **Default**: 0.5
- **Description**: Where to split the payload (0.5 = middle)
- **Impact**: Affects how the payload is divided between segments

### Fake Packet TTL (`fake_ttl`)
- **Range**: 1 to 255
- **Default**: 1
- **Description**: TTL value for fake packet (low values ensure dropping)
- **Impact**: Lower values increase chance of packet being dropped

### Timing Configuration
- **`fake_delay_ms`**: Delay after fake packet (default: 20.0ms)
- **`part2_delay_ms`**: Delay after part 2 (default: 8.0ms)
- **`part1_delay_ms`**: Delay after part 1 (default: 5.0ms)
- **Impact**: Affects timing between segments, can influence DPI behavior

### Fake Payload Options
- **`use_different_fake_payload`**: Generate different fake content (default: True)
- **`custom_fake_payload`**: Use specific fake payload (default: None)
- **`randomize_fake_content`**: Add randomization to fake content (default: True)

### Advanced Options
- **`corrupt_fake_checksum`**: Corrupt fake packet checksum (default: False)
- **`fake_tcp_flags`**: Custom TCP flags for fake packet (default: None)

## Fake Payload Generation

The attack intelligently generates fake payloads based on the original content:

### HTTP GET Requests
```python
# Original: GET /blocked HTTP/1.1
# Fake:     GET /favicon.ico HTTP/1.1
```

### HTTP POST Requests
```python
# Original: POST /api/data HTTP/1.1
# Fake:     GET /robots.txt HTTP/1.1
```

### TLS Handshakes
```python
# Modifies SNI extension and other TLS fields
```

### Generic Payloads
```python
# Creates HTTP-like fake payload for unknown content
```

## Effectiveness Estimation

The attack provides effectiveness estimation based on various factors:

```python
effectiveness = attack.estimate_effectiveness(context)
print(f"Estimated effectiveness: {effectiveness:.1%}")
```

### Factors Affecting Effectiveness
- **Payload Type**: HTTP traffic gets higher effectiveness
- **Payload Length**: Longer payloads provide more confusion opportunities
- **Split Position**: Extreme positions (too early/late) reduce effectiveness
- **Configuration**: Different fake payloads and checksum corruption increase effectiveness

## Validation and Error Handling

### Context Validation
```python
is_valid, error = attack.validate_context(context)
if not is_valid:
    print(f"Validation failed: {error}")
```

### Common Validation Errors
- Empty payload
- Payload too short for splitting (< 10 bytes)
- Invalid TCP sequence numbers
- Invalid split positions

### Error Handling
```python
result = attack.execute(context)
if result.status == AttackStatus.FAILED:
    error = result.metadata.get('error', 'Unknown error')
    print(f"Attack failed: {error}")
```

## Integration with Native Attack Orchestration

The FakedDisorderAttack integrates seamlessly with the Native Attack Orchestration system:

### Segments Architecture
```python
# Attack creates 3 segments
segments = result._segments
# [(fake_payload, 0, fake_options),
#  (part2_payload, split_pos, part2_options),
#  (part1_payload, 0, part1_options)]
```

### Engine Integration
```python
from core.bypass.engines.native_pydivert_engine import NativePyDivertEngine

engine = NativePyDivertEngine(config)
result = engine.execute_attack(attack_result, context)

# Engine automatically handles:
# - Segment timing control
# - TTL modifications
# - Checksum corruption
# - Statistics collection
# - Diagnostic logging
```

## Attack Variants

### Standard Variant
- Balanced configuration for general use
- 50% split position
- Moderate delays
- Different fake payload

### Aggressive Variant
- Maximum confusion tactics
- 30% split position
- Longer delays (30ms fake delay)
- Checksum corruption enabled
- Content randomization

### Subtle Variant
- Minimal detection risk
- 60% split position
- Short delays (10ms fake delay)
- No checksum corruption
- No content randomization

### HTTP-Optimized Variant
- Optimized for HTTP traffic
- 40% split position (after headers)
- HTTP-specific fake generation
- Moderate delays

## Performance Characteristics

### Execution Speed
- Fast segment creation (< 1ms for typical payloads)
- Minimal CPU overhead
- Efficient memory usage

### Network Impact
- 3 packets instead of 1 (200% packet overhead)
- Timing delays add latency
- Fake packet dropped by network (no bandwidth waste at destination)

### Scalability
- Handles large payloads efficiently
- Concurrent execution support
- Thread-safe implementation

## Security Considerations

### Fake Packet Security
- Low TTL ensures fake packets don't reach destination
- Different content prevents payload reconstruction attacks
- Checksum corruption adds additional protection

### Timing Security
- Randomized delays prevent timing fingerprinting
- Configurable timing patterns
- No predictable timing signatures

### Content Security
- Fake payloads don't contain sensitive information
- Original payload integrity maintained
- No data leakage through fake packets

## Troubleshooting

### Common Issues

#### Attack Fails with "Payload too short"
```python
# Solution: Ensure payload is at least 10 bytes
if len(payload) < 10:
    payload = payload + b"padding"
```

#### Poor Effectiveness Estimation
```python
# Check payload type and configuration
info = attack.get_attack_info()
print(f"Attack type: {info['type']}")
print(f"Recommended for: {info['effectiveness']}")
```

#### Validation Errors
```python
# Check context completeness
required_fields = ['dst_ip', 'dst_port', 'payload']
for field in required_fields:
    if not getattr(context, field, None):
        print(f"Missing required field: {field}")
```

### Performance Issues

#### Slow Execution
```python
# Use simpler configuration
config = FakedDisorderConfig(
    randomize_fake_content=False,
    use_different_fake_payload=False
)
```

#### High Memory Usage
```python
# For large payloads, consider splitting differently
if len(payload) > 10000:
    config.split_pos = 0.1  # Smaller first part
```

## Best Practices

### Configuration Selection
1. **For HTTP Traffic**: Use `create_http_optimized_faked_disorder()`
2. **For High Security**: Use `create_aggressive_faked_disorder()`
3. **For Low Latency**: Use `create_subtle_faked_disorder()`
4. **For General Use**: Use default `FakedDisorderAttack()`

### Timing Optimization
```python
# Adjust delays based on network conditions
if high_latency_network:
    config.fake_delay_ms = 50.0
    config.part2_delay_ms = 20.0
    config.part1_delay_ms = 15.0
```

### Split Position Selection
```python
# For HTTP: Split after headers
if b'\r\n\r\n' in payload:
    header_end = payload.find(b'\r\n\r\n') + 4
    config.split_pos = header_end / len(payload)

# For TLS: Split in middle of handshake
elif payload.startswith(b'\x16\x03'):
    config.split_pos = 0.6
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
    print("Consider adjusting attack configuration")
```

## Advanced Usage

### Custom Fake Payload Generation
```python
class CustomFakedDisorderAttack(FakedDisorderAttack):
    def _create_deceptive_fake_payload(self, original_payload: bytes) -> bytes:
        # Custom fake payload logic
        if b'secret' in original_payload:
            return b'GET /public-info HTTP/1.1\r\nHost: public.com\r\n\r\n'
        return super()._create_deceptive_fake_payload(original_payload)
```

### Dynamic Configuration
```python
def create_adaptive_attack(context: AttackContext) -> FakedDisorderAttack:
    config = FakedDisorderConfig()
    
    # Adapt based on payload size
    if len(context.payload) > 1000:
        config.split_pos = 0.2  # Early split for large payloads
    
    # Adapt based on destination port
    if context.dst_port == 443:  # HTTPS
        config.fake_delay_ms = 30.0  # Longer delay for TLS
    
    return FakedDisorderAttack(config=config)
```

### Integration with Other Attacks
```python
# Chain with other attacks
def create_multi_layer_attack():
    attacks = [
        create_faked_disorder_attack(),
        create_other_attack(),  # Additional attack
    ]
    return attacks
```

## Testing and Validation

### Unit Testing
```python
def test_attack_execution():
    attack = FakedDisorderAttack()
    context = create_test_context()
    result = attack.execute(context)
    
    assert result.status == AttackStatus.SUCCESS
    assert len(result._segments) == 3
    assert result._segments[0][2]['ttl'] == 1  # Fake packet TTL
```

### Integration Testing
```python
def test_engine_integration():
    engine = NativePyDivertEngine(config)
    attack = FakedDisorderAttack()
    result = attack.execute(context)
    
    success = engine._execute_segments_orchestration(result, context)
    assert success
```

### Effectiveness Testing
```python
def test_effectiveness_estimation():
    attack = FakedDisorderAttack()
    
    # Test different payload types
    http_context = create_http_context()
    binary_context = create_binary_context()
    
    http_eff = attack.estimate_effectiveness(http_context)
    binary_eff = attack.estimate_effectiveness(binary_context)
    
    assert http_eff > binary_eff  # HTTP should be more effective
```

## Conclusion

The FakedDisorderAttack provides a powerful and flexible approach to bypassing DPI systems that rely on packet order analysis. Key benefits include:

- **High Effectiveness**: Particularly effective against order-dependent DPI
- **Flexibility**: Highly configurable for different scenarios
- **Intelligence**: Adaptive fake payload generation
- **Integration**: Seamless integration with Native Attack Orchestration
- **Performance**: Efficient execution with minimal overhead
- **Security**: Safe fake packet handling with TTL-based dropping

The attack is suitable for various use cases, from subtle bypassing to aggressive DPI confusion, making it a valuable tool in the DPI bypass arsenal.