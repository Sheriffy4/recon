# Reference Attack Implementations

This directory contains comprehensive reference implementations for the Native Attack Orchestration system. These attacks demonstrate the full capabilities of the segment-based architecture and serve as templates for developing custom attacks.

## Overview

The reference attacks showcase different aspects of DPI evasion:

- **TCP-level manipulation**: Timing, flags, window sizes
- **Payload transformation**: Encoding, obfuscation, splitting
- **State confusion**: Disorder, urgent pointers, multisplit
- **Performance optimization**: Efficient segment generation

## Available Attacks

### Core TCP Attacks

1. **[TCP Timing Manipulation](tcp_timing_manipulation_attack.py)**
   - Variable delays between segments
   - Multiple timing patterns (linear, exponential, random, burst, sawtooth, fibonacci)
   - TTL variation for path diversity simulation
   - Congestion control simulation

2. **[Urgent Pointer Manipulation](urgent_pointer_manipulation_attack.py)**
   - TCP URG flag manipulation
   - Custom urgent pointer values
   - False urgent data injection
   - Segment prioritization confusion

3. **[Window Scaling Attack](window_scaling_attack.py)**
   - TCP window size manipulation
   - Flow control confusion
   - Zero window attacks
   - Extreme value boundary testing

### Payload Attacks

4. **[Payload Obfuscation](payload_obfuscation_attack.py)**
   - Multiple encoding methods (Base64, hex, XOR, ROT13, compression)
   - Per-segment obfuscation
   - Noise injection
   - Mixed encoding techniques

5. **[Multisplit Attack](multisplit_attack.py)**
   - Payload splitting into multiple segments
   - Overlapping segments
   - Random split positions
   - Timing variation between chunks

6. **[Faked Disorder Attack](faked_disorder_attack.py)**
   - Out-of-order packet simulation
   - Fake packets with low TTL
   - Real payload reordering
   - State machine confusion

## Quick Start

### Basic Usage

```python
from core.bypass.attacks.reference.tcp_timing_manipulation_attack import create_tcp_timing_attack
from core.bypass.attacks.base import AttackContext

# Create attack context
context = AttackContext(
    dst_ip="203.0.113.10",
    dst_port=443,
    payload=b"GET /api/data HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
    connection_id="test"
)

# Create and execute attack
attack = create_tcp_timing_attack()
result = attack.execute(context)

# Check results
print(f"Status: {result.status}")
print(f"Segments: {len(result._segments)}")
```

### Factory Functions

Each attack provides convenient factory functions:

```python
# TCP Timing variants
timing_attack = create_tcp_timing_attack()
burst_attack = create_burst_timing_attack()
fibonacci_attack = create_fibonacci_timing_attack()

# Urgent Pointer variants
urgent_attack = create_urgent_pointer_attack()
aggressive_urgent = create_aggressive_urgent_attack()
subtle_urgent = create_subtle_urgent_attack()

# Window Scaling variants
window_attack = create_window_scaling_attack()
zero_window = create_zero_window_attack()
oscillating_window = create_oscillating_window_attack()

# Payload Obfuscation variants
obfuscation_attack = create_payload_obfuscation_attack()
base64_attack = create_base64_obfuscation_attack()
xor_attack = create_xor_obfuscation_attack()

# Multisplit variants
multisplit_attack = create_multisplit_attack()
overlapping_multisplit = create_overlapping_multisplit_attack()
random_multisplit = create_random_multisplit_attack()

# Faked Disorder variants
disorder_attack = create_faked_disorder_attack()
aggressive_disorder = create_aggressive_disorder_attack()
subtle_disorder = create_subtle_disorder_attack()
```

## Attack Combinations

### Sequential Execution

```python
attacks = [
    create_payload_obfuscation_attack(name="step1"),
    create_tcp_timing_attack(name="step2"),
    create_window_scaling_attack(name="step3")
]

for attack in attacks:
    result = attack.execute(context)
    # Process result...
```

### Concurrent Execution

```python
import threading
import queue

results_queue = queue.Queue()

def execute_attack(attack, context):
    result = attack.execute(context)
    results_queue.put((attack.name, result))

# Start concurrent executions
threads = []
for attack in attacks:
    thread = threading.Thread(target=execute_attack, args=(attack, context))
    threads.append(thread)
    thread.start()

# Wait for completion
for thread in threads:
    thread.join()
```

## Configuration Examples

### TCP Timing Configuration

```python
attack = create_tcp_timing_attack(
    name="custom_timing",
    timing_pattern=TimingPattern.FIBONACCI,
    segment_count=6,
    base_delay_ms=5.0,
    max_delay_ms=50.0,
    ttl_variation=True
)
```

### Payload Obfuscation Configuration

```python
attack = create_payload_obfuscation_attack(
    name="custom_obfuscation",
    obfuscation_method=ObfuscationMethod.MIXED_ENCODING,
    segment_count=4,
    per_segment_obfuscation=True,
    add_noise=True,
    noise_ratio=0.15
)
```

### Window Scaling Configuration

```python
attack = create_window_scaling_attack(
    name="custom_window",
    window_pattern=WindowPattern.OSCILLATING,
    segment_count=8,
    min_window_size=512,
    max_window_size=32768,
    zero_window_probability=0.3
)
```

## Testing

### Unit Tests

Run individual attack tests:

```bash
python -m pytest tests/test_tcp_timing_manipulation_attack.py -v
python -m pytest tests/test_urgent_pointer_manipulation_attack.py -v
python -m pytest tests/test_window_scaling_attack.py -v
python -m pytest tests/test_payload_obfuscation_attack.py -v
python -m pytest tests/test_multisplit_attack.py -v
python -m pytest tests/test_faked_disorder_attack.py -v
```

### Integration Tests

Run comprehensive integration tests:

```bash
python -m pytest tests/test_reference_attacks_integration.py -v
python -m pytest tests/test_all_reference_attacks_final.py -v
```

### Performance Benchmarks

```bash
python examples/reference_attacks_showcase.py
```

## Examples

### Complete Examples

- **[Reference Attacks Showcase](../../examples/reference_attacks_showcase.py)**: Comprehensive demonstration of all attacks
- **[Individual Attack Examples](../../examples/)**: Specific examples for each attack type

### Documentation Examples

- **[Comprehensive Guide](../../docs/reference_attacks_comprehensive_guide.md)**: Complete documentation with examples
- **[Individual Attack Docs](../../docs/)**: Detailed documentation for each attack

## Performance Characteristics

### Execution Time

| Attack Type | Small Payload | Large Payload | Segments |
|-------------|---------------|---------------|----------|
| TCP Timing | 1-5ms | 5-15ms | 3-8 |
| Urgent Pointer | 1-3ms | 3-8ms | 3-6 |
| Window Scaling | 1-3ms | 3-8ms | 4-8 |
| Payload Obfuscation | 5-20ms | 20-100ms | 3-6 |
| Multisplit | 2-8ms | 8-25ms | 2-8 |
| Faked Disorder | 3-10ms | 10-30ms | 3 |

### Memory Usage

- **Base overhead**: ~100-500 bytes per segment
- **Obfuscation overhead**: 1.3-2x original payload size
- **Timing buffers**: Minimal impact

### Network Impact

- **Packet count**: 2-15 packets per attack
- **Bandwidth overhead**: 10-100% depending on technique
- **Latency addition**: 10-1000ms depending on timing

## Best Practices

### Attack Selection

1. **For signature evasion**: Use payload obfuscation
2. **For timing-based DPI**: Use TCP timing manipulation
3. **For stateful inspection**: Use window scaling or urgent pointer
4. **For comprehensive evasion**: Combine multiple techniques

### Configuration Guidelines

1. **Segment count**: 3-8 segments for optimal balance
2. **Timing delays**: 10-100ms for realistic simulation
3. **Window sizes**: Stay within TCP specification ranges
4. **Obfuscation**: Use mixed methods for maximum effectiveness

### Error Handling

All attacks include comprehensive error handling:

- Context validation before execution
- Graceful handling of edge cases
- Detailed error messages for debugging
- Fallback mechanisms for robustness

## Extension Points

### Custom Timing Patterns

```python
class CustomTimingPattern(TimingPattern):
    CUSTOM = "custom"

def generate_custom_delays(segment_count, base_delay, max_delay):
    # Custom timing logic
    return delays
```

### Custom Obfuscation Methods

```python
class CustomObfuscationMethod(ObfuscationMethod):
    CUSTOM = "custom"

def apply_custom_obfuscation(payload):
    # Custom obfuscation logic
    return obfuscated_payload
```

### Custom Window Patterns

```python
class CustomWindowPattern(WindowPattern):
    CUSTOM = "custom"

def generate_custom_window_sizes(segment_count, min_size, max_size):
    # Custom window sizing logic
    return window_sizes
```

## Troubleshooting

### Common Issues

1. **Segment validation errors**: Check payload size and segment count
2. **Timing precision issues**: Verify system timer resolution
3. **Obfuscation failures**: Check encoding compatibility
4. **Memory issues**: Reduce segment count or payload size

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

attack = create_tcp_timing_attack()
result = attack.execute(context)
```

### Performance Monitoring

```python
import time

start_time = time.time()
result = attack.execute(context)
execution_time = time.time() - start_time

print(f"Execution time: {execution_time*1000:.2f}ms")
print(f"Segments: {len(result._segments)}")
print(f"Throughput: {len(context.payload)/execution_time:.0f} B/s")
```

## Contributing

### Adding New Attacks

1. Inherit from `BaseAttack`
2. Implement required methods
3. Add comprehensive tests
4. Create factory functions
5. Update documentation

### Code Style

- Follow PEP 8 guidelines
- Use type hints
- Include comprehensive docstrings
- Add unit tests for all functionality

### Testing Requirements

- Unit tests with >90% coverage
- Integration tests with real contexts
- Performance benchmarks
- Error handling validation

## License

This code is part of the Native Attack Orchestration system and follows the same licensing terms as the main project.