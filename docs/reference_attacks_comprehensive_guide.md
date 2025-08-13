# Reference Attacks Comprehensive Guide

This document provides a complete guide to all reference attack implementations in the Native Attack Orchestration system.

## Overview

The reference attacks demonstrate the full capabilities of the segment-based attack architecture. Each attack showcases different aspects of the system:

- **TCP Timing Manipulation**: Demonstrates precise timing control and pattern generation
- **Urgent Pointer Manipulation**: Shows TCP flag manipulation and urgent data handling
- **Window Scaling**: Illustrates TCP window size manipulation for flow control bypass
- **Payload Obfuscation**: Demonstrates payload transformation and encoding techniques

## TCP Timing Manipulation Attack

### Description

The TCP Timing Manipulation Attack uses variable delays between packet segments to confuse DPI systems that rely on timing analysis for traffic classification.

### Key Features

- **Multiple Timing Patterns**: Linear, exponential, random, burst, sawtooth, and Fibonacci sequences
- **Configurable Delays**: Precise millisecond-level timing control
- **TTL Variation**: Different TTL values for each segment to simulate network path diversity
- **Segment Splitting**: Intelligent payload division with sequence number management

### Usage Examples

```python
from core.bypass.attacks.reference.tcp_timing_manipulation_attack import (
    create_tcp_timing_attack,
    create_burst_timing_attack,
    create_fibonacci_timing_attack,
    TimingPattern
)

# Basic timing attack
attack = create_tcp_timing_attack(
    name="basic_timing",
    timing_pattern=TimingPattern.RANDOM,
    segment_count=5,
    base_delay_ms=10.0,
    max_delay_ms=100.0
)

# Burst pattern for congestion simulation
burst_attack = create_burst_timing_attack()

# Fibonacci sequence timing
fib_attack = create_fibonacci_timing_attack()
```

### Timing Patterns

1. **LINEAR**: Evenly spaced delays (10ms, 20ms, 30ms, ...)
2. **EXPONENTIAL**: Exponentially increasing delays (10ms, 20ms, 40ms, 80ms, ...)
3. **RANDOM**: Random delays within specified range
4. **BURST**: Short bursts followed by longer pauses
5. **SAWTOOTH**: Increasing then decreasing pattern
6. **FIBONACCI**: Delays following Fibonacci sequence

### Configuration Parameters

- `timing_pattern`: Pattern type for delay generation
- `segment_count`: Number of segments to create (default: 4)
- `base_delay_ms`: Base delay in milliseconds (default: 10.0)
- `max_delay_ms`: Maximum delay in milliseconds (default: 100.0)
- `ttl_variation`: Enable TTL variation between segments (default: True)

## Urgent Pointer Manipulation Attack

### Description

This attack manipulates the TCP urgent pointer and URG flag to create segments that may be processed differently by DPI systems versus the target application.

### Key Features

- **Urgent Flag Control**: Selective URG flag setting on specific segments
- **Pointer Manipulation**: Custom urgent pointer values for confusion
- **Segment Prioritization**: Different processing priorities for urgent vs normal segments
- **False Urgent Data**: Creating urgent segments without actual urgent data

### Usage Examples

```python
from core.bypass.attacks.reference.urgent_pointer_manipulation_attack import (
    create_urgent_pointer_attack,
    create_aggressive_urgent_attack,
    create_subtle_urgent_attack
)

# Standard urgent pointer attack
attack = create_urgent_pointer_attack(
    name="standard_urgent",
    segment_count=4,
    urgent_segments=[1, 3],  # Make segments 1 and 3 urgent
    urgent_pointer_value=10
)

# Aggressive variant - more urgent segments
aggressive = create_aggressive_urgent_attack()

# Subtle variant - fewer urgent segments
subtle = create_subtle_urgent_attack()
```

### Attack Variants

1. **Standard**: Balanced urgent segment distribution
2. **Aggressive**: High percentage of urgent segments
3. **Subtle**: Minimal urgent segments for stealth

### Configuration Parameters

- `segment_count`: Number of segments to create (default: 3)
- `urgent_segments`: List of segment indices to mark as urgent
- `urgent_pointer_value`: Value for urgent pointer field (default: 10)
- `false_urgent_data`: Include fake urgent data (default: True)

## Window Scaling Attack

### Description

The Window Scaling Attack manipulates TCP window size values to create flow control confusion and potentially bypass DPI systems that track connection state.

### Key Features

- **Multiple Window Patterns**: Random, increasing, decreasing, oscillating, zero-window, extreme values
- **Flow Control Simulation**: Realistic window size changes
- **Zero Window Attacks**: Temporary flow control suspension
- **Extreme Value Testing**: Testing DPI boundary conditions

### Usage Examples

```python
from core.bypass.attacks.reference.window_scaling_attack import (
    create_window_scaling_attack,
    create_zero_window_attack,
    create_oscillating_window_attack,
    WindowPattern
)

# Basic window scaling
attack = create_window_scaling_attack(
    name="basic_window",
    window_pattern=WindowPattern.RANDOM,
    segment_count=6,
    min_window_size=1024,
    max_window_size=65535
)

# Zero window attack
zero_attack = create_zero_window_attack()

# Oscillating pattern
osc_attack = create_oscillating_window_attack()
```

### Window Patterns

1. **RANDOM**: Random window sizes within range
2. **INCREASING**: Gradually increasing window sizes
3. **DECREASING**: Gradually decreasing window sizes
4. **OSCILLATING**: Alternating high/low window sizes
5. **ZERO_WINDOW**: Includes zero window segments
6. **EXTREME_VALUES**: Uses boundary values (0, 1, 65535)

### Configuration Parameters

- `window_pattern`: Pattern type for window size generation
- `segment_count`: Number of segments to create (default: 4)
- `min_window_size`: Minimum window size (default: 1024)
- `max_window_size`: Maximum window size (default: 65535)
- `zero_window_probability`: Probability of zero window (default: 0.2)

## Payload Obfuscation Attack

### Description

The Payload Obfuscation Attack transforms payload data using various encoding and encryption techniques to evade signature-based DPI detection.

### Key Features

- **Multiple Obfuscation Methods**: Base64, hex, XOR, ROT13, compression, substitution
- **Per-Segment Obfuscation**: Different encoding for each segment
- **Noise Addition**: Random data padding for signature disruption
- **Mixed Encoding**: Combination of multiple obfuscation techniques

### Usage Examples

```python
from core.bypass.attacks.reference.payload_obfuscation_attack import (
    create_payload_obfuscation_attack,
    create_base64_obfuscation_attack,
    create_xor_obfuscation_attack,
    ObfuscationMethod
)

# Basic obfuscation
attack = create_payload_obfuscation_attack(
    name="basic_obfuscation",
    obfuscation_method=ObfuscationMethod.BASE64,
    segment_count=3,
    per_segment_obfuscation=False
)

# XOR cipher obfuscation
xor_attack = create_xor_obfuscation_attack()

# Mixed encoding attack
mixed_attack = create_mixed_obfuscation_attack()
```

### Obfuscation Methods

1. **BASE64**: Standard Base64 encoding
2. **HEX_ENCODING**: Hexadecimal representation
3. **XOR_CIPHER**: XOR encryption with random key
4. **ROT13**: ROT13 character rotation
5. **COMPRESSION**: Data compression (gzip)
6. **BYTE_SUBSTITUTION**: Custom byte substitution cipher
7. **MIXED_ENCODING**: Combination of multiple methods

### Configuration Parameters

- `obfuscation_method`: Primary obfuscation technique
- `segment_count`: Number of segments to create (default: 3)
- `per_segment_obfuscation`: Use different encoding per segment (default: False)
- `add_noise`: Add random noise data (default: False)
- `noise_ratio`: Ratio of noise to payload data (default: 0.1)

## Attack Combination Strategies

### Sequential Combination

Execute multiple attacks in sequence for layered evasion:

```python
# Create attack sequence
attacks = [
    create_payload_obfuscation_attack(name="step1"),
    create_tcp_timing_attack(name="step2"),
    create_window_scaling_attack(name="step3"),
    create_urgent_pointer_attack(name="step4")
]

# Execute in sequence
for attack in attacks:
    result = attack.execute(context)
    # Process result...
```

### Parallel Combination

Combine attack techniques within a single attack:

```python
# Custom combined attack
class CombinedAttack(BaseAttack):
    def execute(self, context):
        # Apply timing + obfuscation + window scaling
        segments = []
        
        # Obfuscate payload
        obfuscated = self._obfuscate_payload(context.payload)
        
        # Split with timing
        timed_segments = self._apply_timing_pattern(obfuscated)
        
        # Add window scaling
        final_segments = self._apply_window_scaling(timed_segments)
        
        return AttackResult(
            status=AttackStatus.SUCCESS,
            _segments=final_segments,
            metadata={"attack_type": "combined"}
        )
```

## Performance Considerations

### Execution Time

- **Simple attacks** (timing, window): ~1-5ms execution time
- **Complex obfuscation**: ~10-50ms depending on payload size
- **Combined attacks**: Additive execution time

### Memory Usage

- **Segment storage**: ~100-500 bytes per segment
- **Obfuscation overhead**: 1.3-2x original payload size
- **Timing buffers**: Minimal memory impact

### Network Impact

- **Packet count**: 3-15 packets per attack (configurable)
- **Bandwidth overhead**: 10-100% depending on obfuscation
- **Latency addition**: 10-1000ms depending on timing patterns

## Best Practices

### Attack Selection

1. **For signature evasion**: Use payload obfuscation attacks
2. **For timing-based DPI**: Use TCP timing manipulation
3. **For stateful inspection**: Use window scaling or urgent pointer
4. **For comprehensive evasion**: Combine multiple techniques

### Configuration Guidelines

1. **Segment count**: 3-8 segments for balance of effectiveness and performance
2. **Timing delays**: 10-100ms for realistic network simulation
3. **Window sizes**: Stay within realistic TCP window ranges
4. **Obfuscation**: Use mixed methods for maximum effectiveness

### Testing and Validation

1. **Unit testing**: Test each attack individually
2. **Integration testing**: Test with real network engines
3. **Effectiveness testing**: Validate against target DPI systems
4. **Performance testing**: Measure execution time and resource usage

## Troubleshooting

### Common Issues

1. **Segment validation errors**: Check payload size and segment count
2. **Timing precision issues**: Verify system timer resolution
3. **Obfuscation failures**: Check encoding compatibility
4. **Memory issues**: Reduce segment count or payload size

### Debug Information

Enable debug logging to see detailed attack execution:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

attack = create_tcp_timing_attack()
result = attack.execute(context)
```

### Performance Monitoring

Monitor attack performance using built-in metrics:

```python
import time

start_time = time.time()
result = attack.execute(context)
execution_time = time.time() - start_time

print(f"Execution time: {execution_time*1000:.2f}ms")
print(f"Segments created: {len(result._segments)}")
```

## Future Enhancements

### Planned Features

1. **Adaptive timing**: Dynamic timing adjustment based on network conditions
2. **ML-based obfuscation**: Machine learning-driven payload transformation
3. **Protocol-specific attacks**: HTTP/2, QUIC, TLS-specific techniques
4. **Real-time effectiveness**: Live DPI detection and adaptation

### Extension Points

1. **Custom timing patterns**: Implement new TimingPattern enum values
2. **New obfuscation methods**: Add ObfuscationMethod implementations
3. **Window patterns**: Create custom WindowPattern algorithms
4. **Attack combinations**: Develop new combination strategies

## Conclusion

The reference attacks provide a comprehensive foundation for segment-based DPI evasion. They demonstrate the flexibility and power of the Native Attack Orchestration system while serving as templates for developing custom attacks.

For more information, see the individual attack documentation files and example implementations.