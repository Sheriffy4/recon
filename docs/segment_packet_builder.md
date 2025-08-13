# SegmentPacketBuilder Documentation

## Overview

The SegmentPacketBuilder is a specialized packet construction system designed for segments orchestration. It provides precise control over every aspect of packet creation, enabling the implementation of sophisticated DPI bypass techniques like zapret's fakeddisorder and multisplit.

## Key Features

- **Raw Packet Construction**: Direct byte-level packet building for maximum control
- **Precise Header Manipulation**: Complete control over IP and TCP headers
- **TTL Modification**: Set custom TTL values for packet dropping techniques
- **Checksum Corruption**: Intentionally corrupt TCP checksums for DPI confusion
- **TCP Flags Control**: Manipulate TCP flags for state confusion attacks
- **Sequence Number Management**: Precise sequence number offset calculations
- **Performance Monitoring**: Built-in statistics and performance tracking

## Architecture

```
┌─────────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│   AttackContext     │───▶│ SegmentPacketBuilder │───▶│  SegmentPacketInfo  │
│ (TCP Session Info)  │    │                      │    │  (Built Packet)     │
└─────────────────────┘    └──────────────────────┘    └─────────────────────┘
                                      │
                                      ▼
                           ┌──────────────────────┐
                           │   PacketBuilder      │
                           │ (Raw Construction)   │
                           └──────────────────────┘
```

## Core Classes

### SegmentPacketBuilder

Main class for building packets from segment tuples.

```python
class SegmentPacketBuilder:
    def __init__(self, enhanced_builder: Optional[PacketBuilder] = None)
    
    def build_segment(
        self, 
        payload: bytes, 
        seq_offset: int, 
        options: Dict[str, Any], 
        context: AttackContext
    ) -> SegmentPacketInfo
```

### SegmentPacketInfo

Information about a constructed packet.

```python
@dataclass
class SegmentPacketInfo:
    packet_bytes: bytes              # Raw packet bytes
    packet_size: int                 # Total packet size
    construction_time_ms: float      # Build time
    tcp_seq: int                     # TCP sequence number
    tcp_ack: int                     # TCP acknowledgment
    tcp_flags: int                   # TCP flags
    tcp_window: int                  # TCP window size
    ttl: int                         # IP TTL value
    checksum_corrupted: bool         # Checksum corruption status
    options_applied: Dict[str, Any]  # Applied options
```

## Supported Options

The options dictionary supports the following keys:

| Option | Type | Description | Example |
|--------|------|-------------|---------|
| `ttl` | int | IP Time To Live (1-255) | `{"ttl": 2}` |
| `flags` | int | TCP flags (0-255) | `{"flags": 0x18}` |
| `window_size` | int | TCP window size (0-65535) | `{"window_size": 16384}` |
| `bad_checksum` | bool | Corrupt TCP checksum | `{"bad_checksum": True}` |
| `delay_ms` | float | Delay before sending | `{"delay_ms": 5.0}` |

## Usage Examples

### Basic Packet Building

```python
from core.bypass.attacks.segment_packet_builder import SegmentPacketBuilder
from core.bypass.attacks.base import AttackContext

# Create context
context = AttackContext(
    dst_ip="192.168.1.100",
    dst_port=443,
    src_ip="10.0.0.50",
    src_port=12345,
    tcp_seq=1000000,
    tcp_ack=2000000,
    tcp_flags=0x18,
    tcp_window_size=32768
)

# Create builder
builder = SegmentPacketBuilder()

# Build packet
payload = b"GET / HTTP/1.1\r\n"
seq_offset = 0
options = {}

packet_info = builder.build_segment(payload, seq_offset, options, context)
print(f"Built packet: {packet_info.packet_size} bytes")
```

### TTL Manipulation

```python
# Build packet with low TTL (will be dropped by DPI)
options = {"ttl": 2}
packet_info = builder.build_segment(payload, 0, options, context)

# Verify TTL in packet
actual_ttl = packet_info.packet_bytes[8]  # TTL at IP header offset 8
assert actual_ttl == 2
```

### Checksum Corruption

```python
# Build packet with corrupted checksum
options = {"bad_checksum": True}
packet_info = builder.build_segment(payload, 0, options, context)

# Check corruption status
assert packet_info.checksum_corrupted == True

# Verify corrupted checksum (0xDEAD marker)
tcp_checksum = struct.unpack("!H", packet_info.packet_bytes[36:38])[0]
assert tcp_checksum == 0xDEAD
```

### TCP Flags Manipulation

```python
# Build SYN packet
syn_options = {"flags": 0x02}
syn_packet = builder.build_segment(b"", 0, syn_options, context)

# Build FIN+ACK packet
fin_ack_options = {"flags": 0x11}
fin_ack_packet = builder.build_segment(payload, 0, fin_ack_options, context)
```

### Sequence Number Offsets

```python
# Build packets with different sequence offsets
segments = [
    (b"chunk1", 0, {}),      # seq = base_seq + 0
    (b"chunk2", 6, {}),      # seq = base_seq + 6
    (b"chunk3", 12, {})      # seq = base_seq + 12
]

for payload, offset, options in segments:
    packet_info = builder.build_segment(payload, offset, options, context)
    print(f"Seq: {packet_info.tcp_seq}, Offset: {offset}")
```

## Convenience Functions

### build_segment_packet

Build a single segment packet.

```python
from core.bypass.attacks.segment_packet_builder import build_segment_packet

segment = (b"test data", 0, {"ttl": 2})
packet_info = build_segment_packet(segment, context)
```

### build_segments_batch

Build multiple segments efficiently.

```python
from core.bypass.attacks.segment_packet_builder import build_segments_batch

segments = [
    (b"chunk1", 0, {"ttl": 2}),
    (b"chunk2", 6, {"delay_ms": 5}),
    (b"chunk3", 12, {"bad_checksum": True})
]

packet_infos = build_segments_batch(segments, context)
print(f"Built {len(packet_infos)} packets")
```

### validate_segments_for_building

Validate segments before building.

```python
from core.bypass.attacks.segment_packet_builder import validate_segments_for_building

is_valid, error_msg = validate_segments_for_building(segments, context)
if not is_valid:
    print(f"Validation failed: {error_msg}")
```

## Attack Implementation Examples

### FakedDisorder Attack

```python
def create_fakeddisorder_segments(payload: bytes, split_pos: int) -> List[SegmentTuple]:
    """Create segments for FakedDisorder attack."""
    
    # Create fake packet
    fake_payload = b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
    
    # Split real payload
    part1 = payload[:split_pos]
    part2 = payload[split_pos:]
    
    return [
        # Fake packet with low TTL (dropped by DPI)
        (fake_payload, 0, {"ttl": 2, "delay_ms": 5}),
        
        # Second part first (creates disorder)
        (part2, split_pos, {"delay_ms": 10}),
        
        # First part last
        (part1, 0, {})
    ]
```

### Multisplit Attack

```python
def create_multisplit_segments(payload: bytes, split_count: int) -> List[SegmentTuple]:
    """Create segments for Multisplit attack."""
    
    segments = []
    chunk_size = len(payload) // split_count
    
    for i in range(split_count):
        start = i * chunk_size
        end = start + chunk_size if i < split_count - 1 else len(payload)
        chunk = payload[start:end]
        
        segments.append((chunk, start, {
            "delay_ms": i * 3,  # Progressive delays
            "window_size": 32768 - (i * 1024)  # Varying window
        }))
    
    return segments
```

### Timing Manipulation Attack

```python
def create_timing_manipulation_segments(payload: bytes) -> List[SegmentTuple]:
    """Create segments with timing manipulation."""
    
    segments = []
    chunk_size = 8
    
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i:i + chunk_size]
        
        # Variable timing pattern
        delay = (i % 3) * 2.5  # 0, 2.5, 5.0 ms pattern
        
        # Corrupt checksum on every 3rd packet
        corrupt = (len(segments) % 3) == 2
        
        segments.append((chunk, i, {
            "delay_ms": delay,
            "bad_checksum": corrupt,
            "ttl": 2 if i == 0 else 64  # Low TTL on first packet
        }))
    
    return segments
```

## Performance and Statistics

### Statistics Collection

```python
# Build some packets
for i in range(10):
    builder.build_segment(b"test", i, {"ttl": 2}, context)

# Get statistics
stats = builder.get_stats()
print(f"Packets built: {stats['packets_built']}")
print(f"Average build time: {stats['avg_build_time_ms']:.3f} ms")
print(f"TTL modifications: {stats['ttl_modifications']}")
print(f"Checksum corruptions: {stats['checksum_corruptions']}")
```

### Performance Optimization

- **Reuse builder instances** for better performance
- **Batch operations** when building multiple packets
- **Validate segments** before building to catch errors early
- **Monitor statistics** to identify performance bottlenecks

## Packet Structure Analysis

### IP Header (20 bytes)

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | Version/IHL | 1 | IP version (4) + header length |
| 1 | ToS | 1 | Type of Service |
| 2-3 | Total Length | 2 | Total packet length |
| 4-5 | Identification | 2 | Fragment identification |
| 6-7 | Flags/Fragment | 2 | Flags + fragment offset |
| 8 | TTL | 1 | Time To Live |
| 9 | Protocol | 1 | Next protocol (6 for TCP) |
| 10-11 | Checksum | 2 | IP header checksum |
| 12-15 | Source IP | 4 | Source IP address |
| 16-19 | Dest IP | 4 | Destination IP address |

### TCP Header (20+ bytes)

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0-1 | Source Port | 2 | Source port number |
| 2-3 | Dest Port | 2 | Destination port number |
| 4-7 | Sequence | 4 | Sequence number |
| 8-11 | Acknowledgment | 4 | Acknowledgment number |
| 12 | Header Length | 1 | TCP header length |
| 13 | Flags | 1 | TCP flags |
| 14-15 | Window | 2 | Window size |
| 16-17 | Checksum | 2 | TCP checksum |
| 18-19 | Urgent | 2 | Urgent pointer |

## Error Handling

### SegmentPacketBuildError

Raised when packet construction fails.

```python
try:
    packet_info = builder.build_segment(payload, offset, options, context)
except SegmentPacketBuildError as e:
    print(f"Packet building failed: {e}")
```

### Validation Errors

```python
# Validate options before building
if not builder.validate_segment_options(options):
    print("Invalid segment options")

# Validate segments before batch building
is_valid, error = validate_segments_for_building(segments, context)
if not is_valid:
    print(f"Segment validation failed: {error}")
```

## Integration with Engine

The SegmentPacketBuilder integrates with the native engine for packet transmission:

```python
# In native engine
for segment in segments:
    packet_info = builder.build_segment(*segment, context)
    
    # Apply delay if specified
    delay_ms = segment[2].get("delay_ms", 0)
    if delay_ms > 0:
        await asyncio.sleep(delay_ms / 1000.0)
    
    # Send packet via PyDivert
    self.handle.send(packet_info.packet_bytes)
```

## Best Practices

1. **Reuse Builder Instances**: Create one builder per session for better performance
2. **Validate Early**: Use validation functions before building packets
3. **Monitor Statistics**: Track performance and optimization opportunities
4. **Handle Errors**: Implement proper error handling for packet construction
5. **Test Packet Structure**: Verify packet contents in development/testing
6. **Optimize Batch Operations**: Use batch functions for multiple packets

This SegmentPacketBuilder provides the foundation for implementing zapret-level packet manipulation techniques with the precision and control needed for effective DPI bypass.