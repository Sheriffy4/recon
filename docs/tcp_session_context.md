# Enhanced AttackContext with TCP Session Information

## Overview

The enhanced AttackContext provides complete TCP session information for segments orchestration. This enables attacks to have precise control over sequence numbers, flags, window sizes, and connection state - essential for implementing sophisticated techniques like zapret's fakeddisorder and multisplit.

## New TCP Session Fields

### Core TCP Information

```python
# Enhanced TCP session fields
tcp_seq: int = 0                    # TCP sequence number
tcp_ack: int = 0                    # TCP acknowledgment number  
tcp_flags: int = 0x18               # TCP flags (PSH+ACK by default)
tcp_window_size: int = 65535        # TCP window size
tcp_urgent_pointer: int = 0         # TCP urgent pointer
tcp_options: bytes = b""            # TCP options field
```

### Connection State Tracking

```python
# Connection state management
connection_id: str = ""             # Unique connection identifier
packet_id: int = 0                  # Packet counter for this connection
session_established: bool = False   # Session establishment status

# Sequence number management
initial_seq: Optional[int] = None   # Initial sequence number
current_seq_offset: int = 0         # Current offset from initial
expected_ack: Optional[int] = None  # Expected acknowledgment
```

## Key Methods

### Sequence Number Management

```python
def get_next_seq(self, payload_len: int) -> int:
    """Calculate next sequence number after sending payload"""
    return self.tcp_seq + payload_len

def advance_seq(self, payload_len: int) -> None:
    """Advance sequence number after sending payload"""
    self.tcp_seq += payload_len
    self.current_seq_offset += payload_len

def get_seq_with_offset(self, offset: int) -> int:
    """Get sequence number with specific offset"""
    return self.tcp_seq + offset
```

### TCP Flags Management

```python
def set_tcp_flags(self, flags: Union[int, str]) -> None:
    """Set TCP flags from integer or string"""
    # Supports both: 0x18 and "PSH,ACK"

def get_tcp_flags_string(self) -> str:
    """Get TCP flags as human-readable string"""
    # Returns: "PSH,ACK", "SYN", "FIN,ACK", etc.
```

### Connection Tracking

```python
def create_connection_id(self) -> str:
    """Create unique connection identifier"""
    # Returns: "10.0.0.1:12345->192.168.1.1:443"

def increment_packet_id(self) -> int:
    """Increment and return packet ID"""
    self.packet_id += 1
    return self.packet_id
```

### Session Management

```python
def reset_sequence_tracking(self) -> None:
    """Reset sequence tracking to initial state"""

def validate_tcp_session(self) -> bool:
    """Validate TCP session information consistency"""

def copy_tcp_session(self) -> "AttackContext":
    """Create copy with same TCP session info"""
```

## Usage Examples

### Basic TCP Session Setup

```python
context = AttackContext(
    dst_ip="192.168.1.1",
    dst_port=443,
    src_ip="10.0.0.1", 
    src_port=12345,
    
    # TCP session information
    tcp_seq=1000000,
    tcp_ack=2000000,
    tcp_flags=0x18,  # PSH+ACK
    tcp_window_size=32768,
    
    # Connection state
    initial_seq=1000000,
    session_established=True
)
```

### Sequence Number Calculations

```python
# Current sequence
current_seq = context.tcp_seq  # 1000000

# Calculate next sequence after sending 100 bytes
next_seq = context.get_next_seq(100)  # 1000100

# Get sequence with offset
offset_seq = context.get_seq_with_offset(50)  # 1000050

# Advance sequence after sending
context.advance_seq(100)
print(context.tcp_seq)  # 1000100
```

### TCP Flags Manipulation

```python
# Set flags using string
context.set_tcp_flags("SYN,ACK")
print(context.tcp_flags)  # 0x12

# Set flags using integer
context.set_tcp_flags(0x18)  # PSH+ACK

# Get flags as string
flags_str = context.get_tcp_flags_string()  # "PSH,ACK"
```

### Connection State Management

```python
# Create connection ID
conn_id = context.create_connection_id()
# "10.0.0.1:12345->192.168.1.1:443"

# Track packets
for i in range(3):
    packet_id = context.increment_packet_id()
    print(f"Sending packet {packet_id}")

# Reset tracking
context.reset_sequence_tracking()
```

## Attack Implementation Examples

### Sequence-Aware Attack

```python
class SequenceAwareAttack(BaseAttack):
    def execute(self, context: AttackContext) -> AttackResult:
        payload = context.payload
        
        # Split payload with proper sequence offsets
        chunk_size = len(payload) // 2
        part1 = payload[:chunk_size]
        part2 = payload[chunk_size:]
        
        segments = [
            # First part at current sequence
            (part1, 0, {"delay_ms": 5}),
            
            # Second part at calculated offset
            (part2, chunk_size, {"delay_ms": 10})
        ]
        
        return AttackResultHelper.create_segments_result(
            technique_used="sequence_aware",
            segments=segments
        )
```

### Connection State Attack

```python
class ConnectionStateAttack(BaseAttack):
    def execute(self, context: AttackContext) -> AttackResult:
        # Create connection tracking
        conn_id = context.create_connection_id()
        
        segments = []
        for chunk in self._split_payload(context.payload):
            packet_id = context.increment_packet_id()
            
            # Vary behavior based on packet ID
            options = {
                "window_size": context.tcp_window_size // packet_id,
                "delay_ms": packet_id * 2
            }
            
            segments.append((chunk, 0, options))
        
        return AttackResultHelper.create_segments_result(
            technique_used="connection_state",
            segments=segments,
            metadata={"connection_id": conn_id}
        )
```

### Flag Manipulation Attack

```python
class FlagManipulationAttack(BaseAttack):
    def execute(self, context: AttackContext) -> AttackResult:
        payload = context.payload
        
        segments = [
            # First segment with PSH only
            (payload[:10], 0, {
                "flags": 0x08,  # PSH
                "delay_ms": 5
            }),
            
            # Second segment with PSH+ACK+URG
            (payload[10:], 10, {
                "flags": 0x38,  # PSH+ACK+URG
                "delay_ms": 10
            })
        ]
        
        return AttackResultHelper.create_segments_result(
            technique_used="flag_manipulation",
            segments=segments
        )
```

## Integration with Segments

The enhanced AttackContext works seamlessly with the segments orchestration system:

```python
def execute(self, context: AttackContext) -> AttackResult:
    # Use TCP session info for segment construction
    segments = []
    
    for i, chunk in enumerate(self._split_payload(context.payload)):
        # Calculate proper sequence offset
        seq_offset = i * len(chunk)
        
        # Use connection state for options
        packet_id = context.increment_packet_id()
        
        options = {
            "flags": context.tcp_flags,
            "window_size": context.tcp_window_size,
            "delay_ms": packet_id * 5
        }
        
        segments.append((chunk, seq_offset, options))
    
    return AttackResultHelper.create_segments_result(
        technique_used="tcp_session_integrated",
        segments=segments,
        metadata=context.to_dict()
    )
```

## Backward Compatibility

Legacy fields are maintained for compatibility:

```python
# Legacy fields (still supported)
seq: Optional[int] = None
ack: Optional[int] = None  
flags: str = "PA"
window: int = 65535

# New fields (enhanced functionality)
tcp_seq: int = 0
tcp_ack: int = 0
tcp_flags: int = 0x18
tcp_window_size: int = 65535
```

Both can be used simultaneously without conflicts.

## Validation and Debugging

### Session Validation

```python
if context.validate_tcp_session():
    print("TCP session is valid")
else:
    print("Invalid TCP session configuration")
```

### Debug Information

```python
# Get comprehensive session info
session_info = context.to_dict()
print(f"Connection: {session_info['connection']}")
print(f"TCP Session: {session_info['tcp_session']}")
print(f"State: {session_info['state']}")
```

### Connection Tracking

```python
# Track connection lifecycle
conn_id = context.create_connection_id()
print(f"Connection {conn_id} established")

for packet_data in packet_stream:
    packet_id = context.increment_packet_id()
    context.advance_seq(len(packet_data))
    print(f"Packet {packet_id}: seq={context.tcp_seq}")
```

## Benefits

### Precision Control
- Exact sequence number management
- Precise TCP flag manipulation
- Complete window size control
- Connection state tracking

### Zapret Compatibility
- Enables implementation of zapret techniques
- Supports complex multi-packet scenarios
- Provides timing and state control

### Debugging Support
- Comprehensive session information
- Connection tracking capabilities
- Validation and error detection

### Flexibility
- Works with any attack type
- Supports both simple and complex scenarios
- Maintains backward compatibility

This enhanced AttackContext provides the foundation for implementing sophisticated TCP-based attacks with the precision needed to match zapret's effectiveness.