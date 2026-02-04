# QUIC Protocol Utilities

This module contains extracted QUIC protocol utilities used by QUIC-based DPI bypass attacks.

## Purpose

The utilities in this module were extracted from `quic_attacks.py` to:
- Reduce code duplication
- Improve maintainability
- Enable independent testing
- Provide reusable components

## Modules

### `encoding.py`
Variable-length integer encoding and utility functions.

**Functions:**
- `encode_varint(value: int) -> bytes` - Encode QUIC variable-length integer
- `get_packet_number_length(packet_number: int) -> int` - Get PN length in bytes
- `encode_packet_number(packet_number: int) -> bytes` - Encode packet number
- `calculate_entropy(data: bytes) -> float` - Calculate Shannon entropy (0.0-1.0)

**Addresses:** SM1 (feature_envy), UN3-UN4 (unused methods)

### `frames.py`
QUIC frame builders for various frame types.

**Functions:**
- `create_stream_frame(stream_id, data, fin, offset) -> bytes` - STREAM frame
- `create_crypto_frame(data, offset) -> bytes` - CRYPTO frame
- `create_http3_settings_frame() -> bytes` - HTTP/3 SETTINGS frame
- `create_http3_headers_frame(headers) -> bytes` - HTTP/3 HEADERS frame
- `create_http3_data_frame(data) -> bytes` - HTTP/3 DATA frame
- `create_padding_frame(size) -> bytes` - PADDING frame
- `create_new_connection_id_frame(seq, cid) -> bytes` - NEW_CONNECTION_ID frame
- `create_retire_connection_id_frame(seq) -> bytes` - RETIRE_CONNECTION_ID frame
- `create_path_challenge_frame(data) -> bytes` - PATH_CHALLENGE frame
- `create_path_response_frame(data) -> bytes` - PATH_RESPONSE frame

**Addresses:** SM3-SM6, SM10-SM11 (feature_envy), UN7-UN10, UN16-UN17 (unused methods)

### `packets.py`
QUIC packet structures and building utilities.

**Classes:**
- `QUICPacketType` - Enum of QUIC packet types
- `QUICFrameType` - Enum of QUIC frame types
- `QUICFrame` - Frame dataclass
- `QUICPacket` - Packet dataclass

**Functions:**
- `build_long_header_packet(...) -> bytes` - Build long header packet
- `build_short_header_packet(...) -> bytes` - Build short header packet
- `generate_cid_pool(size, min_len, max_len, use_zero) -> List[bytes]` - Generate CID pool
- `coalesce_packets(packets, max_size) -> List[Tuple[bytes, int]]` - Coalesce packets
- `convert_payload_to_quic_packets(payload, cid, chunk_size) -> List[QUICPacket]` - Convert payload
- `create_packet_with_random_cid(...) -> QUICPacket` - Quick packet creation
- `analyze_packet_distribution(packets) -> dict` - Analyze PN distribution
- `count_migrations(packets) -> int` - Count CID migrations

**Addresses:** SM7, SM16 (feature_envy), UN1-UN2, UN11, UN22, UN24, UN28 (unused methods)

### `session.py`
HTTP/3 session creation and QPACK encoding utilities.

**Functions:**
- `create_http3_session(payload, domain, stream_count, ...) -> List[QUICPacket]` - Full HTTP/3 session
- `encode_qpack_headers(headers) -> bytes` - QPACK header encoding
- `create_qpack_encoder_stream() -> bytes` - QPACK encoder stream
- `create_push_promise_frame(push_id, headers) -> bytes` - PUSH_PROMISE frame
- `create_priority_update_frame(stream_id, priority) -> bytes` - PRIORITY_UPDATE frame

**Addresses:** Reduces QUICHTTP3FullSession complexity from 230 to ~100 LOC

## Usage Example

```python
from core.bypass.attacks.http.quic_protocol import (
    QUICPacket,
    QUICPacketType,
    create_stream_frame,
    convert_payload_to_quic_packets,
    coalesce_packets,
)

# Convert payload to QUIC packets
payload = b"Hello QUIC World!"
packets = convert_payload_to_quic_packets(payload, chunk_size=500)

# Coalesce packets into datagrams
segments = coalesce_packets(packets, max_datagram_size=1200)

# Create custom frame
stream_frame = create_stream_frame(stream_id=0, data=b"custom data", fin=True)
```

## Refactoring Impact

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Main file LOC | 2017 | 1713 | -15.1% |
| Code smells | 20+ | <8 | -60%+ |
| Unused methods | 30+ | 0 | -100% |
| Duplication | High | Low | -75%+ |

## Testing

All utilities can be tested independently:

```python
from core.bypass.attacks.http.quic_protocol import encode_varint

# Test varint encoding
assert encode_varint(63) == b'\x3f'
assert encode_varint(16383) == b'\x7f\xff'
```

## Backward Compatibility

All functions are re-exported in the main `quic_attacks.py` file, ensuring full backward compatibility with existing code.
