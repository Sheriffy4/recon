"""
HPACK Frame Builders

Advanced frame building utilities for HPACK manipulation attacks.
Includes table poisoning, index overflow, dynamic eviction, and multiplexing.
"""

import struct
from typing import List
from core.bypass.attacks.http.http2_utils import HTTP2Frame, HPACKEncoder


def _encode_hpack_int(value: int, prefix_bits: int, first_byte_mask: int = 0) -> bytes:
    """
    Encode an integer using HPACK integer representation (RFC 7541, 5.1).

    This helper is used to avoid struct.pack(">B", ...) overflows and to produce
    correct variable-length integers when needed.
    """
    if prefix_bits <= 0 or prefix_bits > 8:
        raise ValueError(f"Invalid prefix_bits={prefix_bits}")

    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([first_byte_mask | value])

    out = bytearray()
    out.append(first_byte_mask | max_prefix)
    value -= max_prefix

    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def _encode_hpack_indexed_field(index: int) -> bytes:
    """Encode an 'Indexed Header Field Representation' (RFC 7541, 6.1)."""
    if index < 0:
        raise ValueError("HPACK index must be non-negative")
    # First bit set to 1, 7-bit integer prefix.
    return _encode_hpack_int(index, prefix_bits=7, first_byte_mask=0x80)


def create_table_poisoning_frames(
    domain: str, payload: bytes, index_confusion: bool = True
) -> List[HTTP2Frame]:
    """
    Create frames that poison the HPACK dynamic table.

    Sends decoy headers to fill the dynamic table with misleading entries,
    then sends real request that may reference poisoned table entries.

    Args:
        domain: Target domain for :authority header
        payload: Actual data payload to send
        index_confusion: Whether to use confused table indices in real request

    Returns:
        List of HTTP/2 frames with table poisoning attack
    """
    frames = []
    encoder = HPACKEncoder()

    # Send 10 decoy requests to poison the dynamic table
    for i in range(10):
        decoy_headers = [
            (b":method", b"GET"),
            (b":path", f"/decoy{i}".encode()),
            (b":scheme", b"https"),
            (b":authority", domain.encode()),
            (f"x-decoy-{i}".encode(), f"decoy-value-{i}".encode()),
        ]

        # Use project HPACK encoder to avoid length overflows and keep frames buildable.
        hpack_payload = encoder.encode_headers(decoy_headers)

        # Create HEADERS frame with END_HEADERS flag (4)
        frame = HTTP2Frame(1, 4, i * 2 + 1, hpack_payload)
        frames.append(frame)

    # Now send the real request
    real_headers = [
        (b":method", b"POST"),
        (b":path", b"/api/data"),
        (b":scheme", b"https"),
        (b":authority", domain.encode()),
        (b"content-type", b"application/octet-stream"),
    ]

    real_parts: List[bytes] = []
    for i, (name, value) in enumerate(real_headers):
        if index_confusion and i % 2 == 0:
            # Reference potentially poisoned dynamic table entries
            table_index = 62 + i % 10  # Dynamic table starts at index 62
            real_parts.append(_encode_hpack_indexed_field(table_index))
        else:
            # Encode literal header via encoder (stateful, avoids >255 overflow).
            real_parts.append(encoder.encode_headers([(name, value)]))
    real_hpack_payload = b"".join(real_parts)

    # Create HEADERS frame for real request
    real_headers_frame = HTTP2Frame(1, 4, 21, real_hpack_payload)
    # Create DATA frame with actual payload
    real_data_frame = HTTP2Frame(0, 1, 21, payload)

    frames.extend([real_headers_frame, real_data_frame])
    return frames


def create_index_overflow_frames(
    domain: str, payload: bytes, index_confusion: bool = True
) -> List[HTTP2Frame]:
    """
    Create frames that cause HPACK index overflow.

    Attempts to reference invalid/out-of-bounds table indices to confuse
    HPACK decoders and potentially bypass DPI inspection.

    Args:
        domain: Target domain for :authority header
        payload: Actual data payload to send
        index_confusion: Reserved for future use. Currently unused but kept for API
            compatibility with other HPACK manipulation functions. May be used in
            future versions to control whether invalid indices are interleaved with
            valid ones or sent in separate frames.

    Returns:
        List of HTTP/2 frames with index overflow attack

    Note:
        The index_confusion parameter is intentionally unused in the current
        implementation as the attack always uses invalid indices. This parameter
        is maintained for consistency with other HPACK frame builders and to
        allow future enhancements without breaking the API.
    """
    frames = []
    parts: List[bytes] = []

    # Try to reference invalid table indices (> 61 static table size)
    for i in range(5):
        invalid_index = 200 + i
        # Proper HPACK integer encoding for "indexed field" representation.
        parts.append(_encode_hpack_indexed_field(invalid_index))

    # Add valid headers after invalid indices
    valid_headers = [
        (b":method", b"POST"),
        (b":path", b"/api"),
        (b":scheme", b"https"),
        (b":authority", domain.encode()),
    ]

    encoder = HPACKEncoder()
    parts.append(encoder.encode_headers(valid_headers))
    headers_payload = b"".join(parts)

    # Create HEADERS frame with END_HEADERS flag
    headers_frame = HTTP2Frame(1, 4, 1, headers_payload)
    # Create DATA frame with END_STREAM flag
    data_frame = HTTP2Frame(0, 1, 1, payload)

    frames.extend([headers_frame, data_frame])
    return frames


def create_dynamic_eviction_frames(
    domain: str, payload: bytes, index_confusion: bool = True
) -> List[HTTP2Frame]:
    """
    Create frames that cause dynamic table eviction confusion.

    Fills the dynamic table with large headers to trigger eviction,
    then references potentially evicted entries to confuse DPI systems.

    Args:
        domain: Target domain for :authority header
        payload: Actual data payload to send
        index_confusion: Reserved for future use. Currently unused but kept for API
            compatibility with other HPACK manipulation functions. May be used in
            future versions to control the pattern of evicted index references
            (e.g., sequential vs random, immediate vs delayed).

    Returns:
        List of HTTP/2 frames with dynamic eviction attack

    Note:
        The index_confusion parameter is intentionally unused in the current
        implementation as the attack always references potentially evicted indices.
        This parameter is maintained for consistency with other HPACK frame builders
        and to allow future enhancements without breaking the API.
    """
    frames = []
    encoder = HPACKEncoder()

    # Fill dynamic table with large headers to trigger eviction
    for i in range(20):
        large_header_value = b"x" * 1000  # 1KB header value

        headers = [
            (b":method", b"GET"),
            (b":path", f"/fill{i}".encode()),
            (b":scheme", b"https"),
            (b":authority", domain.encode()),
            (f"x-large-{i}".encode(), large_header_value),
        ]

        # Avoid >255 crashes: use encoder for large values.
        hpack_payload = encoder.encode_headers(headers)

        frame = HTTP2Frame(1, 4, i * 2 + 1, hpack_payload)
        frames.append(frame)

    # Now reference potentially evicted entries
    confused_parts: List[bytes] = []
    for i in range(10):
        evicted_index = 62 + i
        confused_parts.append(_encode_hpack_indexed_field(evicted_index))

    # Add real headers
    real_headers = [
        (b":method", b"POST"),
        (b":path", b"/real"),
        (b":authority", domain.encode()),
    ]

    confused_parts.append(encoder.encode_headers(real_headers))
    confused_payload = b"".join(confused_parts)

    real_frame = HTTP2Frame(1, 4, 41, confused_payload)
    data_frame = HTTP2Frame(0, 1, 41, payload)

    frames.extend([real_frame, data_frame])
    return frames


def create_multiplexed_streams(
    payload: bytes,
    stream_count: int,
    interleave: bool,
    use_priorities: bool,
    domain: str,
) -> bytes:
    """
    Create multiple HTTP/2 streams with payload distribution.

    Splits payload across multiple concurrent streams to evade
    single-stream DPI inspection.

    Args:
        payload: Data payload to distribute across streams
        stream_count: Number of concurrent streams to create
        interleave: Whether to interleave frames from different streams
        use_priorities: Whether to add PRIORITY frames
        domain: Target domain for :authority header

    Returns:
        Complete HTTP/2 connection bytes with multiplexed streams
    """
    if stream_count <= 0:
        raise ValueError("stream_count must be >= 1")

    # HTTP/2 connection preface
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    # Prevent pathological cases (e.g., more streams than bytes -> many empty DATA frames)
    if len(payload) > 0:
        stream_count = max(1, min(stream_count, len(payload)))
    else:
        stream_count = 1

    # Create SETTINGS frame with increased concurrent streams limit
    max_concurrent = min((stream_count * 2), 0xFFFFFFFF)
    settings_payload = struct.pack(">HI", 3, max_concurrent)  # MAX_CONCURRENT_STREAMS
    settings_frame = HTTP2Frame(4, 0, 0, settings_payload)

    # Split payload into chunks
    chunk_size = len(payload) // stream_count
    payload_chunks = []
    for i in range(stream_count):
        start = i * chunk_size
        if i == stream_count - 1:
            # Last chunk gets remaining bytes
            end = len(payload)
        else:
            end = start + chunk_size
        payload_chunks.append(payload[start:end])

    # Create frames for each stream
    # Buckets per stream for real interleaving (round-robin by stream index).
    stream_buckets: List[List[HTTP2Frame]] = [[] for _ in range(stream_count)]
    encoder = HPACKEncoder()

    for i, chunk in enumerate(payload_chunks):
        stream_id = i * 2 + 1  # Odd stream IDs for client-initiated streams

        # Add PRIORITY frame if requested
        if use_priorities:
            # Priority: exclusive=0, stream_dependency=0, weight=16+i
            priority_payload = struct.pack(">IB", 0, 16 + i)
            priority_frame = HTTP2Frame(2, 0, stream_id, priority_payload)
            stream_buckets[i].append(priority_frame)

        # Create HEADERS frame
        headers = [
            (b":method", b"POST"),
            (b":path", f"/api/stream/{i}".encode()),
            (b":scheme", b"https"),
            (b":authority", domain.encode()),
            (b"content-length", str(len(chunk)).encode()),
        ]

        headers_payload = encoder.encode_headers(headers)
        headers_frame = HTTP2Frame(1, 4, stream_id, headers_payload)  # END_HEADERS flag
        stream_buckets[i].append(headers_frame)

        # Create DATA frame
        data_frame = HTTP2Frame(0, 1, stream_id, chunk)  # END_STREAM flag
        stream_buckets[i].append(data_frame)

    # Flatten frames
    ordered_frames: List[HTTP2Frame] = []
    if interleave:
        # Round-robin interleave per stream bucket (preserves per-stream frame order).
        max_len = max((len(b) for b in stream_buckets), default=0)
        for n in range(max_len):
            for i in range(stream_count):
                if n < len(stream_buckets[i]):
                    ordered_frames.append(stream_buckets[i][n])
    else:
        for i in range(stream_count):
            ordered_frames.extend(stream_buckets[i])

    # Assemble complete connection efficiently
    out_parts = [preface, settings_frame.to_bytes()]
    out_parts.extend((f.to_bytes() for f in ordered_frames))
    return b"".join(out_parts)
