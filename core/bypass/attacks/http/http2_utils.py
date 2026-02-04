"""
HTTP/2 Protocol Utilities

Shared utilities for HTTP/2 frame manipulation, HPACK encoding,
and protocol-specific operations used across multiple attack classes.
"""

import struct
import random
from typing import List, Tuple


class HTTP2Frame:
    """HTTP/2 frame structure."""

    def __init__(self, frame_type: int, flags: int, stream_id: int, payload: bytes):
        self.frame_type = frame_type
        self.flags = flags
        self.stream_id = stream_id
        self.payload = payload
        self.length = len(payload)

    def to_bytes(self) -> bytes:
        """Convert frame to bytes."""
        length_bytes = struct.pack(">I", self.length)[1:]
        header = length_bytes
        header += struct.pack(">B", self.frame_type)
        header += struct.pack(">B", self.flags)
        header += struct.pack(">I", self.stream_id & 2147483647)
        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "HTTP2Frame":
        """Parse frame from bytes."""
        if len(data) < 9:
            raise ValueError("Invalid frame: too short")
        length = struct.unpack(">I", b"\x00" + data[:3])[0]
        frame_type = data[3]
        flags = data[4]
        stream_id = struct.unpack(">I", data[5:9])[0] & 2147483647
        payload = data[9 : 9 + length]
        return cls(frame_type, flags, stream_id, payload)


class HPACKEncoder:
    """Simple HPACK encoder for header compression."""

    STATIC_TABLE = {
        b":authority": 1,
        b":method": 2,
        b":method GET": 2,
        b":method POST": 3,
        b":path": 4,
        b":path /": 4,
        b":scheme": 6,
        b":scheme http": 6,
        b":scheme https": 7,
        b":status": 8,
        b":status 200": 8,
        b"accept": 19,
        b"accept-encoding": 16,
        b"accept-language": 17,
        b"cache-control": 24,
        b"content-length": 28,
        b"content-type": 31,
        b"cookie": 32,
        b"date": 33,
        b"host": 38,
        b"user-agent": 58,
    }

    def encode_header(self, name: bytes, value: bytes) -> bytes:
        """Encode a single header using HPACK."""
        name_lower = name.lower()
        if name_lower in self.STATIC_TABLE:
            index = self.STATIC_TABLE[name_lower]
            result = struct.pack(">B", 64 | index)
        else:
            result = struct.pack(">B", 64)
            result += struct.pack(">B", len(name)) + name
        result += struct.pack(">B", len(value)) + value
        return result

    def encode_headers(self, headers: List[Tuple[bytes, bytes]]) -> bytes:
        """Encode multiple headers."""
        result = b""
        for name, value in headers:
            result += self.encode_header(name, value)
        return result


# HTTP/2 Detection Utilities


def is_http2_traffic(payload: bytes) -> bool:
    """
    Check if payload contains HTTP/2 traffic.

    Args:
        payload: Raw bytes to check

    Returns:
        True if payload appears to be HTTP/2 traffic
    """
    if payload.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
        return True
    if len(payload) >= 9 and looks_like_http2_frame(payload):
        return True
    return False


def looks_like_http2_frame(payload: bytes) -> bool:
    """
    Check if payload looks like a valid HTTP/2 frame.

    Args:
        payload: Raw bytes to check

    Returns:
        True if payload can be parsed as HTTP/2 frame
    """
    try:
        HTTP2Frame.from_bytes(payload)
        return True
    except (ValueError, struct.error, IndexError):
        return False


# HTTP/2 Frame Conversion Utilities


def convert_http1_to_http2(payload: bytes) -> List[HTTP2Frame]:
    """
    Convert HTTP/1.1 request to HTTP/2 frames.

    Args:
        payload: HTTP/1.1 request as bytes

    Returns:
        List of HTTP/2 frames representing the request
    """
    frames = []

    # Add SETTINGS frame
    settings_payload = b""
    settings_frame = HTTP2Frame(4, 0, 0, settings_payload)
    frames.append(settings_frame)

    # Check if payload looks like HTTP/1.1 request
    if not (payload.startswith(b"GET ") or payload.startswith(b"POST ")):
        return frames

    lines = payload.split(b"\r\n")
    request_line = lines[0]
    parts = request_line.split(b" ")

    if len(parts) >= 3:
        method = parts[0]
        path = parts[1]

        # Build pseudo-headers
        headers = [(b":method", method), (b":path", path), (b":scheme", b"https")]

        # Parse HTTP/1.1 headers
        for line in lines[1:]:
            if b":" in line and line != b"":
                name, value = line.split(b":", 1)
                name = name.strip().lower()
                value = value.strip()

                # Convert Host header to :authority pseudo-header
                if name == b"host":
                    headers.insert(-1, (b":authority", value))
                else:
                    headers.append((name, value))

        # Encode headers with HPACK
        encoder = HPACKEncoder()
        headers_payload = encoder.encode_headers(headers)

        # Create HEADERS frame with END_HEADERS flag (5 = 0x04 | 0x01)
        headers_frame = HTTP2Frame(1, 5, 1, headers_payload)
        frames.append(headers_frame)

    return frames


def parse_http2_frames(payload: bytes) -> List[HTTP2Frame]:
    """
    Parse HTTP/2 frames from raw payload.

    Args:
        payload: Raw bytes containing HTTP/2 frames

    Returns:
        List of parsed HTTP/2 frames
    """
    frames = []
    offset = 0

    while offset < len(payload):
        # Check if we have enough bytes for frame header (9 bytes)
        if offset + 9 > len(payload):
            break

        try:
            frame = HTTP2Frame.from_bytes(payload[offset:])
            frames.append(frame)
            offset += 9 + frame.length
        except (ValueError, struct.error, IndexError):
            # Stop parsing on invalid frame
            break

    return frames


# HTTP/2 Frame Splitting Utilities


def split_headers_frame(frames: List[HTTP2Frame], max_size: int) -> List[HTTP2Frame]:
    """
    Split HEADERS frames into smaller CONTINUATION frames.

    Args:
        frames: List of HTTP/2 frames to process
        max_size: Maximum payload size for each frame

    Returns:
        List of frames with large HEADERS frames split into smaller ones
    """
    modified_frames = []

    for frame in frames:
        # Only split HEADERS frames (type 1) that exceed max_size
        if frame.frame_type == 1 and len(frame.payload) > max_size:
            # Split payload into chunks
            payload_chunks = []
            offset = 0
            while offset < len(frame.payload):
                chunk_size = min(max_size, len(frame.payload) - offset)
                payload_chunks.append(frame.payload[offset : offset + chunk_size])
                offset += chunk_size

            # Create CONTINUATION frames (type 9) for each chunk
            for i, chunk in enumerate(payload_chunks):
                flags = 0
                # Preserve original flags on the last chunk
                if i == len(payload_chunks) - 1:
                    flags = frame.flags
                # CONTINUATION frame type is 9
                new_frame = HTTP2Frame(9, flags, frame.stream_id, chunk)
                modified_frames.append(new_frame)
        else:
            modified_frames.append(frame)

    return modified_frames


def split_data_frames(frames: List[HTTP2Frame], max_size: int) -> List[HTTP2Frame]:
    """
    Split DATA frames into smaller frames.

    Args:
        frames: List of HTTP/2 frames to process
        max_size: Maximum payload size for each frame

    Returns:
        List of frames with large DATA frames split into smaller ones
    """
    modified_frames = []

    for frame in frames:
        # Only split DATA frames (type 0) that exceed max_size
        if frame.frame_type == 0 and len(frame.payload) > max_size:
            # Split payload into chunks
            payload_chunks = []
            offset = 0
            while offset < len(frame.payload):
                chunk_size = min(max_size, len(frame.payload) - offset)
                payload_chunks.append(frame.payload[offset : offset + chunk_size])
                offset += chunk_size

            # Create DATA frames for each chunk
            for i, chunk in enumerate(payload_chunks):
                flags = 0
                # Preserve original flags (e.g., END_STREAM) on the last chunk
                if i == len(payload_chunks) - 1:
                    flags = frame.flags
                new_frame = HTTP2Frame(0, flags, frame.stream_id, chunk)
                modified_frames.append(new_frame)
        else:
            modified_frames.append(frame)

    return modified_frames


def split_mixed_frames(frames: List[HTTP2Frame], max_size: int) -> List[HTTP2Frame]:
    """
    Split both HEADERS and DATA frames.

    Args:
        frames: List of HTTP/2 frames to process
        max_size: Maximum payload size for each frame

    Returns:
        List of frames with both HEADERS and DATA frames split
    """
    frames = split_headers_frame(frames, max_size)
    frames = split_data_frames(frames, max_size)
    return frames


# HPACK Manipulation Utilities


def force_literal_headers(payload: bytes) -> bytes:
    """
    Force headers to use literal encoding instead of indexing.

    Converts indexed header representations to literal representations
    by modifying the HPACK encoding bits.

    Args:
        payload: HPACK encoded header block

    Returns:
        Modified HPACK payload with literal encoding
    """
    modified = bytearray(payload)
    for i in range(len(modified)):
        # Check if byte has indexed representation (bit 7 set)
        if modified[i] & 128:
            # Convert to literal with incremental indexing (bit 6 set, bit 7 clear)
            modified[i] = modified[i] & 127 | 64
    return bytes(modified)


def disable_huffman_encoding(payload: bytes) -> bytes:
    """
    Disable Huffman encoding in HPACK headers.

    Removes Huffman encoding flag from string literals in HPACK payload.

    Args:
        payload: HPACK encoded header block

    Returns:
        Modified HPACK payload without Huffman encoding
    """
    modified = bytearray(payload)
    for i in range(len(modified)):
        # Check if byte has Huffman encoding flag (bit 7 set)
        if modified[i] & 128:
            # Clear Huffman encoding bit
            modified[i] &= 127
    return bytes(modified)


def add_header_padding(payload: bytes) -> bytes:
    """
    Add padding headers to HPACK payload.

    Appends dummy padding headers to increase payload size and
    potentially evade size-based DPI detection.

    Args:
        payload: HPACK encoded header block

    Returns:
        HPACK payload with additional padding headers
    """
    padding_headers = [b"@\nx-padding-1\x05dummy", b"@\nx-padding-2\x05value"]
    result = payload
    for padding in padding_headers:
        result += padding
    return result


def manipulate_hpack(hpack_payload: bytes, manipulation_type: str) -> bytes:
    """
    Apply HPACK manipulation based on specified type.

    Args:
        hpack_payload: HPACK encoded header block
        manipulation_type: Type of manipulation to apply:
            - "literal_headers": Force literal encoding
            - "huffman_disable": Disable Huffman encoding
            - "padding": Add padding headers

    Returns:
        Manipulated HPACK payload
    """
    if manipulation_type == "literal_headers":
        return force_literal_headers(hpack_payload)
    elif manipulation_type == "huffman_disable":
        return disable_huffman_encoding(hpack_payload)
    elif manipulation_type == "padding":
        return add_header_padding(hpack_payload)
    else:
        return hpack_payload


# HPACK Bomb Creation Utilities


def create_hpack_bomb(
    compression_ratio: int = 10,
    header_count: int = 100,
    base_pattern: bytes = b"x-custom-header-",
    base_value: bytes = b"repeated-value-pattern-",
) -> bytes:
    """
    Create HPACK compression bomb with repeated headers.

    Creates a large number of headers with repeated values to exploit
    HPACK compression and potentially evade DPI detection.

    Args:
        compression_ratio: Multiplier for value repetition
        header_count: Number of custom headers to generate
        base_pattern: Base pattern for header names
        base_value: Base pattern for header values

    Returns:
        HPACK encoded header block with compression bomb
    """
    headers = []

    # Add standard pseudo-headers
    headers.extend(
        [
            (b":method", b"POST"),
            (b":path", b"/api/data"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
        ]
    )

    # Generate repeated headers with pattern
    repeated_value = base_value * compression_ratio
    for i in range(header_count):
        header_name = base_pattern + str(i).encode()
        header_value = repeated_value + str(i % 10).encode()
        headers.append((header_name, header_value))

    encoder = HPACKEncoder()
    return encoder.encode_headers(headers)


def wrap_hpack_bomb_in_frames(hpack_bomb: bytes, payload: bytes) -> bytes:
    """
    Wrap HPACK bomb in HTTP/2 frames with connection preface.

    Creates a complete HTTP/2 connection with:
    - Connection preface
    - SETTINGS frame
    - HEADERS frame with HPACK bomb
    - DATA frame with actual payload

    Args:
        hpack_bomb: HPACK encoded compression bomb
        payload: Actual data payload to send

    Returns:
        Complete HTTP/2 connection bytes
    """
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    # Create SETTINGS frame with increased limits
    settings_payload = struct.pack(">HI", 1, 4096)  # HEADER_TABLE_SIZE
    settings_payload += struct.pack(">HI", 4, 65535)  # INITIAL_WINDOW_SIZE
    settings_frame = HTTP2Frame(4, 0, 0, settings_payload)

    # Create HEADERS frame with HPACK bomb (flags: END_HEADERS=0x04 | END_STREAM=0x01)
    headers_frame = HTTP2Frame(1, 5, 1, hpack_bomb)

    # Create DATA frame with actual payload (flags: END_STREAM=0x01)
    data_frame = HTTP2Frame(0, 1, 1, payload)

    # Assemble complete connection
    result = preface
    result += settings_frame.to_bytes()
    result += headers_frame.to_bytes()
    result += data_frame.to_bytes()

    return result


def wrap_hpack_bomb_in_frames_split(hpack_bomb: bytes, max_frame_size: int = 16384) -> bytes:
    """
    Wrap HPACK bomb in HTTP/2 frames with automatic splitting for large payloads.

    If HPACK bomb exceeds max_frame_size, splits it across multiple
    HEADERS and CONTINUATION frames.

    Args:
        hpack_bomb: HPACK encoded compression bomb
        max_frame_size: Maximum size for each frame payload

    Returns:
        Complete HTTP/2 connection bytes with split frames
    """
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings_frame = HTTP2Frame(4, 0, 0, b"")

    frames = []

    if len(hpack_bomb) <= max_frame_size:
        # Single HEADERS frame (flags: END_HEADERS=0x04 | END_STREAM=0x01)
        headers_frame = HTTP2Frame(1, 5, 1, hpack_bomb)
        frames.append(headers_frame)
    else:
        # Split across HEADERS + CONTINUATION frames
        chunks = [
            hpack_bomb[i : i + max_frame_size] for i in range(0, len(hpack_bomb), max_frame_size)
        ]

        # First chunk: HEADERS frame with END_STREAM flag only
        first_frame = HTTP2Frame(1, 1, 1, chunks[0])
        frames.append(first_frame)

        # Remaining chunks: CONTINUATION frames
        for i, chunk in enumerate(chunks[1:], 1):
            # Last chunk gets END_HEADERS flag
            flags = 4 if i == len(chunks) - 1 else 0
            cont_frame = HTTP2Frame(9, flags, 1, chunk)
            frames.append(cont_frame)

    # Assemble complete connection
    result = preface + settings_frame.to_bytes()
    for frame in frames:
        result += frame.to_bytes()

    return result


# HTTP/2 Priority Manipulation Utilities


def create_priority_payload(stream_id: int, strategy: str = "normal") -> bytes:
    """
    Create HTTP/2 PRIORITY frame payload.

    Generates a 5-byte priority payload according to HTTP/2 spec:
    - 4 bytes: E (1 bit) + Stream Dependency (31 bits)
    - 1 byte: Weight (0-255, representing 1-256)

    Args:
        stream_id: Current stream ID (used for random dependency calculation)
        strategy: Priority strategy to use:
            - "random": Random exclusive flag, dependency, and weight
            - "high": Highest priority (exclusive, no dependency, max weight)
            - "low": Lowest priority (non-exclusive, no dependency, min weight)
            - "normal" (default): Normal priority (non-exclusive, no dependency, medium weight)

    Returns:
        5-byte priority frame payload
    """
    if strategy == "random":
        exclusive = random.choice([0, 1])
        stream_dependency = random.randint(0, stream_id - 1) if stream_id > 1 else 0
        weight = random.randint(1, 256)
    elif strategy == "high":
        exclusive = 1
        stream_dependency = 0
        weight = 256
    elif strategy == "low":
        exclusive = 0
        stream_dependency = 0
        weight = 1
    else:  # normal
        exclusive = 0
        stream_dependency = 0
        weight = 16

    # Pack E bit (bit 31) and stream dependency (bits 0-30)
    dependency_field = (exclusive << 31) | (stream_dependency & 0x7FFFFFFF)

    # Pack as 4 bytes (dependency) + 1 byte (weight - 1)
    # Weight is encoded as 0-255 representing 1-256
    return struct.pack(">IB", dependency_field, weight - 1)


# H2C (HTTP/2 Cleartext) Utilities


def create_h2c_prior_knowledge_connection(
    payload: bytes, domain: str, path: str = "/api/data"
) -> bytes:
    """
    Create HTTP/2 cleartext connection with prior knowledge.

    Creates a complete h2c connection without HTTP/1.1 upgrade,
    assuming both client and server support HTTP/2.

    Args:
        payload: Data payload to send
        domain: Target domain or IP address
        path: Request path (default: "/api/data")

    Returns:
        Complete h2c connection bytes with preface, SETTINGS, HEADERS, and DATA frames
    """
    # HTTP/2 connection preface
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    # Create SETTINGS frame with h2c-specific settings
    settings_payload = struct.pack(">HI", 2, 0)  # ENABLE_PUSH = 0
    settings_payload += struct.pack(">HI", 3, 1000)  # MAX_CONCURRENT_STREAMS = 1000
    settings_payload += struct.pack(">HI", 4, 65535)  # INITIAL_WINDOW_SIZE = 65535
    settings_frame = HTTP2Frame(4, 0, 0, settings_payload)

    # Create HEADERS frame with pseudo-headers
    headers = [
        (b":method", b"POST"),
        (b":path", path.encode() if isinstance(path, str) else path),
        (b":scheme", b"http"),  # h2c uses http scheme
        (b":authority", domain.encode() if isinstance(domain, str) else domain),
        (b"content-type", b"application/octet-stream"),
        (b"content-length", str(len(payload)).encode()),
    ]

    hpack_encoder = HPACKEncoder()
    headers_payload = hpack_encoder.encode_headers(headers)
    headers_frame = HTTP2Frame(1, 4, 1, headers_payload)  # flags: END_HEADERS

    # Create DATA frame
    data_frame = HTTP2Frame(0, 1, 1, payload)  # flags: END_STREAM

    # Assemble complete connection
    return preface + settings_frame.to_bytes() + headers_frame.to_bytes() + data_frame.to_bytes()


def create_h2c_upgrade_request(payload: bytes, domain: str) -> bytes:
    """
    Create HTTP/1.1 Upgrade request to h2c.

    Creates an HTTP/1.1 request with Upgrade header to negotiate
    HTTP/2 cleartext connection, followed by h2c frames.

    Args:
        payload: Data payload to send
        domain: Target domain or IP address

    Returns:
        HTTP/1.1 upgrade request followed by h2c frames
    """
    # HTTP/1.1 Upgrade request
    upgrade_request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"Connection: Upgrade, HTTP2-Settings\r\n"
        f"Upgrade: h2c\r\n"
        f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
        f"\r\n"
    ).encode()

    # Append h2c frames after upgrade
    h2c_frames = create_h2c_prior_knowledge_connection(payload, domain)

    return upgrade_request + h2c_frames
