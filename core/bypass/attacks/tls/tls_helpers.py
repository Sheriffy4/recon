"""
TLS Helper Utilities

Basic utility functions for TLS attack implementations:
- Type conversion and validation helpers
- Segment normalization for orchestration engines
- TLS packet identification heuristics
"""

from __future__ import annotations

import struct
import logging
from typing import List, Tuple, Dict, Any, Optional

LOG = logging.getLogger(__name__)

# Type alias for segment tuples used by orchestration engines
SegmentTuple = Tuple[bytes, int, Dict[str, Any]]


def clamp_int(value: Any, default: int, *, min_value: int = 1, max_value: int = 1_000_000) -> int:
    """
    Clamp an integer value to a specified range.

    Args:
        value: Value to clamp (will be converted to int)
        default: Default value if conversion fails
        min_value: Minimum allowed value
        max_value: Maximum allowed value

    Returns:
        Clamped integer value
    """
    try:
        iv = int(value)
    except Exception:
        return default
    return max(min_value, min(max_value, iv))


def coalesce(params: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """
    Return first found params[key] for keys, else default.

    Useful for handling legacy/alternate parameter names.

    Args:
        params: Parameter dictionary
        *keys: Keys to search for (in order)
        default: Default value if no key found

    Returns:
        First found value or default
    """
    for k in keys:
        if k in params:
            return params[k]
    return default


def ensure_bytes(payload: Any) -> Optional[bytes]:
    """
    Convert payload to bytes if possible.

    Args:
        payload: Input payload (bytes, bytearray, or other)

    Returns:
        bytes object or None if conversion not possible
    """
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, bytearray):
        return bytes(payload)
    return None


def normalize_segments_to_segment_tuples(segments: List[Any]) -> List[SegmentTuple]:
    """
    Normalize segments into the canonical orchestration shape:
      List[Tuple[payload: bytes, seq_offset: int, options: dict]]

    Accepts input items shaped as:
      - (chunk: bytes, offset: int)
      - (chunk: bytes, offset: int, meta: dict)
      - anything else -> skipped

    Args:
        segments: List of segment tuples in various formats

    Returns:
        Normalized list of SegmentTuple
    """
    normalized: List[SegmentTuple] = []

    for seg in segments:
        try:
            if not isinstance(seg, (tuple, list)) or len(seg) < 2:
                continue
            chunk = ensure_bytes(seg[0])
            if chunk is None:
                continue
            offset = int(seg[1])
            options: Dict[str, Any] = seg[2] if len(seg) >= 3 and isinstance(seg[2], dict) else {}
            normalized.append((chunk, offset, options))
        except Exception:
            continue

    return normalized


def is_tls_handshake_payload(payload: bytes) -> bool:
    """
    Heuristic check: TLS record(Handshake) + first handshake msg is ClientHello.

    Checks:
    - TLSPlaintext.type == handshake (22)
    - Version major == 3
    - HandshakeType == client_hello (1)

    Args:
        payload: Raw packet payload

    Returns:
        True if payload appears to be TLS ClientHello
    """
    if len(payload) < 6:
        return False
    return payload[0] == 22 and payload[1] == 3 and payload[5] == 1


def is_tls_record(payload: bytes) -> bool:
    """
    Check if payload is a valid TLS record.

    Validates:
    - Content type (20-23: ChangeCipherSpec, Alert, Handshake, ApplicationData)
    - Version (0x0300-0x0304: SSL3.0 to TLS1.3)

    Args:
        payload: Raw packet payload

    Returns:
        True if payload appears to be a TLS record
    """
    if len(payload) < 5:
        return False
    content_type = payload[0]
    version = struct.unpack("!H", payload[1:3])[0]
    return content_type in (20, 21, 22, 23) and 768 <= version <= 772


def client_hello_body_offset(payload: bytes) -> Optional[int]:
    """
    Return offset of ClientHello body (after handshake header), or None.

    Structure:
    - TLSPlaintext header: 5 bytes
    - Handshake header: 1(type) + 3(length) => total 4 bytes
    - Body starts at offset 9

    Args:
        payload: Raw TLS ClientHello packet

    Returns:
        Offset to ClientHello body or None if invalid
    """
    if len(payload) < 9:
        return None
    if not is_tls_handshake_payload(payload):
        return None
    return 5 + 4
