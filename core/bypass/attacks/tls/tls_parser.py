"""
TLS Parsing Utilities

Functions for parsing and manipulating TLS packet structures:
- Extension offset calculation
- Length field recalculation
- TLS version normalization
"""

from __future__ import annotations

import struct
import logging
from typing import Any

from core.bypass.attacks.tls.tls_helpers import (
    is_tls_handshake_payload,
    client_hello_body_offset,
)

LOG = logging.getLogger(__name__)


def find_extensions_offset_client_hello(payload: bytes) -> int:
    """
    Find the offset of extensions length field in ClientHello.

    Parses ClientHello structure:
    - TLS record header (5 bytes)
    - Handshake header (4 bytes)
    - ClientHello body:
      - client_version (2 bytes)
      - random (32 bytes)
      - session_id_length (1 byte) + session_id
      - cipher_suites_length (2 bytes) + cipher_suites
      - compression_methods_length (1 byte) + compression_methods
      - extensions_length (2 bytes) <- we return this offset

    Args:
        payload: Raw TLS ClientHello packet

    Returns:
        Offset to extensions length field, or -1 on failure
    """
    try:
        body = client_hello_body_offset(payload)
        if body is None:
            return -1

        offset = body
        # client_version(2) + random(32)
        offset += 2 + 32
        if offset >= len(payload):
            return -1

        session_id_len = payload[offset]
        offset += 1 + session_id_len
        if offset + 2 > len(payload):
            return -1

        cipher_suites_len = struct.unpack("!H", payload[offset : offset + 2])[0]
        offset += 2 + cipher_suites_len
        if offset >= len(payload):
            return -1

        comp_methods_len = payload[offset]
        offset += 1 + comp_methods_len

        # extensions length field (2 bytes) should be present
        if offset + 2 <= len(payload):
            return offset
        return -1
    except Exception:
        LOG.debug("find_extensions_offset_client_hello failed", exc_info=True)
        return -1


def recalculate_tls_handshake_lengths(payload: bytes) -> bytes:
    """
    Best-effort fixup for a single-record ClientHello.

    Updates length fields after payload modification:
    - TLS record length (bytes 3..5)
    - Handshake length (bytes 6..9, 3 bytes)

    This is necessary when extensions are added/removed/modified.

    Args:
        payload: Modified TLS ClientHello packet

    Returns:
        Payload with corrected length fields, or original on error
    """
    try:
        if len(payload) < 9 or not is_tls_handshake_payload(payload):
            return payload
        b = bytearray(payload)
        record_len = len(payload) - 5
        if record_len < 0 or record_len > 0xFFFF:
            return payload
        b[3:5] = struct.pack("!H", record_len)

        hs_len = len(payload) - 9  # after record header(5) + hs header(4)
        if hs_len < 0 or hs_len > 0xFFFFFF:
            return bytes(b)
        b[6:9] = hs_len.to_bytes(3, "big")
        return bytes(b)
    except Exception:
        LOG.debug("recalculate_tls_handshake_lengths failed", exc_info=True)
        return payload


def normalize_tls_version_key(raw: Any) -> str:
    """
    Normalize TLS version string to canonical format.

    Accepts variants:
    - tls12, tls1.2, tls1_2, TLS1.2, TLS 1.2
    - tls10, tls1.0, tls1, TLS1.0
    - tls11, tls1.1, TLS1.1
    - tls13, tls1.3, TLS1.3
    - ssl30, ssl3, SSL3.0

    Args:
        raw: Version string in any format

    Returns:
        Normalized version key (tls10, tls11, tls12, tls13, ssl30)
    """
    if not isinstance(raw, str):
        return "tls12"
    v = raw.strip().lower().replace("_", "").replace(".", "").replace(" ", "")
    # common aliases
    alias = {
        "tls10": "tls10",
        "tls1": "tls10",
        "tls11": "tls11",
        "tls12": "tls12",
        "tls13": "tls13",
        "ssl30": "ssl30",
        "ssl3": "ssl30",
    }
    return alias.get(v, v)
