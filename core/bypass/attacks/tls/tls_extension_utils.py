"""
TLS Extension Manipulation Utilities

Functions for parsing, modifying, and rebuilding TLS extensions:
- Extension parsing and serialization
- Extension order randomization
- Extension insertion and rebuilding
"""

from __future__ import annotations

import struct
import random
import logging
from typing import List, Tuple

LOG = logging.getLogger(__name__)


def parse_extensions(extensions_data: bytes) -> List[Tuple[int, bytes]]:
    """
    Parse TLS extensions from raw bytes.

    Args:
        extensions_data: Raw extension data (without length prefix)

    Returns:
        List of (extension_type, extension_data) tuples
    """
    extensions = []
    offset = 0
    while offset < len(extensions_data):
        if offset + 4 > len(extensions_data):
            break
        ext_type = struct.unpack("!H", extensions_data[offset : offset + 2])[0]
        ext_len = struct.unpack("!H", extensions_data[offset + 2 : offset + 4])[0]
        if offset + 4 + ext_len > len(extensions_data):
            break
        ext_data = extensions_data[offset + 4 : offset + 4 + ext_len]
        extensions.append((ext_type, ext_data))
        offset += 4 + ext_len
    return extensions


def serialize_extensions(extensions: List[Tuple[int, bytes]]) -> bytes:
    """
    Serialize TLS extensions to raw bytes.

    Args:
        extensions: List of (extension_type, extension_data) tuples

    Returns:
        Serialized extension data (without length prefix)
    """
    buf = bytearray()
    for ext_type, ext_data in extensions:
        buf += struct.pack("!H", int(ext_type) & 0xFFFF)
        buf += struct.pack("!H", len(ext_data))
        buf += ext_data
    return bytes(buf)


def randomize_extension_order(
    payload: bytes, extensions_start: int, keep_sni_first: bool = True
) -> bytes:
    """
    Randomize the order of TLS extensions.

    Args:
        payload: Full TLS ClientHello payload
        extensions_start: Offset to extensions length field
        keep_sni_first: If True, keep SNI (type 0) as first extension

    Returns:
        Modified payload with randomized extension order
    """
    try:
        if extensions_start < 0 or extensions_start + 2 > len(payload):
            return payload
        extensions_len = struct.unpack("!H", payload[extensions_start : extensions_start + 2])[0]
        extensions_data = payload[extensions_start + 2 : extensions_start + 2 + extensions_len]

        extensions = parse_extensions(extensions_data)

        if keep_sni_first:
            sni_ext = None
            other_exts = []
            for ext_type, ext_data in extensions:
                if ext_type == 0:
                    sni_ext = (ext_type, ext_data)
                else:
                    other_exts.append((ext_type, ext_data))

            random.shuffle(other_exts)
            reordered_extensions = []
            if sni_ext:
                reordered_extensions.append(sni_ext)
            reordered_extensions.extend(other_exts)
        else:
            reordered_extensions = extensions[:]
            random.shuffle(reordered_extensions)

        new_extensions_data = serialize_extensions(reordered_extensions)
        new_payload = payload[:extensions_start]
        new_payload += struct.pack("!H", len(new_extensions_data))
        new_payload += new_extensions_data
        new_payload += payload[extensions_start + 2 + extensions_len :]
        return new_payload
    except Exception:
        LOG.debug("randomize_extension_order failed", exc_info=True)
        return payload


def insert_extensions(
    payload: bytes,
    extensions_start: int,
    new_extensions: List[Tuple[int, bytes]],
    position: int = -1,
) -> bytes:
    """
    Insert new extensions into ClientHello.

    Args:
        payload: Full TLS ClientHello payload
        extensions_start: Offset to extensions length field
        new_extensions: List of (extension_type, extension_data) to insert
        position: Where to insert (-1 = append at end)

    Returns:
        Modified payload with inserted extensions
    """
    try:
        if extensions_start < 0 or extensions_start + 2 > len(payload):
            return payload
        extensions_len = struct.unpack("!H", payload[extensions_start : extensions_start + 2])[0]
        extensions_data = payload[extensions_start + 2 : extensions_start + 2 + extensions_len]

        existing_extensions = parse_extensions(extensions_data)

        if position < 0 or position >= len(existing_extensions):
            combined_extensions = existing_extensions + new_extensions
        else:
            combined_extensions = (
                existing_extensions[:position] + new_extensions + existing_extensions[position:]
            )

        new_extensions_data = serialize_extensions(combined_extensions)
        new_payload = payload[:extensions_start]
        new_payload += struct.pack("!H", len(new_extensions_data))
        new_payload += new_extensions_data
        new_payload += payload[extensions_start + 2 + extensions_len :]
        return new_payload
    except Exception:
        LOG.debug("insert_extensions failed", exc_info=True)
        return payload


def rebuild_extensions(
    payload: bytes, extensions_start: int, extensions: List[Tuple[int, bytes]]
) -> bytes:
    """
    Rebuild extensions section with new extension list.

    Args:
        payload: Full TLS ClientHello payload
        extensions_start: Offset to extensions length field
        extensions: New list of (extension_type, extension_data) tuples

    Returns:
        Modified payload with rebuilt extensions
    """
    try:
        if extensions_start < 0 or extensions_start + 2 > len(payload):
            return payload
        extensions_len = struct.unpack("!H", payload[extensions_start : extensions_start + 2])[0]

        new_extensions_data = serialize_extensions(extensions)
        new_payload = payload[:extensions_start]
        new_payload += struct.pack("!H", len(new_extensions_data))
        new_payload += new_extensions_data
        new_payload += payload[extensions_start + 2 + extensions_len :]
        return new_payload
    except Exception:
        LOG.debug("rebuild_extensions failed", exc_info=True)
        return payload
