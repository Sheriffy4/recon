"""
Steganography Utilities

Common utilities for steganographic attacks including checksums,
payload splitting, and encoding functions.
"""

import struct
import zlib
from typing import List, Dict


def calculate_ip_checksum(header: bytes) -> int:
    """
    Calculate IP header checksum.

    Args:
        header: IP header bytes (checksum field should be zeroed)

    Returns:
        16-bit checksum value
    """
    # Zero out checksum field (bytes 10-11)
    header = header[:10] + b"\x00\x00" + header[12:]

    # Pad to even length if needed
    if len(header) % 2:
        header += b"\x00"

    checksum = 0
    for i in range(0, len(header), 2):
        word = (header[i] << 8) + header[i + 1]
        checksum += word

    # Add carry bits
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16

    return ~checksum & 0xFFFF


def calculate_icmp_checksum(data: bytes) -> int:
    """
    Calculate ICMP checksum.

    Args:
        data: ICMP packet data

    Returns:
        16-bit checksum value
    """
    # Pad to even length if needed
    if len(data) % 2:
        data += b"\x00"

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word

    # Add carry bits
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16

    return ~checksum & 0xFFFF


def calculate_crc32(data: bytes) -> int:
    """
    Calculate CRC32 checksum for PNG/image formats.

    Args:
        data: Data to checksum

    Returns:
        32-bit CRC32 value
    """
    return zlib.crc32(data) & 0xFFFFFFFF


def split_payload_across_channels(
    payload: bytes, channels: List[str], redundancy_level: int
) -> Dict[str, bytes]:
    """
    Split payload across multiple covert channels.

    Args:
        payload: Data to split
        channels: List of channel names
        redundancy_level: If > 1, duplicate payload across all channels

    Returns:
        Dictionary mapping channel name to payload chunk
    """
    channel_payloads = {}

    if not channels:
        raise ValueError("channels must be a non-empty list")
    if redundancy_level < 0:
        raise ValueError("redundancy_level must be >= 0")

    if redundancy_level > 1:
        # Redundant mode: send full payload on each channel
        for channel in channels:
            channel_payloads[channel] = payload
    else:
        # Split mode: divide payload across channels
        chunk_size = len(payload) // len(channels)
        remainder = len(payload) % len(channels)
        offset = 0

        for i, channel in enumerate(channels):
            # Distribute remainder bytes to first channels
            size = chunk_size + (1 if i < remainder else 0)
            channel_payloads[channel] = payload[offset : offset + size]
            offset += size

    return channel_payloads


def split_payload_into_chunks(payload: bytes, chunk_size: int) -> List[bytes]:
    """
    Split payload into fixed-size chunks with padding.

    Args:
        payload: Data to split
        chunk_size: Size of each chunk in bytes

    Returns:
        List of chunks (last chunk padded with zeros if needed)
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    chunks = []
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i : i + chunk_size]
        # Pad last chunk if needed
        if len(chunk) < chunk_size:
            chunk += b"\x00" * (chunk_size - len(chunk))
        chunks.append(chunk)

    return chunks


def encode_lsb_in_timestamps(data_chunk: bytes, base_timestamp: int) -> tuple:
    """
    Encode data in LSBs of TCP timestamp values.

    Args:
        data_chunk: Data to encode (1 byte)
        base_timestamp: Base timestamp value

    Returns:
        Tuple of (ts_val, ts_ecr) with encoded data
    """
    ts_val = base_timestamp
    ts_ecr = base_timestamp - 1000

    if len(data_chunk) > 0:
        byte_val = data_chunk[0]
        # Encode bits in LSBs of both timestamps
        for i in range(min(8, len(data_chunk) * 8)):
            bit = (byte_val >> i) & 1
            if i < 4:
                # Encode in ts_val LSBs
                pos = i % 4
                low = ts_val & 0x0F
                low = (low & ~(1 << pos)) | (bit << pos)
                ts_val = (ts_val & 0xFFFFFFF0) | low
            else:
                # Encode in ts_ecr LSBs
                pos = (i - 4) % 4
                low = ts_ecr & 0x0F
                low = (low & ~(1 << pos)) | (bit << pos)
                ts_ecr = (ts_ecr & 0xFFFFFFF0) | low

    return (ts_val, ts_ecr)


def encode_full_in_timestamps(data_chunk: bytes, base_timestamp: int) -> tuple:
    """
    Encode data directly in timestamp values (full replacement).

    Args:
        data_chunk: Data to encode (up to 8 bytes)
        base_timestamp: Base timestamp value

    Returns:
        Tuple of (ts_val, ts_ecr) with encoded data
    """
    import time

    ts_val = base_timestamp
    ts_ecr = base_timestamp - 1000
    current_time = int(time.time())

    # Encode first 4 bytes in ts_val
    if len(data_chunk) >= 4:
        ts_val = struct.unpack(">I", data_chunk[:4])[0]
        # Clamp to reasonable range (within 24 hours of current time)
        if ts_val < current_time - 86400 or ts_val > current_time + 86400:
            ts_val = current_time + (ts_val % 86400)

    # Encode next 4 bytes in ts_ecr
    if len(data_chunk) >= 8:
        ts_ecr = struct.unpack(">I", data_chunk[4:8])[0]
        if ts_ecr < current_time - 86400 or ts_ecr > current_time + 86400:
            ts_ecr = current_time - 1000 + (ts_ecr % 86400)

    return (ts_val, ts_ecr)


def encode_modulo_in_timestamps(data_chunk: bytes, base_timestamp: int) -> tuple:
    """
    Encode data in timestamp modulo values.

    Args:
        data_chunk: Data to encode (up to 4 bytes)
        base_timestamp: Base timestamp value

    Returns:
        Tuple of (ts_val, ts_ecr) with encoded data
    """
    ts_val = base_timestamp
    ts_ecr = base_timestamp - 1000

    # Encode first 2 bytes in ts_val lower 16 bits
    if len(data_chunk) >= 2:
        val = struct.unpack(">H", data_chunk[:2])[0]
        ts_val = (ts_val // 65536) * 65536 + val

    # Encode next 2 bytes in ts_ecr lower 16 bits
    if len(data_chunk) >= 4:
        val = struct.unpack(">H", data_chunk[2:4])[0]
        ts_ecr = (ts_ecr // 65536) * 65536 + val

    return (ts_val, ts_ecr)


def encode_sequential_in_id(base_id: int, data_chunk: bytes, sequence: int) -> int:
    """
    Encode data sequentially in IP ID field.

    Args:
        base_id: Base ID value
        data_chunk: Data to encode (up to 2 bytes)
        sequence: Sequence number for fallback

    Returns:
        Encoded ID value (16-bit)
    """
    if len(data_chunk) >= 2:
        data_id = struct.unpack(">H", data_chunk[:2])[0]
        return (base_id + data_id) % 65536
    else:
        return (base_id + sequence) % 65536


def encode_lsb_in_id(base_id: int, data_chunk: bytes, sequence: int) -> int:
    """
    Encode data in LSBs of IP ID field.

    Args:
        base_id: Base ID value
        data_chunk: Data to encode (1 byte)
        sequence: Sequence number

    Returns:
        Encoded ID value (16-bit)
    """
    identification = (base_id + sequence) % 65536

    if len(data_chunk) > 0:
        byte_val = data_chunk[0]
        # Replace lower 8 bits with data
        identification = (identification & 0xFF00) | (byte_val & 0xFF)

    return identification % 65536


def encode_modulo_in_id(base_id: int, data_chunk: bytes, sequence: int) -> int:
    """
    Encode data using modulo operations in IP ID.

    Args:
        base_id: Base ID value
        data_chunk: Data to encode (up to 2 bytes)
        sequence: Sequence number for fallback

    Returns:
        Encoded ID value (16-bit)
    """
    if len(data_chunk) >= 2:
        data_val = struct.unpack(">H", data_chunk[:2])[0]
        return (base_id + (data_val % 1000)) % 65536
    else:
        return (base_id + sequence) % 65536


def split_payload_for_timestamps(payload: bytes, method: str) -> List[bytes]:
    """
    Split payload into chunks suitable for timestamp encoding.

    Args:
        payload: Data to split
        method: Encoding method ('lsb', 'full', 'modulo')

    Returns:
        List of chunks (no padding for timestamps)
    """
    if method == "lsb":
        chunk_size = 1
    elif method == "full":
        chunk_size = 8
    elif method == "modulo":
        chunk_size = 4
    else:
        chunk_size = 4

    chunks = []
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i : i + chunk_size]
        chunks.append(chunk)

    return chunks


def split_payload_for_ip_id(payload: bytes, method: str) -> List[bytes]:
    """
    Split payload into chunks suitable for IP ID encoding.

    Args:
        payload: Data to split
        method: Encoding method ('sequential', 'lsb', 'modulo')

    Returns:
        List of chunks (padded with zeros)
    """
    if method == "sequential":
        chunk_size = 2
    elif method == "lsb":
        chunk_size = 1
    elif method == "modulo":
        chunk_size = 2
    else:
        chunk_size = 2

    return split_payload_into_chunks(payload, chunk_size)


def split_payload_for_field(payload: bytes, field: str) -> List[bytes]:
    """
    Split payload appropriately for specific protocol field type.

    Args:
        payload: Data to split
        field: Field name ('ip_id', 'tcp_timestamp', 'tcp_seq', 'tcp_window', etc.)

    Returns:
        List of chunks (padded with zeros)
    """
    if field == "ip_id":
        chunk_size = 2
    elif field == "tcp_timestamp":
        chunk_size = 8
    elif field == "tcp_seq":
        chunk_size = 4
    elif field == "tcp_window":
        chunk_size = 2
    else:
        chunk_size = 2

    return split_payload_into_chunks(payload, chunk_size)


def split_payload_for_protocol(payload: bytes, protocol: str, fields: List[str]) -> List[bytes]:
    """
    Split payload into chunks that fit in protocol fields.

    Args:
        payload: Data to split
        protocol: Protocol name ('tcp', 'udp', 'icmp')
        fields: List of field names to use

    Returns:
        List of chunks (padded with zeros)
    """
    if protocol in ("tcp", "udp") and not fields:
        raise ValueError("fields must be a non-empty list for tcp/udp protocol splitting")
    if protocol == "tcp":
        chunk_size = len(fields) * 2
    elif protocol == "udp":
        chunk_size = len(fields) * 2
    elif protocol == "icmp":
        chunk_size = 8
    else:
        chunk_size = 4

    return split_payload_into_chunks(payload, chunk_size)


def distribute_payload_across_fields(
    payload: bytes, fields: List[str], redundancy: bool
) -> Dict[str, List[bytes]]:
    """
    Distribute payload data across multiple protocol fields.

    Args:
        payload: Data to distribute
        fields: List of field names
        redundancy: If True, send full payload in each field; if False, split across fields

    Returns:
        Dictionary mapping field name to list of chunks
    """
    field_chunks = {}
    if not fields:
        raise ValueError("fields must be a non-empty list")

    if redundancy:
        # Redundant mode: send full payload in each field
        for field in fields:
            field_chunks[field] = split_payload_for_field(payload, field)
    else:
        # Split mode: divide payload across fields
        chunk_size = len(payload) // len(fields)
        remainder = len(payload) % len(fields)
        offset = 0

        for i, field in enumerate(fields):
            # Distribute remainder bytes to first fields
            field_size = chunk_size + (1 if i < remainder else 0)
            field_payload = payload[offset : offset + field_size]
            field_chunks[field] = split_payload_for_field(field_payload, field)
            offset += field_size

    return field_chunks


def encode_modulo_base(data_chunk: bytes, base_value: int, modulo: int, max_value: int) -> int:
    """
    Base function for modulo-based encoding.

    Args:
        data_chunk: Data to encode (up to 2 bytes)
        base_value: Base value to start from
        modulo: Modulo value to apply
        max_value: Maximum value (for wrapping)

    Returns:
        Encoded value
    """
    if len(data_chunk) >= 2:
        data_val = struct.unpack(">H", data_chunk[:2])[0]
        return (base_value + (data_val % modulo)) % max_value
    else:
        return base_value


def encode_modulo_in_field(data_chunk: bytes, base_value: int, field_size_bits: int) -> int:
    """
    Generic modulo encoding for any field size.

    Args:
        data_chunk: Data to encode
        base_value: Base value
        field_size_bits: Size of field in bits (16 for IP ID, 32 for timestamps)

    Returns:
        Encoded value
    """
    max_value = 2**field_size_bits

    if len(data_chunk) >= 2:
        data_val = struct.unpack(">H", data_chunk[:2])[0]
        # Replace lower 16 bits while preserving upper bits
        if field_size_bits == 32:
            return (base_value // 65536) * 65536 + data_val
        else:
            return data_val % max_value
    else:
        return base_value


# Encoding Pattern Analysis
# -------------------------
# The encoding functions follow common patterns:
#
# 1. LSB Encoding Pattern:
#    - encode_lsb_in_timestamps: Modifies lower 4 bits of two 32-bit values
#    - encode_lsb_in_id: Modifies lower 8 bits of one 16-bit value
#    - Common: Preserves most significant bits, encodes in least significant bits
#
# 2. Full Replacement Pattern:
#    - encode_full_in_timestamps: Replaces entire timestamp values with data
#    - encode_sequential_in_id: Adds data value to base ID
#    - Common: Uses full field capacity for data
#
# 3. Modulo Pattern:
#    - encode_modulo_in_timestamps: Replaces lower 16 bits of 32-bit values
#    - encode_modulo_in_id: Adds (data % 1000) to base ID
#    - Common: Uses modulo arithmetic to constrain values
#
# These patterns can be unified using the generic functions above:
# - encode_modulo_base: Generic modulo encoding
# - encode_modulo_in_field: Field-size-aware modulo encoding
