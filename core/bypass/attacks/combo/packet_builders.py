"""
Packet Builders for Steganography

Functions for creating TCP, UDP, ICMP, and IP packets with steganographic data.
These builders handle binary packet structure creation with proper field manipulation.
"""

import struct
import random
import time
from typing import List, Dict, Tuple


def create_tcp_packet_with_timestamp_stego(
    data_chunk: bytes,
    method: str,
    base_timestamp: int,
    src_port: int = None,
    dst_port: int = 443,
) -> bytes:
    """
    Create TCP packet with steganographic timestamp option.

    Args:
        data_chunk: Data to encode in timestamps
        method: Encoding method ('lsb', 'full', 'modulo')
        base_timestamp: Base timestamp value
        src_port: Source port (random if None)
        dst_port: Destination port

    Returns:
        TCP packet bytes with timestamp option
    """
    from .stego_utils import (
        encode_lsb_in_timestamps,
        encode_full_in_timestamps,
        encode_modulo_in_timestamps,
    )

    if src_port is None:
        src_port = random.randint(49152, 65535)

    seq_num = random.randint(1000000, 9999999)
    ack_num = 0
    header_length = 8  # 8 * 4 = 32 bytes (includes options)
    flags = 0x18  # PSH + ACK
    window = 65535
    checksum = 0
    urgent = 0

    # Encode data in timestamps based on method
    if method == "lsb":
        ts_val, ts_ecr = encode_lsb_in_timestamps(data_chunk, base_timestamp)
    elif method == "full":
        ts_val, ts_ecr = encode_full_in_timestamps(data_chunk, base_timestamp)
    elif method == "modulo":
        ts_val, ts_ecr = encode_modulo_in_timestamps(data_chunk, base_timestamp)
    else:
        ts_val = base_timestamp
        ts_ecr = base_timestamp - 1000

    # Build TCP header
    tcp_header = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq_num,
        ack_num,
        header_length << 4,
        flags,
        window,
        checksum,
        urgent,
    )

    # Add timestamp option (kind=8, length=10, TSval, TSecr)
    timestamp_option = struct.pack(">BBII", 8, 10, ts_val, ts_ecr)
    nop_padding = b"\x01\x01"  # NOP padding
    tcp_options = timestamp_option + nop_padding

    return tcp_header + tcp_options


def create_ip_packet_with_id_stego(
    data_chunk: bytes,
    method: str,
    base_id: int,
    sequence: int,
    src_ip: int = 0xC0A80101,  # 192.168.1.1
    dst_ip: int = 0xC0A80102,  # 192.168.1.2
) -> bytes:
    """
    Create IP packet with steganographic ID field.

    Args:
        data_chunk: Data to encode in IP ID
        method: Encoding method ('sequential', 'lsb', 'modulo')
        base_id: Base ID value
        sequence: Sequence number
        src_ip: Source IP (as integer)
        dst_ip: Destination IP (as integer)

    Returns:
        IP packet bytes with TCP header
    """
    from .stego_utils import (
        encode_sequential_in_id,
        encode_lsb_in_id,
        encode_modulo_in_id,
        calculate_ip_checksum,
    )

    version = 4
    ihl = 5
    tos = 0
    total_length = 40  # IP header (20) + TCP header (20)
    flags = 0x4000  # Don't Fragment
    ttl = 64
    protocol = 6  # TCP
    checksum = 0

    # Encode data in IP ID based on method
    if method == "sequential":
        identification = encode_sequential_in_id(base_id, data_chunk, sequence)
    elif method == "lsb":
        identification = encode_lsb_in_id(base_id, data_chunk, sequence)
    elif method == "modulo":
        identification = encode_modulo_in_id(base_id, data_chunk, sequence)
    else:
        identification = base_id + sequence

    # Build IP header (without checksum)
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        (version << 4) | ihl,
        tos,
        total_length,
        identification,
        flags,
        ttl,
        protocol,
        checksum,
        struct.pack("!I", src_ip),
        struct.pack("!I", dst_ip),
    )

    # Calculate and insert checksum
    checksum = calculate_ip_checksum(ip_header)
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        (version << 4) | ihl,
        tos,
        total_length,
        identification,
        flags,
        ttl,
        protocol,
        checksum,
        struct.pack("!I", src_ip),
        struct.pack("!I", dst_ip),
    )

    # Add minimal TCP header
    tcp_header = struct.pack(">HHIIBBHHH", 80, 8080, sequence, 0, 0x50, 0x18, 65535, 0, 0)

    return ip_header + tcp_header


def create_stego_tcp_packet(data_chunk: bytes, fields: List[str], sequence: int) -> bytes:
    """
    Create TCP packet with steganographic data in specified fields.

    Args:
        data_chunk: Data to embed
        fields: List of field names ('id', 'flags', 'window', 'urgent')
        sequence: Sequence number

    Returns:
        TCP header bytes
    """
    src_port = 80
    dst_port = 8080
    seq_num = sequence
    ack_num = 0
    header_length = 5
    flags = 0x18  # PSH + ACK
    window = 65535
    checksum = 0
    urgent = 0
    data_offset = 0

    # Embed data in specified fields
    for field in fields:
        if data_offset >= len(data_chunk):
            break

        if field == "id" and data_offset + 2 <= len(data_chunk):
            seq_num = struct.unpack(">H", data_chunk[data_offset : data_offset + 2])[0]
            data_offset += 2
        elif field == "flags" and data_offset + 2 <= len(data_chunk):
            flags = struct.unpack(">H", data_chunk[data_offset : data_offset + 2])[0] & 0x3F
            data_offset += 2
        elif field == "window" and data_offset + 2 <= len(data_chunk):
            window = struct.unpack(">H", data_chunk[data_offset : data_offset + 2])[0]
            if window == 0:
                window = 1
            data_offset += 2
        elif field == "urgent" and data_offset + 2 <= len(data_chunk):
            urgent = struct.unpack(">H", data_chunk[data_offset : data_offset + 2])[0]
            data_offset += 2

    tcp_header = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq_num,
        ack_num,
        header_length << 4,
        flags,
        window,
        checksum,
        urgent,
    )

    return tcp_header


def create_stego_udp_packet(data_chunk: bytes, fields: List[str], sequence: int) -> bytes:
    """
    Create UDP packet with steganographic data in specified fields.

    Args:
        data_chunk: Data to embed
        fields: List of field names ('src_port', 'dst_port', 'length', 'checksum')
        sequence: Sequence number (unused but kept for API consistency)

    Returns:
        UDP header bytes
    """
    src_port = 53
    dst_port = 53
    length = 8
    checksum = 0
    data_offset = 0

    # Embed data in specified fields
    for field in fields:
        if data_offset >= len(data_chunk):
            break

        if field == "src_port" and data_offset + 2 <= len(data_chunk):
            src_port = struct.unpack(">H", data_chunk[data_offset : data_offset + 2])[0]
            if src_port == 0:
                src_port = 1024
            data_offset += 2
        elif field == "dst_port" and data_offset + 2 <= len(data_chunk):
            dst_port = struct.unpack(">H", data_chunk[data_offset : data_offset + 2])[0]
            if dst_port == 0:
                dst_port = 53
            data_offset += 2
        elif field == "length" and data_offset + 2 <= len(data_chunk):
            embedded_length = struct.unpack(">H", data_chunk[data_offset : data_offset + 2])[0]
            length = 8 + (embedded_length % 1000)
            data_offset += 2
        elif field == "checksum" and data_offset + 2 <= len(data_chunk):
            checksum = struct.unpack(">H", data_chunk[data_offset : data_offset + 2])[0]
            data_offset += 2

    udp_header = struct.pack(">HHHH", src_port, dst_port, length, checksum)

    return udp_header


def create_stego_icmp_packet(data_chunk: bytes, sequence: int) -> bytes:
    """
    Create ICMP packet with steganographic data.

    Args:
        data_chunk: Data to embed
        sequence: Sequence number

    Returns:
        ICMP header bytes
    """
    from .stego_utils import calculate_icmp_checksum

    icmp_type = 8  # Echo Request
    icmp_code = 0
    checksum = 0

    # Extract ID and sequence from data
    if len(data_chunk) >= 2:
        icmp_id = struct.unpack(">H", data_chunk[:2])[0]
    else:
        icmp_id = sequence

    if len(data_chunk) >= 4:
        icmp_seq = struct.unpack(">H", data_chunk[2:4])[0]
    else:
        icmp_seq = sequence

    # Extract timestamp if available
    if len(data_chunk) >= 8:
        timestamp = struct.unpack(">I", data_chunk[4:8])[0]
    else:
        timestamp = int(time.time())

    # Build ICMP header
    icmp_header = struct.pack(
        ">BBHHHI", icmp_type, icmp_code, checksum, icmp_id, icmp_seq, timestamp
    )

    # Calculate and insert checksum
    checksum = calculate_icmp_checksum(icmp_header)
    icmp_header = struct.pack(
        ">BBHHHI", icmp_type, icmp_code, checksum, icmp_id, icmp_seq, timestamp
    )

    return icmp_header


def create_combined_stego_packet(field_chunks: Dict[str, List[bytes]], packet_index: int) -> bytes:
    """
    Create packet with steganography in multiple fields simultaneously.

    Args:
        field_chunks: Dictionary mapping field names to lists of data chunks
        packet_index: Index of packet to create

    Returns:
        Combined IP + TCP packet with steganographic data
    """
    from .stego_utils import calculate_ip_checksum

    base_timestamp = int(time.time())
    base_id = random.randint(1000, 60000)
    base_seq = random.randint(1000000, 9999999)

    # Extract data for each field
    ip_id_data = b"\x00\x00"
    timestamp_data = b"\x00" * 8
    seq_data = b"\x00" * 4

    if "ip_id" in field_chunks and packet_index < len(field_chunks["ip_id"]):
        ip_id_data = field_chunks["ip_id"][packet_index]
    if "tcp_timestamp" in field_chunks and packet_index < len(field_chunks["tcp_timestamp"]):
        timestamp_data = field_chunks["tcp_timestamp"][packet_index]
    if "tcp_seq" in field_chunks and packet_index < len(field_chunks["tcp_seq"]):
        seq_data = field_chunks["tcp_seq"][packet_index]

    # Decode IP ID
    ip_id = base_id
    if len(ip_id_data) >= 2:
        ip_id = struct.unpack(">H", ip_id_data[:2])[0]

    # Build IP header
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,  # Version 4, IHL 5
        0,  # TOS
        52,  # Total length
        ip_id,
        0x4000,  # Flags: Don't Fragment
        64,  # TTL
        6,  # Protocol: TCP
        0,  # Checksum (will be calculated)
        struct.pack("!I", 0xC0A80101),  # Source IP
        struct.pack("!I", 0xC0A80102),  # Dest IP
    )

    # Calculate and insert IP checksum
    checksum = calculate_ip_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack(">H", checksum) + ip_header[12:]

    # Decode TCP sequence
    tcp_seq = base_seq
    if len(seq_data) >= 4:
        tcp_seq = struct.unpack(">I", seq_data[:4])[0]

    # Build TCP header
    tcp_header = struct.pack(">HHIIBBHHH", 80, 8080, tcp_seq, 0, 0x80, 0x18, 65535, 0, 0)

    # Decode timestamps
    ts_val = base_timestamp
    ts_ecr = base_timestamp - 1000
    if len(timestamp_data) >= 4:
        ts_val = struct.unpack(">I", timestamp_data[:4])[0]
    if len(timestamp_data) >= 8:
        ts_ecr = struct.unpack(">I", timestamp_data[4:8])[0]

    # Clamp timestamps to reasonable range
    current_time = int(time.time())
    if ts_val < current_time - 86400 or ts_val > current_time + 86400:
        ts_val = current_time + (ts_val % 86400)
    if ts_ecr < current_time - 86400 or ts_ecr > current_time + 86400:
        ts_ecr = current_time - 1000 + (ts_ecr % 86400)

    # Add TCP options
    tcp_options = struct.pack(">BBII", 8, 10, ts_val, ts_ecr) + b"\x01\x01"

    return ip_header + tcp_header + tcp_options


# Advanced Protocol Field Steganography Functions


def create_advanced_tcp_stego_packets(
    payload: bytes, fields: List[str], encoding: str
) -> List[Tuple[bytes, int]]:
    """
    Create TCP packets with advanced steganographic field manipulation.

    Args:
        payload: Data to embed
        fields: List of field names to use ('id', 'seq', 'ack', 'window', 'timestamp', 'flags')
        encoding: Encoding method (currently 'direct')

    Returns:
        List of (packet, delay) tuples
    """
    packets = []

    # Calculate bytes per packet based on fields
    bytes_per_packet = 0
    for field in fields:
        if field in ["seq", "ack", "timestamp"]:
            bytes_per_packet += 4
        elif field in ["id", "src_port", "dst_port", "window"]:
            bytes_per_packet += 2
        elif field in ["flags"]:
            bytes_per_packet += 1

    if bytes_per_packet == 0:
        bytes_per_packet = 4  # Default

    # Split payload into chunks
    for i in range(0, len(payload), bytes_per_packet):
        chunk = payload[i : i + bytes_per_packet]
        if len(chunk) < bytes_per_packet:
            chunk += b"\x00" * (bytes_per_packet - len(chunk))

        packet = create_advanced_tcp_packet_with_embedded_data(chunk, fields, encoding)
        packets.append((packet, 10))

    return packets


def create_advanced_tcp_packet_with_embedded_data(
    data: bytes, fields: List[str], encoding: str
) -> bytes:
    """
    Create TCP packet with data embedded in specified fields.

    Args:
        data: Data to embed
        fields: List of field names
        encoding: Encoding method

    Returns:
        TCP packet bytes with embedded data
    """
    src_port = 80
    dst_port = 8080
    seq_num = random.randint(1000000, 9999999)
    ack_num = random.randint(1000000, 9999999)
    flags = 0x18  # PSH + ACK
    window = 65535
    checksum = 0
    urgent = 0
    timestamp = 0
    data_offset = 0

    # Embed data in specified fields
    for field in fields:
        if data_offset >= len(data):
            break

        if field == "id" and data_offset + 2 <= len(data):
            src_port = struct.unpack(">H", data[data_offset : data_offset + 2])[0]
            if src_port < 1024:
                src_port += 1024
            data_offset += 2
        elif field == "seq" and data_offset + 4 <= len(data):
            seq_num = struct.unpack(">I", data[data_offset : data_offset + 4])[0]
            data_offset += 4
        elif field == "ack" and data_offset + 4 <= len(data):
            ack_num = struct.unpack(">I", data[data_offset : data_offset + 4])[0]
            data_offset += 4
        elif field == "window" and data_offset + 2 <= len(data):
            window = struct.unpack(">H", data[data_offset : data_offset + 2])[0]
            if window == 0:
                window = 1
            data_offset += 2
        elif field == "timestamp" and data_offset + 4 <= len(data):
            timestamp = struct.unpack(">I", data[data_offset : data_offset + 4])[0]
            data_offset += 4

    # Build TCP header
    tcp_header = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq_num,
        ack_num,
        5 << 4,
        flags,
        window,
        checksum,
        urgent,
    )

    # Add timestamp option if requested
    if "timestamp" in fields:
        timestamp_opt = struct.pack(">BBII", 8, 10, timestamp, 0)
        tcp_header += timestamp_opt

    return b"TCP_STEGO:" + tcp_header


def create_advanced_ip_stego_packets(
    payload: bytes, fields: List[str], encoding: str
) -> List[Tuple[bytes, int]]:
    """
    Create IP packets with advanced steganographic field manipulation.

    Args:
        payload: Data to embed
        fields: List of field names to use ('id', 'flags', 'frag_offset')
        encoding: Encoding method (currently 'direct')

    Returns:
        List of (packet, delay) tuples
    """
    packets = []

    # Split payload into 4-byte chunks
    for i in range(0, len(payload), 4):
        chunk = payload[i : i + 4]
        if len(chunk) < 4:
            chunk += b"\x00" * (4 - len(chunk))

        packet = create_advanced_ip_packet_with_embedded_data(chunk, fields)
        packets.append((packet, 15))

    return packets


def create_advanced_ip_packet_with_embedded_data(data: bytes, fields: List[str]) -> bytes:
    """
    Create IP packet with data embedded in specified fields.

    Args:
        data: Data to embed
        fields: List of field names

    Returns:
        IP packet bytes with embedded data
    """
    version = 4
    ihl = 5
    tos = 0
    total_length = 20
    identification = random.randint(1, 65535)
    flags = 2  # Don't Fragment
    fragment_offset = 0
    ttl = 64
    protocol = 6  # TCP
    checksum = 0
    src_ip = struct.pack(">I", random.randint(167772161, 167772415))  # 10.0.0.0/24
    dst_ip = struct.pack(">I", random.randint(167772161, 167772415))
    data_offset = 0

    # Embed data in specified fields
    for field in fields:
        if data_offset >= len(data):
            break

        if field == "id" and data_offset + 2 <= len(data):
            identification = struct.unpack(">H", data[data_offset : data_offset + 2])[0]
            data_offset += 2
        elif field == "flags" and data_offset + 1 <= len(data):
            flags = (data[data_offset] >> 5) & 0x07
            data_offset += 1
        elif field == "frag_offset" and data_offset + 2 <= len(data):
            fragment_offset = struct.unpack(">H", data[data_offset : data_offset + 2])[0] & 0x1FFF
            data_offset += 2

    # Combine flags and fragment offset
    flags_and_frag = (flags << 13) | fragment_offset

    # Build IP header
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        (version << 4) | ihl,
        tos,
        total_length,
        identification,
        flags_and_frag,
        ttl,
        protocol,
        checksum,
        src_ip,
        dst_ip,
    )

    return b"IP_STEGO:" + ip_header


def create_advanced_icmp_stego_packets(
    payload: bytes, fields: List[str], encoding: str
) -> List[Tuple[bytes, int]]:
    """
    Create ICMP packets with advanced steganographic field manipulation.

    Args:
        payload: Data to embed
        fields: List of field names to use ('id', 'seq', 'timestamp')
        encoding: Encoding method (currently 'direct')

    Returns:
        List of (packet, delay) tuples
    """
    packets = []

    # Split payload into 8-byte chunks
    for i in range(0, len(payload), 8):
        chunk = payload[i : i + 8]
        if len(chunk) < 8:
            chunk += b"\x00" * (8 - len(chunk))

        packet = create_advanced_icmp_packet_with_embedded_data(chunk, fields)
        packets.append((packet, 20))

    return packets


def create_advanced_icmp_packet_with_embedded_data(data: bytes, fields: List[str]) -> bytes:
    """
    Create ICMP packet with data embedded in specified fields.

    Args:
        data: Data to embed
        fields: List of field names

    Returns:
        ICMP packet bytes with embedded data
    """
    icmp_type = 8  # Echo Request
    icmp_code = 0
    checksum = 0
    identification = random.randint(1, 65535)
    sequence = random.randint(1, 65535)
    timestamp = 0
    data_offset = 0

    # Embed data in specified fields
    for field in fields:
        if data_offset >= len(data):
            break

        if field == "id" and data_offset + 2 <= len(data):
            identification = struct.unpack(">H", data[data_offset : data_offset + 2])[0]
            data_offset += 2
        elif field == "seq" and data_offset + 2 <= len(data):
            sequence = struct.unpack(">H", data[data_offset : data_offset + 2])[0]
            data_offset += 2
        elif field == "timestamp" and data_offset + 4 <= len(data):
            timestamp = struct.unpack(">I", data[data_offset : data_offset + 4])[0]
            data_offset += 4

    # Build ICMP header
    icmp_header = struct.pack(">BBHHH", icmp_type, icmp_code, checksum, identification, sequence)

    # Add timestamp if requested
    if "timestamp" in fields and data_offset >= 4:
        icmp_header += struct.pack(">I", timestamp)

    return b"ICMP_STEGO:" + icmp_header


def create_advanced_stego_packets(
    payload: bytes, protocol: str, fields: List[str], encoding: str
) -> List[Tuple[bytes, int]]:
    """
    Create advanced steganographic packets for specified protocol.

    Args:
        payload: Data to embed
        protocol: Protocol type ('tcp', 'ip', 'icmp')
        fields: List of field names to use
        encoding: Encoding method

    Returns:
        List of (packet, delay) tuples
    """
    if protocol == "tcp":
        return create_advanced_tcp_stego_packets(payload, fields, encoding)
    elif protocol == "ip":
        return create_advanced_ip_stego_packets(payload, fields, encoding)
    elif protocol == "icmp":
        return create_advanced_icmp_stego_packets(payload, fields, encoding)
    else:
        return create_advanced_tcp_stego_packets(payload, fields, encoding)
