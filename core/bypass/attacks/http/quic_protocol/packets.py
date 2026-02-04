"""
QUIC Packet Structures and Utilities

Core QUIC packet/frame dataclasses and packet building functions.
Extracted from quic_attacks.py to reduce duplication.
"""

import random
import secrets
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import List, Tuple, Optional

from .encoding import encode_varint, encode_packet_number, get_packet_number_length


class QUICPacketType(IntEnum):
    """QUIC packet types."""

    INITIAL = 0
    ZERO_RTT = 1
    HANDSHAKE = 2
    RETRY = 3
    ONE_RTT = 64
    VERSION_NEGOTIATION = 255


class QUICFrameType(IntEnum):
    """QUIC frame types."""

    PADDING = 0
    PING = 1
    ACK = 2
    RESET_STREAM = 4
    STOP_SENDING = 5
    CRYPTO = 6
    NEW_TOKEN = 7
    STREAM = 8
    MAX_DATA = 16
    MAX_STREAM_DATA = 17
    NEW_CONNECTION_ID = 24
    RETIRE_CONNECTION_ID = 25
    PATH_CHALLENGE = 26
    PATH_RESPONSE = 27
    CONNECTION_CLOSE = 28


@dataclass
class QUICFrame:
    """QUIC frame structure."""

    frame_type: int
    payload: bytes

    def to_bytes(self) -> bytes:
        """Convert frame to bytes."""
        frame_type_bytes = encode_varint(self.frame_type)
        return frame_type_bytes + self.payload


@dataclass
class QUICPacket:
    """QUIC packet structure."""

    packet_type: QUICPacketType
    connection_id: bytes
    packet_number: int
    payload: bytes
    version: int = 1

    @property
    def is_long_header(self) -> bool:
        return self.packet_type != QUICPacketType.ONE_RTT

    def to_bytes(self) -> bytes:
        """Convert packet to bytes."""
        if self.is_long_header:
            return build_long_header_packet(
                self.packet_type,
                self.connection_id,
                self.packet_number,
                self.payload,
                self.version,
            )
        else:
            return build_short_header_packet(self.connection_id, self.packet_number, self.payload)


def build_long_header_packet(
    packet_type: QUICPacketType,
    connection_id: bytes,
    packet_number: int,
    payload: bytes,
    version: int = 1,
) -> bytes:
    """
    Build long header packet.

    Addresses: UN1 (unused private method now public utility)
    """
    first_byte = 128 | packet_type << 4 | 64
    result = struct.pack(">B", first_byte)
    result += struct.pack(">I", version)
    result += struct.pack(">B", len(connection_id))
    result += connection_id
    result += struct.pack(">B", 0)

    if packet_type == QUICPacketType.INITIAL:
        result += encode_varint(0)

    packet_number_length = get_packet_number_length(packet_number)
    payload_length = packet_number_length + len(payload) + 16
    result += encode_varint(payload_length)
    result += encode_packet_number(packet_number)
    result += payload
    result += secrets.token_bytes(16)

    return result


def build_short_header_packet(connection_id: bytes, packet_number: int, payload: bytes) -> bytes:
    """
    Build short header packet.

    Addresses: UN2 (unused private method now public utility)
    """
    spin_bit = random.randint(0, 1) << 5
    key_phase = random.randint(0, 1) << 2
    pn_length = 1
    first_byte = 64 | spin_bit | key_phase | pn_length

    result = struct.pack(">B", first_byte)
    result += connection_id
    result += encode_packet_number(packet_number)
    result += payload
    result += secrets.token_bytes(16)

    return result


def generate_cid_pool(
    pool_size: int, min_length: int, max_length: int, use_zero_length: bool = True
) -> List[bytes]:
    """
    Generate pool of Connection IDs with variable lengths.

    Addresses: SM7 (feature_envy), UN11 (unused private method)
    """
    cid_pool = []

    if use_zero_length:
        cid_pool.append(b"")

    for i in range(pool_size):
        if i % 5 == 0 and use_zero_length:
            cid_pool.append(b"")
        else:
            length = random.randint(min_length, max_length)
            if i % 3 == 0:
                cid = secrets.token_bytes(length)
            elif i % 3 == 1:
                pattern = bytes([i % 256])
                cid = pattern * length
            else:
                cid = secrets.token_bytes(length // 2) + bytes([255] * (length - length // 2))
            cid_pool.append(cid)

    return cid_pool


def coalesce_packets(
    packets: List[QUICPacket], max_datagram_size: int = 1200
) -> List[Tuple[bytes, int]]:
    """
    Coalesce multiple packets into single UDP datagrams.

    Addresses: SM16 (feature_envy), UN22, UN28 (unused coalescing methods)
    """
    segments = []
    current_datagram = b""
    current_size = 0

    for packet in packets:
        packet_bytes = packet.to_bytes()
        packet_size = len(packet_bytes)

        if current_size + packet_size <= max_datagram_size:
            current_datagram += packet_bytes
            current_size += packet_size
        else:
            if current_datagram:
                segments.append((current_datagram, 0))
            current_datagram = packet_bytes
            current_size = packet_size

    if current_datagram:
        segments.append((current_datagram, 0))

    return segments


def convert_payload_to_quic_packets(
    payload: bytes,
    connection_id: Optional[bytes] = None,
    chunk_size: int = 500,
    stream_id: int = 0,
) -> List[QUICPacket]:
    """
    Convert raw payload to QUIC packets with STREAM frames.

    Helper function to reduce duplication across attack classes.

    Args:
        payload: Raw data to convert
        connection_id: Connection ID (generated if None)
        chunk_size: Size of each chunk
        stream_id: QUIC stream ID to use

    Returns:
        List of QUICPacket objects
    """
    from .frames import create_stream_frame

    packets = []
    if connection_id is None:
        connection_id = secrets.token_bytes(8)

    packet_number = 0
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i : i + chunk_size]
        packet_type = QUICPacketType.INITIAL if i == 0 else QUICPacketType.ONE_RTT
        stream_frame = create_stream_frame(stream_id, chunk)
        packet = QUICPacket(
            packet_type=packet_type,
            connection_id=connection_id,
            packet_number=packet_number,
            payload=stream_frame,
        )
        packets.append(packet)
        packet_number += 1

    return packets


def create_packet_with_random_cid(
    packet_type: QUICPacketType,
    packet_number: int,
    payload: bytes,
    cid_length: int = 8,
) -> QUICPacket:
    """
    Create a QUIC packet with random connection ID.

    Helper for quick packet creation in attacks.
    """
    return QUICPacket(
        packet_type=packet_type,
        connection_id=secrets.token_bytes(cid_length),
        packet_number=packet_number,
        payload=payload,
    )
