"""
QUIC/HTTP3 Session Utilities

Functions for creating HTTP/3 sessions and related utilities.
Extracted from quic_attacks.py to reduce QUICHTTP3FullSession complexity.
"""

import secrets
from typing import Dict, List

from .encoding import encode_varint
from .frames import (
    create_stream_frame,
    create_http3_settings_frame,
    create_http3_headers_frame,
    create_http3_data_frame,
)
from .packets import QUICPacket, QUICPacketType
from .utils import encode_qpack_headers


def create_qpack_encoder_stream() -> bytes:
    """Create QPACK encoder stream data."""
    stream_data = b""
    stream_data += b"\x80"
    stream_data += b"\x10"
    stream_data += encode_varint(4096)
    return stream_data


def create_push_promise_frame(push_id: int, headers: Dict[str, str]) -> bytes:
    """Create PUSH_PROMISE frame."""
    frame_type = encode_varint(5)
    push_id_encoded = encode_varint(push_id)
    encoded_headers = encode_qpack_headers(headers)
    length = encode_varint(len(push_id_encoded) + len(encoded_headers))
    return frame_type + length + push_id_encoded + encoded_headers


def create_priority_update_frame(stream_id: int, priority: int) -> bytes:
    """Create PRIORITY_UPDATE frame."""
    frame_type = encode_varint(15)
    prioritized_element_type = 0
    prioritized_element_id = encode_varint(stream_id)
    priority_value = f"u={priority}".encode()
    content = bytes([prioritized_element_type]) + prioritized_element_id + priority_value
    length = encode_varint(len(content))
    return frame_type + length + content


def create_http3_session(
    payload: bytes,
    domain: str,
    stream_count: int = 3,
    use_qpack_dynamic: bool = True,
    simulate_push: bool = True,
) -> List[QUICPacket]:
    """
    Create complete HTTP/3 session.

    Reduces QUICHTTP3FullSession complexity by extracting session creation logic.
    """
    packets = []
    connection_id = secrets.token_bytes(8)
    packet_number = 0

    # SETTINGS frame
    settings_frame = create_http3_settings_frame()
    settings_stream = create_stream_frame(0, settings_frame)
    settings_packet = QUICPacket(
        packet_type=QUICPacketType.ONE_RTT,
        connection_id=connection_id,
        packet_number=packet_number,
        payload=settings_stream,
    )
    packets.append(settings_packet)
    packet_number += 1

    # QPACK encoder stream
    if use_qpack_dynamic:
        encoder_data = create_qpack_encoder_stream()
        encoder_stream = create_stream_frame(2, encoder_data)
        encoder_packet = QUICPacket(
            packet_type=QUICPacketType.ONE_RTT,
            connection_id=connection_id,
            packet_number=packet_number,
            payload=encoder_stream,
        )
        packets.append(encoder_packet)
        packet_number += 1

    # Multiple streams
    stream_id = 4
    for i in range(stream_count):
        headers = {
            ":method": "GET",
            ":scheme": "https",
            ":authority": domain,
            ":path": f"/stream_{i}",
            "user-agent": "QUIC-Bypass/1.0",
            "accept": "*/*",
        }
        headers_frame = create_http3_headers_frame(headers)

        chunk_size = len(payload) // stream_count
        chunk_start = i * chunk_size
        chunk_end = chunk_start + chunk_size if i < stream_count - 1 else len(payload)
        chunk = payload[chunk_start:chunk_end]
        data_frame = create_http3_data_frame(chunk)

        stream_data = headers_frame + data_frame
        stream_frame = create_stream_frame(stream_id, stream_data, fin=True)
        stream_packet = QUICPacket(
            packet_type=QUICPacketType.ONE_RTT,
            connection_id=connection_id,
            packet_number=packet_number,
            payload=stream_frame,
        )
        packets.append(stream_packet)
        packet_number += 1
        stream_id += 4

    # Server push simulation
    if simulate_push:
        push_id = 0
        push_headers = {
            ":method": "GET",
            ":scheme": "https",
            ":authority": domain,
            ":path": "/pushed_resource",
        }
        push_promise_frame = create_push_promise_frame(push_id, push_headers)
        push_stream = create_stream_frame(1, push_promise_frame)
        push_packet = QUICPacket(
            packet_type=QUICPacketType.ONE_RTT,
            connection_id=connection_id,
            packet_number=packet_number,
            payload=push_stream,
        )
        packets.append(push_packet)
        packet_number += 1

    # Priority updates
    for i in range(stream_count):
        priority_frame = create_priority_update_frame(4 + i * 4, i * 10)
        priority_stream = create_stream_frame(0, priority_frame)
        priority_packet = QUICPacket(
            packet_type=QUICPacketType.ONE_RTT,
            connection_id=connection_id,
            packet_number=packet_number,
            payload=priority_stream,
        )
        packets.append(priority_packet)
        packet_number += 1

    return packets
