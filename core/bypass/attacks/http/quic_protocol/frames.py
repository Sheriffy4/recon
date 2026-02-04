"""
QUIC Frame Builders

Functions for creating various QUIC frame types.
Extracted from quic_attacks.py to reduce duplication (addresses SM3-SM6, UN7-UN10).
"""

import secrets
import struct
from typing import Dict

from .encoding import encode_varint
from .packets import QUICFrameType


def create_stream_frame(stream_id: int, data: bytes, fin: bool = False, offset: int = 0) -> bytes:
    """
    Create STREAM frame.

    Addresses: SM3 (feature_envy), UN7 (unused private method)
    """
    frame_type = QUICFrameType.STREAM
    if offset > 0:
        frame_type |= 4
    if len(data) > 0:
        frame_type |= 2
    if fin:
        frame_type |= 1

    frame = encode_varint(frame_type)
    frame += encode_varint(stream_id)
    if offset > 0:
        frame += encode_varint(offset)
    if len(data) > 0:
        frame += encode_varint(len(data))
        frame += data

    return frame


def create_crypto_frame(data: bytes, offset: int = 0) -> bytes:
    """
    Create CRYPTO frame.

    Addresses: SM4 (feature_envy), UN8 (unused private method)
    """
    result = encode_varint(QUICFrameType.CRYPTO)
    result += encode_varint(offset)
    result += encode_varint(len(data))
    result += data
    return result


def create_http3_settings_frame() -> bytes:
    """
    Create HTTP/3 SETTINGS frame.

    Addresses: SM5 (feature_envy), UN9 (unused private method)
    """
    settings = {1: 100, 6: 16384, 7: 100}
    frame_type = encode_varint(4)
    payload = b""
    for setting_id, value in settings.items():
        payload += encode_varint(setting_id)
        payload += encode_varint(value)
    return frame_type + payload


def create_http3_headers_frame(headers: Dict[str, str]) -> bytes:
    """
    Create HTTP/3 HEADERS frame with QPACK encoding.

    Addresses: SM6 (feature_envy), UN10 (unused private method)
    """
    encoded_headers = b""
    for name, value in headers.items():
        encoded_headers += b"P"
        encoded_headers += struct.pack(">B", len(name))
        encoded_headers += name.encode()
        encoded_headers += struct.pack(">B", len(value))
        encoded_headers += value.encode()

    frame_type = encode_varint(1)
    length = encode_varint(len(encoded_headers))
    return frame_type + length + encoded_headers


def create_http3_data_frame(data: bytes) -> bytes:
    """Create HTTP/3 DATA frame."""
    frame_type = encode_varint(0)
    length = encode_varint(len(data))
    return frame_type + length + data


def create_padding_frame(size: int) -> bytes:
    """
    Create PADDING frame of specified size.

    Addresses: Feature envy pattern in packet space confusion
    """
    return bytes([QUICFrameType.PADDING]) * size


def create_new_connection_id_frame(sequence_number: int, connection_id: bytes) -> bytes:
    """
    Create NEW_CONNECTION_ID frame.

    Addresses: SM10 (feature_envy), UN16 (unused private method)
    """
    frame = encode_varint(QUICFrameType.NEW_CONNECTION_ID)
    frame += encode_varint(sequence_number)
    frame += encode_varint(max(0, sequence_number - 2))
    frame += struct.pack(">B", len(connection_id))
    frame += connection_id
    frame += secrets.token_bytes(16)
    return frame


def create_retire_connection_id_frame(sequence_number: int) -> bytes:
    """
    Create RETIRE_CONNECTION_ID frame.

    Addresses: SM11 (feature_envy), UN17 (unused private method)
    """
    frame = encode_varint(QUICFrameType.RETIRE_CONNECTION_ID)
    frame += encode_varint(sequence_number)
    return frame


def create_path_challenge_frame(data: bytes) -> bytes:
    """Create PATH_CHALLENGE frame."""
    frame = bytes([QUICFrameType.PATH_CHALLENGE])
    frame += data[:8]
    return frame


def create_path_response_frame(data: bytes) -> bytes:
    """Create PATH_RESPONSE frame."""
    frame = bytes([QUICFrameType.PATH_RESPONSE])
    frame += data[:8]
    return frame
