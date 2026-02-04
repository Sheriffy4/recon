"""
QUIC Encoding Utilities

Variable-length integer encoding, packet number encoding, and entropy calculation.
Extracted from quic_attacks.py to reduce duplication (addresses SM1, clone groups).
"""

import struct
from typing import Dict


def encode_varint(value: int) -> bytes:
    """
    Encode variable-length integer per QUIC spec.

    Addresses: SM1 (feature_envy), clone group structural_d25bc76a70c3f8c7a59b65430ee5408b
    """
    if value < 64:
        return struct.pack(">B", value)
    elif value < 16384:
        return struct.pack(">H", 16384 | value)
    elif value < 1073741824:
        return struct.pack(">I", 2147483648 | value)
    else:
        return struct.pack(">Q", 13835058055282163712 | value)


def get_packet_number_length(packet_number: int) -> int:
    """
    Get packet number length in bytes.

    Addresses: UN3 (unused private method now public utility)
    """
    if packet_number < 128:
        return 1
    elif packet_number < 32768:
        return 2
    else:
        return 4


def encode_packet_number(packet_number: int) -> bytes:
    """
    Encode packet number based on its value.

    Addresses: UN4 (unused private method now public utility)
    """
    length = get_packet_number_length(packet_number)
    if length == 1:
        return struct.pack(">B", packet_number & 255)
    elif length == 2:
        return struct.pack(">H", packet_number & 65535)
    else:
        return struct.pack(">I", packet_number & 4294967295)


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data (0.0 to 1.0).

    Addresses: SM12 (feature_envy)
    """
    if not data:
        return 0.0

    frequencies: Dict[int, int] = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1

    entropy = 0.0
    data_len = len(data)
    for count in frequencies.values():
        probability = count / data_len
        if probability > 0:
            import math

            entropy -= probability * math.log2(probability)

    # Normalize to 0.0-1.0 range (max entropy for byte is 8 bits)
    max_entropy = 8.0
    return min(1.0, max(0.0, entropy / max_entropy))
