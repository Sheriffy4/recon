"""
QUIC Protocol Utilities

Shared utility functions for QUIC attacks to eliminate code duplication.
Extracted from quic_attacks.py, session.py, and packets.py.

Addresses:
- FD1 (sim=0.98): encode_qpack_headers duplication
- Clone groups: exact_262b913c6d63239a2f36627e12fc0135, exact_ee42765fcf328482add4c640afbd8f52
- Clone groups: exact_374663da9748d4a61d429ddbce4d1e24, exact_32f2e38ddf8582ccdc0e051604e8ea88
"""

import struct
from typing import Dict, List, Any
from .packets import QUICPacket


def encode_qpack_headers(headers: Dict[str, str]) -> bytes:
    """
    Simplified QPACK header encoding.

    Unified implementation addressing FD1 (functional dedup cluster).
    Previously duplicated in:
    - quic_attacks.py:1111-1120 (QUICHTTP3FullSession._encode_qpack_headers)
    - session.py:22-31 (encode_qpack_headers)

    Args:
        headers: Dictionary of header name-value pairs

    Returns:
        Encoded QPACK headers as bytes
    """
    encoded = b""
    for name, value in headers.items():
        encoded += b"P"
        encoded += struct.pack(">B", len(name))
        encoded += name.encode()
        encoded += struct.pack(">B", len(value))
        encoded += value.encode()
    return encoded


def analyze_pn_distribution(packets: List[QUICPacket]) -> Dict[str, Any]:
    """
    Analyze packet number distribution by packet type.

    Unified implementation addressing exact clone groups:
    - exact_ee42765fcf328482add4c640afbd8f52
    - exact_4acf775cb04d43e64df3cf58c52c33d8

    Previously duplicated in:
    - quic_attacks.py:536-556 (AdvancedPacketNumberSpaceConfusion._analyze_pn_distribution)
    - packets.py:276-291 (analyze_packet_distribution)

    Args:
        packets: List of QUIC packets to analyze

    Returns:
        Dictionary with statistics per packet type (min, max, count, unique, duplicates)
    """
    if not packets:
        return {}

    pn_by_type = {}
    for packet in packets:
        pn_type = packet.packet_type.name
        if pn_type not in pn_by_type:
            pn_by_type[pn_type] = []
        pn_by_type[pn_type].append(packet.packet_number)

    analysis = {}
    for pn_type, pns in pn_by_type.items():
        if pns:
            analysis[pn_type] = {
                "min": min(pns),
                "max": max(pns),
                "count": len(pns),
                "unique": len(set(pns)),
                "duplicates": len(pns) - len(set(pns)),
            }

    return analysis


def count_migrations(packets: List[QUICPacket]) -> int:
    """
    Count number of connection ID changes (migrations).

    Unified implementation addressing exact clone groups:
    - exact_32f2e38ddf8582ccdc0e051604e8ea88

    Previously duplicated in:
    - quic_attacks.py:903-913 (QUICMigrationSimulation._count_migrations)
    - packets.py:307-310 (count_migrations)

    Args:
        packets: List of QUIC packets to analyze

    Returns:
        Number of connection ID changes detected
    """
    if not packets:
        return 0

    migrations = 0
    last_cid = packets[0].connection_id
    for packet in packets[1:]:
        if packet.connection_id != last_cid:
            migrations += 1
            last_cid = packet.connection_id

    return migrations
