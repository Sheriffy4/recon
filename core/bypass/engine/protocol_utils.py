"""
Protocol detection utilities for bypass engine.

This module provides low-level protocol detection functions for TLS
and transport protocols. Extracted from base_engine.py to reduce
god class complexity.
"""

from typing import Optional, Any


def is_tls_clienthello(payload: Optional[bytes]) -> bool:
    """
    Detect TLS ClientHello messages.

    Requirement 6.1: Accurate ClientHello counting for telemetry.

    Args:
        payload: Raw packet payload bytes

    Returns:
        True if payload contains TLS ClientHello, False otherwise
    """
    try:
        if not payload or len(payload) < 43:
            return False
        # TLS Content Type: Handshake (0x16)
        if payload[0] != 0x16:
            return False
        # Handshake Type: ClientHello (0x01)
        if payload[5] != 0x01:
            return False
        return True
    except Exception:
        return False


def is_tls_serverhello(payload: Optional[bytes]) -> bool:
    """
    Detect TLS ServerHello messages.

    Requirement 6.1: Accurate ServerHello counting for telemetry.

    Args:
        payload: Raw packet payload bytes

    Returns:
        True if payload contains TLS ServerHello, False otherwise
    """
    try:
        if not payload or len(payload) < 43:
            return False
        # TLS Content Type: Handshake (0x16)
        if payload[0] != 0x16:
            return False
        # Handshake Type: ServerHello (0x02)
        if payload[5] != 0x02:
            return False
        return True
    except Exception:
        return False


def get_protocol(packet: Any) -> int:
    """
    Extract protocol number from packet.

    Args:
        packet: Packet object with protocol attribute

    Returns:
        Protocol number (e.g., 6 for TCP, 17 for UDP), or 0 if not available
    """
    p = getattr(packet, "protocol", None)
    if isinstance(p, tuple) and p:
        return int(p[0])
    return int(p) if p is not None else 0


def is_tcp(packet: Any) -> bool:
    """
    Check if packet uses TCP protocol.

    Args:
        packet: Packet object

    Returns:
        True if packet is TCP (protocol 6), False otherwise
    """
    return get_protocol(packet) == 6


def is_udp(packet: Any) -> bool:
    """
    Check if packet uses UDP protocol.

    Args:
        packet: Packet object

    Returns:
        True if packet is UDP (protocol 17), False otherwise
    """
    return get_protocol(packet) == 17


def is_tcp_handshake(packet: Any) -> bool:
    """
    Check if packet is part of TCP 3-way handshake.

    Task 19: Fix TCP handshake issue - Don't apply strategy to TCP handshake packets.
    This ensures curl can establish TCP connection before TLS handshake.

    Args:
        packet: Packet object with tcp attribute

    Returns:
        True if packet is TCP handshake (SYN, SYN-ACK, or ACK without data)
        False otherwise
    """
    try:
        # Check if packet has TCP layer
        if not hasattr(packet, "tcp") or not packet.tcp or len(packet.tcp.raw) < 14:
            return False

        # Extract TCP flags (byte 13 in TCP header)
        tcp_flags = bytes(packet.tcp.raw)[13]

        # TCP flag constants
        SYN_FLAG = 0x02
        ACK_FLAG = 0x10

        # Check for SYN (with or without ACK) - this is SYN or SYN-ACK
        if tcp_flags & SYN_FLAG:
            return True

        # Check for pure ACK without payload (final handshake ACK)
        if tcp_flags == ACK_FLAG and not hasattr(packet, "payload"):
            return True
        if tcp_flags == ACK_FLAG and hasattr(packet, "payload") and not packet.payload:
            return True

        return False

    except Exception:
        return False
