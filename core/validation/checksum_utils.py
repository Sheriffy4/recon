"""
TCP Checksum calculation and validation utilities.

This module provides pure functions for calculating and validating TCP checksums,
extracted from PacketValidator to eliminate duplication with SimplePacketValidator.
"""

import struct


def calculate_tcp_checksum(data: bytes) -> int:
    """
    Calculate Internet checksum (RFC 1071).

    Args:
        data: Data to checksum

    Returns:
        Checksum value (16-bit)
    """
    # Pad data to even length
    if len(data) % 2 == 1:
        data += b"\x00"

    # Sum all 16-bit words
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word

    # Add carry bits
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # One's complement
    checksum = ~checksum & 0xFFFF

    return checksum


def validate_tcp_checksum(ip_header: bytes, tcp_header: bytes, payload: bytes) -> bool:
    """
    Validate TCP checksum using pseudo-header.

    Args:
        ip_header: IP header bytes (minimum 20 bytes)
        tcp_header: TCP header bytes (minimum 20 bytes)
        payload: TCP payload bytes

    Returns:
        True if checksum is valid, False otherwise
    """
    try:
        # Extract source and destination IPs from IP header
        if len(ip_header) < 20:
            return False

        src_ip = ip_header[12:16]
        dst_ip = ip_header[16:20]

        # Build pseudo header for TCP checksum calculation
        # Format: src_ip (4) + dst_ip (4) + zero (1) + protocol (1) + tcp_length (2)
        pseudo_header = src_ip + dst_ip
        pseudo_header += struct.pack(">BBH", 0, 6, len(tcp_header) + len(payload))

        # Zero out checksum field in TCP header for calculation
        tcp_header_copy = bytearray(tcp_header)
        tcp_header_copy[16:18] = b"\x00\x00"

        # Combine all parts: pseudo_header + tcp_header + payload
        data = pseudo_header + bytes(tcp_header_copy) + payload

        # Calculate checksum
        calculated_checksum = calculate_tcp_checksum(data)

        # Get original checksum from TCP header
        original_checksum = struct.unpack(">H", tcp_header[16:18])[0]

        return calculated_checksum == original_checksum

    except (struct.error, IndexError):
        # If validation fails due to malformed data, assume invalid
        return False
