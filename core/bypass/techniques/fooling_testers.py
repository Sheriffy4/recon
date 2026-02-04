#!/usr/bin/env python3
"""
Fooling method testing utilities.

This module provides functions for testing TCP fooling methods
like badsum and md5sig manipulation.
"""

import struct
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Constants for packet structure
TCP_CHECKSUM_OFFSET = 36  # Offset of TCP checksum in IP+TCP header
EXPECTED_BADSUM_CHECKSUM = 0xDEAD
EXPECTED_MD5SIG_CHECKSUM = 0xBEEF


def create_mock_tcp_packet() -> bytearray:
    """
    Create a mock TCP packet for testing.

    Returns:
        Bytearray containing simplified IP + TCP headers
    """
    # Simplified IP header (20 bytes)
    ip_header = bytearray(
        [
            0x45,  # Version (4) + IHL (5)
            0x00,  # ToS
            0x00,
            0x3C,  # Total Length
            0x00,
            0x00,  # ID
            0x40,
            0x00,  # Flags + Fragment Offset
            0x40,  # TTL
            0x06,  # Protocol (TCP)
            0x00,
            0x00,  # Header Checksum
            0xC0,
            0xA8,
            0x01,
            0x01,  # Source IP (192.168.1.1)
            0xC0,
            0xA8,
            0x01,
            0x02,  # Dest IP (192.168.1.2)
        ]
    )

    # Simplified TCP header (20 bytes)
    tcp_header = bytearray(
        [
            0x04,
            0xD2,  # Source Port (1234)
            0x01,
            0xBB,  # Dest Port (443)
            0x00,
            0x00,
            0x00,
            0x01,  # Seq Number
            0x00,
            0x00,
            0x00,
            0x00,  # Ack Number
            0x50,
            0x18,  # Data Offset (5) + Flags (PSH, ACK)
            0x20,
            0x00,  # Window Size
            0x00,
            0x00,  # Checksum (will be modified by fooling methods)
            0x00,
            0x00,  # Urgent Pointer
        ]
    )

    return ip_header + tcp_header


def test_badsum_fooling(packet: bytearray) -> Dict[str, Any]:
    """
    Test badsum fooling method.

    Args:
        packet: Mock TCP packet to test

    Returns:
        Dictionary with test results
    """
    from core.bypass.techniques.primitives import BypassTechniques

    logger.info("  Testing badsum fooling...")

    original_checksum = struct.unpack("!H", packet[TCP_CHECKSUM_OFFSET : TCP_CHECKSUM_OFFSET + 2])[
        0
    ]

    modified_packet = BypassTechniques.apply_badsum_fooling(packet)
    new_checksum = struct.unpack(
        "!H", modified_packet[TCP_CHECKSUM_OFFSET : TCP_CHECKSUM_OFFSET + 2]
    )[0]

    issues = []
    if new_checksum != EXPECTED_BADSUM_CHECKSUM:
        issues.append(
            f"Expected checksum 0x{EXPECTED_BADSUM_CHECKSUM:04X}, got 0x{new_checksum:04X}"
        )

    return {
        "name": "badsum_fooling",
        "original_checksum": f"0x{original_checksum:04X}",
        "new_checksum": f"0x{new_checksum:04X}",
        "issues": issues,
        "passed": len(issues) == 0,
    }


def test_md5sig_fooling(packet: bytearray) -> Dict[str, Any]:
    """
    Test md5sig fooling method.

    Args:
        packet: Mock TCP packet to test

    Returns:
        Dictionary with test results
    """
    from core.bypass.techniques.primitives import BypassTechniques

    logger.info("  Testing md5sig fooling...")

    original_checksum = struct.unpack("!H", packet[TCP_CHECKSUM_OFFSET : TCP_CHECKSUM_OFFSET + 2])[
        0
    ]

    modified_packet = BypassTechniques.apply_md5sig_fooling(packet)
    new_checksum = struct.unpack(
        "!H", modified_packet[TCP_CHECKSUM_OFFSET : TCP_CHECKSUM_OFFSET + 2]
    )[0]

    issues = []
    if new_checksum != EXPECTED_MD5SIG_CHECKSUM:
        issues.append(
            f"Expected checksum 0x{EXPECTED_MD5SIG_CHECKSUM:04X}, got 0x{new_checksum:04X}"
        )

    return {
        "name": "md5sig_fooling",
        "original_checksum": f"0x{original_checksum:04X}",
        "new_checksum": f"0x{new_checksum:04X}",
        "issues": issues,
        "passed": len(issues) == 0,
    }
