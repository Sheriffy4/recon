"""
Timing Channel Encoding for Steganography

Functions for encoding data in timing patterns between packets.
Supports binary, morse, interval, differential, frequency, and burst timing methods.
"""

from __future__ import annotations

import asyncio
import random
import struct
import os
from typing import List, Tuple, Dict, Any


def _randbytes(n: int) -> bytes:
    """
    Compatibility helper for Python versions where random.randbytes may be unavailable.
    Falls back to os.urandom().
    """
    rb = getattr(random, "randbytes", None)
    if callable(rb):
        return rb(n)
    return os.urandom(n)


# Morse code mapping for morse timing encoding
MORSE_CODE_MAP = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    " ": "/",
}


async def encode_binary_timing(
    payload: bytes, base_delay: int, bit_delay: int
) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    Encode payload using binary timing (short delay = 0, long delay = 1).

    Args:
        payload: Data to encode
        base_delay: Base delay in milliseconds (represents bit 0)
        bit_delay: Additional delay for bit 1

    Returns:
        List of (packet, seq_offset, options) tuples
    """
    segments = []
    dummy_packet = b"\x00\x01\x02\x03"
    segments.append((dummy_packet, 0, {"delay_ms": 0}))

    for byte in payload:
        for bit_pos in range(8):
            bit = (byte >> (7 - bit_pos)) & 1
            dummy_packet = _randbytes(4)

            if bit == 0:
                delay = base_delay
            else:
                delay = base_delay + bit_delay

            segments.append((dummy_packet, 0, {"delay_ms": delay}))

    end_packet = b"\xff\xfe\xfd\xfc"
    segments.append((end_packet, 0, {"delay_ms": base_delay * 2}))

    return segments


async def encode_morse_timing(
    payload: bytes, base_delay: int, bit_delay: int
) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    Encode payload using Morse code timing patterns.

    Args:
        payload: Data to encode
        base_delay: Base delay for dot (.)
        bit_delay: Additional delay for dash (-)

    Returns:
        List of (packet, seq_offset, options) tuples
    """
    segments = []

    # Try to decode as text, fallback to hex
    try:
        text = payload.decode("utf-8", errors="ignore").upper()
    except (UnicodeDecodeError, AttributeError):
        text = payload.hex().upper()

    dummy_packet = b"\x00\x01\x02\x03"
    segments.append((dummy_packet, 0, {"delay_ms": 0}))

    for char in text:
        if char in MORSE_CODE_MAP:
            morse_code = MORSE_CODE_MAP[char]
            for symbol in morse_code:
                dummy_packet = _randbytes(4)

                if symbol == ".":
                    delay = base_delay
                elif symbol == "-":
                    delay = base_delay + bit_delay
                else:  # "/" for space
                    delay = base_delay + bit_delay * 2

                segments.append((dummy_packet, 0, {"delay_ms": delay}))

            # Inter-character delay
            segments.append((_randbytes(4), 0, {"delay_ms": base_delay // 2}))

    return segments


async def encode_interval_timing(
    payload: bytes, base_delay: int, bit_delay: int
) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    Encode payload using interval timing (delay represents byte value).

    Args:
        payload: Data to encode
        base_delay: Base delay in milliseconds
        bit_delay: Delay multiplier for byte value

    Returns:
        List of (packet, seq_offset, options) tuples
    """
    segments = []
    dummy_packet = b"\x00\x01\x02\x03"
    segments.append((dummy_packet, 0, {"delay_ms": 0}))

    for byte in payload:
        dummy_packet = _randbytes(4)
        delay = base_delay + (byte * bit_delay // 10)
        segments.append((dummy_packet, 0, {"delay_ms": delay}))

    end_packet = b"\xff\xfe\xfd\xfc"
    segments.append((end_packet, 0, {"delay_ms": base_delay}))

    return segments


async def encode_advanced_binary_timing(
    payload: bytes, base_delay: int, bit_delay: int, precision: str = "high"
) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    Encode using advanced binary timing with jitter compensation.

    Args:
        payload: Data to encode
        base_delay: Base delay in milliseconds
        bit_delay: Additional delay for bit 1
        precision: Jitter control ('high', 'medium', 'low')

    Returns:
        List of (packet, seq_offset, options) tuples
    """
    segments = []

    # Set jitter range based on precision
    if precision == "high":
        jitter_range = 2
    elif precision == "medium":
        jitter_range = 5
    else:
        jitter_range = 10

    # Synchronization packet
    sync_packet = b"SYNC_START_" + bytes([170, 85, 170, 85])
    segments.append((sync_packet, 0, {"delay_ms": 0}))

    for byte_idx, byte in enumerate(payload):
        for bit_pos in range(8):
            bit = (byte >> (7 - bit_pos)) & 1

            # Create carrier packet with metadata
            carrier_data = struct.pack(">HH", byte_idx, bit_pos) + bytes(
                [random.randint(0, 255) for _ in range(4)]
            )

            # Calculate delay with jitter
            if bit == 0:
                delay = base_delay + random.randint(-jitter_range, jitter_range)
            else:
                delay = base_delay + bit_delay + random.randint(-jitter_range, jitter_range)

            delay = max(delay, 10)  # Minimum delay
            segments.append((b"TIMING_BIT:" + carrier_data, 0, {"delay_ms": delay}))

    # End synchronization packet
    end_packet = b"SYNC_END___" + bytes([85, 170, 85, 170])
    segments.append((end_packet, 0, {"delay_ms": base_delay}))

    return segments


async def encode_differential_timing(
    payload: bytes, base_delay: int, bit_delay: int
) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    Encode using differential timing (delay differences encode data).

    Args:
        payload: Data to encode
        base_delay: Initial delay in milliseconds
        bit_delay: Delay change for each bit

    Returns:
        List of (packet, seq_offset, options) tuples
    """
    segments = []
    previous_delay = base_delay

    start_packet = b"DIFF_START_" + bytes([255, 0, 255, 0])
    segments.append((start_packet, 0, {"delay_ms": 0}))

    for byte in payload:
        for bit_pos in range(8):
            bit = (byte >> (7 - bit_pos)) & 1

            # Adjust delay based on bit value
            if bit == 0:
                current_delay = previous_delay - bit_delay
            else:
                current_delay = previous_delay + bit_delay

            # Clamp delay to reasonable range
            current_delay = max(20, min(current_delay, 500))

            carrier_packet = b"DIFF_BIT:" + bytes([random.randint(0, 255) for _ in range(8)])
            segments.append((carrier_packet, 0, {"delay_ms": current_delay}))

            previous_delay = current_delay

    return segments


async def encode_frequency_timing(
    payload: bytes, base_delay: int, bit_delay: int
) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    Encode using frequency-based timing patterns.

    Args:
        payload: Data to encode
        base_delay: Base delay in milliseconds
        bit_delay: Not used (kept for API consistency)

    Returns:
        List of (packet, seq_offset, options) tuples
    """
    segments = []

    # Calibration packet
    cal_packet = b"FREQ_CAL:" + bytes([170] * 8)
    segments.append((cal_packet, 0, {"delay_ms": 0}))

    for byte in payload:
        # Frequency is derived from byte value (1-8 packets per time unit)
        frequency = 1 + (byte % 8)
        time_unit = base_delay * 4
        packet_interval = time_unit // frequency

        for i in range(frequency):
            freq_packet = (
                b"FREQ_DATA:" + bytes([byte, i]) + bytes([random.randint(0, 255) for _ in range(6)])
            )

            delay = packet_interval if i > 0 else base_delay
            segments.append((freq_packet, 0, {"delay_ms": delay}))

    return segments


async def encode_burst_timing(
    payload: bytes, base_delay: int, bit_delay: int
) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    Encode using burst timing patterns.

    Args:
        payload: Data to encode
        base_delay: Base delay between bursts
        bit_delay: Delay multiplier for burst spacing

    Returns:
        List of (packet, seq_offset, options) tuples
    """
    segments = []

    start_packet = b"BURST_START" + bytes([187] * 4)
    segments.append((start_packet, 0, {"delay_ms": 0}))

    for byte in payload:
        # Burst size derived from byte value (1-7 packets)
        burst_size = 1 + (byte % 7)
        # Inter-burst delay encodes high bits
        inter_burst_delay = base_delay + ((byte >> 3) * bit_delay)

        for i in range(burst_size):
            burst_packet = (
                b"BURST_PKT:" + bytes([byte, i]) + bytes([random.randint(0, 255) for _ in range(6)])
            )

            if i == 0:
                delay = inter_burst_delay
            else:
                delay = 5  # Fast intra-burst packets

            segments.append((burst_packet, 0, {"delay_ms": delay}))

    return segments


async def encode_payload_in_timing(
    payload: bytes, method: str, base_delay: int, bit_delay: int
) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    Encode payload data in timing patterns using specified method.

    Args:
        payload: Data to encode
        method: Encoding method ('binary', 'morse', 'interval')
        base_delay: Base delay in milliseconds
        bit_delay: Additional delay parameter

    Returns:
        List of (packet_bytes, seq_offset, options) tuples
    """
    if method == "binary":
        return await encode_binary_timing(payload, base_delay, bit_delay)
    elif method == "morse":
        return await encode_morse_timing(payload, base_delay, bit_delay)
    elif method == "interval":
        return await encode_interval_timing(payload, base_delay, bit_delay)
    else:
        return await encode_binary_timing(payload, base_delay, bit_delay)


async def encode_payload_with_advanced_timing(
    payload: bytes, method: str, base_delay: int, bit_delay: int, precision: str = "high"
) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    Encode payload using advanced timing patterns.

    Args:
        payload: Data to encode
        method: Encoding method ('binary', 'differential', 'frequency', 'burst')
        base_delay: Base delay in milliseconds
        bit_delay: Additional delay parameter
        precision: Jitter control for binary method ('high', 'medium', 'low')

    Returns:
        List of (packet_bytes, seq_offset, options) tuples
    """
    if method == "binary":
        return await encode_advanced_binary_timing(payload, base_delay, bit_delay, precision)
    elif method == "differential":
        return await encode_differential_timing(payload, base_delay, bit_delay)
    elif method == "frequency":
        return await encode_frequency_timing(payload, base_delay, bit_delay)
    elif method == "burst":
        return await encode_burst_timing(payload, base_delay, bit_delay)
    else:
        return await encode_advanced_binary_timing(payload, base_delay, bit_delay, precision)
