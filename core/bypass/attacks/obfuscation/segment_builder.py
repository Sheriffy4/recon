"""
Segment building utilities for protocol mimicry attacks.

Provides unified segment construction logic for all protocol types.
"""

from typing import List, Tuple, Dict, Any, Callable, Optional


async def build_protocol_segments(
    packets: List[bytes],
    protocol_type: str,
    delay_calculator: Callable,
    packet_type_getter: Callable,
    metadata_base: Optional[Dict[str, Any]] = None,
    **kwargs,
) -> Tuple[List[Tuple[bytes, int, Dict[str, Any]]], int, int]:
    """
    Build protocol segments with timing and metadata.

    Args:
        packets: List of packet bytes to process
        protocol_type: Protocol type (http, tls, smtp, ftp)
        delay_calculator: Async function to calculate delays
        packet_type_getter: Function to get packet type description
        metadata_base: Base metadata to include in all segments
        **kwargs: Additional arguments for delay calculation

    Returns:
        Tuple of (segments, packets_sent, bytes_sent)
        - segments: List of (packet, seq_offset, metadata) tuples
        - packets_sent: Number of packets
        - bytes_sent: Total bytes
    """
    segments = []
    seq_offset = 0
    metadata_base = metadata_base or {}

    for i, packet in enumerate(packets):
        delay = await delay_calculator(protocol_type, i, **kwargs)
        packet_type = packet_type_getter(i, len(packets), **kwargs)

        segment_metadata = {
            **metadata_base,
            "packet_type": packet_type,
            "delay_ms": delay,
        }

        segments.append((packet, seq_offset, segment_metadata))
        seq_offset = (seq_offset + len(packet)) & 0xFFFFFFFF

    packets_sent = len(packets)
    bytes_sent = sum(len(packet) for packet in packets)

    return segments, packets_sent, bytes_sent
