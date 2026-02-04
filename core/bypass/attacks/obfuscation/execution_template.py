"""
Execution template for protocol mimicry attacks.

Provides a unified template method pattern for all protocol mimicry attack execution,
reducing code duplication and improving maintainability.
"""

import time
from typing import List, Dict, Any, Callable, Awaitable
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from .error_handling import handle_attack_execution_error


async def execute_protocol_mimicry(
    context: AttackContext,
    technique_name: str,
    packet_generator: Callable[[AttackContext, Dict[str, Any]], Awaitable[List[bytes]]],
    segment_builder: Callable[[List[bytes], int, Dict[str, Any]], Awaitable[tuple[list, int, int]]],
    metadata_extractor: Callable[[AttackContext, Dict[str, Any]], Dict[str, Any]],
) -> AttackResult:
    """
    Template method for executing protocol mimicry attacks.

    This function encapsulates the common execution pattern:
    1. Extract parameters
    2. Generate protocol packets
    3. Build segments with timing
    4. Return success result with metadata

    Args:
        context: Attack execution context
        technique_name: Name of the technique (e.g., "http_protocol_mimicry")
        packet_generator: Async function that generates protocol packets
        segment_builder: Async function that builds segments from packets
        metadata_extractor: Function that extracts metadata for result

    Returns:
        AttackResult with execution status and metadata
    """
    start_time = time.time()
    try:
        # Extract parameters (protocol-specific)
        params = {}

        # Generate protocol packets
        packets = await packet_generator(context, params)

        # Build segments with timing and metadata
        segments, packets_sent, bytes_sent = await segment_builder(packets, 0, params)

        # Calculate latency
        latency = (time.time() - start_time) * 1000

        # Extract metadata
        metadata = metadata_extractor(context, params)
        metadata.update(
            {
                "original_size": len(context.payload),
                "total_size": bytes_sent,
                "segments": segments,
            }
        )

        return AttackResult(
            status=AttackStatus.SUCCESS,
            latency_ms=latency,
            packets_sent=packets_sent,
            bytes_sent=bytes_sent,
            connection_established=True,
            data_transmitted=True,
            technique_used=technique_name,
            metadata=metadata,
        )
    except Exception as e:
        return handle_attack_execution_error(e, start_time, technique_name)


async def build_segments_with_timing(
    packets: List[bytes],
    protocol_type: str,
    delay_calculator: Callable,
    packet_type_getter: Callable,
    metadata_base: Dict[str, Any],
) -> tuple[list, int, int]:
    """
    Build segments with timing information for a list of packets.

    Args:
        packets: List of packet bytes
        protocol_type: Protocol type (http, tls, smtp, ftp)
        delay_calculator: Async function to calculate delays
        packet_type_getter: Function to get packet type description
        metadata_base: Base metadata to include in all segments

    Returns:
        Tuple of (segments, packets_sent, bytes_sent)
    """
    segments = []
    seq_offset = 0

    for i, packet in enumerate(packets):
        delay = await delay_calculator(protocol_type, i)
        packet_type = packet_type_getter(i, len(packets))

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
