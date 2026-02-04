"""
Timing Utilities

Unified delay calculation for protocol mimicry attacks to simulate
realistic network timing patterns.
"""

import asyncio
import random


def _compute_delay_ms(protocol: str, packet_index: int, total_packets: int = 0, **kwargs) -> int:
    delay = 0
    protocol = (protocol or "").lower()
    total_packets = max(0, int(total_packets or 0))
    if protocol == "http":
        mimicry_type = kwargs.get("mimicry_type", "web_browsing")
        if mimicry_type == "web_browsing":
            delay = random.randint(50, 200) if packet_index == 0 else random.randint(100, 500)
        elif mimicry_type == "api_call":
            delay = random.randint(10, 50) if packet_index == 0 else random.randint(20, 100)
        else:
            delay = random.randint(25, 150)

    elif protocol == "tls":
        include_handshake = kwargs.get("include_handshake", True)
        if include_handshake:
            if packet_index == 0:
                delay = 0
            elif packet_index == 1:
                delay = random.randint(20, 80)
            elif packet_index == 2:
                delay = random.randint(5, 20)
            elif packet_index == 3:
                delay = random.randint(10, 30)
            else:
                delay = random.randint(50, 200)
        else:
            delay = random.randint(10, 50)

    elif protocol == "smtp":
        if packet_index == 0:
            delay = 0
        elif packet_index < 5:
            delay = random.randint(10, 50)
        else:
            delay = random.randint(20, 100)

    elif protocol == "ftp":
        if packet_index == 0:
            delay = 0
        elif packet_index < 6:
            delay = random.randint(20, 100)
        elif packet_index < total_packets - 3:
            delay = random.randint(50, 200)
        else:
            delay = random.randint(10, 50)

    return delay


async def calculate_protocol_delay(
    protocol: str, packet_index: int, total_packets: int = 0, **kwargs
) -> int:
    """
    Calculate realistic delay for various protocols.

    Args:
        protocol: Protocol name (http, tls, smtp, ftp)
        packet_index: Current packet index
        total_packets: Total number of packets (for protocols that need it)
        **kwargs: Protocol-specific parameters

    Returns:
        Delay in milliseconds
    """
    # Backward-compatible behavior: by default we actually sleep.
    do_sleep = kwargs.get("do_sleep", True)
    delay = _compute_delay_ms(protocol, packet_index, total_packets, **kwargs)

    if do_sleep and delay > 0:
        await asyncio.sleep(delay / 1000.0)
    return delay
