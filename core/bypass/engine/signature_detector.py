"""
SNI and DPI signature detection.

Utilities for finding SNI positions and signature-containing fragments.
"""

import logging
from functools import lru_cache
from typing import Any, Dict, List

from .packet_segment import PacketSegment

logger = logging.getLogger(__name__)


@lru_cache(maxsize=256)
def find_sni_position_cached(payload: bytes, fallback_pos: int) -> int:
    """Cached SNI position finder using LRU cache."""
    try:
        from core.bypass.sni.manipulator import SNIManipulator

        sni_pos = SNIManipulator.find_sni_position(payload)
        if sni_pos:
            return sni_pos.sni_value_start
    except ImportError:
        logger.debug("SNIManipulator not available")
    except Exception as e:
        logger.debug(f"Error finding SNI: {e}")
    return fallback_pos


def find_sni_position(payload: bytes, fallback_pos: int, enable_cache: bool = True) -> int:
    """Find SNI position with optional caching."""
    if enable_cache:
        return find_sni_position_cached(payload, fallback_pos)

    # Non-cached path
    try:
        from core.bypass.sni.manipulator import SNIManipulator

        sni_pos = SNIManipulator.find_sni_position(payload)
        if sni_pos:
            return sni_pos.sni_value_start
    except ImportError:
        logger.debug("SNIManipulator not available")
    except Exception as e:
        logger.debug(f"Error finding SNI: {e}")

    return fallback_pos


def find_signature_fragments(
    fragments: List[PacketSegment], packet_info: Dict[str, Any]
) -> List[int]:
    """Find fragments containing DPI signatures."""
    try:
        full_payload = b"".join(frag.data for frag in fragments)

        # TLS SNI
        if full_payload.startswith(b"\x16\x03"):
            from core.bypass.sni.manipulator import SNIManipulator

            sni_pos = SNIManipulator.find_sni_position(full_payload)
            if sni_pos:
                return fragments_in_range(
                    fragments,
                    sni_pos.sni_value_start,
                    sni_pos.sni_value_start + len(sni_pos.sni_value),
                )

        # HTTP Host header
        host_pos = full_payload.lower().find(b"host:")
        if host_pos != -1:
            host_end = full_payload.find(b"\r\n", host_pos)
            if host_end == -1:
                host_end = len(full_payload)
            return fragments_in_range(fragments, host_pos, host_end)

    except Exception as e:
        logger.debug(f"Signature search failed: {e}")

    return []


def fragments_in_range(fragments: List[PacketSegment], start: int, end: int) -> List[int]:
    """Find fragment indices overlapping with byte range."""
    result = []
    offset = 0

    for i, frag in enumerate(fragments):
        frag_end = offset + len(frag.data)
        if not (frag_end <= start or offset >= end):
            result.append(i)
        offset = frag_end

    return result
