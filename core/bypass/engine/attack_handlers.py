"""
Attack handler implementations.

Core attack logic for fake, split, multisplit, and disorder operations.
"""

import logging
import random
from typing import Any, Dict, List

from .attack_constants import AttackConstants
from .packet_segment import PacketSegment
from .attack_helpers import get_fake_params, generate_fake_payload

logger = logging.getLogger(__name__)


def apply_fake(
    payload: bytes, params: Dict[str, Any], packet_info: Dict[str, Any]
) -> List[PacketSegment]:
    """Generate fake packet segment."""
    ttl, fooling = get_fake_params(params)
    fake_payload = generate_fake_payload(payload, fooling)

    segment = PacketSegment(data=fake_payload, offset=0, ttl=ttl, is_fake=True, fooling=fooling)

    logger.info(
        "🎭 Generated fake packet: size=%dB, ttl=%d, fooling=%s",
        len(fake_payload),
        ttl,
        fooling,
    )

    return [segment]


def apply_split(
    payload: bytes,
    params: Dict[str, Any],
    packet_info: Dict[str, Any],
    get_real_ttl_func,
    find_sni_position_func,
) -> List[PacketSegment]:
    """Split payload into fragments."""
    # Guard: cannot split payload shorter than 2 bytes without creating empty segments
    if len(payload) < 2:
        real_ttl = get_real_ttl_func(packet_info)
        return [PacketSegment(data=payload, offset=0, ttl=real_ttl, fragment_index=0)]

    # Backward/forward compatible parameter names
    split_count = params.get("split_count", params.get("split_cnt"))
    split_pos = params.get("split_pos", params.get("split_position"))

    # Multisplit mode
    if split_count is not None:
        try:
            split_count = int(split_count)
        except (TypeError, ValueError):
            logger.warning(f"Invalid split_count {split_count!r}, falling back to 2")
            split_count = 2

        # Avoid generating empty fragments
        max_by_payload = max(2, min(len(payload), AttackConstants.MAX_SPLIT_COUNT))
        split_count = max(AttackConstants.MIN_SPLIT_COUNT, min(split_count, max_by_payload))
        return apply_multisplit(payload, split_count, packet_info, get_real_ttl_func)

    # Single split mode
    if split_pos is None:
        split_pos = AttackConstants.DEFAULT_SPLIT_POS
    else:
        # configs/CLI may supply strings/numbers
        if not (isinstance(split_pos, str) and split_pos == "sni"):
            try:
                split_pos = int(split_pos)
            except (TypeError, ValueError):
                logger.warning(f"Invalid split_pos {split_pos!r}, using default")
                split_pos = AttackConstants.DEFAULT_SPLIT_POS

    # Handle SNI position
    if isinstance(split_pos, str) and split_pos == "sni":
        fallback = params.get("split_pos_fallback", AttackConstants.DEFAULT_SPLIT_POS)
        split_pos = find_sni_position_func(payload, fallback)

    # Ensure valid position
    split_pos = max(1, min(int(split_pos), len(payload) - 1))

    # Get real TTL
    real_ttl = get_real_ttl_func(packet_info)

    segments = [
        PacketSegment(data=payload[:split_pos], offset=0, ttl=real_ttl, fragment_index=0),
        PacketSegment(data=payload[split_pos:], offset=split_pos, ttl=real_ttl, fragment_index=1),
    ]

    logger.info(
        f"✂️ Split at position {split_pos}: "
        f"{len(segments[0].data)} + {len(segments[1].data)} bytes"
    )

    return segments


def apply_multisplit(
    payload: bytes, split_count: int, packet_info: Dict[str, Any], get_real_ttl_func
) -> List[PacketSegment]:
    """Split payload into multiple fragments."""
    if len(payload) < 2:
        real_ttl = get_real_ttl_func(packet_info)
        return [PacketSegment(data=payload, offset=0, ttl=real_ttl, fragment_index=0)]

    # Ensure split_count cannot exceed payload length to avoid empty segments
    split_count = max(AttackConstants.MIN_SPLIT_COUNT, min(int(split_count), len(payload)))

    fragment_size = len(payload) // split_count
    remainder = len(payload) % split_count
    offset = 0

    # Get real TTL
    real_ttl = get_real_ttl_func(packet_info)

    segments = []
    for i in range(split_count):
        current_size = fragment_size + (1 if i < remainder else 0)
        fragment = payload[offset : offset + current_size]

        segments.append(PacketSegment(data=fragment, offset=offset, ttl=real_ttl, fragment_index=i))
        offset += current_size

    logger.info(
        f"✂️ Multisplit into {split_count} fragments: "
        f"base={fragment_size}B, remainder={remainder}"
    )

    return segments


def apply_disorder(
    payload: bytes, params: Dict[str, Any], packet_info: Dict[str, Any], get_real_ttl_func
) -> List[PacketSegment]:
    """Apply disorder to single payload (creates single segment)."""
    # For single payload, disorder doesn't change anything
    real_ttl = get_real_ttl_func(packet_info)
    segment = PacketSegment(data=payload, offset=0, ttl=real_ttl)
    return [segment]


def apply_disorder_segments(
    segments: List[PacketSegment], params: Dict[str, Any]
) -> List[PacketSegment]:
    """Reorder existing segments."""
    if len(segments) <= 1:
        return segments

    method = params.get("disorder_method", AttackConstants.DEFAULT_DISORDER_METHOD)
    if method not in AttackConstants.VALID_DISORDER:
        logger.warning(f"Invalid disorder method '{method}', using default")
        method = AttackConstants.DEFAULT_DISORDER_METHOD

    logger.info(f"🔀 Applying disorder: {method}")

    if method == AttackConstants.DISORDER_REVERSE:
        return segments[::-1]

    elif method == AttackConstants.DISORDER_RANDOM:
        shuffled = list(segments)
        random.shuffle(shuffled)
        return shuffled

    elif method == AttackConstants.DISORDER_SWAP:
        if len(segments) >= 2:
            swapped = list(segments)
            swapped[0], swapped[-1] = swapped[-1], swapped[0]
            return swapped

    return segments
