"""
Fake packet positioning strategies.

Implements various strategies for inserting fake packets relative to real fragments.
"""

import logging
from typing import Any, Dict, List

from .attack_constants import AttackConstants
from .packet_segment import PacketSegment
from .attack_helpers import get_fake_params, generate_fake_payload

logger = logging.getLogger(__name__)


def apply_fake_to_fragments(
    fragments: List[PacketSegment],
    params: Dict[str, Any],
    packet_info: Dict[str, Any],
    fake_position: str,
    get_real_ttl_func,
    find_signature_fragments_func,
) -> List[PacketSegment]:
    """Apply fake packets to fragments based on fake_mode."""
    fake_mode = params.get("fake_mode", AttackConstants.DEFAULT_FAKE_MODE)
    if fake_mode not in AttackConstants.VALID_FAKE_MODES:
        logger.warning("Invalid fake_mode '%s', using default '%s'", fake_mode, AttackConstants.DEFAULT_FAKE_MODE)
        fake_mode = AttackConstants.DEFAULT_FAKE_MODE

    if fake_position not in ("before", "after", "interleaved"):
        logger.warning("Invalid fake_position '%s', using 'before'", fake_position)
        fake_position = "before"

    ttl, fooling = get_fake_params(params)

    # Get real TTL (original or default)
    real_ttl = get_real_ttl_func(packet_info)

    # Choose strategy
    if fake_mode == AttackConstants.FAKE_MODE_PER_FRAGMENT:
        return fake_per_fragment(fragments, ttl, fooling, real_ttl, fake_position)

    elif fake_mode == AttackConstants.FAKE_MODE_PER_SIGNATURE:
        signature_indices = find_signature_fragments_func(fragments, packet_info)
        return fake_for_indices(fragments, ttl, fooling, real_ttl, signature_indices, fake_position)

    elif fake_mode == AttackConstants.FAKE_MODE_SMART:
        signature_indices = find_signature_fragments_func(fragments, packet_info)
        if not signature_indices:
            # Fallback: fake first 3 fragments
            signature_indices = list(range(min(3, len(fragments))))
        return fake_for_indices(fragments, ttl, fooling, real_ttl, signature_indices, fake_position)

    else:  # FAKE_MODE_SINGLE
        return fake_for_indices(fragments, ttl, fooling, real_ttl, [0], fake_position)


def fake_per_fragment(
    fragments: List[PacketSegment],
    fake_ttl: int,
    fooling: str,
    real_ttl: int,
    position: str,
) -> List[PacketSegment]:
    """Create fake packet for each fragment."""
    result = []

    for i, frag in enumerate(fragments):
        fake_data = generate_fake_payload(frag.data, fooling)
        fake_seg = PacketSegment(
            data=fake_data,
            offset=frag.offset,
            ttl=fake_ttl,
            is_fake=True,
            fooling=fooling,
            fragment_index=i,
        )

        real_seg = PacketSegment(data=frag.data, offset=frag.offset, ttl=real_ttl, fragment_index=i)

        # Apply fake_position
        if position == "before":
            result.extend([fake_seg, real_seg])
        elif position == "after":
            result.extend([real_seg, fake_seg])
        else:  # interleaved
            if i % 2 == 0:
                result.extend([fake_seg, real_seg])
            else:
                result.extend([real_seg, fake_seg])

    logger.info(
        f"✅ per_fragment: {len(fragments)} fake + {len(fragments)} real " f"(position={position})"
    )

    return result


def fake_for_indices(
    fragments: List[PacketSegment],
    fake_ttl: int,
    fooling: str,
    real_ttl: int,
    indices: List[int],
    position: str,
) -> List[PacketSegment]:
    """
    Create fake packets only for specified indices.
    FIXED: properly handles all position modes.
    """
    result = []
    indices_set = set(indices)

    for i, frag in enumerate(fragments):
        fake_seg = None
        if i in indices_set:
            fake_data = generate_fake_payload(frag.data, fooling)
            fake_seg = PacketSegment(
                data=fake_data,
                offset=frag.offset,
                ttl=fake_ttl,
                is_fake=True,
                fooling=fooling,
                fragment_index=i,
            )

            # Position logic (FIX: Improved interleaved - Expert 2 fix #4)
            if position == "before":
                result.append(fake_seg)
            elif position == "interleaved":
                # True interleaved based on fragment index
                if i % 2 == 0:
                    result.append(fake_seg)

        # Always add real segment
        result.append(
            PacketSegment(data=frag.data, offset=frag.offset, ttl=real_ttl, fragment_index=i)
        )

        # Add fake after real if needed
        if fake_seg:
            if position == "after":
                result.append(fake_seg)
            elif position == "interleaved" and i % 2 == 1:
                result.append(fake_seg)

    logger.info(
        f"✅ fake for indices {indices}: {len(indices)} fake + {len(fragments)} real "
        f"(position={position})"
    )

    return result
