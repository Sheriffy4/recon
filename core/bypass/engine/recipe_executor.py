"""
Recipe execution orchestrators.

Handles different execution modes for attack recipes.
"""

import logging
from typing import Any, Dict, List

from .attack_constants import AttackConstants
from .packet_segment import PacketSegment
from .attack_helpers import get_fake_params, generate_fake_payload

logger = logging.getLogger(__name__)


def execute_fake_split_combo(
    recipe,
    payload: bytes,
    packet_info: Dict[str, Any],
    apply_split_func,
    apply_fake_to_fragments_func,
) -> List[PacketSegment]:
    """
    Execute fake+split combination with proper ordering.

    Integrated mode: split first, then fake per fragment based on fake_mode.
    """
    # Get split step
    split_step = next(
        (s for s in getattr(recipe, "steps", []) if s.attack_type in ("split", "multisplit")),
        None,
    )
    if split_step is None:
        logger.warning("execute_fake_split_combo called without split step; falling back to pass-through")
        return [PacketSegment(data=payload, offset=0)]

    # Apply split first
    fragments = apply_split_func(payload, split_step.params, packet_info)

    # Get fake step and mode
    fake_step = next(
        (s for s in getattr(recipe, "steps", []) if (s.attack_type == "fake" or s.attack_type.startswith("fake"))),
        None,
    )
    if fake_step is None:
        logger.warning("execute_fake_split_combo called without fake step; returning split fragments")
        return fragments
    fake_mode = fake_step.params.get("fake_mode", AttackConstants.DEFAULT_FAKE_MODE)

    # Validate fake mode
    if fake_mode not in AttackConstants.VALID_FAKE_MODES:
        logger.warning(f"Invalid fake_mode '{fake_mode}', using default")
        fake_mode = AttackConstants.DEFAULT_FAKE_MODE

    # Apply fake to fragments
    if fake_mode in (
        AttackConstants.FAKE_MODE_PER_FRAGMENT,
        AttackConstants.FAKE_MODE_PER_SIGNATURE,
        AttackConstants.FAKE_MODE_SMART,
        AttackConstants.FAKE_MODE_SINGLE,
    ):
        # Integrated fake per fragment (now includes SINGLE)
        segments = apply_fake_to_fragments_func(fragments, fake_step.params, packet_info)
    else:
        # Fallback for unknown modes
        ttl, fooling = get_fake_params(fake_step.params)
        fake_payload = generate_fake_payload(payload, fooling)
        fake_segment = PacketSegment(
            data=fake_payload, offset=0, ttl=ttl, is_fake=True, fooling=fooling
        )
        segments = [fake_segment] + fragments

    return segments


def execute_sequential(
    recipe, payload: bytes, packet_info: Dict[str, Any], get_handler_func
) -> List[PacketSegment]:
    """Execute attacks sequentially (for non-combo recipes)."""
    segments: List[PacketSegment] = []
    current_payload = payload

    for step in recipe.steps:
        # Skip disorder (handled at the end)
        if "disorder" in step.attack_type:
            continue

        # Apply attack
        handler = get_handler_func(step.attack_type)
        if handler:
            step_segments = handler(current_payload, step.params, packet_info)
            segments.extend(step_segments)

            # For split attacks, update current payload
            if step.attack_type in ("split", "multisplit") and step_segments:
                # Prefer reconstructing "real" payload from real segments.
                # This avoids accidental usage of a fake segment if a handler ever changes ordering.
                current_payload = b"".join(seg.data for seg in step_segments if not seg.is_fake)

    return segments
