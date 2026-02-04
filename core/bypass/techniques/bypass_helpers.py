# path: core/bypass/techniques/bypass_helpers.py
# REFACTORING STEP 7: Extract common logging/validation patterns from BypassTechniques
# This module contains helper functions for common patterns in bypass techniques

import logging
from typing import List, Tuple, Dict


def _safe_param_value(v):
    # avoid flooding logs with huge blobs
    if isinstance(v, (bytes, bytearray)):
        return f"<{type(v).__name__} {len(v)}b>"
    if isinstance(v, list) and len(v) > 20:
        return f"<list len={len(v)}>"
    return v


def log_attack_execution(
    attack_name: str, payload_len: int, segments: List[Tuple[bytes, int, Dict]], **params
) -> None:
    """
    Standardized logging for attack execution.

    Extracts common logging pattern used across multiple attack methods.

    Args:
        attack_name: Name of the attack being executed
        payload_len: Length of original payload
        segments: Generated segments list
        **params: Additional parameters to log
    """
    log = logging.getLogger("BypassTechniques")

    # Build parameter string
    param_str = ", ".join(f"{k}={_safe_param_value(v)}" for k, v in params.items())

    # Keep INFO concise; details should be in DEBUG.
    log.info(
        "✅ %s: payload=%sb, segments=%s, %s", attack_name, payload_len, len(segments), param_str
    )


def validate_payload_size(payload: bytes, min_size: int = 2) -> bool:
    """
    Validate payload meets minimum size requirements.

    Extracts common validation pattern used across multiple attack methods.

    Args:
        payload: Payload to validate
        min_size: Minimum required size in bytes

    Returns:
        True if payload is valid, False otherwise
    """
    log = logging.getLogger("BypassTechniques")

    if len(payload) < min_size:
        log.warning(
            f"Payload too small ({len(payload)}b < {min_size}b), " "falling back to single segment"
        )
        return False

    return True


def create_fallback_segment(payload: bytes) -> List[Tuple[bytes, int, Dict]]:
    """
    Create fallback single segment for small/invalid payloads.

    Extracts common fallback pattern used across multiple attack methods.

    Args:
        payload: Original payload

    Returns:
        Single-segment recipe
    """
    return [(payload, 0, {"is_fake": False, "tcp_flags": 0x18})]


def validate_and_adjust_split_position(
    split_pos: int, payload_len: int, validate: bool = True
) -> int:
    """
    Validate and adjust split position to be within valid bounds.

    Extracts common validation logic from multiple methods.

    Args:
        split_pos: Requested split position
        payload_len: Length of payload
        validate: Whether to adjust invalid positions

    Returns:
        Valid split position

    Raises:
        ValueError: If position is invalid and validate=False
    """
    log = logging.getLogger("BypassTechniques")

    if validate:
        if split_pos <= 0:
            log.debug(f"Adjusting split_pos from {split_pos} to 1")
            return 1
        elif split_pos >= payload_len:
            adjusted = payload_len - 1
            log.debug(f"Adjusting split_pos from {split_pos} to {adjusted}")
            return adjusted
        return split_pos
    else:
        if split_pos <= 0 or split_pos >= payload_len:
            raise ValueError(f"Invalid split_pos {split_pos} for payload length {payload_len}")
        return split_pos


def build_segment_metadata(
    segment_index: int, total_segments: int, attack_type: str, **extra_metadata
) -> Dict:
    """
    Build standardized segment metadata.

    Extracts common metadata building pattern.

    Args:
        segment_index: Index of this segment (0-based)
        total_segments: Total number of segments
        attack_type: Type of attack (e.g., "multisplit", "multidisorder")
        **extra_metadata: Additional metadata fields

    Returns:
        Metadata dictionary
    """
    metadata = {
        "segment_index": segment_index,
        "total_segments": total_segments,
        "attack_type": attack_type,
    }
    metadata.update(extra_metadata)
    return metadata


def calculate_fragment_delays(
    fragment_count: int, base_delay_ms: int = 1, max_delay_ms: int = 5
) -> List[int]:
    """
    Calculate optimized delays for fragment transmission.

    Extracts common delay calculation pattern.

    Args:
        fragment_count: Number of fragments
        base_delay_ms: Base delay in milliseconds
        max_delay_ms: Maximum delay in milliseconds

    Returns:
        List of delays for each fragment
    """
    import random

    delays = []
    for i in range(fragment_count - 1):  # Last fragment has no delay
        delay = random.randint(base_delay_ms, max_delay_ms)
        delays.append(delay)
    delays.append(0)  # No delay after last fragment

    return delays


def optimize_fragment_positions(
    positions: List[int], payload_len: int, min_fragment_size: int = 3, max_fragments: int = 8
) -> List[int]:
    """
    Optimize fragment positions for reasonable fragment sizes.

    Extracts common position optimization logic from multisplit/multidisorder.

    Args:
        positions: Requested split positions
        payload_len: Length of payload
        min_fragment_size: Minimum bytes per fragment
        max_fragments: Maximum number of fragments

    Returns:
        Optimized list of positions
    """
    log = logging.getLogger("BypassTechniques")

    # Filter positions to ensure reasonable fragment sizes
    optimized = []
    for pos in sorted(positions):
        if not optimized or pos - optimized[-1] >= min_fragment_size:
            optimized.append(pos)

    # Ensure we have at least one position
    if not optimized:
        optimized = [payload_len // 2]
        log.debug("No valid positions after optimization, using middle split")

    # Limit number of fragments for performance
    if len(optimized) > max_fragments:
        step = len(optimized) // max_fragments
        optimized = optimized[::step][:max_fragments]
        log.debug(f"Limited to {max_fragments} fragments for performance")

    return optimized


def create_fragment_list(payload: bytes, split_positions: List[int]) -> List[Tuple[bytes, int]]:
    """
    Create list of fragments from payload and split positions.

    Extracts common fragment creation logic.

    Args:
        payload: Original payload
        split_positions: List of split positions (sorted)

    Returns:
        List of (fragment_data, offset) tuples
    """
    log = logging.getLogger("BypassTechniques")

    all_splits = sorted(list(set([0] + split_positions + [len(payload)])))
    fragments = []

    for i in range(len(all_splits) - 1):
        start, end = all_splits[i], all_splits[i + 1]
        if start < end and end - start >= 1:
            fragment_data = payload[start:end]
            fragments.append((fragment_data, start))
            log.debug(f"Fragment {len(fragments)}: bytes[{start}:{end}] = {len(fragment_data)}b")

    return fragments
