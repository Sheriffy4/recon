# path: core/bypass/techniques/primitives_utils.py
"""
Shared utility functions for bypass techniques.

This module contains low-level helper functions extracted from primitives.py
to reduce code duplication and improve maintainability.

Functions:
    - gen_fake_sni: Generate fake SNI for DPI fooling
    - split_payload: Split payload at specified position with validation
    - create_segment_options: Build segment options dictionary with fooling methods
    - normalize_positions: Convert various position formats to validated list
    - handle_small_payload: Handle edge case of payloads too small to split
"""

import random
import string
import logging
from typing import List, Tuple, Dict, Optional, Any


def gen_fake_sni(original: Optional[str] = None, custom_sni: Optional[str] = None) -> str:
    """
    Generate fake SNI in zapret style.

    Args:
        original: Original SNI (currently unused, kept for API compatibility)
        custom_sni: Custom SNI value to use instead of generating random

    Returns:
        SNI value to use (custom if provided, otherwise random)

    Examples:
        >>> gen_fake_sni()  # Random like "abc123def.com"
        >>> gen_fake_sni(custom_sni="example.org")  # "example.org"
    """
    if custom_sni is not None:
        return custom_sni

    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 14)))
    tld = random.choice(["edu", "com", "net", "org"])
    return f"{label}.{tld}"


def validated_split_pos(payload_len: int, split_pos: Any, validate: bool = True) -> int:
    """
    Validate/adjust split position to a safe integer in range [1, payload_len-1].

    IMPORTANT: split_payload() may adjust split_pos, but callers also need the
    adjusted value when they use split_pos as a TCP sequence offset.

    This helper is additive (does not change existing interfaces).
    """
    log = logging.getLogger("primitives_utils")
    if payload_len < 2:
        return 0

    # Handle special string values
    if isinstance(split_pos, str):
        if split_pos.lower() == "random":
            import random

            sp = random.randint(1, max(1, payload_len - 1))
            log.warning(f"split_pos='random' was not resolved earlier, resolving now to {sp}")
        else:
            try:
                sp = int(split_pos)
            except ValueError:
                if validate:
                    log.warning("split_pos %r is not int-like, using middle", split_pos)
                    sp = payload_len // 2
                else:
                    raise
    else:
        try:
            sp = int(split_pos)
        except (TypeError, ValueError):
            if validate:
                log.warning("split_pos %r is not int-like, using middle", split_pos)
                sp = payload_len // 2
            else:
                raise

    if validate:
        if sp <= 0:
            log.warning("split_pos %s <= 0, adjusting to 1", sp)
            sp = 1
        elif sp >= payload_len:
            log.warning(
                "split_pos %s >= payload size %s, adjusting to %s", sp, payload_len, payload_len - 1
            )
            sp = payload_len - 1
    else:
        if sp <= 0 or sp >= payload_len:
            raise ValueError(f"Invalid split_pos {sp} for payload of length {payload_len}")

    return sp


def split_payload(payload: bytes, split_pos: int, validate: bool = True) -> Tuple[bytes, bytes]:
    """
    Shared payload splitting logic for all disorder family attacks.

    OPTIMIZED: Reduced logging overhead for common cases.

    This helper function provides consistent payload splitting with validation
    for disorder, disorder2, multidisorder, fakeddisorder, and related attacks.

    Args:
        payload: The original payload to split
        split_pos: Position to split at (1-based, must be < len(payload))
        validate: Whether to validate and adjust split_pos if needed

    Returns:
        Tuple of (part1, part2) where:
        - part1: payload[:split_pos]
        - part2: payload[split_pos:]

    Raises:
        ValueError: If split_pos is invalid and validate=False

    Examples:
        >>> payload = b"Hello World"
        >>> part1, part2 = split_payload(payload, 5)
        >>> part1  # b"Hello"
        >>> part2  # b" World"
    """
    payload_len = len(payload)

    # OPTIMIZATION: Fast path for common case - no validation needed
    if not validate and 0 < split_pos < payload_len:
        return payload[:split_pos], payload[split_pos:]

    # Handle edge cases
    log = logging.getLogger("primitives_utils")
    if payload_len < 2:
        if validate:
            log.warning(f"Payload too small ({payload_len} bytes), returning as single part")
            return payload, b""
        else:
            raise ValueError(f"Payload too small for splitting: {payload_len} bytes")

    sp = validated_split_pos(payload_len, split_pos, validate=validate)

    # Perform the split
    part1 = payload[:sp]
    part2 = payload[sp:]

    # OPTIMIZATION: Only log in debug mode
    if log.isEnabledFor(logging.DEBUG):
        log.debug(
            "Split payload: %sb -> part1=%sb, part2=%sb at pos=%s",
            payload_len,
            len(part1),
            len(part2),
            sp,
        )

    return part1, part2


def split_payload_with_pos(
    payload: bytes, split_pos: Any, validate: bool = True
) -> Tuple[bytes, bytes, int]:
    """
    Split payload and also return the EFFECTIVE split_pos after validation/adjustment.

    Additive helper to prevent callers from using the ORIGINAL split_pos as an
    offset when split_payload() had to adjust it.
    """
    sp = validated_split_pos(len(payload), split_pos, validate=validate)
    part1 = payload[:sp]
    part2 = payload[sp:]
    return part1, part2, sp


# OPTIMIZATION: Cache for common segment options patterns
_SEGMENT_OPTIONS_CACHE: Dict[tuple, Dict[str, Any]] = {}
_CACHE_MAX_SIZE = 100  # Limit cache size to prevent memory bloat


def create_segment_options(
    is_fake: bool,
    ttl: Optional[int] = None,
    fooling_methods: Optional[List[str]] = None,
    tcp_flags: int = 0x18,
    delay_ms_after: Optional[int] = None,
    window_size_override: Optional[int] = None,
    tcp_options: Optional[bytes] = None,
    custom_sni: Optional[str] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Shared segment options builder for all attacks.

    OPTIMIZED: Added caching for common option patterns to reduce repeated dict construction.

    This helper function provides consistent segment option creation
    with standardized fooling method handling across all attack types.

    Args:
        is_fake: Whether this is a fake segment (with low TTL)
        ttl: Time-to-live for the segment (required for fake segments)
        fooling_methods: List of DPI fooling methods to apply
        tcp_flags: TCP flags for the segment (default: PSH+ACK = 0x18)
        delay_ms_after: Milliseconds to delay after sending this segment
        window_size_override: TCP window size override for flow control
        tcp_options: Raw TCP options bytes to include
        custom_sni: Custom SNI for fakesni fooling method
        **kwargs: Additional options to include in the segment

    Returns:
        Dictionary of segment options ready for use in attack recipes

    Fooling Methods:
        - "badsum": Corrupt TCP checksum
        - "badseq": Use far-future sequence offset (0x10000000) to avoid overlap
        - "md5sig": Add TCP MD5 signature option
        - "fakesni": Generate fake SNI (stored in fooling_sni field)

    Examples:
        >>> # Fake segment with badsum fooling
        >>> opts = create_segment_options(
        ...     is_fake=True, ttl=3, fooling_methods=["badsum"]
        ... )
        >>> opts["corrupt_tcp_checksum"]  # True

        >>> # Real segment with window manipulation
        >>> opts = create_segment_options(
        ...     is_fake=False, window_size_override=1
        ... )
        >>> opts["window_size_override"]  # 1
    """
    # OPTIMIZATION: Create cache key for common patterns (skip if kwargs or custom_sni)
    # Only cache simple cases without custom parameters
    cache_key = None
    if not kwargs and custom_sni is None and tcp_options is None:
        # Convert fooling_methods to tuple for hashability
        fooling_tuple = tuple(sorted(fooling_methods)) if fooling_methods else None
        cache_key = (is_fake, ttl, fooling_tuple, tcp_flags, delay_ms_after, window_size_override)

        # Check cache
        if cache_key in _SEGMENT_OPTIONS_CACHE:
            # Return copy to prevent mutation of cached dict
            return _SEGMENT_OPTIONS_CACHE[cache_key].copy()

    # Start with base options
    options = {"is_fake": is_fake, "tcp_flags": tcp_flags}

    # Add TTL for fake segments
    if is_fake and ttl is not None:
        options["ttl"] = int(ttl)

    # Add delay if specified
    if delay_ms_after is not None:
        options["delay_ms_after"] = int(delay_ms_after)

    # Add window size override if specified
    if window_size_override is not None:
        options["window_size_override"] = int(window_size_override)

    # Add TCP options if specified
    if tcp_options is not None:
        options["tcp_options"] = tcp_options

    # Process fooling methods
    if fooling_methods:
        for method in fooling_methods:
            if method == "badsum":
                # NOTE: badsum should not be applied to REAL segments.
                # Keep behavior safe by only enabling it for fake segments.
                if is_fake:
                    options["corrupt_tcp_checksum"] = True
            elif method == "badseq":
                # Use far-future sequence offset to avoid overlap with real packet
                # 0x10000000 (268,435,456 bytes) places fake packet far in future
                # This confuses DPI while remaining acceptable to legitimate servers
                options["seq_offset"] = 0x10000000
            elif method == "md5sig":
                options["add_md5sig_option"] = True
            elif method == "fakesni":
                # Use custom SNI if provided in kwargs, otherwise generate random
                resolved_custom_sni = kwargs.get("resolved_custom_sni", custom_sni)
                options["fooling_sni"] = gen_fake_sni(custom_sni=resolved_custom_sni)

    # Add any additional options
    options.update(kwargs)

    # OPTIMIZATION: Store in cache if applicable
    if cache_key is not None and len(_SEGMENT_OPTIONS_CACHE) < _CACHE_MAX_SIZE:
        _SEGMENT_OPTIONS_CACHE[cache_key] = options.copy()

    return options


# OPTIMIZATION: Cache for special position values
_SPECIAL_POSITIONS = {
    "sni": 43,  # TLS SNI extension start
    "cipher": 11,  # TLS cipher suites start
}


def normalize_positions(positions: Any, payload_len: int, validate: bool = True) -> List[int]:
    """
    Convert various position formats to List[int] and handle special values.

    OPTIMIZED: Reduced string comparisons and improved fast path for common cases.

    This helper function provides consistent position normalization
    for multisplit, multidisorder, and other position-based attacks.

    Args:
        positions: Position specification in various formats:
            - int: Single position (converted to [position])
            - List[int]: Multiple positions (validated and sorted)
            - str: Special values ("sni", "cipher", "midsld")
            - List[str/int]: Mixed list (each element processed)
        payload_len: Length of payload for validation and special value resolution
        validate: Whether to validate positions are within payload bounds

    Returns:
        List of valid integer positions, sorted and deduplicated

    Special Values:
        - "sni": Position 43 (TLS SNI extension start)
        - "cipher": Position 11 (TLS cipher suites start)
        - "midsld": Middle of payload (payload_len // 2)

    Examples:
        >>> # Single position
        >>> normalize_positions(5, 100)  # [5]

        >>> # Multiple positions
        >>> normalize_positions([1, 5, 3], 100)  # [1, 3, 5]

        >>> # Special value
        >>> normalize_positions("sni", 100)  # [43]

        >>> # Mixed list
        >>> normalize_positions([1, "sni", 5], 100)  # [1, 5, 43]
    """
    # Handle None or empty input
    if positions is None:
        return []

    # OPTIMIZATION: Fast path for single integer (most common case)
    if isinstance(positions, int):
        if not validate:
            return [positions]
        if 0 < positions < payload_len:
            return [positions]
        # Fall through to validation logic

    # Convert to list if single value
    if not isinstance(positions, (list, tuple)):
        positions = [positions]

    # OPTIMIZATION: Fast path for list of integers only
    if all(isinstance(p, int) for p in positions):
        if not validate:
            return sorted(list(set(positions)))
        # Fall through to validation logic

    log = logging.getLogger("primitives_utils")
    normalized = []

    for pos in positions:
        if isinstance(pos, int):
            normalized.append(pos)
        elif isinstance(pos, str):
            # OPTIMIZATION: Use dict lookup instead of if-elif chain
            if pos in _SPECIAL_POSITIONS:
                special_pos = _SPECIAL_POSITIONS[pos]
                if validate and special_pos >= payload_len:
                    log.warning(
                        f"{pos.upper()} position {special_pos} >= payload length {payload_len}, using middle"
                    )
                    special_pos = payload_len // 2
                normalized.append(special_pos)
            elif pos == "midsld":
                # Middle of payload (computed dynamically)
                normalized.append(payload_len // 2)
            else:
                log.warning(f"Unknown special position value: {pos}, ignoring")
        else:
            try:
                # Try to convert to int
                normalized.append(int(pos))
            except (ValueError, TypeError):
                log.warning(f"Cannot convert position to int: {pos}, ignoring")

    # Remove duplicates and sort
    normalized = sorted(set(normalized))

    # Validate positions are within bounds
    if validate:
        valid_positions = []
        for pos in normalized:
            if pos <= 0:
                if log.isEnabledFor(logging.WARNING):
                    log.warning(f"Position {pos} <= 0, adjusting to 1")
                pos = 1
            elif pos >= payload_len:
                if log.isEnabledFor(logging.WARNING):
                    log.warning(
                        f"Position {pos} >= payload length {payload_len}, adjusting to {payload_len - 1}"
                    )
                pos = payload_len - 1

            # Only add if it's a valid split position
            if 0 < pos < payload_len:
                valid_positions.append(pos)

        normalized = sorted(set(valid_positions))

    if log.isEnabledFor(logging.DEBUG):
        log.debug(f"Normalized positions: {positions} → {normalized} (payload_len={payload_len})")

    return normalized


def handle_small_payload(
    payload: bytes, is_fake: bool = False
) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    Handle edge case of payloads too small to split.

    This consolidates duplicate code that appears in multiple attack methods
    when dealing with payloads smaller than 2 bytes.

    Args:
        payload: The small payload (typically < 2 bytes)
        is_fake: Whether to mark this as a fake segment

    Returns:
        Single-segment recipe with the payload

    Examples:
        >>> handle_small_payload(b"X")  # [(b"X", 0, {"is_fake": False, ...})]
    """
    return [(payload, 0, create_segment_options(is_fake=is_fake))]
