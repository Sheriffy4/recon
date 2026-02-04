#!/usr/bin/env python3
# File: core/bypass/packet/validation.py

"""
Validation utilities for TCP sequence number overlap detection and offset validation.

This module provides utility functions for detecting and preventing TCP sequence number
overlaps in badseq fooling attacks. These utilities help ensure that FAKE packets do not
overlap with REAL packets, which would cause legitimate servers to reject connections.

Key Functions:
- detect_sequence_overlap(): Check if FAKE and REAL packets have overlapping sequences
- validate_seq_offset(): Validate that a sequence offset won't create overlaps
- suggest_safe_offset(): Recommend safe offset values for badseq attacks

Requirements Addressed:
- Requirement 2.1: Verify that (fake_seq + fake_length) < real_seq
- Requirement 2.2: Adjust sequence numbers to prevent overlap
- Requirement 6.1: Include validation functions that detect sequence number overlaps
- Requirement 6.2: Provide test utilities that verify badseq behavior

Usage Example:
    # Check for overlap between FAKE and REAL packets
    has_overlap = detect_sequence_overlap(
        fake_seq=0x185ECF97,
        fake_len=1412,
        real_seq=0x185ECF98,
        real_len=1412
    )

    # Validate a sequence offset
    is_valid, message = validate_seq_offset(
        seq_offset=-1,
        payload_len=1412,
        base_seq=0x185ECF98
    )

    # Get a safe offset recommendation
    safe_offset = suggest_safe_offset(payload_len=1412)
"""

import logging
from typing import Tuple, Optional


# Default safe offset for badseq attacks (far-future sequence)
# This value places the FAKE packet 268,435,456 bytes in the future,
# which is far enough to avoid overlap while confusing DPI systems
DEFAULT_SAFE_OFFSET = 0x10000000  # 268,435,456 bytes


def detect_sequence_overlap(
    fake_seq: int, fake_len: int, real_seq: int, real_len: int, log: Optional[logging.Logger] = None
) -> bool:
    """
    Detect if FAKE and REAL packets have overlapping TCP sequence ranges.

    This function checks whether a FAKE packet's sequence number range overlaps
    with a REAL packet's sequence number range. Overlapping sequences cause
    legitimate servers to reject connections as they interpret overlaps as
    retransmissions or attacks.

    Overlap Detection Logic:
    - FAKE packet covers byte range: [fake_seq, fake_seq + fake_len)
    - REAL packet covers byte range: [real_seq, real_seq + real_len)
    - Overlap exists if these ranges intersect

    Common Overlap Scenarios:
    1. seq_extra=-1: FAKE at N-1, REAL at N → 1-byte overlap
    2. Negative offset too small: FAKE end extends into REAL start
    3. Zero-length payloads: No overlap possible (edge case)

    Args:
        fake_seq: FAKE packet TCP sequence number (32-bit unsigned)
        fake_len: FAKE packet payload length in bytes
        real_seq: REAL packet TCP sequence number (32-bit unsigned)
        real_len: REAL packet payload length in bytes
        log: Optional logger for debug output

    Returns:
        True if sequence ranges overlap, False otherwise

    Examples:
        >>> # Classic seq_extra=-1 overlap (BROKEN)
        >>> detect_sequence_overlap(
        ...     fake_seq=0x185ECF97,  # N-1
        ...     fake_len=1412,
        ...     real_seq=0x185ECF98,  # N
        ...     real_len=1412
        ... )
        True  # OVERLAP! FAKE covers [N-1, N+1411], REAL covers [N, N+1411]

        >>> # Far-future offset (CORRECT)
        >>> detect_sequence_overlap(
        ...     fake_seq=0x285ECF98,  # N + 0x10000000
        ...     fake_len=1412,
        ...     real_seq=0x185ECF98,  # N
        ...     real_len=1412
        ... )
        False  # No overlap! FAKE is far in the future

        >>> # Zero-length payload (edge case)
        >>> detect_sequence_overlap(
        ...     fake_seq=0x185ECF97,
        ...     fake_len=0,
        ...     real_seq=0x185ECF98,
        ...     real_len=1412
        ... )
        False  # No overlap with zero-length payload

    Requirements:
        - Requirement 2.1: Verify that (fake_seq + fake_length) < real_seq
        - Requirement 6.1: Include validation functions that detect overlaps
    """
    if log is None:
        log = logging.getLogger(__name__)

    # Handle edge cases
    if fake_len == 0 and real_len == 0:
        log.debug("Both payloads are zero-length, no overlap possible")
        return False

    # Calculate end positions (handle 32-bit wraparound)
    fake_end = (fake_seq + fake_len) & 0xFFFFFFFF
    real_end = (real_seq + real_len) & 0xFFFFFFFF

    # Normalize sequences to handle wraparound
    # Convert to signed 64-bit for comparison
    fake_seq_64 = fake_seq
    fake_end_64 = fake_end
    real_seq_64 = real_seq
    real_end_64 = real_end

    # Handle wraparound: if end < start, it wrapped around
    if fake_end < fake_seq:
        fake_end_64 = fake_end + 0x100000000
    if real_end < real_seq:
        real_end_64 = real_end + 0x100000000

    # Check for overlap using interval intersection logic
    # Two ranges [A, B) and [C, D) overlap if: A < D and C < B
    # Simplified: NOT (B <= C or D <= A)

    # No overlap if one range ends before the other starts
    if fake_end_64 <= real_seq_64:
        log.debug(f"No overlap: FAKE ends (0x{fake_end:08X}) before REAL starts (0x{real_seq:08X})")
        return False

    if real_end_64 <= fake_seq_64:
        log.debug(f"No overlap: REAL ends (0x{real_end:08X}) before FAKE starts (0x{fake_seq:08X})")
        return False

    # If we reach here, ranges overlap
    overlap_start = max(fake_seq_64, real_seq_64) & 0xFFFFFFFF
    overlap_end = min(fake_end_64, real_end_64) & 0xFFFFFFFF
    overlap_size = (overlap_end - overlap_start) & 0xFFFFFFFF

    log.warning(
        f"OVERLAP DETECTED: "
        f"FAKE [0x{fake_seq:08X}, 0x{fake_end:08X}) overlaps with "
        f"REAL [0x{real_seq:08X}, 0x{real_end:08X}) "
        f"by {overlap_size} bytes at [0x{overlap_start:08X}, 0x{overlap_end:08X})"
    )

    return True


def validate_seq_offset(
    seq_offset: int,
    payload_len: int,
    base_seq: Optional[int] = None,
    rel_seq: int = 0,
    log: Optional[logging.Logger] = None,
) -> Tuple[bool, str]:
    """
    Validate that a sequence offset value won't create overlaps with the real packet.

    This function checks whether a given seq_offset (or legacy seq_extra) value
    will cause the FAKE packet to overlap with the REAL packet. It validates
    against common problematic patterns like seq_extra=-1.

    Validation Rules:
    1. seq_offset=-1 with non-empty payload → INVALID (creates 1-byte overlap)
    2. Negative offset where |offset| < payload_len → INVALID (creates overlap)
    3. Zero offset → VALID (no fooling, but no overlap)
    4. Large positive offset (e.g., 0x10000000) → VALID (far-future, no overlap)
    5. Large negative offset (e.g., -0x10000000) → VALID (far-past, no overlap)

    Args:
        seq_offset: Sequence number offset to validate (can be negative)
        payload_len: Length of the FAKE packet payload in bytes
        base_seq: Optional base sequence number for detailed validation
        rel_seq: Relative sequence offset (default: 0)
        log: Optional logger for validation messages

    Returns:
        Tuple of (is_valid: bool, message: str)
        - is_valid: True if offset is safe, False if it creates overlap
        - message: Explanation of validation result

    Examples:
        >>> # Validate seq_extra=-1 (BROKEN)
        >>> is_valid, msg = validate_seq_offset(seq_offset=-1, payload_len=1412)
        >>> print(is_valid, msg)
        False "seq_offset=-1 with payload_len=1412 creates overlap..."

        >>> # Validate far-future offset (CORRECT)
        >>> is_valid, msg = validate_seq_offset(seq_offset=0x10000000, payload_len=1412)
        >>> print(is_valid, msg)
        True "seq_offset=0x10000000 is safe (far-future sequence)"

        >>> # Validate zero offset (SAFE but no fooling)
        >>> is_valid, msg = validate_seq_offset(seq_offset=0, payload_len=1412)
        >>> print(is_valid, msg)
        True "seq_offset=0 is safe (no sequence manipulation)"

    Requirements:
        - Requirement 2.2: Adjust sequence numbers to prevent overlap
        - Requirement 4.3: Validate that seq_offset values do not create overlaps
        - Requirement 6.1: Include validation functions that detect overlaps
    """
    if log is None:
        log = logging.getLogger(__name__)

    # Handle edge case: zero-length payload
    if payload_len == 0:
        return True, "Zero-length payload cannot create overlap"

    # Case 1: seq_offset=-1 (most common broken case)
    if seq_offset == -1:
        message = (
            f"seq_offset=-1 with payload_len={payload_len} creates overlap! "
            f"FAKE packet at seq-1 will overlap with REAL packet at seq. "
            f"Recommendation: Use seq_offset=0x{DEFAULT_SAFE_OFFSET:08X} instead."
        )
        log.error(f"❌ INVALID: {message}")
        return False, message

    # Case 2: Negative offset that's too small (creates overlap)
    if seq_offset < 0 and abs(seq_offset) < payload_len:
        overlap_bytes = payload_len + seq_offset  # How many bytes overlap
        message = (
            f"seq_offset={seq_offset} with payload_len={payload_len} creates "
            f"{overlap_bytes}-byte overlap! FAKE packet will extend {overlap_bytes} "
            f"bytes into REAL packet's sequence range. "
            f"Recommendation: Use seq_offset=0x{DEFAULT_SAFE_OFFSET:08X} or "
            f"seq_offset=-0x{DEFAULT_SAFE_OFFSET:08X} instead."
        )
        log.error(f"❌ INVALID: {message}")
        return False, message

    # Case 3: Zero offset (safe but no fooling)
    if seq_offset == 0:
        message = "seq_offset=0 is safe (no sequence manipulation, no fooling)"
        log.info(f"✅ VALID: {message}")
        return True, message

    # Case 4: Large positive offset (far-future, recommended)
    if seq_offset > 0:
        if seq_offset >= 0x08000000:  # At least 128MB in future
            message = (
                f"seq_offset=0x{seq_offset:08X} is safe (far-future sequence, "
                f"confuses DPI while avoiding overlap)"
            )
            log.info(f"✅ VALID: {message}")
            return True, message
        else:
            # Small positive offset - might be within TCP window
            message = (
                f"seq_offset=0x{seq_offset:08X} is safe but small. "
                f"Consider using larger offset (0x{DEFAULT_SAFE_OFFSET:08X}) "
                f"for better DPI evasion."
            )
            log.warning(f"⚠️  VALID (with warning): {message}")
            return True, message

    # Case 5: Large negative offset (far-past)
    if seq_offset < 0 and abs(seq_offset) >= payload_len:
        if abs(seq_offset) >= 0x08000000:  # At least 128MB in past
            message = (
                f"seq_offset=-0x{abs(seq_offset):08X} is safe (far-past sequence, "
                f"confuses DPI while avoiding overlap)"
            )
            log.info(f"✅ VALID: {message}")
            return True, message
        else:
            # Negative offset just barely avoids overlap
            message = (
                f"seq_offset={seq_offset} is safe but close to overlap boundary. "
                f"Consider using larger offset (0x{DEFAULT_SAFE_OFFSET:08X}) "
                f"for better safety margin."
            )
            log.warning(f"⚠️  VALID (with warning): {message}")
            return True, message

    # Fallback: should not reach here
    message = f"seq_offset={seq_offset} validation inconclusive"
    log.warning(f"⚠️  {message}")
    return True, message


def suggest_safe_offset(
    payload_len: int,
    prefer_future: bool = True,
    randomize: bool = False,
    log: Optional[logging.Logger] = None,
) -> int:
    """
    Suggest a safe sequence offset value for badseq attacks.

    This function recommends a safe seq_offset value that:
    1. Avoids sequence overlap with the REAL packet
    2. Confuses DPI systems effectively
    3. Remains acceptable to legitimate servers

    Recommendation Strategy:
    - Default: 0x10000000 (268,435,456 bytes in future)
    - This places FAKE packet far outside TCP window
    - DPI sees FAKE first and gets confused
    - Server ignores FAKE (out of window + low TTL)
    - Server accepts REAL packet with correct sequence

    Alternative Strategies:
    - Far-past: -0x10000000 (268,435,456 bytes in past)
    - Randomized: Random offset in safe range

    Args:
        payload_len: Length of the FAKE packet payload in bytes
        prefer_future: If True, suggest positive offset (default: True)
                      If False, suggest negative offset
        randomize: If True, add random component to offset (default: False)
        log: Optional logger for recommendation messages

    Returns:
        Recommended safe sequence offset value

    Examples:
        >>> # Get default safe offset (far-future)
        >>> offset = suggest_safe_offset(payload_len=1412)
        >>> print(f"0x{offset:08X}")
        0x10000000

        >>> # Get far-past offset
        >>> offset = suggest_safe_offset(payload_len=1412, prefer_future=False)
        >>> print(f"-0x{abs(offset):08X}")
        -0x10000000

        >>> # Get randomized offset
        >>> offset = suggest_safe_offset(payload_len=1412, randomize=True)
        >>> print(f"0x{offset:08X}")
        0x0F8A3C12  # Random value in safe range

    Requirements:
        - Requirement 4.2: Use a safe default value that prevents overlap
        - Requirement 6.2: Provide test utilities that verify badseq behavior
    """
    if log is None:
        log = logging.getLogger(__name__)

    # Base safe offset (far-future or far-past)
    base_offset = DEFAULT_SAFE_OFFSET

    # Add randomization if requested
    if randomize:
        import random

        # Randomize within ±25% of base offset
        variation = int(base_offset * 0.25)
        random_delta = random.randint(-variation, variation)
        base_offset += random_delta
        log.debug(f"Randomized offset: 0x{base_offset:08X} (±25% variation)")

    # Apply direction preference
    if prefer_future:
        recommended_offset = base_offset
        direction = "far-future"
    else:
        recommended_offset = -base_offset
        direction = "far-past"

    # Validate the recommendation
    is_valid, message = validate_seq_offset(
        seq_offset=recommended_offset, payload_len=payload_len, log=log
    )

    if not is_valid:
        # This should never happen with our default values, but handle it anyway
        log.error(
            f"Recommended offset 0x{recommended_offset:08X} failed validation! "
            f"Falling back to 0x{DEFAULT_SAFE_OFFSET:08X}"
        )
        recommended_offset = DEFAULT_SAFE_OFFSET

    log.info(
        f"💡 Recommended seq_offset: 0x{recommended_offset:08X} "
        f"({direction} sequence, payload_len={payload_len})"
    )

    return recommended_offset


def validate_packet_sequences(
    fake_seq: int, fake_len: int, real_seq: int, real_len: int, log: Optional[logging.Logger] = None
) -> Tuple[bool, str]:
    """
    Comprehensive validation of FAKE and REAL packet sequences.

    This is a convenience function that combines overlap detection with
    detailed validation and recommendations. It provides a complete
    validation report for packet sequences.

    Args:
        fake_seq: FAKE packet TCP sequence number
        fake_len: FAKE packet payload length
        real_seq: REAL packet TCP sequence number
        real_len: REAL packet payload length
        log: Optional logger for validation messages

    Returns:
        Tuple of (is_valid: bool, report: str)
        - is_valid: True if sequences are valid (no overlap)
        - report: Detailed validation report

    Example:
        >>> is_valid, report = validate_packet_sequences(
        ...     fake_seq=0x185ECF97,
        ...     fake_len=1412,
        ...     real_seq=0x185ECF98,
        ...     real_len=1412
        ... )
        >>> print(report)
        ❌ VALIDATION FAILED: Sequence overlap detected
        FAKE packet: seq=0x185ECF97, len=1412, range=[0x185ECF97, 0x185ED3FF)
        REAL packet: seq=0x185ECF98, len=1412, range=[0x185ECF98, 0x185ED400)
        Overlap: 1411 bytes
        Recommendation: Use seq_offset=0x10000000 instead of current offset
    """
    if log is None:
        log = logging.getLogger(__name__)

    # Detect overlap
    has_overlap = detect_sequence_overlap(
        fake_seq=fake_seq, fake_len=fake_len, real_seq=real_seq, real_len=real_len, log=log
    )

    # Calculate ranges
    fake_end = (fake_seq + fake_len) & 0xFFFFFFFF
    real_end = (real_seq + real_len) & 0xFFFFFFFF

    # Build report
    report_lines = []

    if has_overlap:
        # Calculate overlap details
        overlap_start = max(fake_seq, real_seq)
        overlap_end = min(fake_end, real_end)
        overlap_size = (overlap_end - overlap_start) & 0xFFFFFFFF

        # Calculate offset that was used
        seq_diff = (fake_seq - real_seq) & 0xFFFFFFFF
        if seq_diff > 0x80000000:  # Negative offset (wraparound)
            seq_offset = seq_diff - 0x100000000
        else:
            seq_offset = seq_diff

        report_lines.append("❌ VALIDATION FAILED: Sequence overlap detected")
        report_lines.append(
            f"FAKE packet: seq=0x{fake_seq:08X}, len={fake_len}, "
            f"range=[0x{fake_seq:08X}, 0x{fake_end:08X})"
        )
        report_lines.append(
            f"REAL packet: seq=0x{real_seq:08X}, len={real_len}, "
            f"range=[0x{real_seq:08X}, 0x{real_end:08X})"
        )
        report_lines.append(f"Overlap: {overlap_size} bytes")
        report_lines.append(f"Current offset: {seq_offset}")

        # Get recommendation
        safe_offset = suggest_safe_offset(payload_len=fake_len, log=log)
        report_lines.append(
            f"💡 Recommendation: Use seq_offset=0x{safe_offset:08X} " f"instead of current offset"
        )

        is_valid = False
    else:
        report_lines.append("✅ VALIDATION PASSED: No sequence overlap detected")
        report_lines.append(
            f"FAKE packet: seq=0x{fake_seq:08X}, len={fake_len}, "
            f"range=[0x{fake_seq:08X}, 0x{fake_end:08X})"
        )
        report_lines.append(
            f"REAL packet: seq=0x{real_seq:08X}, len={real_len}, "
            f"range=[0x{real_seq:08X}, 0x{real_end:08X})"
        )

        # Calculate sequence difference
        seq_diff = (fake_seq - real_seq) & 0xFFFFFFFF
        if seq_diff > 0x80000000:  # Negative offset
            seq_offset = seq_diff - 0x100000000
            report_lines.append(f"Sequence difference: {seq_offset} bytes (FAKE before REAL)")
        else:
            report_lines.append(f"Sequence difference: +{seq_diff} bytes (FAKE after REAL)")

        is_valid = True

    report = "\n".join(report_lines)

    # Log the report
    if is_valid:
        log.info(report)
    else:
        log.error(report)

    return is_valid, report


# Module-level constants for easy import
SAFE_OFFSET_FAR_FUTURE = DEFAULT_SAFE_OFFSET
SAFE_OFFSET_FAR_PAST = -DEFAULT_SAFE_OFFSET
SAFE_OFFSET_NONE = 0


# Convenience aliases for backward compatibility
check_overlap = detect_sequence_overlap
check_offset = validate_seq_offset
get_safe_offset = suggest_safe_offset
