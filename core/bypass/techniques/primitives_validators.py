#!/usr/bin/env python3
"""
Validation helpers for attack primitives testing.

This module provides reusable validation functions for segment validation,
reducing code duplication in primitives_audit.py.
"""

from typing import List, Tuple, Dict, Any


def validate_segment_count(segments: List, expected: int) -> List[str]:
    """
    Validate that segment count matches expected value.

    Args:
        segments: List of segments to validate
        expected: Expected number of segments

    Returns:
        List of issue descriptions (empty if validation passes)
    """
    issues = []
    if len(segments) != expected:
        issues.append(f"Expected {expected} segments, got {len(segments)}")
    return issues


def validate_fake_segment(
    segment: Tuple[bytes, int, Dict[str, Any]],
    expected_ttl: int,
    expected_offset: int,
    expected_payload: bytes,
) -> List[str]:
    """
    Validate fake segment properties.

    Args:
        segment: Tuple of (payload, offset, options)
        expected_ttl: Expected TTL value
        expected_offset: Expected offset value
        expected_payload: Expected payload content

    Returns:
        List of issue descriptions (empty if validation passes)
    """
    issues = []
    payload, offset, opts = segment

    if not opts.get("is_fake", False):
        issues.append("Segment should be marked as fake")

    if opts.get("ttl") != expected_ttl:
        issues.append(f"Expected TTL={expected_ttl}, got {opts.get('ttl')}")

    if offset != expected_offset:
        issues.append(f"Expected offset={expected_offset}, got {offset}")

    if payload != expected_payload:
        issues.append("Payload doesn't match expected content")

    return issues


def validate_real_segment(
    segment: Tuple[bytes, int, Dict[str, Any]],
    expected_offset: int,
    expected_payload: bytes,
) -> List[str]:
    """
    Validate real segment properties.

    Args:
        segment: Tuple of (payload, offset, options)
        expected_offset: Expected offset value
        expected_payload: Expected payload content

    Returns:
        List of issue descriptions (empty if validation passes)
    """
    issues = []
    payload, offset, opts = segment

    if opts.get("is_fake", True):
        issues.append("Segment should not be marked as fake")

    if offset != expected_offset:
        issues.append(f"Expected offset={expected_offset}, got {offset}")

    if payload != expected_payload:
        issues.append("Payload doesn't match expected content")

    return issues


def validate_overlap_offsets(
    fake_segment: Tuple[bytes, int, Dict[str, Any]],
    real_segment: Tuple[bytes, int, Dict[str, Any]],
    split_pos: int,
    overlap_size: int,
) -> List[str]:
    """
    Validate overlap offset calculations.

    Args:
        fake_segment: Fake segment tuple
        real_segment: Real segment tuple
        split_pos: Split position
        overlap_size: Overlap size

    Returns:
        List of issue descriptions (empty if validation passes)
    """
    issues = []
    _, fake_offset, _ = fake_segment
    _, real_offset, _ = real_segment

    expected_fake_offset = split_pos - overlap_size
    expected_real_offset = split_pos

    if fake_offset != expected_fake_offset:
        issues.append(f"Expected fake offset={expected_fake_offset}, got {fake_offset}")

    if real_offset != expected_real_offset:
        issues.append(f"Expected real offset={expected_real_offset}, got {real_offset}")

    return issues


def validate_fooling_options(opts: Dict[str, Any], expected_methods: List[str]) -> List[str]:
    """
    Validate that fooling methods are applied correctly.

    Args:
        opts: Options dictionary from segment
        expected_methods: List of expected fooling method names

    Returns:
        List of issue descriptions (empty if validation passes)
    """
    issues = []

    fooling_map = {
        "badsum": "corrupt_tcp_checksum",
        "md5sig": "add_md5sig_option",
        "badseq": "corrupt_sequence",
    }

    for method in expected_methods:
        opt_key = fooling_map.get(method)
        if opt_key and not opts.get(opt_key, False):
            issues.append(f"{method} fooling not applied")

    return issues
