"""
Padding Generation Utilities

Common padding generation functions for traffic obfuscation attacks.
Consolidates duplicate padding logic from multiple attack classes.
"""

import random
from typing import Literal


PaddingStrategy = Literal["zero", "random", "pattern", "http_like", "auto"]


def _random_bytes(size: int) -> bytes:
    """Generate random bytes with best available compatibility."""
    rb = getattr(random, "randbytes", None)
    if callable(rb):
        return rb(size)
    return bytes(random.getrandbits(8) for _ in range(size))


def generate_padding(size: int, strategy: PaddingStrategy = "auto") -> bytes:
    """
    Generate padding bytes for traffic obfuscation.

    Args:
        size: Number of padding bytes to generate
        strategy: Padding strategy to use. If "auto", randomly selects a strategy.

    Returns:
        Padding bytes of the specified size

    Strategies:
        - zero: All null bytes
        - random: Random bytes
        - pattern: Repeating pattern (ABCDEFGH or PADDING)
        - http_like: HTTP-style padding header
        - auto: Randomly select from all strategies
    """
    if size <= 0:
        return b""

    if strategy == "auto":
        strategy = random.choice(["zero", "random", "pattern", "http_like"])

    if strategy == "zero":
        return b"\x00" * size
    elif strategy == "random":
        return _random_bytes(size)
    elif strategy == "pattern":
        # Use different patterns for variety
        patterns = [
            b"ABCDEFGH",
            b"PADDING",
        ]
        pattern = random.choice(patterns)
        return (pattern * (size // len(pattern) + 1))[:size]
    elif strategy == "http_like":
        prefix = b"X-Padding: "
        if size <= len(prefix):
            return (b"x" * size)[:size]
        return (prefix + (b"x" * (size - len(prefix))))[:size]
    else:
        # Fallback to random
        return _random_bytes(size)


def generate_realistic_padding(size: int) -> bytes:
    """
    Generate realistic padding data using various patterns.

    This is a convenience wrapper around generate_padding with "auto" strategy
    that includes additional realistic patterns like spaces.

    Args:
        size: Number of padding bytes to generate

    Returns:
        Padding bytes of the specified size
    """
    if size <= 0:
        return b""

    # Choose first, then generate to avoid wasting RNG/CPU on unused variants.
    variant = random.choice(["zero", "random", "pattern", "space"])
    if variant == "zero":
        return b"\x00" * size
    if variant == "random":
        return _random_bytes(size)
    if variant == "pattern":
        return (b"PADDING" * (size // 7 + 1))[:size]
    return b" " * size
