"""
Attack parameter constants.

Centralized constants for attack types, modes, and validation.
"""

from typing import ClassVar, Set


class AttackConstants:
    """Attack parameter constants - simple class, no overengineering."""

    # Fooling methods
    FOOLING_BADSUM = "badsum"
    FOOLING_BADSEQ = "badseq"
    FOOLING_MD5SIG = "md5sig"
    DEFAULT_FOOLING = FOOLING_BADSUM

    # Fake modes
    FAKE_MODE_PER_FRAGMENT = "per_fragment"
    FAKE_MODE_PER_SIGNATURE = "per_signature"
    FAKE_MODE_SMART = "smart"
    FAKE_MODE_SINGLE = "single"
    DEFAULT_FAKE_MODE = FAKE_MODE_SINGLE

    # Disorder methods
    DISORDER_REVERSE = "reverse"
    DISORDER_RANDOM = "random"
    DISORDER_SWAP = "swap"
    DEFAULT_DISORDER_METHOD = DISORDER_REVERSE

    # Validation sets
    VALID_FOOLING: ClassVar[Set[str]] = {FOOLING_BADSUM, FOOLING_BADSEQ, FOOLING_MD5SIG}
    VALID_FAKE_MODES: ClassVar[Set[str]] = {
        FAKE_MODE_PER_FRAGMENT,
        FAKE_MODE_PER_SIGNATURE,
        FAKE_MODE_SMART,
        FAKE_MODE_SINGLE,
    }
    VALID_DISORDER: ClassVar[Set[str]] = {DISORDER_REVERSE, DISORDER_RANDOM, DISORDER_SWAP}

    # TTL values
    MIN_FAKE_TTL = 1
    DEFAULT_REAL_TTL = 64  # Будет переопределяться оригинальным TTL если доступен

    # Split limits
    MIN_SPLIT_COUNT = 2
    MAX_SPLIT_COUNT = 64
    DEFAULT_SPLIT_POS = 2

    # Payload limits
    MIN_PAYLOAD_SIZE = 5
    MAX_PAYLOAD_SIZE = 65535
