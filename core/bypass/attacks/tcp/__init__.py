# recon/core/bypass/attacks/tcp/__init__.py
"""
TCP-based DPI bypass attacks.

This package contains all TCP-level attacks for bypassing DPI systems.
"""

# Import all TCP attack modules to ensure they are registered
from . import manipulation
from . import timing
from . import race_attacks
from . import stateful_attacks
from . import fooling

# Re-export key classes for convenience
from .manipulation import (
    TCPWindowScalingAttack,
    UrgentPointerAttack,
    TCPOptionsPaddingAttack,
    TCPTimestampAttack,
    TCPMultiSplitAttack,
    TCPWindowSizeLimitAttack,
)

from .timing import (
    DripFeedAttack,
    TimingBasedEvasionAttack,
    BurstTimingEvasionAttack,
)

from .race_attacks import (
    BadChecksumRaceAttack,
    LowTTLPoisoningAttack,
    CacheConfusionAttack,
    MD5SigRaceAttack,
)

from .stateful_attacks import (
    FakeDisorderAttack,
    MultiDisorderAttack,
    SequenceOverlapAttack,
    TimingManipulationAttack,
)

from .fooling import (
    BadSumFoolingAttack,
    MD5SigFoolingAttack,
    BadSeqFoolingAttack,
    TTLManipulationAttack,
)

__all__ = [
    # Manipulation attacks
    "TCPWindowScalingAttack",
    "UrgentPointerAttack",
    "TCPOptionsPaddingAttack",
    "TCPTimestampAttack",
    "TCPMultiSplitAttack",
    "TCPWindowSizeLimitAttack",
    # Timing attacks
    "DripFeedAttack",
    "TimingBasedEvasionAttack",
    "BurstTimingEvasionAttack",
    # Race condition attacks
    "BadChecksumRaceAttack",
    "LowTTLPoisoningAttack",
    "CacheConfusionAttack",
    "MD5SigRaceAttack",
    # Stateful attacks
    "FakeDisorderAttack",
    "MultiDisorderAttack",
    "SequenceOverlapAttack",
    "TimingManipulationAttack",
    # Fooling attacks
    "BadSumFoolingAttack",
    "MD5SigFoolingAttack",
    "BadSeqFoolingAttack",
    "TTLManipulationAttack",
]
