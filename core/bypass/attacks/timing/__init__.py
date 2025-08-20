# recon/core/bypass/attacks/timing/__init__.py

"""
Advanced packet timing attacks for DPI bypass.

This module implements sophisticated timing-based evasion techniques including:
- Packet timing manipulation
- Jitter injection attacks
- Delay-based evasion techniques
- Burst traffic generation attacks
"""

from .timing_base import TimingAttackBase, TimingResult
from .jitter_injection import JitterInjectionAttack
from .delay_evasion import DelayEvasionAttack
from .burst_traffic import BurstTrafficAttack

__all__ = [
    "TimingAttackBase",
    "TimingResult",
    "JitterInjectionAttack",
    "DelayEvasionAttack",
    "BurstTrafficAttack",
]
