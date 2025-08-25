"""
Advanced packet timing attacks for DPI bypass.

This module implements sophisticated timing-based evasion techniques including:
- Packet timing manipulation
- Jitter injection attacks
- Delay-based evasion techniques
- Burst traffic generation attacks
"""
from core.bypass.attacks.timing.timing_base import TimingAttackBase, TimingResult
from core.bypass.attacks.timing.jitter_injection import JitterInjectionAttack
from core.bypass.attacks.timing.delay_evasion import DelayEvasionAttack
from core.bypass.attacks.timing.burst_traffic import BurstTrafficAttack
__all__ = ['TimingAttackBase', 'TimingResult', 'JitterInjectionAttack', 'DelayEvasionAttack', 'BurstTrafficAttack']