"""
Advanced packet timing attacks for DPI bypass.

This module implements sophisticated timing-based evasion techniques including:
- Packet timing manipulation
- Jitter injection attacks
- Delay-based evasion techniques
- Burst traffic generation attacks
"""
from recon.core.bypass.attacks.timing.timing_base import TimingAttackBase, TimingResult
from recon.core.bypass.attacks.timing.jitter_injection import JitterInjectionAttack
from recon.core.bypass.attacks.timing.delay_evasion import DelayEvasionAttack
from recon.core.bypass.attacks.timing.burst_traffic import BurstTrafficAttack
__all__ = ['TimingAttackBase', 'TimingResult', 'JitterInjectionAttack', 'DelayEvasionAttack', 'BurstTrafficAttack']