"""
Base classes for different attack categories.

This module provides standardized base classes for implementing DPI bypass attacks:
- PayloadAttackBase: For payload manipulation attacks
- HTTPAttackBase: For HTTP-layer attacks
- IPAttackBase: For IP-layer attacks
- DNSAttackBase: For DNS-layer attacks
- UDPAttackBase: For UDP-layer attacks
"""

from .payload_attack_base import PayloadAttackBase
from .http_attack_base import HTTPAttackBase
from .ip_attack_base import IPAttackBase
from .dns_attack_base import DNSAttackBase
from .udp_attack_base import UDPAttackBase

__all__ = [
    "PayloadAttackBase",
    "HTTPAttackBase",
    "IPAttackBase",
    "DNSAttackBase",
    "UDPAttackBase",
]
