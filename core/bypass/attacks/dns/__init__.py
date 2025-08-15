# recon/core/bypass/attacks/dns/__init__.py

"""
DNS tunneling and evasion attacks module.
Implements various DNS-based bypass techniques including DoH, DoT, and query manipulation.
"""

from .dns_tunneling import (
    DNSTunnelingAttack,
    DoHAttack,
    DoTAttack,
    DNSQueryManipulation,
    DNSCachePoisoningPrevention
)

__all__ = [
    'DNSTunnelingAttack',
    'DoHAttack', 
    'DoTAttack',
    'DNSQueryManipulation',
    'DNSCachePoisoningPrevention'
]