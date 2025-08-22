"""
DNS tunneling and evasion attacks module.
Implements various DNS-based bypass techniques including DoH, DoT, and query manipulation.
"""
from recon.core.bypass.attacks.dns.dns_tunneling import DNSTunnelingAttack, DoHAttack, DoTAttack, DNSQueryManipulation, DNSCachePoisoningPrevention
__all__ = ['DNSTunnelingAttack', 'DoHAttack', 'DoTAttack', 'DNSQueryManipulation', 'DNSCachePoisoningPrevention']