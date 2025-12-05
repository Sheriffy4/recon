"""
Tunneling-based DPI bypass attacks.

This package contains all tunneling attacks for bypassing DPI systems.
Attack modules are loaded explicitly by the main application entry point.
"""

# Import all tunneling attack modules to ensure registration
from . import icmp_tunneling
from . import protocol_tunneling
from . import quic_fragmentation
from . import dns_tunneling_legacy

__all__ = [
    'icmp_tunneling',
    'protocol_tunneling',
    'quic_fragmentation',
    'dns_tunneling_legacy'
]
