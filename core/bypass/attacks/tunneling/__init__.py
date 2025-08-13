# recon/core/bypass/attacks/tunneling/__init__.py
"""
Tunneling-based DPI bypass attacks.

This package contains all tunneling attacks for bypassing DPI systems.
"""

# Import all tunneling attack modules to ensure they are registered
from . import dns_tunneling
from . import icmp_tunneling
from . import protocol_tunneling

__all__ = []