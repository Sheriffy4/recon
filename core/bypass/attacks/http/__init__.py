"""
HTTP-based DPI bypass attacks.

This package contains all HTTP-level attacks for bypassing DPI systems.
Attack modules are loaded explicitly by the main application entry point.
"""

# Import all HTTP attack modules to ensure registration
from . import http2_attacks
from . import header_attacks  
from . import method_attacks
from . import quic_attacks

__all__ = [
    'http2_attacks',
    'header_attacks', 
    'method_attacks',
    'quic_attacks'
]
