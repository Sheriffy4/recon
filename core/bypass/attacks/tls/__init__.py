"""
TLS-based DPI bypass attacks.

This package contains all TLS-level attacks for bypassing DPI systems.
Attack modules are loaded explicitly by the main application entry point.
"""

# Import all TLS attack modules to ensure registration
from . import ech_attacks
from . import extension_attacks
from . import confusion
from . import early_data_smuggling
from . import early_data_tunnel
from . import ja3_mimicry
from . import record_manipulation
from . import tls_evasion

__all__ = [
    "ech_attacks",
    "extension_attacks",
    "confusion",
    "early_data_smuggling",
    "early_data_tunnel",
    "ja3_mimicry",
    "record_manipulation",
    "tls_evasion",
]
