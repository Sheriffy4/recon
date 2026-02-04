"""
Payload-based DPI bypass attacks.

This package contains all payload-level attacks for bypassing DPI systems.
Attack modules are loaded explicitly by the main application entry point.
"""

# Import all payload attack modules to ensure registration
from . import encryption
from . import noise
from . import obfuscation
from . import base64_encoding
from . import padding_injection

__all__ = ["encryption", "noise", "obfuscation", "base64_encoding", "padding_injection"]
