"""
Compatibility shim for techniques module.

This module provides backward compatibility for code that tries to import
from core.bypass.attacks.techniques.primitives instead of the correct path
core.bypass.techniques.primitives.
"""

# Re-export primitives from the correct location
from core.bypass.techniques.primitives import *  # noqa: F401, F403
from core.bypass.techniques import primitives  # noqa: F401

__all__ = ["primitives"]
