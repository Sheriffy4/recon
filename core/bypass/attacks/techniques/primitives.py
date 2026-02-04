"""
Compatibility shim for primitives module.

This module provides backward compatibility for code that tries to import
from core.bypass.attacks.techniques.primitives instead of the correct path
core.bypass.techniques.primitives.

All functionality is re-exported from the correct location.
"""

# Re-export everything from the correct location
from core.bypass.techniques.primitives import *  # noqa: F401, F403

# Ensure BypassTechniques is available
from core.bypass.techniques.primitives import BypassTechniques  # noqa: F401

__all__ = ["BypassTechniques"]
