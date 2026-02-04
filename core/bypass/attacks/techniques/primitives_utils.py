"""
Compatibility shim for primitives_utils module.

This module provides backward compatibility for code that tries to import
from core.bypass.attacks.techniques.primitives_utils instead of the correct path
core.bypass.techniques.primitives_utils.
"""

# Re-export everything from the correct location
from core.bypass.techniques.primitives_utils import *  # noqa: F401, F403
