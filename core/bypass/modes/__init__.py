# recon/core/bypass/modes/__init__.py
"""
Mode management system for bypass engines.

This module provides the infrastructure for managing different operation modes
(native vs emulated) with safe fallback mechanisms and capability detection.
"""

from .mode_controller import ModeController, OperationMode
from .capability_detector import CapabilityDetector
from .mode_transition import ModeTransitionManager
from .exceptions import ModeError, ModeTransitionError, CapabilityDetectionError

__all__ = [
    "ModeController",
    "OperationMode",
    "CapabilityDetector",
    "ModeTransitionManager",
    "ModeError",
    "ModeTransitionError",
    "CapabilityDetectionError",
]
