"""
Mode management system for bypass engines.

This module provides the infrastructure for managing different operation modes
(native vs emulated) with safe fallback mechanisms and capability detection.
"""

from core.bypass.modes.mode_controller import ModeController, OperationMode
from core.bypass.modes.capability_detector import CapabilityDetector
from core.bypass.modes.mode_transition import ModeTransitionManager
from core.bypass.modes.exceptions import (
    ModeError,
    ModeTransitionError,
    CapabilityDetectionError,
)

__all__ = [
    "ModeController",
    "OperationMode",
    "CapabilityDetector",
    "ModeTransitionManager",
    "ModeError",
    "ModeTransitionError",
    "CapabilityDetectionError",
]
