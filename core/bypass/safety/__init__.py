# recon/core/bypass/safety/__init__.py

"""
Safe attack execution framework for the modernized bypass engine.
Provides comprehensive safety controls, resource management, and sandboxing.
"""

from .safety_controller import SafetyController
from .resource_manager import ResourceManager, ResourceLimits
from .attack_sandbox import AttackSandbox
from .emergency_stop import EmergencyStopManager
from .safety_validator import SafetyValidator
from .exceptions import (
    SafetyError,
    ResourceLimitExceededError,
    AttackTimeoutError,
    SandboxViolationError,
    EmergencyStopError,
)

__all__ = [
    "SafetyController",
    "ResourceManager",
    "ResourceLimits",
    "AttackSandbox",
    "EmergencyStopManager",
    "SafetyValidator",
    "SafetyError",
    "ResourceLimitExceededError",
    "AttackTimeoutError",
    "SandboxViolationError",
    "EmergencyStopError",
]
