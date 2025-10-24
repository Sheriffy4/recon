"""
Registry module for backward compatibility.
This module provides imports from attack_registry.py for compatibility with existing code.
"""

# Import all the main functions and classes from attack_registry
from .attack_registry import (
    AttackRegistry,
    get_attack_registry,
    register_attack,
    get_attack_handler,
    validate_attack_parameters,
    list_attacks,
    get_attack_metadata,
    clear_registry,
)

# Make sure the registry is available
__all__ = [
    "AttackRegistry",
    "get_attack_registry",
    "register_attack",
    "get_attack_handler",
    "validate_attack_parameters",
    "list_attacks",
    "get_attack_metadata",
    "clear_registry",
]
