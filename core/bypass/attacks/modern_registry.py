"""
Modern registry module for backward compatibility.
This module provides modern registry functionality using the existing attack_registry.
"""

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

# Alias for modern registry
ModernAttackRegistry = AttackRegistry


def get_modern_registry():
    """Get the modern attack registry (alias for get_attack_registry)."""
    return get_attack_registry()


# Make sure all functions are available
__all__ = [
    "ModernAttackRegistry",
    "get_modern_registry",
    "AttackRegistry",
    "get_attack_registry",
    "register_attack",
    "get_attack_handler",
    "validate_attack_parameters",
    "list_attacks",
    "get_attack_metadata",
    "clear_registry",
]
