"""
Attack type ↔ modification type matching utilities.

Centralizes mapping logic that was previously duplicated in correlation/combination code.
This module is intentionally small and dependency-free to avoid circular imports.
"""

from typing import Any


def normalize_attack_type(attack_type: Any) -> str:
    """Normalize attack type value to a lower-case string."""
    if attack_type is None:
        return ""
    return str(attack_type).strip().lower()


def normalize_modification_type(mod_type: Any) -> str:
    """
    Normalize modification type to a lower-case string.

    Supports:
    - Enum-like objects with .value
    - Plain strings
    - Fallback to str(...)
    """
    if mod_type is None:
        return ""
    value = getattr(mod_type, "value", None)
    if value is not None:
        return str(value).strip().lower()
    return str(mod_type).strip().lower()


def attack_type_matches_modification_type(attack_type: Any, modification_type: Any) -> bool:
    """
    Decide if a modification_type can be considered as evidence/implementation of attack_type.

    This preserves the existing semantics from CombinationCorrelationEngine._modification_matches_attack_type:
    - direct match is OK
    - multisplit is implemented as split modifications
    - fake/disorder can match ttl_modification as well
    """
    at = normalize_attack_type(attack_type)
    mt = normalize_modification_type(modification_type)

    if not at or not mt:
        return False

    # Direct match
    if at == mt:
        return True

    # Special cases (kept consistent with previous inline logic)
    if at == "multisplit" and mt == "split":
        return True

    if at in ("fake", "disorder") and mt in ("fake", "disorder", "ttl_modification"):
        return True

    return False


def modification_matches_attack_type(modification: Any, attack_type: Any) -> bool:
    """
    Convenience wrapper: extract modification.modification_type and compare to attack_type.
    """
    mod_type = getattr(modification, "modification_type", None)
    return attack_type_matches_modification_type(attack_type, mod_type)
