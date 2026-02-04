"""
Semantic validation functions for attack correlation.

This module provides attack-specific semantic validation logic extracted
from the correlation engine to improve modularity and reduce god class complexity.
"""

from typing import List, Dict, Any
from .attack_type_matching import normalize_modification_type


def _get_attack_params(attack) -> Dict[str, Any]:
    """
    Best-effort extraction of attack parameters without binding to a single model shape.
    """
    for attr in ("params", "parameters", "attack_params"):
        value = getattr(attack, attr, None)
        if isinstance(value, dict):
            return value
    return {}


def validate_split_semantics(attack, modifications: List) -> bool:
    """
    Validate split attack semantics.

    Args:
        attack: Attack event with parameters
        modifications: List of packet modifications

    Returns:
        True if split semantics are valid
    """
    params = _get_attack_params(attack)
    # SR1-SR5: if split_position is provided, validate its range.
    split_position = params.get("split_position")
    if split_position is not None:
        try:
            sp = float(split_position)
        except (TypeError, ValueError):
            return False
        if not (0.0 <= sp <= 1.0):
            return False

    # Split should result in packet size reduction
    for mod in modifications:
        if mod.modified_packet.size >= mod.original_packet.size:
            return False
    return True


def validate_multisplit_semantics(attack, modifications: List) -> bool:
    """
    Validate multisplit attack semantics.

    Args:
        attack: Attack event with parameters
        modifications: List of packet modifications

    Returns:
        True if multisplit semantics are valid
    """
    params = _get_attack_params(attack)
    expected_count = params.get("split_count")
    if expected_count is not None:
        try:
            expected_count = int(expected_count)
        except (TypeError, ValueError):
            return False
        if expected_count < 1:
            return False

    # Multisplit should have split modifications (can be just one in simple cases)
    split_count = len([mod for mod in modifications if mod.modification_type.value == "split"])
    if expected_count is not None:
        return split_count >= expected_count
    return split_count >= 1


def validate_disorder_semantics(attack, modifications: List) -> bool:
    """
    Validate disorder attack semantics.

    Args:
        attack: Attack event with parameters
        modifications: List of packet modifications

    Returns:
        True if disorder semantics are valid
    """
    params = _get_attack_params(attack)
    expected_disorder = params.get("disorder_count")
    if expected_disorder is not None:
        try:
            expected_disorder = int(expected_disorder)
        except (TypeError, ValueError):
            return False
        if expected_disorder < 1:
            return False

    # Disorder should involve sequence number changes
    seq_changes = 0
    for mod in modifications:
        if "sequence_number" in mod.modified_fields:
            seq_changes += 1
            if expected_disorder is None:
                return True

    if expected_disorder is not None:
        return seq_changes >= expected_disorder
    return False


def validate_fake_semantics(attack, modifications: List) -> bool:
    """
    Validate fake attack semantics.

    Args:
        attack: Attack event with parameters
        modifications: List of packet modifications

    Returns:
        True if fake semantics are valid
    """
    params = _get_attack_params(attack)
    expected_fake = params.get("fake_packet_count")
    if expected_fake is not None:
        try:
            expected_fake = int(expected_fake)
        except (TypeError, ValueError):
            return False
        if expected_fake < 1:
            return False
        return len(modifications) >= expected_fake

    # Fake attacks should create additional packets
    return len(modifications) > 0


def validate_combo_semantics(attack, modifications: List) -> bool:
    """
    Validate combination attack semantics.

    Args:
        attack: Attack event with parameters
        modifications: List of packet modifications

    Returns:
        True if combo semantics are valid
    """
    # Combo attacks should have modifications from multiple attack types
    mod_types = {
        normalize_modification_type(getattr(mod, "modification_type", None))
        for mod in modifications
    }
    return len(mod_types) > 1


def validate_attack_specific_semantics(attack, modifications: List) -> bool:
    """
    Validate attack-specific semantic rules.

    Args:
        attack: Attack event with type and parameters
        modifications: Actual packet modifications

    Returns:
        True if attack-specific semantics are valid
    """
    attack_type = attack.attack_type.lower()

    if attack_type == "split":
        return validate_split_semantics(attack, modifications)
    elif attack_type == "multisplit":
        return validate_multisplit_semantics(attack, modifications)
    elif attack_type == "disorder":
        return validate_disorder_semantics(attack, modifications)
    elif attack_type == "fake":
        return validate_fake_semantics(attack, modifications)
    elif "combo" in attack_type:
        return validate_combo_semantics(attack, modifications)

    # Default validation for unknown attack types
    return len(modifications) > 0
