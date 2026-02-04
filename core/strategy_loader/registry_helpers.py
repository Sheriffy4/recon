"""
Registry Helper Methods Module for UnifiedStrategyLoader.

This module contains helper methods for interacting with AttackRegistry.
"""

import logging
from typing import Dict, Any, List, Optional, Set


def get_attack_metadata(
    attack_type: str,
    attack_registry: Any,
    logger: logging.Logger,
) -> Optional[Any]:
    """
    Get attack metadata from AttackRegistry.

    Args:
        attack_type: Type of attack
        attack_registry: AttackRegistry instance (or None)
        logger: Logger instance

    Returns:
        AttackMetadata object or None if not found
    """
    try:
        if attack_registry is None:
            from core.bypass.attacks.attack_registry import get_attack_registry

            attack_registry = get_attack_registry()

        return attack_registry.get_attack_metadata(attack_type)
    except Exception as e:
        logger.warning(f"Failed to get metadata for attack '{attack_type}': {e}")
        return None


def list_available_attacks(
    attack_registry: Any,
    known_attacks: Set[str],
    logger: logging.Logger,
    category: Optional[str] = None,
) -> List[str]:
    """
    List all available attacks from AttackRegistry.

    Args:
        attack_registry: AttackRegistry instance (or None)
        known_attacks: Set of known attack types (fallback)
        logger: Logger instance
        category: Optional category filter

    Returns:
        List of attack types
    """
    try:
        if attack_registry is None:
            from core.bypass.attacks.attack_registry import get_attack_registry

            attack_registry = get_attack_registry()

        return attack_registry.list_attacks(category)
    except Exception as e:
        logger.warning(f"Failed to list attacks: {e}")
        # Fall back to known_attacks
        if category is None:
            return list(known_attacks)
        else:
            # Can't filter by category without registry
            return []


def get_attack_aliases(
    attack_type: str,
    attack_registry: Any,
    logger: logging.Logger,
) -> List[str]:
    """
    Get all aliases for an attack type.

    Args:
        attack_type: Type of attack
        attack_registry: AttackRegistry instance (or None)
        logger: Logger instance

    Returns:
        List of aliases
    """
    try:
        if attack_registry is None:
            from core.bypass.attacks.attack_registry import get_attack_registry

            attack_registry = get_attack_registry()

        return attack_registry.get_attack_aliases(attack_type)
    except (ImportError, AttributeError, KeyError) as e:
        logger.warning(f"Failed to get aliases for attack '{attack_type}': {e}")
        return []


def validate_attack_parameters_with_registry(
    attack_type: str,
    params: Dict[str, Any],
    attack_registry: Any,
    known_attacks: Set[str],
    required_params: Dict[str, List[str]],
    logger: logging.Logger,
) -> bool:
    """
    Validate parameters for a specific attack type using AttackRegistry.

    Args:
        attack_type: Type of attack
        params: Parameters to validate
        attack_registry: AttackRegistry instance (or None)
        known_attacks: Set of known attack types (for fallback)
        required_params: Dict of required parameters (for fallback)
        logger: Logger instance

    Returns:
        True if valid

    Raises:
        Exception: If validation fails (StrategyValidationError)
    """
    try:
        if attack_registry is None:
            from core.bypass.attacks.attack_registry import get_attack_registry

            attack_registry = get_attack_registry()

        validation_result = attack_registry.validate_parameters(attack_type, params)

        if not validation_result.is_valid:
            raise ValueError(
                f"Parameter validation failed for '{attack_type}': {validation_result.error_message}"
            )

        # Log warnings
        if validation_result.has_warnings():
            for warning in validation_result.warnings:
                logger.warning(f"Parameter validation warning for '{attack_type}': {warning}")

        return True

    except Exception as e:
        logger.warning(f"Failed to validate parameters for attack '{attack_type}': {e}")
        # Fall back to legacy validation
        return legacy_validate_attack_parameters(
            attack_type, params, known_attacks, required_params
        )


def legacy_validate_attack_parameters(
    attack_type: str,
    params: Dict[str, Any],
    known_attacks: Set[str],
    required_params: Dict[str, List[str]],
) -> bool:
    """
    Legacy parameter validation for backward compatibility.

    Args:
        attack_type: Type of attack
        params: Parameters to validate
        known_attacks: Set of known attack types
        required_params: Dict of required parameters

    Returns:
        True if valid

    Raises:
        Exception: If validation fails (StrategyValidationError)
    """
    if attack_type not in known_attacks:
        raise KeyError(f"Unknown attack type: {attack_type}")

    required = required_params.get(attack_type, [])
    missing = [param for param in required if param not in params]
    if missing:
        raise ValueError(f"Attack '{attack_type}' missing required parameters: {missing}")

    return True


def is_attack_supported(
    attack_type: str,
    attack_registry: Any,
    known_attacks: Set[str],
    logger: logging.Logger,
) -> bool:
    """
    Check if an attack type is supported.

    Args:
        attack_type: Type of attack to check
        attack_registry: AttackRegistry instance (or None)
        known_attacks: Set of known attack types (fallback)
        logger: Logger instance

    Returns:
        True if supported, False otherwise
    """
    try:
        if attack_registry is None:
            from core.bypass.attacks.attack_registry import get_attack_registry

            attack_registry = get_attack_registry()

        # Check if attack is registered in AttackRegistry
        metadata = attack_registry.get_attack_metadata(attack_type)
        return metadata is not None

    except (ImportError, AttributeError, KeyError) as e:
        logger.warning(f"Failed to check attack support for '{attack_type}': {e}")
        # Fall back to known_attacks check
        return attack_type in known_attacks


def get_attack_handler(
    attack_type: str,
    attack_registry: Any,
    logger: logging.Logger,
) -> Optional[Any]:
    """
    Get attack handler from AttackRegistry.

    Args:
        attack_type: Type of attack
        attack_registry: AttackRegistry instance (or None)
        logger: Logger instance

    Returns:
        Attack handler function or None if not found
    """
    try:
        if attack_registry is None:
            from core.bypass.attacks.attack_registry import get_attack_registry

            attack_registry = get_attack_registry()

        return attack_registry.get_attack_handler(attack_type)
    except (ImportError, AttributeError, KeyError) as e:
        logger.warning(f"Failed to get handler for attack '{attack_type}': {e}")
        return None


def get_registry_status(
    attack_registry: Any,
    known_attacks: Set[str],
    required_params: Dict[str, List[str]],
    logger: logging.Logger,
) -> Dict[str, Any]:
    """
    Get status information about AttackRegistry integration.

    Args:
        attack_registry: AttackRegistry instance (or None)
        known_attacks: Set of known attack types
        required_params: Dict of required parameters
        logger: Logger instance

    Returns:
        Dictionary with status information
    """
    status = {
        "registry_available": False,
        "registry_attacks_count": 0,
        "known_attacks_count": len(known_attacks),
        "required_params_count": len(required_params),
        "integration_active": False,
    }

    try:
        if attack_registry is None:
            from core.bypass.attacks.attack_registry import get_attack_registry

            attack_registry = get_attack_registry()

        if attack_registry:
            status["registry_available"] = True
            status["registry_attacks_count"] = len(attack_registry.list_attacks())
            status["integration_active"] = True

    except (ImportError, AttributeError) as e:
        logger.warning(f"Failed to get registry status: {e}")

    return status
