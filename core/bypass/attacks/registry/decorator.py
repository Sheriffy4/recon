"""
Attack registration decorator for external attack modules.

This module provides a decorator that allows attack classes to register
themselves with the global attack registry when they are imported.
"""

import asyncio
import inspect
import logging
from typing import Any, Callable, Dict, List, Optional, Type
from .models import AttackMetadata, RegistrationPriority

logger = logging.getLogger(__name__)

# Global list to store pending registrations
_pending_registrations: List[Dict[str, Any]] = []


def register_attack(
    name: Optional[str],
    category: Optional[str] = None,
    priority: RegistrationPriority = RegistrationPriority.NORMAL,
    required_params: Optional[List[str]] = None,
    optional_params: Optional[Dict[str, Any]] = None,
    aliases: Optional[List[str]] = None,
    description: str = "",
) -> Callable[[Type], Type]:
    """
    Queue attack registration for later processing.

    This decorator does NOT register the attack immediately. Instead it stores
    registration data in a global queue. Use process_pending_registrations(registry)
    to perform the actual registry registration.

    Args:
        name: Canonical name of the attack (if None, uses class name)
        category: Attack category (from AttackCategories), defaults to CUSTOM if not provided
        priority: Registration priority (default: NORMAL)
        required_params: List of required parameter names
        optional_params: Dictionary of optional parameters with defaults
        aliases: List of alternative names for the attack
        description: Human-readable description of the attack

    Returns:
        Decorator function that registers the attack class

    Example:
        @register_attack(
            name="my_attack",
            category=AttackCategories.FAKE,
            priority=RegistrationPriority.NORMAL,
            required_params=["split_pos"],
            optional_params={"ttl": 3},
            aliases=["my_attack_alias"],
            description="My custom attack"
        )
        class MyAttack(BaseAttack):
            pass
    """

    def decorator(cls: Type) -> Type:
        """Inner decorator that stores registration info."""
        from ..metadata import AttackCategories

        # Use CUSTOM category if not provided
        attack_category = category if category is not None else AttackCategories.CUSTOM

        # Determine attack_type (never None)
        attack_type = name or cls.__name__

        # Create metadata
        metadata = AttackMetadata(
            name=attack_type,
            description=description or cls.__doc__ or "",
            required_params=required_params or [],
            optional_params=optional_params or {},
            aliases=aliases or [],
            category=attack_category,
        )

        # Store registration info for later processing
        registration_info = {
            "attack_type": attack_type,
            "attack_class": cls,
            "metadata": metadata,
            "priority": priority,
        }

        _pending_registrations.append(registration_info)

        logger.debug(f"Queued registration for attack '{attack_type}' from class {cls.__name__}")

        return cls

    return decorator


def get_pending_registrations() -> List[Dict[str, Any]]:
    """
    Get list of pending attack registrations.

    Returns:
        List of registration info dictionaries
    """
    return _pending_registrations.copy()


def clear_pending_registrations() -> None:
    """Clear the list of pending registrations."""
    _pending_registrations.clear()


def process_pending_registrations(registry) -> int:
    """
    Process all pending attack registrations.

    Args:
        registry: AttackRegistry instance to register attacks with

    Returns:
        Number of attacks successfully registered
    """
    registered_count = 0

    for reg_info in _pending_registrations:
        try:
            attack_type = reg_info["attack_type"]
            attack_class = reg_info["attack_class"]
            metadata = reg_info["metadata"]
            priority = reg_info["priority"]

            # Create a handler function that instantiates and executes the attack
            def create_handler(attack_cls):
                def handler(*args, **kwargs):
                    """
                    Compatibility handler.

                    Supports BOTH calling conventions:
                    1) New-style: handler(context)
                    2) Legacy-style: handler(techniques, payload: bytes, **params)
                    """
                    # Determine calling convention
                    if (
                        len(args) == 1
                        and hasattr(args[0], "payload")
                        and hasattr(args[0], "params")
                    ):
                        context = args[0]
                    else:
                        # Legacy calling convention
                        techniques = args[0] if len(args) >= 1 else None
                        payload = args[1] if len(args) >= 2 else kwargs.pop("payload", b"")
                        params = dict(kwargs)

                        from ..base import AttackContext

                        # AttackContext doesn't have techniques parameter, store it in params if needed
                        if techniques is not None:
                            params["_techniques"] = techniques

                        context = AttackContext(
                            dst_ip="0.0.0.0", dst_port=443, payload=payload, params=params
                        )

                    attack_instance = attack_cls()
                    result = attack_instance.execute(context)

                    # Support async execute()
                    if inspect.iscoroutine(result):
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                loop = asyncio.new_event_loop()
                                try:
                                    result = loop.run_until_complete(result)
                                finally:
                                    loop.close()
                            else:
                                result = loop.run_until_complete(result)
                        except RuntimeError:
                            loop = asyncio.new_event_loop()
                            try:
                                result = loop.run_until_complete(result)
                            finally:
                                loop.close()

                    # Convert result to expected format
                    if hasattr(result, "segments"):
                        return result.segments
                    if isinstance(result, list):
                        return result
                    return []

                return handler

            handler = create_handler(attack_class)

            # Register with the registry
            result = registry.register_attack(
                attack_type=attack_type,
                handler=handler,
                metadata=metadata,
                priority=priority,
            )

            if result.success:
                registered_count += 1
                logger.info(f"Registered attack '{attack_type}' from decorator")
            else:
                logger.warning(f"Failed to register attack '{attack_type}': {result.message}")

        except Exception as e:
            logger.error(
                f"Error processing registration for {reg_info.get('attack_type', 'unknown')}: {e}"
            )

    # Clear pending registrations after processing
    clear_pending_registrations()

    return registered_count
