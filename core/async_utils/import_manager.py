#!/usr/bin/env python3
"""
Import Manager for safe module imports and context management.

This module provides utilities for ensuring imports are available in different
execution contexts, particularly for background tasks and async operations.
"""

import importlib
import logging
from typing import Any, Dict

LOG = logging.getLogger("ImportManager")


class ImportManager:
    """Manages safe imports and ensures modules are available in execution context."""

    _import_cache: Dict[str, Any] = {}

    @classmethod
    def safe_import(cls, module_name: str, fallback: Any = None) -> Any:
        """
        Safely import a module with fallback.

        Args:
            module_name: Full module name to import
            fallback: Fallback value if import fails

        Returns:
            Imported module or fallback value
        """
        if module_name in cls._import_cache:
            return cls._import_cache[module_name]

        try:
            module = importlib.import_module(module_name)
            cls._import_cache[module_name] = module
            return module
        except ImportError as e:
            LOG.warning(f"Failed to import {module_name}: {e}")
            if fallback is not None:
                cls._import_cache[module_name] = fallback
            return fallback

    @classmethod
    def safe_import_from(cls, module_name: str, item_name: str, fallback: Any = None) -> Any:
        """
        Safely import an item from a module.

        Args:
            module_name: Module name to import from
            item_name: Item name to import
            fallback: Fallback value if import fails

        Returns:
            Imported item or fallback value
        """
        cache_key = f"{module_name}.{item_name}"

        if cache_key in cls._import_cache:
            return cls._import_cache[cache_key]

        try:
            module = importlib.import_module(module_name)
            item = getattr(module, item_name)
            cls._import_cache[cache_key] = item
            return item
        except (ImportError, AttributeError) as e:
            LOG.warning(f"Failed to import {item_name} from {module_name}: {e}")
            if fallback is not None:
                cls._import_cache[cache_key] = fallback
            return fallback

    @classmethod
    def ensure_attack_imports(cls) -> Dict[str, Any]:
        """
        Ensure all common attack imports are available.

        Returns:
            Dictionary of imported items
        """
        imports = {}

        # Import AttackStatus and related classes
        imports["AttackStatus"] = cls.safe_import_from("core.bypass.attacks.base", "AttackStatus")
        imports["AttackResult"] = cls.safe_import_from("core.bypass.attacks.base", "AttackResult")
        imports["AttackContext"] = cls.safe_import_from("core.bypass.attacks.base", "AttackContext")
        imports["BlockType"] = cls.safe_import_from("core.bypass.attacks.base", "BlockType")

        # Log any missing imports
        missing = [k for k, v in imports.items() if v is None]
        if missing:
            LOG.error(f"Missing critical attack imports: {missing}")
        else:
            LOG.debug("All attack imports available")

        return imports

    @classmethod
    def inject_imports_into_globals(cls, target_globals: Dict[str, Any]) -> None:
        """
        Inject common imports into a global namespace.

        Args:
            target_globals: Target global namespace to inject into
        """
        imports = cls.ensure_attack_imports()

        for name, value in imports.items():
            if value is not None:
                target_globals[name] = value

    @classmethod
    def ensure_module_in_path(cls, module_path: str) -> bool:
        """
        Ensure a module path is available for import.

        Args:
            module_path: Module path to check

        Returns:
            True if module is available
        """
        try:
            importlib.import_module(module_path)
            return True
        except ImportError:
            return False

    @classmethod
    def get_import_context(cls) -> Dict[str, Any]:
        """
        Get a complete import context for attack execution.

        Returns:
            Dictionary with all necessary imports
        """
        context = {}

        # Core attack imports
        attack_imports = cls.ensure_attack_imports()
        context.update(attack_imports)

        # Additional utility imports
        context["time"] = cls.safe_import("time")
        context["logging"] = cls.safe_import("logging")
        context["asyncio"] = cls.safe_import("asyncio")

        # Scapy imports (commonly used in attacks)
        context["scapy"] = cls.safe_import("scapy.all")

        return context

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the import cache."""
        cls._import_cache.clear()

    @classmethod
    def get_cache_info(cls) -> Dict[str, Any]:
        """Get information about the import cache."""
        return {
            "cached_imports": len(cls._import_cache),
            "cache_keys": list(cls._import_cache.keys()),
        }


def ensure_attack_execution_context() -> Dict[str, Any]:
    """
    Ensure all necessary imports are available for attack execution.

    This function should be called before executing attacks in background
    tasks or other contexts where imports might not be available.

    Returns:
        Dictionary of imported items that can be injected into globals
    """
    return ImportManager.get_import_context()


def inject_attack_imports(target_globals: Dict[str, Any]) -> None:
    """
    Inject attack imports into a target global namespace.

    Args:
        target_globals: Target global namespace (usually globals())
    """
    ImportManager.inject_imports_into_globals(target_globals)


# Decorator for functions that need attack imports
def with_attack_imports(func):
    """
    Decorator that ensures attack imports are available in function context.
    """

    def wrapper(*args, **kwargs):
        # Get current globals
        func_globals = func.__globals__

        # Inject imports if not already present
        if "AttackStatus" not in func_globals:
            inject_attack_imports(func_globals)

        return func(*args, **kwargs)

    return wrapper
