"""
Attack Registration Manager for the Attack Registry system.

This module handles attack registration, lazy loading, and promotion logic.
Extracted from the monolithic AttackRegistry class to improve separation of concerns.
"""

import logging
from pathlib import Path
from typing import Any, Callable, Dict, List
from datetime import datetime
from .models import (
    AttackEntry,
    AttackMetadata,
    RegistrationPriority,
    RegistrationResult,
)

logger = logging.getLogger(__name__)


class RegistrationManager:
    """
    Manager for attack registration and lazy loading.

    This class handles:
    - Duplicate registration detection and resolution
    - Priority-based registration conflicts
    - Lazy loading of external attack modules
    - Attack promotion and demotion
    - Registration statistics and history
    """

    def __init__(self):
        """Initialize the registration manager."""
        self._unloaded_modules: Dict[str, str] = {}
        self._loaded_modules: set = set()
        logger.debug("RegistrationManager initialized")

    def set_lazy_loading_state(self, unloaded_modules: Dict[str, str], loaded_modules: set) -> None:
        """
        Allow AttackRegistry to share the same lazy-loading state containers with this manager.

        This avoids split-brain when AttackRegistry maintains its own dict/set and manager has its own.

        Args:
            unloaded_modules: Reference to registry's _unloaded_modules dict
            loaded_modules: Reference to registry's _loaded_modules set
        """
        self._unloaded_modules = unloaded_modules
        self._loaded_modules = loaded_modules

    def handle_duplicate_registration(
        self,
        attack_type: str,
        handler: Callable,
        metadata: AttackMetadata,
        priority: RegistrationPriority,
        source_module: str,
        existing_entry: AttackEntry,
        attacks: Dict[str, AttackEntry],
        alias_manager,
    ) -> RegistrationResult:
        """
        Handle duplicate attack registration based on priorities.

        Conflict resolution logic:
        1. If new priority is higher - replace existing attack
        2. If priorities are equal - skip with warning
        3. If new priority is lower - skip with info message

        Args:
            attack_type: Type of attack
            handler: New handler
            metadata: New metadata
            priority: New priority
            source_module: Source module of new attack
            existing_entry: Existing registry entry
            attacks: Dictionary of registered attacks
            alias_manager: Alias manager for updating aliases

        Returns:
            RegistrationResult with result of duplicate handling
        """
        existing_priority = existing_entry.priority
        existing_history = getattr(existing_entry, "promotion_history", None) or []
        existing_perf = getattr(existing_entry, "performance_data", None) or {}
        existing_source = getattr(existing_entry, "source_module", "unknown")

        if priority.value > existing_priority.value:
            # New priority is higher - replace
            logger.info(
                f"Replacing attack '{attack_type}' (priority {existing_priority.name} -> {priority.name}) from {source_module}"
            )

            # Save replacement info in history
            promotion_info = {
                "timestamp": datetime.now().isoformat(),
                "action": "replaced_by_higher_priority",
                "old_priority": existing_priority.name,
                "new_priority": priority.name,
                "old_source": existing_source,
                "new_source": source_module,
                "reason": f"Higher priority registration ({priority.name} > {existing_priority.name})",
            }

            # Create new entry
            new_entry = AttackEntry(
                attack_type=attack_type,
                handler=handler,
                metadata=metadata,
                priority=priority,
                source_module=source_module,
                registration_time=datetime.now(),
                is_canonical=True,
                promotion_history=existing_history + [promotion_info],
                performance_data=existing_perf,
            )

            attacks[attack_type] = new_entry

            # Update aliases
            conflicts = []
            for alias in metadata.aliases:
                if (
                    alias in alias_manager.get_alias_mapping()
                    and alias_manager.get_alias_mapping()[alias] != attack_type
                ):
                    conflicts.append(
                        f"Alias '{alias}' reassigned from '{alias_manager.get_alias_mapping()[alias]}' to '{attack_type}'"
                    )
                alias_manager.register_alias(alias, attack_type)

            return RegistrationResult(
                success=True,
                action="replaced",
                message=f"Replaced attack '{attack_type}' with higher priority version ({priority.name} > {existing_priority.name})",
                attack_type=attack_type,
                conflicts=conflicts,
                previous_priority=existing_priority,
                new_priority=priority,
            )

        elif priority.value == existing_priority.value:
            # Same priority - skip with warning
            logger.warning(
                f"Skipping duplicate registration of '{attack_type}' with same priority {priority.name} from {source_module}"
            )

            return RegistrationResult(
                success=False,
                action="skipped",
                message=f"Skipped duplicate registration of '{attack_type}' with same priority {priority.name}",
                attack_type=attack_type,
                conflicts=[],
                previous_priority=existing_priority,
                new_priority=priority,
            )

        else:
            # Lower priority - skip with info
            logger.info(
                f"Skipping lower priority registration of '{attack_type}' ({priority.name} < {existing_priority.name}) from {source_module}"
            )

            return RegistrationResult(
                success=False,
                action="skipped_lower_priority",
                message=f"Skipped lower priority registration of '{attack_type}' ({priority.name} < {existing_priority.name})",
                attack_type=attack_type,
                conflicts=[],
                previous_priority=existing_priority,
                new_priority=priority,
            )

    def discover_external_attacks(self, attacks_dir: Path) -> int:
        """
        Discover external attacks without loading them (for lazy loading).

        Args:
            attacks_dir: Directory containing attack modules

        Returns:
            Number of discovered attack modules
        """
        if not attacks_dir.exists():
            logger.warning(f"Attacks directory not found: {attacks_dir}")
            return 0

        discovered_count = 0

        # System files to exclude
        excluded_files = {
            "attack_registry.py",
            "metadata.py",
            "base.py",
            "__init__.py",
            "real_effectiveness_tester.py",
            "simple_attack_executor.py",
            "alias_map.py",
            "attack_classifier.py",
            "attack_definition.py",
            "learning_memory.py",
            "multisplit_segment_fix.py",
            "proper_testing_methodology.py",
            "safe_result_utils.py",
            "segment_packet_builder.py",
            "timing_controller.py",
            "engine.py",
            "http_manipulation.py",
        }

        for module_file in attacks_dir.glob("*.py"):
            if module_file.name.startswith("_") or module_file.name in excluded_files:
                continue

            if module_file.is_dir():
                continue

            module_name = module_file.stem
            module_path = f"core.bypass.attacks.{module_name}"
            attack_name = module_name.replace("_", "")

            # Store module path for later loading
            self._unloaded_modules[attack_name] = module_path
            discovered_count += 1
            logger.debug(f"Discovered attack module: {module_path}")

        logger.info(f"Discovered {discovered_count} potential attack modules for lazy loading")
        return discovered_count

    def load_module_on_demand(self, module_path: str, registry) -> bool:
        """
        Load a module on demand and register found attacks.

        Args:
            module_path: Python module path to load
            registry: AttackRegistry instance for registration

        Returns:
            True if module loaded successfully, False otherwise
        """
        if module_path in self._loaded_modules:
            logger.debug(f"Module already loaded: {module_path}")
            return True

        try:
            import importlib

            module = importlib.import_module(module_path)
            self._loaded_modules.add(module_path)

            # Look for attack classes or registration functions
            loaded_attacks = 0

            for attr_name in dir(module):
                if attr_name.startswith("_"):
                    continue

                attr = getattr(module, attr_name)

                # Check if it's an attack class
                if registry._is_attack_class(attr):
                    registry._register_attack_class(attr)
                    loaded_attacks += 1

            # IMPORTANT: also process queued decorator registrations if module used
            # core.bypass.attacks.registry.decorator.register_attack
            try:
                from .decorator import process_pending_registrations

                loaded_attacks += process_pending_registrations(registry)
            except Exception as e:
                logger.debug(f"Skipping pending decorator registrations for {module_path}: {e}")

            if loaded_attacks > 0:
                logger.info(f"Loaded {loaded_attacks} attacks from {module_path}")
                return True
            else:
                logger.debug(f"No attacks found in {module_path}")
                return False

        except Exception as e:
            logger.error(f"Failed to load module {module_path}: {e}")
            return False

    def ensure_attack_loaded(self, attack_type: str, registry) -> bool:
        """
        Ensure an attack is loaded (for lazy loading).

        Args:
            attack_type: Type of attack to ensure is loaded
            registry: AttackRegistry instance

        Returns:
            True if attack is loaded or was successfully loaded
        """
        # Check if already loaded
        if attack_type in registry.attacks:
            return True

        # Normalize type for matching (helps with underscores / attack= prefix)
        normalized = attack_type.lower().strip()
        if normalized.startswith("attack="):
            normalized = normalized[7:]

        # Try to find and load the module
        for module_name, module_path in self._unloaded_modules.items():
            mn = module_name.lower()
            if mn == normalized or normalized in mn or mn in normalized:
                logger.info(f"Lazy loading attack '{attack_type}' from {module_path}")
                if self.load_module_on_demand(module_path, registry):
                    # Check if attack is now available
                    if attack_type in registry.attacks:
                        return True

        return False

    def get_lazy_loading_stats(self, attacks: Dict) -> Dict[str, Any]:
        """
        Get lazy loading statistics.

        Args:
            attacks: Dictionary of registered attacks

        Returns:
            Dictionary with lazy loading statistics
        """
        return {
            "lazy_loading_enabled": len(self._unloaded_modules) > 0,
            "loaded_attacks": len(attacks),
            "unloaded_modules": len(self._unloaded_modules),
            "loaded_modules": len(self._loaded_modules),
            "unloaded_module_list": list(self._unloaded_modules.keys()),
            "loaded_module_list": list(self._loaded_modules),
        }

    def get_registration_conflicts(self, attacks: Dict) -> List[Dict[str, Any]]:
        """
        Get list of all registration conflicts from history.

        Args:
            attacks: Dictionary of registered attacks

        Returns:
            List of conflicts with detailed information
        """
        conflicts = []

        for attack_type, entry in attacks.items():
            history = getattr(entry, "promotion_history", None) or []
            if history:
                for promotion in history:
                    if promotion.get("action") in [
                        "replaced_by_higher_priority",
                        "promoted",
                    ]:
                        conflicts.append(
                            {
                                "attack_type": attack_type,
                                "conflict_type": promotion.get("action"),
                                "timestamp": promotion.get("timestamp"),
                                "old_priority": promotion.get("old_priority"),
                                "new_priority": promotion.get("new_priority"),
                                "old_source": promotion.get("old_source"),
                                "new_source": promotion.get("new_source"),
                                "reason": promotion.get("reason"),
                            }
                        )

        return conflicts

    def get_priority_statistics(self, attacks: Dict) -> Dict[str, Any]:
        """
        Get statistics on attack priorities.

        Args:
            attacks: Dictionary of registered attacks

        Returns:
            Dictionary with priority statistics
        """
        stats = {
            "total_attacks": len(attacks),
            "by_priority": {},
            "by_source": {},
            "core_attacks": [],
            "external_attacks": [],
        }

        for attack_type, entry in attacks.items():
            priority_name = entry.priority.name
            source = entry.source_module

            # Statistics by priority
            if priority_name not in stats["by_priority"]:
                stats["by_priority"][priority_name] = {"count": 0, "attacks": []}
            stats["by_priority"][priority_name]["count"] += 1
            stats["by_priority"][priority_name]["attacks"].append(attack_type)

            # Statistics by source
            if source not in stats["by_source"]:
                stats["by_source"][source] = {"count": 0, "attacks": []}
            stats["by_source"][source]["count"] += 1
            stats["by_source"][source]["attacks"].append(attack_type)

            # Categorize as core or external
            if entry.priority == RegistrationPriority.CORE:
                stats["core_attacks"].append(attack_type)
            else:
                stats["external_attacks"].append(attack_type)

        return stats
