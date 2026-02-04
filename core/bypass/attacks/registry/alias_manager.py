"""
Attack Alias Manager for the refactored Attack Registry system.

This module provides the AttackAliasManager class that handles all alias
management functionality extracted from the monolithic AttackRegistry.
"""

import logging
from typing import Dict, List, Optional


logger = logging.getLogger(__name__)


class AttackAliasManager:
    """
    Manages aliases for attack types and provides name resolution.

    This class handles:
    - Registration of aliases for canonical attack names
    - Resolution of aliases to canonical names
    - Conflict detection and management
    - Support for "attack=" prefix compatibility
    - Validation of alias mappings

    The alias manager maintains a bidirectional mapping between aliases
    and canonical names, allowing efficient lookup in both directions.
    """

    def __init__(self):
        """Initialize the alias manager with empty mappings."""
        # Primary mapping: alias -> canonical_name
        self._aliases: Dict[str, str] = {}

        # Reverse mapping: canonical_name -> [aliases]
        # This is built dynamically for efficiency
        self._reverse_aliases: Dict[str, List[str]] = {}

        logger.debug("AttackAliasManager initialized")

    def register_alias(self, alias: str, canonical_name: str) -> bool:
        """
        Register an alias for a canonical attack name.

        Args:
            alias: The alias name to register
            canonical_name: The canonical attack name this alias points to

        Returns:
            True if registration was successful, False if there was a conflict

        Note:
            This method will overwrite existing aliases with a warning.
            It's the caller's responsibility to check for conflicts if needed.
        """
        if not alias or not canonical_name:
            logger.error("Cannot register empty alias or canonical name")
            return False

        # Check for existing alias
        if alias in self._aliases:
            old_target = self._aliases[alias]
            if old_target != canonical_name:
                logger.warning(f"Overwriting alias '{alias}': '{old_target}' -> '{canonical_name}'")
                # Remove from old reverse mapping
                if old_target in self._reverse_aliases:
                    try:
                        self._reverse_aliases[old_target].remove(alias)
                        if not self._reverse_aliases[old_target]:
                            del self._reverse_aliases[old_target]
                    except ValueError:
                        pass  # Alias wasn't in reverse mapping
            else:
                # Same mapping already exists
                logger.debug(f"Alias '{alias}' -> '{canonical_name}' already exists")
                return True

        # Register the alias
        self._aliases[alias] = canonical_name

        # Update reverse mapping
        if canonical_name not in self._reverse_aliases:
            self._reverse_aliases[canonical_name] = []
        if alias not in self._reverse_aliases[canonical_name]:
            self._reverse_aliases[canonical_name].append(alias)

        logger.debug(f"Registered alias '{alias}' -> '{canonical_name}'")
        return True

    def resolve_name(self, name: str) -> str:
        """
        Resolve an alias or name to its canonical form.

        This method handles:
        - Direct canonical names (returned as-is)
        - Aliases (resolved to canonical names)
        - "attack=" prefix (stripped and then resolved)

        Args:
            name: The name or alias to resolve

        Returns:
            The canonical name, or the original name if no alias exists
        """
        if not name:
            return name

        # Handle "attack=" prefix for compatibility
        normalized_name = name
        if normalized_name.startswith("attack="):
            normalized_name = normalized_name[7:]  # Remove "attack=" prefix

        # Resolve alias to canonical name
        return self._aliases.get(normalized_name, normalized_name)

    def get_aliases(self, canonical_name: str) -> List[str]:
        """
        Get all aliases for a canonical attack name.

        Args:
            canonical_name: The canonical attack name

        Returns:
            List of aliases for this attack (empty if none exist)
        """
        return self._reverse_aliases.get(canonical_name, []).copy()

    def is_alias(self, name: str) -> bool:
        """
        Check if a name is an alias (not a canonical name).

        Args:
            name: The name to check

        Returns:
            True if the name is an alias, False otherwise
        """
        # Handle "attack=" prefix
        normalized_name = name
        if normalized_name.startswith("attack="):
            normalized_name = normalized_name[7:]

        return normalized_name in self._aliases

    def get_all_names(self, canonical_name: str) -> List[str]:
        """
        Get all names (canonical + aliases) for an attack.

        Args:
            canonical_name: The canonical attack name

        Returns:
            List containing the canonical name and all its aliases
        """
        names = [canonical_name]
        names.extend(self.get_aliases(canonical_name))
        return names

    def validate_alias_conflicts(self) -> List[str]:
        """
        Check for potential conflicts in alias mappings.

        Returns:
            List of conflict descriptions (empty if no conflicts)
        """
        conflicts = []

        # Check for circular references (shouldn't happen with current design)
        for alias, canonical in self._aliases.items():
            if canonical in self._aliases and self._aliases[canonical] == alias:
                conflicts.append(f"Circular reference: '{alias}' <-> '{canonical}'")

        # Check for orphaned reverse mappings
        for canonical, aliases in self._reverse_aliases.items():
            for alias in aliases:
                if alias not in self._aliases or self._aliases[alias] != canonical:
                    conflicts.append(f"Orphaned reverse mapping: '{canonical}' -> '{alias}'")

        # Check for missing reverse mappings
        for alias, canonical in self._aliases.items():
            if (
                canonical not in self._reverse_aliases
                or alias not in self._reverse_aliases[canonical]
            ):
                conflicts.append(f"Missing reverse mapping: '{alias}' -> '{canonical}'")

        return conflicts

    def get_alias_count(self) -> int:
        """
        Get the total number of registered aliases.

        Returns:
            Number of aliases
        """
        return len(self._aliases)

    def get_canonical_names_with_aliases(self) -> List[str]:
        """
        Get all canonical names that have at least one alias.

        Returns:
            List of canonical names that have aliases
        """
        return list(self._reverse_aliases.keys())

    def remove_alias(self, alias: str) -> bool:
        """
        Remove an alias from the manager.

        Args:
            alias: The alias to remove

        Returns:
            True if the alias was removed, False if it didn't exist
        """
        if alias not in self._aliases:
            return False

        canonical = self._aliases[alias]

        # Remove from primary mapping
        del self._aliases[alias]

        # Remove from reverse mapping
        if canonical in self._reverse_aliases:
            try:
                self._reverse_aliases[canonical].remove(alias)
                if not self._reverse_aliases[canonical]:
                    del self._reverse_aliases[canonical]
            except ValueError:
                pass  # Alias wasn't in reverse mapping

        logger.debug(f"Removed alias '{alias}' -> '{canonical}'")
        return True

    def clear_aliases_for_canonical(self, canonical_name: str) -> int:
        """
        Remove all aliases for a canonical name.

        Args:
            canonical_name: The canonical name to clear aliases for

        Returns:
            Number of aliases removed
        """
        if canonical_name not in self._reverse_aliases:
            return 0

        aliases_to_remove = self._reverse_aliases[canonical_name].copy()
        count = 0

        for alias in aliases_to_remove:
            if self.remove_alias(alias):
                count += 1

        return count

    def get_alias_mapping(self) -> Dict[str, str]:
        """
        Get a copy of the complete alias mapping.

        Returns:
            Dictionary mapping aliases to canonical names
        """
        return self._aliases.copy()

    def get_reverse_mapping(self) -> Dict[str, List[str]]:
        """
        Get a copy of the reverse alias mapping.

        Returns:
            Dictionary mapping canonical names to lists of aliases
        """
        return {k: v.copy() for k, v in self._reverse_aliases.items()}

    def import_aliases(self, alias_mapping: Dict[str, str]) -> int:
        """
        Import multiple aliases from a mapping.

        Args:
            alias_mapping: Dictionary of alias -> canonical_name mappings

        Returns:
            Number of aliases successfully imported
        """
        count = 0
        for alias, canonical in alias_mapping.items():
            if self.register_alias(alias, canonical):
                count += 1

        logger.info(f"Imported {count} aliases from mapping")
        return count

    def export_aliases(self) -> Dict[str, str]:
        """
        Export all aliases as a mapping suitable for serialization.

        Returns:
            Dictionary of alias -> canonical_name mappings
        """
        return self.get_alias_mapping()

    def get_stats(self) -> Dict[str, int]:
        """
        Get statistics about the alias manager.

        Returns:
            Dictionary with statistics
        """
        return {
            "total_aliases": len(self._aliases),
            "canonical_names_with_aliases": len(self._reverse_aliases),
            "conflicts": len(self.validate_alias_conflicts()),
        }

    def __len__(self) -> int:
        """Return the number of aliases."""
        return len(self._aliases)

    def __contains__(self, alias: str) -> bool:
        """Check if an alias exists."""
        return alias in self._aliases

    def __repr__(self) -> str:
        """Return string representation."""
        return f"AttackAliasManager(aliases={len(self._aliases)})"
