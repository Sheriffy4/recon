"""
Strategy Name Normalizer

This module provides utilities for normalizing strategy names to enable
consistent comparison across different naming conventions.

Feature: pcap-validator-combo-detection
Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
"""


class StrategyNameNormalizer:
    """
    Utility class for normalizing strategy names.

    Provides consistent normalization across all components to enable
    accurate strategy comparison even when names differ in:
    - Prefix conventions (smart_combo_, combo_)
    - Attack name variants (multisplit vs split)
    - Attack ordering

    Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
    """

    # Attack equivalence mapping: variant → canonical form
    # Requirement 5.3: multisplit normalizes to split
    ATTACK_EQUIVALENTS = {
        "multisplit": "split",
    }

    # Attacks that are implementation details and should be ignored during comparison
    # seqovl is a side effect of disorder attack, not a separate attack
    # badsum, badseq are fooling methods, not core attacks
    IGNORABLE_ATTACKS = {"seqovl", "badsum", "badseq", "ttl_manipulation"}

    # Special combo patterns that have unique names
    # Requirement: fake + disorder → fakeddisorder
    SPECIAL_COMBOS = {
        frozenset(["fake", "disorder"]): "fakeddisorder",
    }

    @classmethod
    def normalize(cls, strategy_name: str) -> str:
        """
        Normalizes a strategy name for comparison.

        Normalization steps:
        1. Remove "smart_combo_" and "combo_" prefixes (Requirement 5.1)
        2. Split into attack components
        3. Normalize each attack using ATTACK_EQUIVALENTS (Requirement 5.3)
        4. Remove duplicates and sort alphabetically (Requirement 5.5)
        5. Check for special combo patterns
        6. Join back with underscores

        Task 4.3: Handle special characters in strategy names (Requirement 7.5)
        - Test normalization with special characters
        - Ensure no exceptions are raised
        - Log warnings if special characters found

        Args:
            strategy_name: Strategy name to normalize

        Returns:
            Normalized strategy name

        Examples:
            >>> StrategyNameNormalizer.normalize("smart_combo_disorder_multisplit")
            'disorder_split'
            >>> StrategyNameNormalizer.normalize("disorder_multisplit")
            'disorder_split'
            >>> StrategyNameNormalizer.normalize("multisplit")
            'split'
            >>> StrategyNameNormalizer.normalize("smart_combo_fake_split")
            'fake_split'

        Requirements: 5.1, 5.2, 5.3, 5.5, 7.5
        """
        import logging
        import re

        logger = logging.getLogger(__name__)

        # Handle empty or special values
        if not strategy_name or strategy_name in ("none", "unknown", "error"):
            return strategy_name

        # Task 4.3: Check for special characters and log warning
        # Allow only alphanumeric, underscore, and hyphen
        if not re.match(r"^[a-zA-Z0-9_-]+$", strategy_name):
            logger.warning(
                f"⚠️ Edge case: strategy name contains special characters: '{strategy_name}'"
            )
            # Remove special characters except underscore and hyphen
            strategy_name = re.sub(r"[^a-zA-Z0-9_-]", "", strategy_name)
            logger.warning(f"⚠️ Cleaned strategy name: '{strategy_name}'")

        # Task 4.3: Ensure no exceptions are raised - wrap in try-except
        try:
            # Requirement 5.1: Remove prefixes
            name = strategy_name.replace("smart_combo_", "")
            name = name.replace("combo_", "")

            # Split into components
            components = name.split("_")

            # Requirement 5.3: Normalize each component using equivalence mapping
            # Also filter out ignorable attacks (implementation details)
            normalized = []
            for comp in components:
                if comp:  # Skip empty components
                    # Skip ignorable attacks (seqovl, badsum, etc.)
                    if comp in cls.IGNORABLE_ATTACKS:
                        continue
                    normalized.append(cls.ATTACK_EQUIVALENTS.get(comp, comp))

            # Requirement 5.5: Remove duplicates and sort
            unique_sorted = sorted(set(normalized))

            # Check for special combo patterns
            attack_set = frozenset(unique_sorted)
            if attack_set in cls.SPECIAL_COMBOS:
                return cls.SPECIAL_COMBOS[attack_set]

            return "_".join(unique_sorted)

        except Exception as e:
            # Task 4.3: Ensure no exceptions are raised - return original on error
            logger.error(
                f"❌ Edge case: normalization failed for '{strategy_name}': {e}. "
                f"Returning original name."
            )
            return strategy_name

    @classmethod
    def are_equivalent(cls, strategy1: str, strategy2: str) -> bool:
        """
        Checks if two strategy names are equivalent after normalization.

        Two strategies are equivalent if they normalize to the same value,
        meaning they differ only in:
        - Prefix conventions
        - Attack name variants (multisplit vs split)
        - Attack ordering

        Args:
            strategy1: First strategy name
            strategy2: Second strategy name

        Returns:
            True if strategies are equivalent after normalization

        Examples:
            >>> StrategyNameNormalizer.are_equivalent(
            ...     "smart_combo_disorder_multisplit",
            ...     "smart_combo_disorder_split"
            ... )
            True
            >>> StrategyNameNormalizer.are_equivalent(
            ...     "disorder_multisplit",
            ...     "multisplit_disorder"
            ... )
            True
            >>> StrategyNameNormalizer.are_equivalent(
            ...     "split",
            ...     "fake"
            ... )
            False

        Requirements: 5.4, 5.5
        """
        return cls.normalize(strategy1) == cls.normalize(strategy2)
