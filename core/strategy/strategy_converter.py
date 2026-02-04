#!/usr/bin/env python3
"""
Strategy Conversion Module

Handles loading, building, and converting DPI bypass strategies.
Extracted from cli.py to improve modularity and reduce complexity.
"""

import logging
from typing import Any, Dict, Optional

# Get logger
LOG = logging.getLogger("recon.strategy_converter")


class StrategyConverter:
    """
    Handles strategy loading, recipe building, and zapret command conversion.

    This class encapsulates all strategy conversion logic that was previously
    scattered in cli.py, providing a clean interface for strategy operations.
    """

    def __init__(self):
        """Initialize the strategy converter with feature flags and availability checks."""
        # Import feature flag
        try:
            from config import USE_NEW_ATTACK_SYSTEM

            self.use_new_attack_system = USE_NEW_ATTACK_SYSTEM
        except ImportError:
            self.use_new_attack_system = True  # Default to enabled

        # Check ComboAttackBuilder availability
        try:
            from core.strategy.combo_builder import ComboAttackBuilder, AttackRecipe

            self.ComboAttackBuilder = ComboAttackBuilder
            self.AttackRecipe = AttackRecipe
            self.combo_builder_available = True
        except ImportError as e:
            LOG.warning(f"ComboAttackBuilder not available: {e}")
            self.ComboAttackBuilder = None
            self.AttackRecipe = None
            self.combo_builder_available = False

        # Import StrategyLoader
        try:
            from core.strategy.loader import StrategyLoader

            self.StrategyLoader = StrategyLoader
        except ImportError as e:
            LOG.error(f"StrategyLoader not available: {e}")
            self.StrategyLoader = None

    def load_for_domain(
        self, domain: str, force: bool = False, no_fallbacks: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Load strategy for a domain from domain_rules.json using StrategyLoader.

        This function implements Requirements 1.1, 1.2, 1.4, 5.2, 5.5:
        - Uses StrategyLoader.find_strategy() for domain matching
        - Prioritizes attacks field over type field
        - Ensures consistent force and no_fallbacks parameters
        - Adds logging for loaded strategy details

        Task 22: Checks USE_NEW_ATTACK_SYSTEM flag before using new system

        Args:
            domain: Domain name to load strategy for
            force: Whether to force the strategy (no fallbacks)
            no_fallbacks: Whether to disable fallback strategies

        Returns:
            Dictionary with strategy parameters or None if no strategy found
        """
        # Task 22: Check feature flag
        if not self.use_new_attack_system:
            LOG.debug(f"New attack system disabled, skipping StrategyLoader for {domain}")
            return None

        if not self.StrategyLoader:
            LOG.error("StrategyLoader not available")
            return None

        try:
            loader = self.StrategyLoader(rules_path="domain_rules.json")
            strategy = loader.find_strategy(domain)

            if strategy is None:
                LOG.debug(f"No strategy found for domain {domain}")
                return None

            # Log loaded strategy details (Requirement 1.5)
            LOG.info(f"📖 Loaded strategy for {domain}")
            LOG.info(f"  Attacks: {strategy.attacks}")
            LOG.info(f"  Params: {strategy.params}")

            # Ensure attacks field is used (Requirement 1.2, 5.2)
            if not strategy.attacks:
                LOG.warning(f"Strategy for {domain} has no attacks defined")
                return None

            # Convert Strategy object to dictionary format expected by cli.py
            strategy_dict = {
                "attacks": strategy.attacks,  # Use attacks field as source of truth
                "params": strategy.params.copy(),
                "metadata": strategy.metadata.copy(),
            }

            # Apply force and no_fallbacks consistently (Requirement 1.4)
            strategy_dict["params"]["force"] = force
            strategy_dict["params"]["no_fallbacks"] = no_fallbacks

            # Log the final strategy configuration
            LOG.info(f"  Force: {force}, No fallbacks: {no_fallbacks}")

            return strategy_dict

        except Exception as e:
            LOG.error(f"Failed to load strategy for {domain}: {e}")
            return None

    def build_recipe(self, strategy_dict: Dict[str, Any]) -> Optional[Any]:
        """
        Build AttackRecipe from strategy dictionary using ComboAttackBuilder.

        This function implements Requirements 2.1, 2.5, 2.6:
        - Creates unified recipe from attacks list
        - Validates attack compatibility
        - Handles incompatible combinations with error reporting

        Task 22: Checks USE_NEW_ATTACK_SYSTEM flag before using new system

        Args:
            strategy_dict: Strategy dictionary with 'attacks' and 'params' keys

        Returns:
            AttackRecipe object or None if building fails
        """
        # Task 22: Check feature flag
        if not self.use_new_attack_system:
            LOG.debug("New attack system disabled, skipping ComboAttackBuilder")
            return None

        if not self.combo_builder_available:
            LOG.warning("ComboAttackBuilder not available, cannot build recipe")
            return None

        try:
            attacks = strategy_dict.get("attacks", [])
            params = strategy_dict.get("params", {})

            if not attacks:
                LOG.warning("No attacks in strategy, cannot build recipe")
                return None

            # Create ComboAttackBuilder
            builder = self.ComboAttackBuilder()

            # Build recipe (this validates compatibility automatically)
            recipe = builder.build_recipe(attacks, params)

            # Log recipe details (Requirement 1.5)
            LOG.info(f"🎯 Built attack recipe with {len(recipe.steps)} steps")
            LOG.info(f"  Attack order: {' → '.join(s.attack_type for s in recipe.steps)}")

            return recipe

        except ValueError as e:
            # Incompatible combination detected (Requirement 2.6)
            LOG.error(f"❌ Incompatible attack combination: {e}")
            LOG.error(f"  Attacks: {strategy_dict.get('attacks', [])}")
            return None
        except Exception as e:
            LOG.error(f"Failed to build attack recipe: {e}")
            return None

    def to_zapret_command(self, strategy_dict: Dict[str, Any]) -> str:
        """
        Convert a strategy dictionary to zapret command format.

        This ensures that the attacks field is properly converted to zapret commands.

        Args:
            strategy_dict: Strategy dictionary with 'attacks' and 'params' keys

        Returns:
            Zapret command string
        """
        attacks = strategy_dict.get("attacks", [])
        params = strategy_dict.get("params", {})

        if not attacks:
            return ""

        # Build zapret command from attacks list
        parts = []

        # Map attacks to desync types
        desync_types = []
        for attack in attacks:
            if attack in ["fake", "split", "multisplit", "disorder"]:
                desync_types.append(attack)
            elif attack == "fakeddisorder":
                desync_types.extend(["fake", "disorder"])
            elif attack == "disorder_short_ttl_decoy":
                desync_types.extend(["fake", "disorder"])
            else:
                desync_types.append(attack)

        if desync_types:
            parts.append(f"--dpi-desync={','.join(desync_types)}")

        # Add parameters
        if "split_pos" in params:
            parts.append(f"--dpi-desync-split-pos={params['split_pos']}")

        if "ttl" in params:
            parts.append(f"--dpi-desync-ttl={params['ttl']}")

        if "fooling" in params:
            fooling = params["fooling"]
            if isinstance(fooling, list):
                parts.append(f"--dpi-desync-fooling={','.join(fooling)}")
            else:
                parts.append(f"--dpi-desync-fooling={fooling}")

        if "split_count" in params:
            parts.append(f"--dpi-desync-split-count={params['split_count']}")

        if "split_seqovl" in params:
            parts.append(f"--dpi-desync-split-seqovl={params['split_seqovl']}")

        if "disorder_method" in params:
            parts.append(f"--dpi-desync-disorder={params['disorder_method']}")

        # Add force and no_fallbacks flags
        if params.get("force"):
            parts.append("--force")

        if params.get("no_fallbacks"):
            parts.append("--no-fallbacks")

        return " ".join(parts)


# Create singleton instance for backward compatibility
_converter = StrategyConverter()


# Export convenience functions
def load_strategy_for_domain(
    domain: str, force: bool = False, no_fallbacks: bool = False
) -> Optional[Dict[str, Any]]:
    """Convenience function for loading strategy for a domain."""
    return _converter.load_for_domain(domain, force, no_fallbacks)


def build_attack_recipe(strategy_dict: Dict[str, Any]) -> Optional[Any]:
    """Convenience function for building attack recipe."""
    return _converter.build_recipe(strategy_dict)


def convert_strategy_to_zapret_command(strategy_dict: Dict[str, Any]) -> str:
    """Convenience function for converting strategy to zapret command."""
    return _converter.to_zapret_command(strategy_dict)
