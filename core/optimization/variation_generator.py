"""
Strategy variation generator for optimization.

This module provides functionality to generate strategy variations for
optimization testing by varying parameters like split_pos, split_count,
and attack combinations.
"""

from typing import List, Dict, Any, TYPE_CHECKING
import itertools
import importlib.util
from pathlib import Path

if TYPE_CHECKING:
    from core.optimization.models import Strategy


# Import models module directly to avoid core.__init__ triggering scapy imports
_models_path = Path(__file__).parent / "models.py"
_spec = importlib.util.spec_from_file_location("optimization_models_variation", _models_path)
_models = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_models)


class VariationGenerator:
    """
    Generates strategy variations for optimization testing.

    Creates variations by:
    - Varying split_pos (1, 2, 3, 5, 10, 15, 20)
    - Varying split_count (2, 4, 6, 8, 11, 16)
    - Testing different attack combinations
    - Adjusting TTL values

    Attributes:
        SPLIT_POS_VALUES: List of split position values to test
        SPLIT_COUNT_VALUES: List of split count values to test
        ATTACK_COMBINATIONS: List of attack combination lists to test
    """

    SPLIT_POS_VALUES = [1, 2, 3, 5, 10, 15, 20]
    SPLIT_COUNT_VALUES = [2, 4, 6, 8, 11, 16]
    ATTACK_COMBINATIONS = [
        ["split"],
        ["multisplit"],
        ["disorder", "split"],
        ["disorder", "multisplit"],
        ["fake", "split"],
        ["fake", "disorder", "multisplit"],
    ]

    def generate_variations(
        self,
        base_strategy: "Strategy",
        max_variations: int = 50,
    ) -> List["Strategy"]:
        """
        Generate variations of a base strategy.

        Takes a working base strategy and creates variations by modifying
        parameters like split_pos, split_count, and attack combinations.

        Args:
            base_strategy: Working strategy to vary
            max_variations: Maximum variations to generate

        Returns:
            List of strategy variations (may be less than max_variations
            if parameter space is exhausted)
        """
        Strategy = _models.Strategy
        variations = []

        # Get base parameters
        base_params = base_strategy.params.copy()
        base_attacks = base_strategy.attacks

        # Determine which parameters to vary based on attack types
        has_split = any(attack in base_attacks for attack in ["split", "multisplit"])
        has_fake = "fake" in base_attacks

        # Generate variations by varying parameters
        variation_configs = []

        # 1. Vary split_pos if strategy uses split/multisplit
        if has_split and "split_pos" in base_params:
            for split_pos in self.SPLIT_POS_VALUES:
                if split_pos != base_params.get("split_pos"):
                    params = base_params.copy()
                    params["split_pos"] = split_pos
                    variation_configs.append((base_strategy.type, base_attacks, params))

        # 2. Vary split_count if strategy uses multisplit
        if "multisplit" in base_attacks and "split_count" in base_params:
            for split_count in self.SPLIT_COUNT_VALUES:
                if split_count != base_params.get("split_count"):
                    params = base_params.copy()
                    params["split_count"] = split_count
                    variation_configs.append((base_strategy.type, base_attacks, params))

        # 3. Vary both split_pos and split_count together (for multisplit)
        if (
            "multisplit" in base_attacks
            and "split_pos" in base_params
            and "split_count" in base_params
        ):
            # Try a few combinations (not all to avoid explosion)
            for split_pos, split_count in itertools.islice(
                itertools.product(self.SPLIT_POS_VALUES[:4], self.SPLIT_COUNT_VALUES[:4]),
                10,  # Limit to 10 combinations
            ):
                if split_pos != base_params.get("split_pos") or split_count != base_params.get(
                    "split_count"
                ):
                    params = base_params.copy()
                    params["split_pos"] = split_pos
                    params["split_count"] = split_count
                    variation_configs.append((base_strategy.type, base_attacks, params))

        # 4. Try different attack combinations
        for attack_combo in self.ATTACK_COMBINATIONS:
            if attack_combo != base_attacks:
                # Adapt parameters for the new attack combination
                params = self._adapt_params_for_attacks(base_params, attack_combo)
                # Use the first attack as the type (convention in the codebase)
                strategy_type = (
                    attack_combo[0] if len(attack_combo) == 1 else "_".join(attack_combo)
                )
                variation_configs.append((strategy_type, attack_combo, params))

        # 5. Vary TTL if present
        if "ttl" in base_params:
            for ttl in [1, 2, 5, 8]:
                if ttl != base_params.get("ttl"):
                    params = base_params.copy()
                    params["ttl"] = ttl
                    variation_configs.append((base_strategy.type, base_attacks, params))

        # Create Strategy objects from configs, limiting to max_variations
        for strategy_type, attacks, params in variation_configs[:max_variations]:
            try:
                variation = Strategy(
                    type=strategy_type,
                    attacks=attacks,
                    params=params,
                )
                variations.append(variation)
            except ValueError:
                # Skip invalid strategies
                continue

        return variations

    def generate_default_strategies(self, domain: str) -> List["Strategy"]:
        """
        Generate default strategies when no base strategy exists.

        Creates a set of common strategies that work for many domains,
        using standard parameter values.

        Args:
            domain: Target domain (used for logging/tracking)

        Returns:
            List of default strategy configurations to test
        """
        Strategy = _models.Strategy
        strategies = []

        # Generate strategies for each attack combination
        for attack_combo in self.ATTACK_COMBINATIONS:
            # Determine strategy type from attacks
            strategy_type = attack_combo[0] if len(attack_combo) == 1 else "_".join(attack_combo)

            # Build parameters based on attack types
            params = {}

            # Add split parameters if needed
            if any(attack in attack_combo for attack in ["split", "multisplit"]):
                params["split_pos"] = 2  # Default split position

            # Add split_count for multisplit
            if "multisplit" in attack_combo:
                params["split_count"] = 6  # Default split count

            # Add TTL for fake attacks
            if "fake" in attack_combo:
                params["ttl"] = 5  # Default TTL for fake packets

            # Add disorder parameters if needed
            if "disorder" in attack_combo:
                params["disorder"] = True

            try:
                strategy = Strategy(
                    type=strategy_type,
                    attacks=attack_combo,
                    params=params,
                )
                strategies.append(strategy)
            except ValueError:
                # Skip invalid strategies
                continue

        # Also generate some variations with different split_pos values
        for split_pos in [1, 3, 5, 10]:
            for attack_combo in [["split"], ["multisplit"]]:
                strategy_type = attack_combo[0]
                params = {"split_pos": split_pos}

                if "multisplit" in attack_combo:
                    params["split_count"] = 6

                try:
                    strategy = Strategy(
                        type=strategy_type,
                        attacks=attack_combo,
                        params=params,
                    )
                    strategies.append(strategy)
                except ValueError:
                    continue

        return strategies

    def _adapt_params_for_attacks(
        self,
        base_params: Dict[str, Any],
        attacks: List[str],
    ) -> Dict[str, Any]:
        """
        Adapt parameters for a new attack combination.

        Ensures that parameters are appropriate for the given attack types.
        For example, adds split_pos for split attacks, split_count for multisplit, etc.

        Args:
            base_params: Original parameter dictionary
            attacks: New attack combination

        Returns:
            Adapted parameter dictionary
        """
        params = {}

        # Copy relevant parameters based on attack types
        has_split = any(attack in attacks for attack in ["split", "multisplit"])
        has_fake = "fake" in attacks
        has_disorder = "disorder" in attacks

        # Add split parameters
        if has_split:
            params["split_pos"] = base_params.get("split_pos", 2)

        # Add split_count for multisplit
        if "multisplit" in attacks:
            params["split_count"] = base_params.get("split_count", 6)

        # Add TTL for fake attacks
        if has_fake:
            params["ttl"] = base_params.get("ttl", 5)

        # Add disorder flag
        if has_disorder:
            params["disorder"] = True

        # Copy other common parameters
        for key in ["fooling", "no_fallbacks"]:
            if key in base_params:
                params[key] = base_params[key]

        return params
