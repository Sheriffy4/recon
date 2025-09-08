import logging
from typing import Dict, List, Any, Optional

from core.fingerprint.advanced_models import DPIFingerprint

# TODO: from core.learning.cache import AdaptiveLearningCache
from core.bypass.attacks.modern_registry import (
    ModernAttackRegistry,
    get_modern_registry,
)

LOG = logging.getLogger(__name__)


class StrategyGenerator:
    """
    Generates intelligent bypass strategies based on a detailed DPI fingerprint,
    a set of rules, and historical performance data from a learning cache.
    """

    def __init__(
        self, attack_registry: ModernAttackRegistry, learning_cache=None
    ):  # Optional[AdaptiveLearningCache]
        self.attack_registry = attack_registry
        self.learning_cache = learning_cache
        self.rules = [
            {
                "if": ["vulnerable_to_fragmentation"],
                "then": "tcp_multisplit",
                "score": 0.9,
                "params": {"split_count": 3},
            },
            {
                "if": ["vulnerable_to_fragmentation"],
                "then": "ip_fragmentation_disorder",
                "score": 0.85,
            },
            {
                "if": ["vulnerable_to_sni_case"],
                "then": "sni_manipulation",
                "score": 0.95,
                "params": {"manipulation_type": "random_case"},
            },
            {
                "if": ["vulnerable_to_bad_checksum_race"],
                "then": "badsum_race",
                "score": 1.0,
            },
            {
                "if": ["is_stateful", "rst_injection_detected"],
                "then": "faked_disorder",
                "score": 0.8,
            },
            {
                "if": ["is_stateful", "rst_injection_detected"],
                "then": "seqovl",
                "score": 0.75,
            },
        ]

    def generate_strategies(
        self, fingerprint: DPIFingerprint, count: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Generates a ranked list of bypass strategies based on the DPI fingerprint.
        """
        candidate_strategies = []

        # 1. Apply rules to find matching strategies
        for rule in self.rules:
            conditions = rule["if"]
            if not isinstance(conditions, list):
                conditions = [conditions]

            match = all(getattr(fingerprint, cond, False) for cond in conditions)

            if match:
                strategy = {
                    "name": rule["then"],
                    "params": rule.get("params", {}),
                    "estimated_score": rule["score"],
                    "reason": f"Rule matched: {rule['if']}",
                }
                # Ensure strategy name is valid
                if self.attack_registry.get_attack_definition(strategy["name"]):
                    candidate_strategies.append(strategy)
                else:
                    LOG.warning(
                        f"Strategy '{strategy['name']}' from rules is not in the attack registry. Skipping."
                    )

        # 2. Adjust scores with learning cache
        if self.learning_cache:
            dpi_hash = fingerprint.short_hash()
            recommendations = self.learning_cache.get_dpi_recommendations(dpi_hash)
            rec_map = {rec[0]: rec[1] for rec in recommendations}

            for strategy in candidate_strategies:
                if strategy["name"] in rec_map:
                    historical_success_rate = rec_map[strategy["name"]]
                    # Weighted average: 60% historical, 40% rule score
                    strategy["estimated_score"] = (
                        strategy["estimated_score"] * 0.4
                    ) + (historical_success_rate * 0.6)
                    strategy[
                        "reason"
                    ] += f", historical success: {historical_success_rate:.2f}"

        # 3. Sort by score
        candidate_strategies.sort(
            key=lambda x: x.get("estimated_score", 0), reverse=True
        )

        # 4. Remove duplicates
        seen = set()
        unique_strategies = []
        for s in candidate_strategies:
            s_name = s["name"]
            if s_name not in seen:
                unique_strategies.append(s)
                seen.add(s_name)

        # 5. Ensure we have enough strategies (fallback to generic ones if needed)
        if len(unique_strategies) < count:
            LOG.debug(
                f"Generated {len(unique_strategies)} strategies from rules, need {count}. Adding generic fallbacks."
            )
            # Get a list of generic, high-quality strategies
            generic_attacks = self.attack_registry.get_attacks_by_category("generic")
            for attack_name in generic_attacks:
                if len(unique_strategies) >= count:
                    break
                if attack_name not in seen:
                    unique_strategies.append(
                        {
                            "name": attack_name,
                            "params": {},
                            "estimated_score": 0.5,  # Default score for generic
                            "reason": "Generic fallback",
                        }
                    )
                    seen.add(attack_name)

        return unique_strategies[:count]

    def generate_combo_strategies(
        self, fingerprint: DPIFingerprint, best_single_strategies: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Generates composite strategies by combining the most effective single strategies.
        """
        combos = []
        if len(best_single_strategies) < 2:
            return []

        # Combine the top 2 strategies for now
        strat1 = best_single_strategies[0]
        strat2 = best_single_strategies[1]

        # Check if dynamic_combo attack is registered
        if not self.attack_registry.get_attack_definition("dynamic_combo"):
            LOG.warning(
                "`dynamic_combo` attack not found in registry, cannot generate combo strategies."
            )
            return []

        combo_strategy = {
            "name": "dynamic_combo",
            "params": {
                "layers": [
                    {"name": strat1["name"], "params": strat1.get("params", {})},
                    {"name": strat2["name"], "params": strat2.get("params", {})},
                ]
            },
            "estimated_score": (
                strat1.get("estimated_score", 0.5) + strat2.get("estimated_score", 0.5)
            )
            / 2
            * 0.9,  # Combo is slightly less certain
            "reason": f"Combo of {strat1['name']} and {strat2['name']}",
        }
        combos.append(combo_strategy)
        return combos
