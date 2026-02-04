"""
Strategy Consistency Validator

Ensures that the strategy being tested matches the strategy actually applied.
This prevents false positives from strategy substitution bugs.
"""

import logging
from typing import Dict, List, Any, Optional

LOG = logging.getLogger(__name__)


class StrategyConsistencyValidator:
    """
    Validates that declared strategy matches applied strategy.

    This prevents the strategy substitution bug where:
    - Test declares: smart_combo_split_fake = ['split', 'fake']
    - But applies: ['multisplit', 'disorder'] from domain_rules.json
    """

    def __init__(self):
        self.logger = LOG

    def validate_strategy_consistency(
        self, declared_strategy: Dict[str, Any], applied_strategy: Dict[str, Any], domain: str
    ) -> bool:
        """
        Validate that declared strategy matches applied strategy.

        Args:
            declared_strategy: Strategy that was supposed to be tested
            applied_strategy: Strategy that was actually applied
            domain: Domain being tested

        Returns:
            bool: True if strategies match, False if mismatch detected
        """
        try:
            # Extract attack lists
            declared_attacks = declared_strategy.get("attacks", [])
            applied_attacks = applied_strategy.get("attacks", [])

            # Normalize attack lists (handle different formats)
            declared_attacks = self._normalize_attacks(declared_attacks)
            applied_attacks = self._normalize_attacks(applied_attacks)

            # Check if attacks match
            if set(declared_attacks) != set(applied_attacks):
                self.logger.error(f"❌ STRATEGY MISMATCH for {domain}:")
                self.logger.error(f"   Declared: {declared_attacks}")
                self.logger.error(f"   Applied:  {applied_attacks}")
                self.logger.error(
                    f"   This indicates domain_rules.json is overriding test strategy!"
                )
                return False

            # Check critical parameters
            declared_params = declared_strategy.get("params", {})
            applied_params = applied_strategy.get("params", {})

            critical_params = ["split_pos", "ttl", "fooling", "split_count"]
            for param in critical_params:
                if param in declared_params and param in applied_params:
                    if declared_params[param] != applied_params[param]:
                        self.logger.warning(f"⚠️ Parameter mismatch for {domain}.{param}:")
                        self.logger.warning(f"   Declared: {declared_params[param]}")
                        self.logger.warning(f"   Applied:  {applied_params[param]}")

            self.logger.info(f"✅ Strategy consistency validated for {domain}")
            return True

        except Exception as e:
            self.logger.error(f"❌ Strategy validation error for {domain}: {e}")
            return False

    def _normalize_attacks(self, attacks: Any) -> List[str]:
        """Normalize attacks to consistent format."""
        if isinstance(attacks, str):
            return [attacks]
        elif isinstance(attacks, list):
            return attacks
        else:
            return []
