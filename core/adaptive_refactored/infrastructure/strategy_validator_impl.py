"""
Concrete implementation of IStrategyValidator interface.

This module provides strategy validation functionality to ensure
strategies are properly configured before testing.
"""

import logging
from typing import List

from ..interfaces import IStrategyValidator
from ..models import Strategy

LOG = logging.getLogger(__name__)


class StrategyValidatorImpl(IStrategyValidator):
    """
    Concrete implementation of IStrategyValidator.

    Validates strategy configurations to ensure they are properly
    formed and contain all required parameters.
    """

    def __init__(self):
        """Initialize the strategy validator."""
        LOG.info("✅ StrategyValidator initialized")

    async def validate_strategy(self, strategy: Strategy) -> bool:
        """
        Validate strategy configuration.

        Args:
            strategy: Strategy to validate

        Returns:
            True if strategy is valid, False otherwise
        """
        try:
            errors = self.get_validation_errors(strategy)

            if errors:
                LOG.warning(f"⚠️ Strategy validation failed with {len(errors)} errors")
                for error in errors:
                    LOG.debug(f"  - {error}")
                return False

            LOG.debug(f"✅ Strategy '{strategy.name}' is valid")
            return True

        except Exception as e:
            LOG.error(f"❌ Error validating strategy: {e}")
            return False

    def get_validation_errors(self, strategy: Strategy) -> List[str]:
        """
        Get validation errors for strategy.

        Args:
            strategy: Strategy to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        try:
            # Validate strategy name
            if not strategy.name or not strategy.name.strip():
                errors.append("Strategy name cannot be empty")

            # Validate attack combination
            if not strategy.attack_combination:
                errors.append("Strategy must have at least one attack in attack_combination")
            elif not isinstance(strategy.attack_combination, list):
                errors.append("attack_combination must be a list")
            else:
                # Validate each attack name
                for i, attack in enumerate(strategy.attack_combination):
                    if not attack or not isinstance(attack, str):
                        errors.append(f"Invalid attack at index {i}: must be a non-empty string")

            # Validate parameters
            if strategy.parameters is None:
                errors.append("Strategy parameters cannot be None (use empty dict instead)")
            elif not isinstance(strategy.parameters, dict):
                errors.append("Strategy parameters must be a dictionary")

            # Validate strategy type
            if not hasattr(strategy, "strategy_type") or strategy.strategy_type is None:
                errors.append("Strategy must have a strategy_type")

            # Validate success rate if present
            if hasattr(strategy, "success_rate") and strategy.success_rate is not None:
                if not isinstance(strategy.success_rate, (int, float)):
                    errors.append("success_rate must be a number")
                elif strategy.success_rate < 0.0 or strategy.success_rate > 1.0:
                    errors.append("success_rate must be between 0.0 and 1.0")

            # Validate metadata if present
            if hasattr(strategy, "metadata") and strategy.metadata is not None:
                if not isinstance(strategy.metadata, dict):
                    errors.append("metadata must be a dictionary")

            # Additional validation for specific attack types
            self._validate_attack_specific_parameters(strategy, errors)

        except Exception as e:
            errors.append(f"Validation error: {str(e)}")

        return errors

    def _validate_attack_specific_parameters(self, strategy: Strategy, errors: List[str]) -> None:
        """
        Validate attack-specific parameters.

        Args:
            strategy: Strategy to validate
            errors: List to append errors to
        """
        try:
            # Check for common attack types and their required parameters
            for attack in strategy.attack_combination:
                attack_lower = attack.lower()

                # Fragmentation attacks need fragment size
                if "fragment" in attack_lower or "split" in attack_lower:
                    if (
                        "fragment_size" not in strategy.parameters
                        and "split_position" not in strategy.parameters
                    ):
                        LOG.debug(
                            f"⚠️ Fragmentation attack '{attack}' missing fragment_size or split_position parameter"
                        )

                # Fake packets need fake packet parameters
                if "fake" in attack_lower:
                    if "fake_packet_count" not in strategy.parameters:
                        LOG.debug(
                            f"⚠️ Fake packet attack '{attack}' missing fake_packet_count parameter"
                        )

                # TTL attacks need TTL value
                if "ttl" in attack_lower:
                    if "ttl" not in strategy.parameters:
                        LOG.debug(f"⚠️ TTL attack '{attack}' missing ttl parameter")

                # Disorder attacks need disorder parameters
                if "disorder" in attack_lower:
                    if "disorder_count" not in strategy.parameters:
                        LOG.debug(f"⚠️ Disorder attack '{attack}' missing disorder_count parameter")

        except Exception as e:
            LOG.warning(f"⚠️ Error in attack-specific validation: {e}")
