"""
StrategyProcessor - Unified strategy processing component.

This module implements the IStrategyProcessor interface for loading, normalizing,
validating, and configuring strategies for the UnifiedBypassEngine refactoring.

Feature: unified-engine-refactoring
Requirements: 1.2, 1.3
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field

from .loader import StrategyLoader, Strategy
from .normalizer import ParameterNormalizer
from .validator import StrategyValidator
from .exceptions import ValidationError, ImplementationError
from ..unified_engine_models import BypassDefaults, StrategyError


logger = logging.getLogger(__name__)


# ============================================================================
# Interface Definition (Requirement 1.2)
# ============================================================================


class IStrategyProcessor(ABC):
    """
    Interface for strategy processing functionality.

    Requirement 1.2: Component isolation through well-defined interfaces.
    """

    @abstractmethod
    def load_strategy(self, strategy_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Load and normalize strategy configuration.

        Args:
            strategy_data: Raw strategy configuration data

        Returns:
            Normalized strategy configuration

        Raises:
            StrategyError: If strategy loading fails
        """
        pass

    @abstractmethod
    def validate_strategy(self, strategy: Dict[str, Any]) -> bool:
        """
        Validate strategy configuration.

        Args:
            strategy: Strategy configuration to validate

        Returns:
            True if strategy is valid, False otherwise

        Raises:
            ValidationError: If validation fails with specific error details
        """
        pass

    @abstractmethod
    def create_forced_override(self, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create forced override configuration for testing mode.

        Args:
            strategy: Base strategy configuration

        Returns:
            Strategy configuration with forced overrides applied
        """
        pass

    @abstractmethod
    def ensure_testing_mode_compatibility(self, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure strategy is compatible with testing mode requirements.

        Args:
            strategy: Strategy configuration to make compatible

        Returns:
            Testing-mode compatible strategy configuration
        """
        pass


# ============================================================================
# Strategy Configuration Model
# ============================================================================


@dataclass
class StrategyConfig:
    """
    Normalized strategy configuration.

    Requirement 1.3: Single responsibility - encapsulates strategy data.
    """

    strategy_type: str
    parameters: Dict[str, Any]
    target_domains: List[str] = field(default_factory=list)
    priority: int = 0
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_engine_format(self) -> Dict[str, Any]:
        """
        Convert to engine-compatible format.

        Returns:
            Dictionary format compatible with bypass engine
        """
        return {
            "type": self.strategy_type,
            "params": self.parameters,
            "domains": self.target_domains,
            "priority": self.priority,
            "enabled": self.enabled,
            "metadata": self.metadata,
        }

    def validate(self) -> List[str]:
        """
        Validate configuration and return errors.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        if not self.strategy_type:
            errors.append("Strategy type cannot be empty")

        if not isinstance(self.parameters, dict):
            errors.append("Parameters must be a dictionary")

        if not isinstance(self.target_domains, list):
            errors.append("Target domains must be a list")

        if not isinstance(self.priority, int):
            errors.append("Priority must be an integer")

        if not isinstance(self.enabled, bool):
            errors.append("Enabled must be a boolean")

        return errors


# ============================================================================
# StrategyProcessor Implementation
# ============================================================================


class StrategyProcessor(IStrategyProcessor):
    """
    Unified strategy processing component.

    This class implements strategy loading, normalization, validation, and
    configuration for both testing and service modes. It integrates existing
    components while providing a clean interface for the UnifiedBypassEngine.

    Requirements:
    - 1.2: Component isolation through well-defined interfaces
    - 1.3: Single responsibility for strategy processing
    """

    def __init__(
        self,
        strategy_loader: Optional[StrategyLoader] = None,
        parameter_normalizer: Optional[ParameterNormalizer] = None,
        strategy_validator: Optional[StrategyValidator] = None,
        debug: bool = False,
    ):
        """
        Initialize StrategyProcessor with optional component dependencies.

        Args:
            strategy_loader: Strategy loader instance (creates default if None)
            parameter_normalizer: Parameter normalizer instance (creates default if None)
            strategy_validator: Strategy validator instance (creates default if None)
            debug: Enable debug logging
        """
        self.logger = logging.getLogger(__name__)
        if debug:
            self.logger.setLevel(logging.DEBUG)

        # Initialize components with defaults if not provided
        self.strategy_loader = strategy_loader or StrategyLoader()
        self.parameter_normalizer = parameter_normalizer or ParameterNormalizer()
        self.strategy_validator = strategy_validator or StrategyValidator(debug=debug)

        # Configuration cache for performance
        self._config_cache: Dict[str, StrategyConfig] = {}

        self.logger.info("StrategyProcessor initialized")
        self.logger.debug(
            f"Components: loader={type(self.strategy_loader).__name__}, "
            f"normalizer={type(self.parameter_normalizer).__name__}, "
            f"validator={type(self.strategy_validator).__name__}"
        )

    def load_strategy(self, strategy_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Load and normalize strategy configuration.

        Requirement 1.2: Component isolation - delegates to specialized components.

        Args:
            strategy_data: Raw strategy configuration data

        Returns:
            Normalized strategy configuration

        Raises:
            StrategyError: If strategy loading fails
        """
        try:
            self.logger.debug(f"Loading strategy: {strategy_data}")

            # Extract strategy type and parameters
            strategy_type = strategy_data.get("type", "")
            if not strategy_type:
                raise StrategyError("Strategy type is required", {"strategy_data": strategy_data})

            # Get parameters, handling both 'params' and 'parameters' keys
            raw_params = strategy_data.get("params", strategy_data.get("parameters", {}))

            # Normalize parameters using the parameter normalizer
            normalized_params = self.parameter_normalizer.normalize(raw_params)

            # Validate normalized parameters
            self.parameter_normalizer.validate(normalized_params)

            # Detect conflicts and log warnings
            attacks = strategy_data.get("attacks", [strategy_type])
            conflicts = self.parameter_normalizer.detect_conflicts(normalized_params, attacks)
            for conflict in conflicts:
                self.logger.warning(conflict)

            # Create normalized strategy configuration
            normalized_strategy = {
                "type": strategy_type,
                "params": normalized_params,
                "attacks": attacks,
                "domains": strategy_data.get("domains", strategy_data.get("target_domains", [])),
                "priority": strategy_data.get("priority", 0),
                "enabled": strategy_data.get("enabled", True),
                "metadata": strategy_data.get("metadata", {}),
            }

            self.logger.debug(f"Strategy loaded successfully: {strategy_type}")
            return normalized_strategy

        except ValidationError as e:
            # Re-raise validation errors as strategy errors
            raise StrategyError(
                f"Strategy validation failed: {e}", {"strategy_data": strategy_data}
            )
        except Exception as e:
            self.logger.error(f"Failed to load strategy: {e}", exc_info=True)
            raise StrategyError(f"Strategy loading failed: {e}", {"strategy_data": strategy_data})

    def validate_strategy(self, strategy: Dict[str, Any]) -> bool:
        """
        Validate strategy configuration.

        Requirement 1.2: Component isolation - delegates to validator component.

        Args:
            strategy: Strategy configuration to validate

        Returns:
            True if strategy is valid, False otherwise

        Raises:
            ValidationError: If validation fails with specific error details
        """
        try:
            self.logger.debug(f"Validating strategy: {strategy.get('type', 'unknown')}")

            # Use the strategy validator for comprehensive validation
            validation_result = self.strategy_validator.validate_strategy(strategy)

            if not validation_result.is_valid:
                error_msg = f"Strategy validation failed: {', '.join(validation_result.errors)}"
                self.logger.warning(error_msg)
                raise ValidationError(
                    error_msg,
                    {
                        "strategy": strategy,
                        "errors": validation_result.errors,
                        "warnings": validation_result.warnings,
                    },
                )

            # Log warnings if any
            for warning in validation_result.warnings:
                self.logger.warning(f"Strategy validation warning: {warning}")

            self.logger.debug("Strategy validation successful")
            return True

        except ValidationError:
            # Re-raise validation errors
            raise
        except Exception as e:
            self.logger.error(f"Strategy validation failed with exception: {e}", exc_info=True)
            raise ValidationError(f"Validation exception: {e}", {"strategy": strategy})

    def create_forced_override(self, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create forced override configuration for testing mode.

        Requirement 1.3: Single responsibility - handles testing mode configuration.

        Args:
            strategy: Base strategy configuration

        Returns:
            Strategy configuration with forced overrides applied
        """
        try:
            self.logger.debug(
                f"Creating forced override for strategy: {strategy.get('type', 'unknown')}"
            )

            # Create a copy to avoid modifying the original
            override_strategy = strategy.copy()
            override_params = override_strategy.get("params", {}).copy()

            # Apply forced overrides for testing mode
            # These ensure consistent behavior during testing

            # Force specific TTL for fake attacks to ensure predictable behavior
            if "ttl" in override_params:
                override_params["ttl"] = BypassDefaults.FAKE_TTL
                self.logger.debug(f"Forced TTL to {BypassDefaults.FAKE_TTL}")

            # Force specific fooling methods for consistency
            if "fooling_methods" in override_params:
                override_params["fooling_methods"] = ["badsum"]
                self.logger.debug("Forced fooling_methods to ['badsum']")

            # Force disorder method for predictable results
            if "disorder_method" in override_params:
                override_params["disorder_method"] = "reverse"
                self.logger.debug("Forced disorder_method to 'reverse'")

            # Force fake mode for consistent behavior
            if "fake_mode" in override_params:
                override_params["fake_mode"] = "single"
                self.logger.debug("Forced fake_mode to 'single'")

            # Update strategy with forced parameters
            override_strategy["params"] = override_params

            # Add metadata to indicate this is a forced override
            metadata = override_strategy.get("metadata", {})
            metadata["forced_override"] = True
            metadata["original_params"] = strategy.get("params", {})
            override_strategy["metadata"] = metadata

            self.logger.debug("Forced override created successfully")
            return override_strategy

        except Exception as e:
            self.logger.error(f"Failed to create forced override: {e}", exc_info=True)
            raise StrategyError(f"Forced override creation failed: {e}", {"strategy": strategy})

    def ensure_testing_mode_compatibility(self, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure strategy is compatible with testing mode requirements.

        Requirement 1.3: Single responsibility - handles testing mode compatibility.

        Args:
            strategy: Strategy configuration to make compatible

        Returns:
            Testing-mode compatible strategy configuration
        """
        try:
            self.logger.debug(
                f"Ensuring testing mode compatibility for: {strategy.get('type', 'unknown')}"
            )

            # Create a copy to avoid modifying the original
            compatible_strategy = strategy.copy()
            compatible_params = compatible_strategy.get("params", {}).copy()

            # Ensure parameters are compatible with testing mode

            # Ensure TTL is within reasonable range for testing
            if "ttl" in compatible_params:
                ttl = compatible_params["ttl"]
                if not isinstance(ttl, int) or ttl < 1 or ttl > 10:
                    compatible_params["ttl"] = BypassDefaults.FAKE_TTL
                    self.logger.debug(
                        f"Adjusted TTL from {ttl} to {BypassDefaults.FAKE_TTL} for testing"
                    )

            # Ensure split positions are reasonable for testing
            if "split_pos" in compatible_params:
                split_pos = compatible_params["split_pos"]
                if isinstance(split_pos, int) and split_pos > 1000:
                    compatible_params["split_pos"] = "sni"
                    self.logger.debug(f"Adjusted split_pos from {split_pos} to 'sni' for testing")

            # Ensure split count is reasonable for testing
            if "split_count" in compatible_params:
                split_count = compatible_params["split_count"]
                if isinstance(split_count, int) and split_count > 10:
                    compatible_params["split_count"] = 3
                    self.logger.debug(f"Adjusted split_count from {split_count} to 3 for testing")

            # Ensure overlap size is reasonable for testing
            if "overlap_size" in compatible_params:
                overlap_size = compatible_params["overlap_size"]
                if isinstance(overlap_size, int) and overlap_size > 500:
                    compatible_params["overlap_size"] = BypassDefaults.SEQOVL_OVERLAP_SIZE
                    self.logger.debug(
                        f"Adjusted overlap_size from {overlap_size} to {BypassDefaults.SEQOVL_OVERLAP_SIZE} for testing"
                    )

            # Ensure fooling methods are valid for testing
            if "fooling_methods" in compatible_params:
                fooling_methods = compatible_params["fooling_methods"]
                if not isinstance(fooling_methods, list) or not fooling_methods:
                    compatible_params["fooling_methods"] = ["badsum"]
                    self.logger.debug("Set default fooling_methods for testing")

            # Update strategy with compatible parameters
            compatible_strategy["params"] = compatible_params

            # Add metadata to indicate testing mode compatibility
            metadata = compatible_strategy.get("metadata", {})
            metadata["testing_mode_compatible"] = True
            if "original_params" not in metadata:
                metadata["original_params"] = strategy.get("params", {})
            compatible_strategy["metadata"] = metadata

            self.logger.debug("Testing mode compatibility ensured")
            return compatible_strategy

        except Exception as e:
            self.logger.error(f"Failed to ensure testing mode compatibility: {e}", exc_info=True)
            raise StrategyError(f"Testing mode compatibility failed: {e}", {"strategy": strategy})

    def create_strategy_config(self, strategy_data: Dict[str, Any]) -> StrategyConfig:
        """
        Create a StrategyConfig object from strategy data.

        Args:
            strategy_data: Raw strategy data

        Returns:
            StrategyConfig instance

        Raises:
            StrategyError: If configuration creation fails
        """
        try:
            # Load and normalize the strategy first
            normalized_strategy = self.load_strategy(strategy_data)

            # Create StrategyConfig instance
            config = StrategyConfig(
                strategy_type=normalized_strategy["type"],
                parameters=normalized_strategy["params"],
                target_domains=normalized_strategy.get("domains", []),
                priority=normalized_strategy.get("priority", 0),
                enabled=normalized_strategy.get("enabled", True),
                metadata=normalized_strategy.get("metadata", {}),
            )

            # Validate the configuration
            errors = config.validate()
            if errors:
                raise StrategyError(
                    f"Configuration validation failed: {', '.join(errors)}",
                    {"strategy_data": strategy_data, "errors": errors},
                )

            return config

        except StrategyError:
            # Re-raise strategy errors
            raise
        except Exception as e:
            self.logger.error(f"Failed to create strategy config: {e}", exc_info=True)
            raise StrategyError(
                f"Configuration creation failed: {e}", {"strategy_data": strategy_data}
            )

    def get_supported_strategy_types(self) -> List[str]:
        """
        Get list of supported strategy types.

        Returns:
            List of supported strategy type names
        """
        # This could be extended to query the strategy loader for supported types
        return [
            "fake",
            "split",
            "multisplit",
            "disorder",
            "fakeddisorder",
            "disorder_short_ttl_decoy",
            "seqovl",
            "combo",
        ]

    def clear_cache(self) -> None:
        """Clear internal configuration cache."""
        self._config_cache.clear()
        self.logger.debug("Configuration cache cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        return {
            "cache_size": len(self._config_cache),
            "cached_configs": list(self._config_cache.keys()),
        }


# ============================================================================
# Factory Function
# ============================================================================


def create_strategy_processor(
    strategy_loader: Optional[StrategyLoader] = None,
    parameter_normalizer: Optional[ParameterNormalizer] = None,
    strategy_validator: Optional[StrategyValidator] = None,
    debug: bool = False,
) -> StrategyProcessor:
    """
    Factory function to create a StrategyProcessor instance.

    Args:
        strategy_loader: Optional strategy loader instance
        parameter_normalizer: Optional parameter normalizer instance
        strategy_validator: Optional strategy validator instance
        debug: Enable debug logging

    Returns:
        Configured StrategyProcessor instance
    """
    return StrategyProcessor(
        strategy_loader=strategy_loader,
        parameter_normalizer=parameter_normalizer,
        strategy_validator=strategy_validator,
        debug=debug,
    )
