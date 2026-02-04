# Файл: core/unified_strategy_loader.py
"""
Unified Strategy Loader - Single strategy loading interface for all modes

This module provides a unified interface for loading and normalizing strategies
across both testing mode and service mode, ensuring identical behavior.
"""

import json
import logging
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path

from core.strategy_loader.registry_integration import (
    get_hardcoded_attacks,
    enhance_loader_with_registry,
    get_registry_instance,
)
from core.strategy_loader.param_normalizer import (
    normalize_params,
    normalize_special_parameters,
    add_missing_attack_parameters,
    apply_attack_specific_transformations,
)
from core.strategy_loader.format_detection import (
    is_zapret_style,
    is_function_style,
    is_colon_style,
    is_semicolon_combo_style,
    is_comma_separated_combo,
    is_simple_attack_name,
)
from core.strategy_loader import strategy_parsers
from core.strategy_loader.strategy_validator import (
    validate_attack_combination,
    validate_strategy_with_registry,
    legacy_validate_strategy,
    validate_parameter_values,
    validate_parameter_combinations,
    validate_attack_type_specific_requirements,
    validate_single_position,
    is_valid_domain_name,
)
from core.strategy_loader.file_operations import (
    load_strategies_from_file as load_strategies_from_file_impl,
    load_all_strategies_from_domain_file,
    save_strategy_to_file,
    save_all_strategies_to_file,
)
from core.strategy_loader.registry_helpers import (
    get_attack_metadata as get_attack_metadata_impl,
    list_available_attacks as list_available_attacks_impl,
    get_attack_aliases as get_attack_aliases_impl,
    validate_attack_parameters_with_registry,
    legacy_validate_attack_parameters as legacy_validate_attack_parameters_impl,
    is_attack_supported as is_attack_supported_impl,
    get_attack_handler as get_attack_handler_impl,
    get_registry_status as get_registry_status_impl,
)
from core.strategy_loader.strategy_helpers import (
    sanitize_strategy_name,
    normalize_attack_parameters,
    create_forced_override_config,
    normalize_strategy_dict_format,
)


class StrategyLoadError(Exception):
    """Raised when strategy loading fails."""

    pass


class StrategyValidationError(Exception):
    """Raised when strategy validation fails."""

    pass


@dataclass
class NormalizedStrategy:
    """Normalized strategy configuration."""

    type: str
    params: Dict[str, Any]
    attacks: List[str] = None  # Complete attack sequence for combination attacks
    no_fallbacks: bool = True
    forced: bool = True
    raw_string: str = ""
    source_format: str = ""

    def __post_init__(self):
        """Initialize attacks field if not provided."""
        if self.attacks is None:
            # Default to single attack based on type
            self.attacks = [self.type]

    def to_engine_format(self) -> Dict[str, Any]:
        """Convert to format expected by BypassEngine."""
        return {
            "type": self.type,
            "params": self.params,
            "attacks": self.attacks,
            "no_fallbacks": self.no_fallbacks,
            "forced": self.forced,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return asdict(self)


class UnifiedStrategyLoader:
    """
    Unified strategy loader for all modes.
    """

    def __init__(self, debug: bool = False, validator=None):
        self.logger = logging.getLogger(__name__)
        self.debug = debug
        self._attack_registry = None
        self._validator = validator

        # Initialize with hardcoded attacks as baseline
        self.known_attacks, self.required_params = get_hardcoded_attacks()

        # Try to enhance with AttackRegistry data
        self.known_attacks, self.required_params, self._attack_registry = (
            enhance_loader_with_registry(
                self.known_attacks, self.required_params, debug=self.debug, logger=self.logger
            )
        )

        if self.debug:
            self.logger.setLevel(logging.DEBUG)

    def _normalize_params_with_registry(
        self, attack_type: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Normalize parameters using AttackRegistry metadata."""
        try:
            # Use stored registry reference if available, otherwise get it
            registry = get_registry_instance(self._attack_registry)

            if registry:
                metadata = registry.get_attack_metadata(attack_type)
            else:
                metadata = None

            if metadata:
                # Start with normalized params
                normalized = normalize_params(params, self.logger)

                # Add missing optional parameters with their defaults
                for param_name, default_value in metadata.optional_params.items():
                    if param_name not in normalized:
                        # Специальная логика для fooling/fooling_methods - не добавляем дубликаты
                        if param_name == "fooling_methods" and "fooling" in normalized:
                            continue  # Пропускаем fooling_methods если уже есть fooling
                        if param_name == "fooling" and "fooling_methods" in normalized:
                            continue  # Пропускаем fooling если уже есть fooling_methods
                        normalized[param_name] = default_value

                # Apply attack-specific transformations BEFORE special parameter normalization
                normalized = apply_attack_specific_transformations(
                    attack_type, normalized, self.debug, self.logger
                )

                # Normalize special parameters
                normalized = normalize_special_parameters(normalized, self.logger)

                return normalized
            else:
                # Fall back to basic normalization if no metadata found
                normalized = normalize_params(params, self.logger)
                normalized = apply_attack_specific_transformations(
                    attack_type, normalized, self.debug, self.logger
                )
                return normalize_special_parameters(normalized, self.logger)

        except (KeyError, ValueError, TypeError) as e:
            self.logger.warning(f"Failed to normalize params with registry for {attack_type}: {e}")
            normalized = normalize_params(params, self.logger)
            normalized = apply_attack_specific_transformations(
                attack_type, normalized, self.debug, self.logger
            )
            return normalize_special_parameters(normalized, self.logger)

    def _sanitize_strategy_name(self, name: str) -> str:
        """Remove 'existing_' prefix from strategy name."""
        return sanitize_strategy_name(name, self.debug, self.logger)

    def load_strategy(self, strategy_input: Union[str, Dict[str, Any]]) -> NormalizedStrategy:
        """Load and normalize a strategy from various input formats."""
        try:
            # Sanitize strategy input to remove 'existing_' prefix
            if isinstance(strategy_input, str):
                strategy_input = self._sanitize_strategy_name(strategy_input)
            elif isinstance(strategy_input, dict):
                # Sanitize all strategy name fields
                if "type" in strategy_input:
                    strategy_input["type"] = self._sanitize_strategy_name(strategy_input["type"])
                if "attack_name" in strategy_input:
                    strategy_input["attack_name"] = self._sanitize_strategy_name(
                        strategy_input["attack_name"]
                    )
                if "attack_type" in strategy_input:
                    strategy_input["attack_type"] = self._sanitize_strategy_name(
                        strategy_input["attack_type"]
                    )
                if "strategy_name" in strategy_input:
                    strategy_input["strategy_name"] = self._sanitize_strategy_name(
                        strategy_input["strategy_name"]
                    )
                if "attacks" in strategy_input and isinstance(strategy_input["attacks"], list):
                    strategy_input["attacks"] = [
                        self._sanitize_strategy_name(a) if isinstance(a, str) else a
                        for a in strategy_input["attacks"]
                    ]

            if isinstance(strategy_input, dict):
                strategy = self._load_from_dict(strategy_input)
            elif isinstance(strategy_input, str):
                strategy = self._load_from_string(strategy_input)
            else:
                raise StrategyLoadError(f"Unsupported strategy input type: {type(strategy_input)}")

            self.validate_strategy(strategy)
            return strategy

        except (StrategyLoadError, StrategyValidationError) as e:
            self.logger.error(f"Failed to load and validate strategy: {e}")
            raise
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            # Catch common errors during strategy parsing and normalization
            self.logger.error(f"Strategy parsing error: {e}", exc_info=self.debug)
            raise StrategyLoadError(f"Strategy loading failed: {e}") from e

    def _load_from_string(self, strategy_string: str) -> NormalizedStrategy:
        strategy_string = strategy_string.strip()
        if not strategy_string:
            raise StrategyLoadError("Empty strategy string")

        if is_zapret_style(strategy_string):
            return strategy_parsers.parse_zapret_style(
                strategy_string, self._normalize_params_with_registry, self.debug, self.logger
            )
        elif is_function_style(strategy_string):
            return strategy_parsers.parse_function_style(
                strategy_string, self._normalize_params_with_registry
            )
        elif is_colon_style(strategy_string):
            return strategy_parsers.parse_colon_style(
                strategy_string, self._normalize_params_with_registry
            )
        elif strategy_string.startswith("--"):
            return strategy_parsers.parse_generic_cli_style(
                strategy_string, self._normalize_params_with_registry
            )
        elif is_semicolon_combo_style(strategy_string):
            return strategy_parsers.parse_semicolon_combo_style(
                strategy_string, self._normalize_params_with_registry, self.debug, self.logger
            )
        elif is_comma_separated_combo(strategy_string):
            return strategy_parsers.parse_comma_separated_combo(strategy_string)
        elif is_simple_attack_name(strategy_string, self.known_attacks):
            # Простое имя атаки без параметров (например, "smart_combo_split_fake")
            return strategy_parsers.parse_simple_attack_name(
                strategy_string, self._attack_registry, self.debug, self.logger
            )
        else:
            raise StrategyLoadError(f"Unknown strategy format: {strategy_string}")

    def _normalize_attack_parameters(
        self, attacks: List[str], params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Normalize attack parameters to ensure required parameters are present."""
        return normalize_attack_parameters(attacks, params)

    def _load_from_dict(self, strategy_dict: Dict[str, Any]) -> NormalizedStrategy:
        """Load strategy from dictionary format."""
        if "type" not in strategy_dict:
            raise StrategyLoadError("Strategy dict missing 'type' field")

        attack_type = strategy_dict["type"]
        params = strategy_dict.get("params", {})

        # DEBUG: Log incoming params
        if self.debug:
            self.logger.debug(f"📥 _load_from_dict: type={attack_type}, incoming params={params}")

        # Extract attacks field from strategy dictionary
        attacks = strategy_dict.get("attacks", [])

        # ИСПРАВЛЕНИЕ: Если это smart_combo стратегия, парсим её через parse_simple_attack_name
        if (
            attack_type.startswith("smart_combo_")
            and (not attacks or attacks == [attack_type])
            and not params
        ):
            if self.debug:
                self.logger.debug(f"📋 Detected smart_combo without params, parsing: {attack_type}")
            # Используем парсер для извлечения атак и параметров
            parsed = strategy_parsers.parse_simple_attack_name(
                attack_type, self._attack_registry, self.debug, self.logger
            )
            attacks = parsed.attacks
            params = parsed.params
            if self.debug:
                self.logger.debug(f"📋 Parsed smart_combo: attacks={attacks}, params={params}")
        elif not attacks:
            # Fall back to single attack if attacks field missing (backward compatibility)
            attacks = [attack_type]
            if self.debug:
                self.logger.debug(
                    f"Strategy for {attack_type} missing 'attacks' field, "
                    f"assuming single attack"
                )

        # Log the loaded attack combination
        if self.debug:
            self.logger.debug(f"Loading strategy: type={attack_type}, attacks={attacks}")

        # ✅ NEW: Add missing parameters BEFORE validation to prevent warnings
        params = add_missing_attack_parameters(attack_type, params, self.debug, self.logger)

        # Validate attack combination after adding missing parameters
        self._validate_attack_combination(attacks, params)

        normalized_params = self._normalize_params_with_registry(attack_type, params)

        # DEBUG: Log normalized params
        if self.debug:
            self.logger.debug(
                f"📤 _load_from_dict: type={attack_type}, normalized params={normalized_params}"
            )

        return NormalizedStrategy(
            type=attack_type,
            attacks=attacks,
            params=normalized_params,
            no_fallbacks=True,
            forced=True,
            raw_string=str(strategy_dict),
            source_format="dict",
        )

    def _validate_attack_combination(self, attacks: List[str], params: Dict[str, Any]) -> None:
        """
        Validate that attack combination is complete and consistent.

        This method ensures that attack combinations have all required parameters
        and logs comprehensive warnings for missing or invalid configurations.

        Args:
            attacks: List of attack types in the combination
            params: Strategy parameters

        Raises:
            StrategyValidationError: If validation fails critically
        """
        # Delegate to extracted validation function
        validate_attack_combination(
            attacks=attacks,
            params=params,
            known_attacks=self.known_attacks,
            logger=self.logger,
            debug=self.debug,
        )

    def create_forced_override(
        self, strategy: Union[NormalizedStrategy, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create a forced override configuration from a strategy."""
        return create_forced_override_config(strategy, self.debug, self.logger)

    def validate_strategy(self, strategy: NormalizedStrategy) -> bool:
        """Validate strategy parameters and configuration using AttackRegistry."""
        # Delegate to extracted validation function
        registry = getattr(self, "_attack_registry", None)
        return validate_strategy_with_registry(
            strategy=strategy,
            attack_registry=registry,
            logger=self.logger,
            debug=self.debug,
        )

    def _legacy_validate_strategy(self, strategy: NormalizedStrategy) -> bool:
        """Legacy strategy validation for backward compatibility."""
        # Delegate to extracted validation function
        return legacy_validate_strategy(
            strategy=strategy,
            known_attacks=self.known_attacks,
            required_params=self.required_params,
            logger=self.logger,
            debug=self.debug,
        )

    def _validate_parameter_values(self, strategy: NormalizedStrategy) -> None:
        """Validate individual parameter values including special parameters."""
        # Delegate to extracted validation function
        validate_parameter_values(strategy=strategy, logger=self.logger, debug=self.debug)

    def _validate_single_position(
        self, position: Any, param_name: str, special_values: List[str]
    ) -> None:
        """Validate a single position parameter (can be int or special string value)."""
        # Delegate to extracted validation function
        validate_single_position(position, param_name, special_values, self.logger)

    def _is_valid_domain_name(self, domain: str) -> bool:
        """Basic domain name validation."""
        # Delegate to extracted validation function
        return is_valid_domain_name(domain)

    def _validate_parameter_combinations(self, strategy: NormalizedStrategy) -> None:
        """Validate special parameter combinations and dependencies."""
        # Delegate to extracted validation function
        validate_parameter_combinations(strategy=strategy, logger=self.logger, debug=self.debug)

    def _validate_attack_type_specific_requirements(
        self, attack_type: str, params: Dict[str, Any]
    ) -> None:
        """Validate attack type specific parameter requirements."""
        # Delegate to extracted validation function
        validate_attack_type_specific_requirements(attack_type, params, self.logger)

    def load_strategies_from_file(
        self, file_path: Union[str, Path]
    ) -> Dict[str, NormalizedStrategy]:
        """
        Load multiple strategies from a JSON file.

        Args:
            file_path: Path to JSON file containing strategies

        Returns:
            Dict mapping domain/key to normalized strategy

        Raises:
            StrategyLoadError: If file cannot be loaded
        """
        # Delegate to extracted file operations function
        try:
            return load_strategies_from_file_impl(
                file_path=file_path,
                load_strategy_func=self.load_strategy,
                logger=self.logger,
                debug=self.debug,
            )
        except (FileNotFoundError, json.JSONDecodeError, StrategyLoadError) as e:
            raise StrategyLoadError(f"Failed to load strategies from file: {e}") from e

    def normalize_strategy_dict(self, strategy_dict: Dict[str, Any]) -> NormalizedStrategy:
        """Normalize a strategy dictionary to standard format."""
        return normalize_strategy_dict_format(strategy_dict, self.debug, self.logger)

    def get_attack_metadata(self, attack_type: str) -> Optional[Any]:
        """
        Get attack metadata from AttackRegistry.

        Args:
            attack_type: Type of attack

        Returns:
            AttackMetadata object or None if not found
        """
        # Delegate to extracted registry helper function
        registry = getattr(self, "_attack_registry", None)
        return get_attack_metadata_impl(
            attack_type=attack_type,
            attack_registry=registry,
            logger=self.logger,
        )

    def list_available_attacks(self, category: Optional[str] = None) -> List[str]:
        """
        List all available attacks from AttackRegistry.

        Args:
            category: Optional category filter

        Returns:
            List of attack types
        """
        # Delegate to extracted registry helper function
        registry = getattr(self, "_attack_registry", None)
        return list_available_attacks_impl(
            attack_registry=registry,
            known_attacks=self.known_attacks,
            logger=self.logger,
            category=category,
        )

    def get_attack_aliases(self, attack_type: str) -> List[str]:
        """
        Get all aliases for an attack type.

        Args:
            attack_type: Type of attack

        Returns:
            List of aliases
        """
        # Delegate to extracted registry helper function
        registry = getattr(self, "_attack_registry", None)
        return get_attack_aliases_impl(
            attack_type=attack_type,
            attack_registry=registry,
            logger=self.logger,
        )

    def validate_attack_parameters(self, attack_type: str, params: Dict[str, Any]) -> bool:
        """
        Validate parameters for a specific attack type using AttackRegistry.

        Args:
            attack_type: Type of attack
            params: Parameters to validate

        Returns:
            True if valid, raises StrategyValidationError if not
        """
        # Delegate to extracted registry helper function
        registry = getattr(self, "_attack_registry", None)
        try:
            return validate_attack_parameters_with_registry(
                attack_type=attack_type,
                params=params,
                attack_registry=registry,
                known_attacks=self.known_attacks,
                required_params=self.required_params,
                logger=self.logger,
            )
        except (KeyError, ValueError, TypeError) as e:
            raise StrategyValidationError(f"Parameter validation failed: {e}") from e

    def _legacy_validate_attack_parameters(self, attack_type: str, params: Dict[str, Any]) -> bool:
        """Legacy parameter validation for backward compatibility."""
        # Delegate to extracted registry helper function
        try:
            return legacy_validate_attack_parameters_impl(
                attack_type=attack_type,
                params=params,
                known_attacks=self.known_attacks,
                required_params=self.required_params,
            )
        except (KeyError, ValueError) as e:
            raise StrategyValidationError(f"Legacy parameter validation failed: {e}") from e

    def is_attack_supported(self, attack_type: str) -> bool:
        """
        Check if an attack type is supported.

        Args:
            attack_type: Type of attack to check

        Returns:
            True if supported, False otherwise
        """
        # Delegate to extracted registry helper function
        registry = getattr(self, "_attack_registry", None)
        return is_attack_supported_impl(
            attack_type=attack_type,
            attack_registry=registry,
            known_attacks=self.known_attacks,
            logger=self.logger,
        )

    def get_attack_handler(self, attack_type: str) -> Optional[Any]:
        """
        Get attack handler from AttackRegistry.

        Args:
            attack_type: Type of attack

        Returns:
            Attack handler function or None if not found
        """
        # Delegate to extracted registry helper function
        registry = getattr(self, "_attack_registry", None)
        return get_attack_handler_impl(
            attack_type=attack_type,
            attack_registry=registry,
            logger=self.logger,
        )

    def refresh_registry_integration(self) -> bool:
        """
        Refresh the integration with AttackRegistry.

        This method can be called to re-sync with AttackRegistry
        if new attacks have been registered.

        Returns:
            True if refresh was successful, False otherwise
        """
        try:
            # Clear cached registry reference
            self._attack_registry = None

            # Re-enhance with registry data
            self._enhance_with_registry()

            if self.debug:
                self.logger.debug("Successfully refreshed AttackRegistry integration")

            return True

        except (ImportError, AttributeError) as e:
            # Registry unavailable or import failed
            self.logger.error(f"Failed to refresh AttackRegistry integration: {e}")
            return False

    def get_registry_status(self) -> Dict[str, Any]:
        """
        Get status information about AttackRegistry integration.

        Returns:
            Dictionary with status information
        """
        # Delegate to extracted registry helper function
        registry = getattr(self, "_attack_registry", None)
        return get_registry_status_impl(
            attack_registry=registry,
            known_attacks=self.known_attacks,
            required_params=self.required_params,
            logger=self.logger,
        )

    def load_all_strategies(
        self, file_path: str = "domain_strategies.json"
    ) -> Dict[str, NormalizedStrategy]:
        """
        Load all strategies from domain_strategies.json file.

        Args:
            file_path: Path to the strategies JSON file (default: domain_strategies.json)

        Returns:
            Dict mapping domain to normalized strategy

        Raises:
            StrategyLoadError: If file cannot be loaded or parsed
        """
        # Delegate to extracted file operations function
        try:
            return load_all_strategies_from_domain_file(
                file_path=file_path,
                load_strategy_func=self.load_strategy,
                logger=self.logger,
                debug=self.debug,
            )
        except (FileNotFoundError, json.JSONDecodeError, StrategyLoadError) as e:
            raise StrategyLoadError(f"Failed to load all strategies: {e}") from e

    def save_strategy(
        self,
        domain: str,
        strategy: Union[str, Dict[str, Any], NormalizedStrategy],
        file_path: str = "domain_strategies.json",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Save a strategy for a domain to domain_strategies.json file.

        Args:
            domain: Domain name
            strategy: Strategy to save (string, dict, or NormalizedStrategy)
            file_path: Path to the strategies JSON file (default: domain_strategies.json)
            metadata: Optional metadata to save with the strategy (success_rate, latency, etc.)

        Raises:
            StrategyLoadError: If file cannot be written
        """
        # Delegate to extracted file operations function
        try:
            save_strategy_to_file(
                domain=domain,
                strategy=strategy,
                file_path=file_path,
                load_strategy_func=self.load_strategy,
                logger=self.logger,
                debug=self.debug,
                metadata=metadata,
            )
        except (OSError, json.JSONDecodeError, StrategyLoadError) as e:
            raise StrategyLoadError(f"Failed to save strategy: {e}") from e

    def save_all_strategies(
        self,
        strategies: Dict[str, Union[str, Dict[str, Any], NormalizedStrategy]],
        file_path: str = "domain_strategies.json",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Save multiple strategies to domain_strategies.json file.

        Args:
            strategies: Dict mapping domain to strategy
            file_path: Path to the strategies JSON file (default: domain_strategies.json)
            metadata: Optional global metadata

        Raises:
            StrategyLoadError: If file cannot be written
        """
        # Delegate to extracted file operations function
        try:
            save_all_strategies_to_file(
                strategies=strategies,
                file_path=file_path,
                load_strategy_func=self.load_strategy,
                logger=self.logger,
                debug=self.debug,
                metadata=metadata,
            )
        except (OSError, json.JSONDecodeError, StrategyLoadError) as e:
            raise StrategyLoadError(f"Failed to save all strategies: {e}") from e


# Convenience functions for backward compatibility
def load_strategy(
    strategy_input: Union[str, Dict[str, Any]], debug: bool = False
) -> NormalizedStrategy:
    """Convenience function to load a single strategy."""
    loader = UnifiedStrategyLoader(debug=debug)
    return loader.load_strategy(strategy_input)


def create_forced_override(
    strategy: Union[NormalizedStrategy, Dict[str, Any]], debug: bool = False
) -> Dict[str, Any]:
    """Convenience function to create forced override."""
    loader = UnifiedStrategyLoader(debug=debug)
    return loader.create_forced_override(strategy)


def load_strategies_from_file(
    file_path: Union[str, Path], debug: bool = False
) -> Dict[str, NormalizedStrategy]:
    """Convenience function to load strategies from file."""
    loader = UnifiedStrategyLoader(debug=debug)
    return loader.load_strategies_from_file(file_path)
