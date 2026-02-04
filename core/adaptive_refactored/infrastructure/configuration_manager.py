"""
Configuration Manager implementation for the refactored Adaptive Engine.

This component manages all configuration aspects with validation and type safety.
"""

import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from ..interfaces import IConfigurationManager
from ..config import (
    AdaptiveEngineConfig,
    StrategyConfig,
    TestingConfig,
    CacheConfig,
    AnalyticsConfig,
    NetworkingConfig,
    ErrorHandlingConfig,
)
from ..models import ValidationError


logger = logging.getLogger(__name__)


class ConfigurationManager(IConfigurationManager):
    """
    Implementation of configuration management with validation and type safety.

    Provides centralized configuration management with validation,
    type safety, and support for configuration reloading.
    """

    def __init__(self, config: AdaptiveEngineConfig, config_path: Optional[str] = None):
        self._config = config
        self._config_path = config_path
        self._validation_errors: List[ValidationError] = []
        self._validate_on_init()

    def _validate_on_init(self) -> None:
        """Validate configuration on initialization."""
        errors = self.validate_configuration()
        if errors:
            logger.warning(f"Configuration validation found {len(errors)} issues")
            for error in errors:
                logger.warning(f"Config validation: {error.field} - {error.message}")
        else:
            logger.info("Configuration validation passed")

    def get_strategy_config(self) -> StrategyConfig:
        """Get strategy configuration."""
        return self._config.strategy

    def get_testing_config(self) -> TestingConfig:
        """Get testing configuration."""
        return self._config.testing

    def get_cache_config(self) -> CacheConfig:
        """Get cache configuration."""
        return self._config.caching

    def get_analytics_config(self) -> AnalyticsConfig:
        """Get analytics configuration."""
        return self._config.analytics

    def get_networking_config(self) -> NetworkingConfig:
        """Get networking configuration."""
        return self._config.networking

    def get_error_handling_config(self) -> ErrorHandlingConfig:
        """Get error handling configuration."""
        return self._config.error_handling

    @property
    def config(self) -> AdaptiveEngineConfig:
        """Get the complete configuration object."""
        return self._config

    def validate_configuration(self) -> List[ValidationError]:
        """Validate all configuration and return any errors."""
        validation_errors = []

        # Validate main configuration
        config_errors = self._config.validate()
        for error in config_errors:
            validation_errors.append(
                ValidationError(
                    field=error, message="Configuration validation failed", severity="error"
                )
            )

        # Additional cross-component validation
        validation_errors.extend(self._validate_cross_component_constraints())

        self._validation_errors = validation_errors
        return validation_errors

    def _validate_cross_component_constraints(self) -> List[ValidationError]:
        """Validate constraints that span multiple configuration components."""
        errors = []

        # Validate that parallel workers don't exceed reasonable limits
        strategy_workers = self._config.strategy.max_parallel_workers
        testing_workers = self._config.testing.max_parallel_workers
        total_workers = strategy_workers + testing_workers

        if total_workers > 20:  # Reasonable limit
            errors.append(
                ValidationError(
                    field="parallel_workers",
                    message=f"Total parallel workers ({total_workers}) may be too high",
                    severity="warning",
                    suggested_fix="Consider reducing max_parallel_workers in strategy or testing config",
                )
            )

        # Validate cache sizes vs memory limits
        total_cache_size = (
            self._config.caching.fingerprint_cache_size
            + self._config.caching.strategy_cache_size
            + self._config.caching.domain_cache_size
            + self._config.caching.metrics_cache_size
        )

        if total_cache_size > 10000:  # Reasonable limit
            errors.append(
                ValidationError(
                    field="cache_sizes",
                    message=f"Total cache entries ({total_cache_size}) may consume excessive memory",
                    severity="warning",
                    suggested_fix="Consider reducing individual cache sizes",
                )
            )

        # Validate timeout relationships
        if self._config.testing.connection_timeout >= self._config.testing.strategy_timeout:
            errors.append(
                ValidationError(
                    field="timeouts",
                    message="Connection timeout should be less than strategy timeout",
                    severity="error",
                    suggested_fix="Set connection_timeout < strategy_timeout",
                )
            )

        return errors

    def reload_configuration(self) -> None:
        """Reload configuration from source."""
        if not self._config_path:
            logger.warning("No config path specified, cannot reload")
            return

        try:
            config_file = Path(self._config_path)
            if not config_file.exists():
                logger.error(f"Config file not found: {self._config_path}")
                return

            with open(config_file, "r") as f:
                config_dict = json.load(f)

            new_config = AdaptiveEngineConfig.from_dict(config_dict)

            # Validate new configuration
            old_config = self._config
            self._config = new_config
            errors = self.validate_configuration()

            if any(error.severity == "error" for error in errors):
                # Revert to old configuration if validation fails
                self._config = old_config
                logger.error("Configuration reload failed validation, reverted to previous config")
                return

            logger.info(f"Configuration reloaded from {self._config_path}")

        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")

    def get_full_config(self) -> AdaptiveEngineConfig:
        """Get the complete configuration object."""
        return self._config

    def update_config(self, config_updates: Dict[str, Any]) -> bool:
        """Update configuration with new values."""
        try:
            # Create a copy of current config as dict
            current_dict = self._config.to_dict()

            # Apply updates
            self._deep_update(current_dict, config_updates)

            # Create new config from updated dict
            new_config = AdaptiveEngineConfig.from_dict(current_dict)

            # Validate new configuration
            old_config = self._config
            self._config = new_config
            errors = self.validate_configuration()

            if any(error.severity == "error" for error in errors):
                # Revert to old configuration if validation fails
                self._config = old_config
                logger.error("Configuration update failed validation")
                return False

            logger.info("Configuration updated successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to update configuration: {e}")
            return False

    def _deep_update(self, base_dict: Dict[str, Any], updates: Dict[str, Any]) -> None:
        """Deep update dictionary with nested updates."""
        for key, value in updates.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def export_config(self, file_path: str) -> bool:
        """Export current configuration to file."""
        try:
            config_dict = self._config.to_dict()

            with open(file_path, "w") as f:
                json.dump(config_dict, f, indent=2, default=str)

            logger.info(f"Configuration exported to {file_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export configuration: {e}")
            return False

    def get_validation_summary(self) -> Dict[str, Any]:
        """Get summary of validation results."""
        errors_by_severity = {}
        for error in self._validation_errors:
            severity = error.severity
            if severity not in errors_by_severity:
                errors_by_severity[severity] = []
            errors_by_severity[severity].append(
                {
                    "field": error.field,
                    "message": error.message,
                    "suggested_fix": error.suggested_fix,
                }
            )

        return {
            "total_errors": len(self._validation_errors),
            "errors_by_severity": errors_by_severity,
            "is_valid": not any(error.severity == "error" for error in self._validation_errors),
        }
