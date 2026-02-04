"""
Centralized configuration for the Attack Registry system.

This module provides RegistryConfig for managing all configuration
settings for the refactored attack registry components.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set
import logging


@dataclass
class RegistryConfig:
    """
    Centralized configuration for the Attack Registry system.

    This configuration class manages settings for all registry components:
    - Lazy loading behavior
    - Validation settings
    - Logging configuration
    - Discovery paths and exclusions
    - Performance tuning parameters
    """

    # Core behavior settings
    lazy_loading: bool = False
    """Enable lazy loading of external attack modules"""

    validation_enabled: bool = True
    """Enable parameter validation for attacks"""

    # Logging configuration
    log_level: str = "INFO"
    """Logging level for registry operations"""

    # Performance settings
    max_handler_cache_size: int = 100
    """Maximum number of handlers to cache"""

    # Discovery settings
    discovery_paths: List[str] = field(default_factory=lambda: ["core/bypass/attacks"])
    """Paths to search for external attack modules"""

    excluded_modules: Set[str] = field(
        default_factory=lambda: {
            "attack_registry.py",
            "metadata.py",
            "base.py",
            "__init__.py",
            "registry.py",
            "modern_registry.py",
            "dynamic_attack_registry.py",
            "dynamic_attack_registry_old.py",
            "dynamic_attack_registry_fixed.py",
            "registry_adapter.py",
        }
    )
    """Module files to exclude from discovery"""

    # Validation configuration
    strict_validation: bool = False
    """Enable strict parameter validation mode"""

    allow_unknown_params: bool = True
    """Allow parameters not defined in metadata"""

    validate_param_types: bool = True
    """Validate parameter types against metadata"""

    validate_param_ranges: bool = True
    """Validate parameter value ranges"""

    # Lazy loading configuration
    preload_critical_attacks: bool = True
    """Preload critical attacks even in lazy mode"""

    lazy_cache_size: int = 50
    """Cache size for lazy-loaded modules"""

    discovery_timeout: float = 5.0
    """Timeout for module discovery operations"""

    # Priority management
    enable_promotion_tracking: bool = True
    """Track attack promotion history"""

    max_promotion_history: int = 10
    """Maximum promotion history entries per attack"""

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> "RegistryConfig":
        """
        Create configuration from dictionary.

        Args:
            config_dict: Dictionary containing configuration values

        Returns:
            RegistryConfig instance
        """
        # Filter only known fields
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_dict = {k: v for k, v in config_dict.items() if k in valid_fields}

        # Handle special cases for sets and lists
        if "excluded_modules" in filtered_dict and isinstance(
            filtered_dict["excluded_modules"], list
        ):
            filtered_dict["excluded_modules"] = set(filtered_dict["excluded_modules"])

        return cls(**filtered_dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.

        Returns:
            Dictionary representation of configuration
        """
        result = {}
        for field_name, field_def in self.__dataclass_fields__.items():
            value = getattr(self, field_name)

            # Convert sets to lists for JSON serialization
            if isinstance(value, set):
                value = list(value)

            result[field_name] = value

        return result

    def update(self, **kwargs) -> None:
        """
        Update configuration with new values.

        Args:
            **kwargs: Configuration values to update
        """
        valid_fields = {f.name for f in self.__dataclass_fields__.values()}

        for key, value in kwargs.items():
            if key not in valid_fields:
                raise ValueError(f"Unknown configuration field: {key}")

            # Handle special type conversions
            if key == "excluded_modules" and isinstance(value, list):
                value = set(value)

            setattr(self, key, value)

    def get_logger(self, name: str) -> logging.Logger:
        """
        Get a logger with the configured log level.

        Args:
            name: Logger name

        Returns:
            Configured logger instance
        """
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, self.log_level.upper(), logging.INFO))
        return logger

    def validate(self) -> List[str]:
        """
        Validate configuration settings.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Validate log level
        valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in valid_log_levels:
            errors.append(f"Invalid log_level: {self.log_level}. Must be one of {valid_log_levels}")

        # Validate numeric ranges
        if self.max_handler_cache_size <= 0:
            errors.append("max_handler_cache_size must be positive")

        if self.lazy_cache_size <= 0:
            errors.append("lazy_cache_size must be positive")

        if self.discovery_timeout <= 0:
            errors.append("discovery_timeout must be positive")

        if self.max_promotion_history <= 0:
            errors.append("max_promotion_history must be positive")

        # Validate paths
        if not self.discovery_paths:
            errors.append("discovery_paths cannot be empty")

        return errors

    def is_valid(self) -> bool:
        """
        Check if configuration is valid.

        Returns:
            True if configuration is valid
        """
        return len(self.validate()) == 0


# Default configuration instance
DEFAULT_CONFIG = RegistryConfig()
