"""
Configuration Loader for Results Validation System.

Extracted from results_validation_system.py to reduce god class complexity.
Handles loading, merging, and validating configuration files.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any

LOG = logging.getLogger("ValidationConfigLoader")


class ValidationConfigLoader:
    """Loads and manages validation system configuration."""

    @staticmethod
    def get_default_config() -> Dict[str, Any]:
        """
        Get default configuration for validation system.

        Returns:
            Dictionary with default configuration values
        """
        return {
            "results_dir": "validation_results",
            "strategy_validation": {
                "enabled": True,
                "test_count_per_strategy": 5,
                "success_threshold": 0.8,
                "consistency_threshold": 0.7,
                "timeout_seconds": 30,
            },
            "fingerprint_validation": {
                "enabled": True,
                "accuracy_threshold": 0.75,
                "confidence_threshold": 0.6,
                "test_domains_count": 10,
            },
            "ab_testing": {
                "enabled": True,
                "sample_size": 20,
                "significance_level": 0.05,
                "minimum_effect_size": 0.1,
            },
            "quality_metrics": {
                "enabled": True,
                "collection_interval_hours": 24,
                "retention_days": 30,
                "alert_thresholds": {
                    "success_rate": 0.7,
                    "avg_trials": 10,
                    "fingerprint_accuracy": 0.6,
                },
            },
        }

    @staticmethod
    def merge_configs(default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge user configuration with default configuration.

        Args:
            default: Default configuration dictionary
            user: User-provided configuration dictionary

        Returns:
            Merged configuration dictionary
        """
        # Deep-merge dictionaries to avoid forcing users to duplicate entire sections.
        merged: Dict[str, Any] = dict(default)
        for key, value in (user or {}).items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = ValidationConfigLoader.merge_configs(merged[key], value)
            else:
                merged[key] = value
        return merged

    def load_config(self, config_file: str) -> Dict[str, Any]:
        """
        Load validation configuration from file.

        Args:
            config_file: Path to configuration file

        Returns:
            Configuration dictionary (merged with defaults)
        """
        config_path = Path(config_file)
        default_config = self.get_default_config()

        if not config_path.exists():
            LOG.info(f"Config file {config_file} not found, using defaults")
            return default_config

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                merged_config = self.merge_configs(default_config, user_config)
                LOG.info(f"Configuration loaded from {config_file}")
                return merged_config

        except json.JSONDecodeError as e:
            LOG.warning(f"Invalid JSON in config file {config_file}: {e}. Using defaults.")
            return default_config

        except (IOError, OSError) as e:
            LOG.warning(f"Failed to read config file {config_file}: {e}. Using defaults.")
            return default_config
