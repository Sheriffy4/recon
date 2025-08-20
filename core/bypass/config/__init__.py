"""
Configuration management module for bypass engine modernization.

This module provides:
- Migration tools for existing best_strategy.json files
- New pool-based configuration format
- Configuration validation and error checking
- Configuration backup and restore functionality
"""

from .config_models import (
    PoolConfiguration,
    LegacyConfiguration,
    ConfigurationVersion,
    MigrationResult,
)
from .config_migrator import ConfigurationMigrator
from .config_validator import ConfigurationValidator
from .config_manager import ConfigurationManager
from .backup_manager import BackupManager

__all__ = [
    "PoolConfiguration",
    "LegacyConfiguration",
    "ConfigurationVersion",
    "MigrationResult",
    "ConfigurationMigrator",
    "ConfigurationValidator",
    "ConfigurationManager",
    "BackupManager",
]
