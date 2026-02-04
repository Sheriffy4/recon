"""
Configuration Rollback Utilities

This module provides utilities for creating configuration rollback points
and managing configuration backups for the bypass engine.

Extracted from base_engine.py to reduce god class complexity and improve testability.
"""

import json
import shutil
import time
import logging
from pathlib import Path
from typing import List, Optional


def create_rollback_point(
    filtering_mode: str,
    domain_based_filtering_enabled: bool,
    logger: logging.Logger,
    config_files: Optional[List[str]] = None,
) -> str:
    """
    Create a rollback point for current configuration.

    This function creates backups of current configuration files that can be
    used to rollback in case of issues with domain-based filtering.

    Args:
        filtering_mode: Current filtering mode (e.g., "domain", "ip", "hybrid")
        domain_based_filtering_enabled: Whether domain-based filtering is enabled
        logger: Logger instance for status messages
        config_files: Optional list of config files to backup (uses defaults if None)

    Returns:
        Path to the rollback directory as string

    Raises:
        Exception: If rollback point creation fails

    Examples:
        >>> logger = logging.getLogger("test")
        >>> rollback_dir = create_rollback_point("domain", True, logger)
        >>> print(f"Rollback created at: {rollback_dir}")
    """
    # Default config files to backup
    if config_files is None:
        config_files = [
            "domain_rules.json",
            "sites.txt",
            "config/engine_config.json",
            "config/feature_flags.json",
            "strategies.txt",
            "domain_strategies.json",
        ]

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    rollback_dir = Path(f"config_rollback_{timestamp}")

    try:
        rollback_dir.mkdir(exist_ok=True)

        # Backup configuration files
        backed_up_files = []
        for config_file in config_files:
            source_path = Path(config_file)
            if source_path.exists():
                dest_path = rollback_dir / source_path.name
                shutil.copy2(source_path, dest_path)
                backed_up_files.append(config_file)

        # Create rollback info file
        rollback_info = {
            "timestamp": timestamp,
            "filtering_mode": filtering_mode,
            "domain_based_filtering_enabled": domain_based_filtering_enabled,
            "backed_up_files": backed_up_files,
            "instructions": [
                "To rollback: copy files from this directory " "back to original locations",
                "Restart the service after rollback",
                "Check logs for any configuration issues",
            ],
        }

        with open(rollback_dir / "rollback_info.json", "w", encoding="utf-8") as f:
            json.dump(rollback_info, f, indent=2)

        logger.info(f"✅ Configuration rollback point created: {rollback_dir}")
        logger.info(f"   Backed up {len(backed_up_files)} configuration files")

        return str(rollback_dir)

    except Exception as e:
        logger.error(f"❌ Failed to create rollback point: {e}")
        raise
