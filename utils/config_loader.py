"""
Utility functions for loading configuration files.
"""

import json
import logging
from pathlib import Path
from typing import Any, Optional

LOG = logging.getLogger("ConfigLoader")


def load_json_config(
    file_path: str | Path, default: Optional[Any] = None, encoding: str = "utf-8"
) -> Any:
    """
    Load JSON configuration from file with error handling.

    Args:
        file_path: Path to JSON file
        default: Default value to return if file doesn't exist or is invalid
        encoding: File encoding (default: utf-8)

    Returns:
        Loaded configuration or default value

    Raises:
        ValueError: If file exists but contains invalid JSON and no default provided
        IOError: If file read fails and no default provided
    """
    file_path = Path(file_path)

    if not file_path.exists():
        if default is not None:
            LOG.debug(f"Config file not found: {file_path}, using default")
            return default
        raise FileNotFoundError(f"Config file not found: {file_path}")

    try:
        with open(file_path, "r", encoding=encoding) as f:
            config = json.load(f)
        LOG.debug(f"Loaded config from {file_path}")
        return config
    except json.JSONDecodeError as e:
        if default is not None:
            LOG.warning(f"Invalid JSON in {file_path}: {e}, using default")
            return default
        raise ValueError(f"Invalid JSON in {file_path}: {e}") from e
    except IOError as e:
        if default is not None:
            LOG.warning(f"Failed to read {file_path}: {e}, using default")
            return default
        raise IOError(f"Failed to read {file_path}: {e}") from e


def save_json_config(
    file_path: str | Path,
    config: Any,
    encoding: str = "utf-8",
    indent: int = 2,
    ensure_ascii: bool = False,
) -> None:
    """
    Save configuration to JSON file.

    Args:
        file_path: Path to JSON file
        config: Configuration to save
        encoding: File encoding (default: utf-8)
        indent: JSON indentation (default: 2)
        ensure_ascii: Whether to escape non-ASCII characters (default: False)

    Raises:
        IOError: If file write fails
        TypeError: If config is not JSON serializable
    """
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(file_path, "w", encoding=encoding) as f:
            json.dump(config, f, indent=indent, ensure_ascii=ensure_ascii)
        LOG.debug(f"Saved config to {file_path}")
    except (IOError, TypeError) as e:
        LOG.error(f"Failed to save config to {file_path}: {e}")
        raise
