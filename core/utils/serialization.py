"""
Serialization utilities for strategy comparison.

Extracted from strategy_comparator.py to eliminate duplication.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)


def save_capture_to_json(
    capture_data: Dict[str, Any],
    output_dir: Path,
    prefix: str,
    domain: str,
    timestamp: str,
) -> None:
    """
    Save capture data to JSON file.

    Args:
        capture_data: Data to save
        output_dir: Output directory
        prefix: Filename prefix
        domain: Domain name
        timestamp: Timestamp string

    Raises:
        IOError: If file write fails
        OSError: If directory creation fails
        json.JSONDecodeError: If JSON encoding fails
    """
    # Be permissive: callers sometimes pass str-like paths.
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / f"{prefix}_{domain}_{timestamp}.json"

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            # Keep capture saving robust even if capture_data contains non-JSON objects.
            json.dump(capture_data, f, indent=2, default=str)

        logger.info(f"Saved {prefix} results to {output_file}")

    except (IOError, OSError, json.JSONDecodeError) as e:
        logger.error(f"Failed to save {prefix} capture results: {e}")
        raise
    """
    Save capture results to JSON file.

    Args:
        capture_data: Dictionary with capture data to save
        output_dir: Directory to save the file
        prefix: Prefix for filename (e.g., 'discovery', 'service')
        domain: Domain name
        timestamp: Timestamp string

    Raises:
        IOError: If file write fails
        OSError: If file system operation fails
        json.JSONDecodeError: If JSON encoding fails
    """
    # Be permissive: callers sometimes pass str-like paths.
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / f"{prefix}_{domain}_{timestamp}.json"

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            # Keep capture saving robust even if capture_data contains non-JSON objects.
            json.dump(capture_data, f, indent=2, default=str)

        logger.info(f"Saved {prefix} results to {output_file}")

    except (IOError, OSError, json.JSONDecodeError) as e:
        logger.error(f"Failed to save {prefix} capture results: {e}")
        raise


def save_json_file(
    data: Dict[str, Any],
    output_file: Path,
    description: str = "data",
    default_handler: Any = str,
) -> None:
    """
    Save data to JSON file with error handling.

    Args:
        data: Dictionary to save
        output_file: Path to output file
        description: Description for logging
        default_handler: Handler for non-serializable objects

    Raises:
        IOError: If file write fails
        OSError: If file system operation fails
        json.JSONDecodeError: If JSON encoding fails
    """
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=default_handler)

        logger.info(f"Saved {description} to {output_file}")

    except (IOError, OSError, json.JSONDecodeError) as e:
        logger.error(f"Failed to save {description}: {e}")
        raise
