"""
Capture I/O utilities for saving strategy capture results.

This module provides utilities for saving capture data to JSON files
with consistent naming and structure.
"""

import re
from pathlib import Path
from typing import Dict, Any, Union

from core.utils.serialization import save_capture_to_json


# Regex for sanitizing filenames (compiled once at module level)
_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9.\-]+")


def safe_filename_component(value: str) -> str:
    """
    Sanitize untrusted string for filesystem-safe filenames.

    Removes or replaces characters that are unsafe for filenames,
    ensuring cross-platform compatibility.

    Args:
        value: String to sanitize

    Returns:
        Sanitized string safe for use in filenames

    Note:
        Does not change any public interfaces; used only for artifact names.
    """
    value = (value or "").strip()
    if not value:
        return "unknown"
    return _SAFE_NAME_RE.sub("_", value)


def save_strategy_capture(
    capture_data: Dict[str, Any],
    output_dir: Union[str, Path],
    prefix: str,
    domain: str,
    timestamp: str,
) -> None:
    """
    Save strategy capture results to JSON file with standardized naming.

    Args:
        capture_data: Capture data dictionary (from StrategyCapture.to_dict())
        output_dir: Output directory path
        prefix: File prefix (e.g., "discovery", "service")
        domain: Domain name (will be sanitized for filename)
        timestamp: Timestamp string for filename

    Note:
        This is a thin wrapper around save_capture_to_json that adds
        filename sanitization for the domain component.
    """
    file_domain = safe_filename_component(domain)
    save_capture_to_json(
        capture_data=capture_data,
        output_dir=output_dir,
        prefix=prefix,
        domain=file_domain,
        timestamp=timestamp,
    )
