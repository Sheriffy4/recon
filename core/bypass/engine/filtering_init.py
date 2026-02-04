"""
Runtime Filtering Initialization Utilities

This module provides utilities for initializing runtime packet filtering
components, including RuntimePacketFilter and WinDivertFilterGenerator.

Extracted from base_engine.py to reduce god class complexity and improve testability.
"""

import logging
from pathlib import Path
from typing import Tuple, Optional, Set, Any


def load_domains_from_sites_file(
    sites_file_path: str = "sites.txt", logger: Optional[logging.Logger] = None
) -> Set[str]:
    """
    Load domains from sites.txt file.

    Args:
        sites_file_path: Path to sites.txt file (default: "sites.txt")
        logger: Optional logger instance for status messages

    Returns:
        Set of domains from sites.txt, empty set if file not found

    Examples:
        >>> logger = logging.getLogger("test")
        >>> domains = load_domains_from_sites_file("sites.txt", logger)
        >>> print(f"Loaded {len(domains)} domains")
    """
    domains = set()
    sites_file = Path(sites_file_path)

    if sites_file.exists():
        try:
            with open(sites_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains.add(line.lower())

            if logger:
                logger.info(
                    f"✅ Loaded {len(domains)} domains from {sites_file_path} "
                    f"for runtime filtering"
                )

        except Exception as e:
            if logger:
                logger.warning(f"Failed to load domains from {sites_file_path}: {e}")
    else:
        if logger:
            logger.warning(
                f"{sites_file_path} not found, " f"runtime filtering will use empty domain list"
            )

    return domains


def initialize_runtime_filtering(
    runtime_filter_class: Optional[type],
    filter_config_class: Optional[type],
    windivert_generator_class: Optional[type],
    filter_mode_enum: Optional[type],
    logger: logging.Logger,
    sites_file_path: str = "sites.txt",
) -> Tuple[Optional[Any], Optional[Any], bool]:
    """
    Initialize runtime packet filtering components.

    This function initializes RuntimePacketFilter and WinDivertFilterGenerator
    with domains loaded from sites.txt file.

    Args:
        runtime_filter_class: RuntimePacketFilter class (or None if unavailable)
        filter_config_class: FilterConfig class (or None if unavailable)
        windivert_generator_class: WinDivertFilterGenerator class (or None)
        filter_mode_enum: FilterMode enum (or None if unavailable)
        logger: Logger instance for status messages
        sites_file_path: Path to sites.txt file (default: "sites.txt")

    Returns:
        Tuple of (runtime_filter, windivert_generator, use_runtime_filtering):
        - runtime_filter: Initialized RuntimePacketFilter or None
        - windivert_generator: Initialized WinDivertFilterGenerator or None
        - use_runtime_filtering: Boolean indicating if filtering is enabled

    Examples:
        >>> logger = logging.getLogger("test")
        >>> filter, generator, enabled = initialize_runtime_filtering(
        ...     RuntimePacketFilter, FilterConfig, WinDivertFilterGenerator,
        ...     FilterMode, logger
        ... )
    """
    # Check if all required components are available
    if not all(
        [
            runtime_filter_class,
            filter_config_class,
            windivert_generator_class,
            filter_mode_enum,
        ]
    ):
        logger.warning(
            "Runtime filtering components not available, " "using legacy IP-based filtering"
        )
        return None, None, False

    try:
        # Load domains from sites.txt
        domains = load_domains_from_sites_file(sites_file_path, logger)

        # Initialize with blacklist mode
        default_config = filter_config_class(mode=filter_mode_enum.BLACKLIST, domains=domains)
        runtime_filter = runtime_filter_class(default_config)
        windivert_generator = windivert_generator_class()

        # Simple port-based filtering is now always enabled
        logger.info("Using simple port-based WinDivert filtering " "(no IP list based filtering)")

        logger.info("Runtime packet filtering components initialized")

        return runtime_filter, windivert_generator, False

    except Exception as e:
        logger.warning(f"Failed to initialize runtime filtering: {e}")
        return None, None, False
