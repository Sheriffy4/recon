"""
Filtering configuration and management utilities.

This module provides filtering mode management, domain extraction failure handling,
and runtime filtering configuration. Extracted from base_engine.py to reduce
god class complexity.
"""

import logging
import time
from typing import Any, Dict, Optional, Set


class FilteringManager:
    """
    Manages filtering modes and domain extraction failure handling.

    This class encapsulates filtering configuration logic including:
    - Domain-based filtering enable/disable
    - Runtime filtering enable/disable
    - Domain extraction failure tracking and automatic fallback
    - Configuration rollback
    """

    def __init__(
        self,
        logger: logging.Logger,
        domain_extraction_failure_threshold: int = 10,
    ):
        self.logger = logger
        self._domain_extraction_failures = 0
        self._domain_extraction_failure_threshold = domain_extraction_failure_threshold
        self._domain_extraction_success_count = 0
        self._last_domain_extraction_failure_time = 0

    def handle_domain_extraction_failure(
        self,
        domain_strategy_engine_ref: Dict[str, Any],
        use_domain_based_filtering_ref: Dict[str, bool],
    ) -> None:
        """
        Handle domain extraction failure and implement automatic fallback logic.

        If domain extraction fails repeatedly, automatically fall back to legacy
        IP-based filtering to maintain system stability.

        Args:
            domain_strategy_engine_ref: Reference dict with 'value' key for engine
            use_domain_based_filtering_ref: Reference dict with 'value' key for flag
        """
        self._domain_extraction_failures += 1
        self._last_domain_extraction_failure_time = time.time()

        if self._domain_extraction_failures >= self._domain_extraction_failure_threshold:
            self.logger.error(
                f"❌ Domain extraction failed {self._domain_extraction_failures} times consecutively"
            )
            self.logger.error("🔄 Automatically falling back to legacy IP-based filtering")

            # Disable domain-based filtering
            domain_strategy_engine_ref["value"] = None
            use_domain_based_filtering_ref["value"] = False

            # Reset failure counter
            self._domain_extraction_failures = 0

            self.logger.warning(
                "⚠️ AUTOMATIC FALLBACK: Domain-based filtering disabled due to repeated failures"
            )
            self.logger.info("   System will continue using legacy IP-based filtering")
            self.logger.info(
                "   To re-enable domain filtering, restart the service or call enable_domain_based_filtering()"
            )

    def handle_domain_extraction_success(self) -> None:
        """
        Handle successful domain extraction.

        Resets failure counters when domain extraction succeeds.
        """
        if self._domain_extraction_failures > 0:
            self.logger.debug(
                f"Domain extraction recovered after {self._domain_extraction_failures} failures"
            )
            self._domain_extraction_failures = 0

        self._domain_extraction_success_count += 1

    def get_filtering_mode(
        self,
        use_domain_based_filtering: bool,
        domain_strategy_engine: Any,
        use_runtime_filtering: bool,
        runtime_filter: Any,
    ) -> str:
        """
        Get current filtering mode.

        Args:
            use_domain_based_filtering: Whether domain-based filtering is enabled
            domain_strategy_engine: Domain strategy engine instance
            use_runtime_filtering: Whether runtime filtering is enabled
            runtime_filter: Runtime filter instance

        Returns:
            String describing current filtering mode
        """
        if use_domain_based_filtering and domain_strategy_engine:
            return "domain-based"
        elif use_runtime_filtering and runtime_filter:
            return "runtime-filtering"
        else:
            return "legacy-ip-based"

    def reset_failure_counters(self) -> None:
        """Reset all failure tracking counters."""
        self._domain_extraction_failures = 0
        self._domain_extraction_success_count = 0
        self._last_domain_extraction_failure_time = 0

    def get_failure_stats(self) -> Dict[str, Any]:
        """
        Get domain extraction failure statistics.

        Returns:
            Dictionary with failure statistics
        """
        return {
            "total_failures": self._domain_extraction_failures,
            "total_successes": self._domain_extraction_success_count,
            "last_failure_time": self._last_domain_extraction_failure_time,
            "failure_threshold": self._domain_extraction_failure_threshold,
        }


def parse_filter_config(filter_config: Dict[str, Any], FilterMode: Any) -> tuple:
    """
    Parse filter configuration dictionary.

    Args:
        filter_config: Configuration dict with 'mode' and 'domains' keys
        FilterMode: FilterMode enum class

    Returns:
        Tuple of (mode, domains_set)
    """
    mode_str = filter_config.get("mode", "blacklist")
    domains = set(filter_config.get("domains", []))

    if mode_str == "blacklist":
        mode = FilterMode.BLACKLIST
    elif mode_str == "whitelist":
        mode = FilterMode.WHITELIST
    else:
        mode = FilterMode.NONE

    return mode, domains


def load_domains_from_sites_file(sites_file_path: str = "sites.txt") -> Set[str]:
    """
    Load domains from sites.txt file.

    Args:
        sites_file_path: Path to sites file

    Returns:
        Set of domain strings
    """
    try:
        from pathlib import Path

        sites_path = Path(sites_file_path)
        if not sites_path.exists():
            return set()

        domains = set()
        with open(sites_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line)

        return domains

    except Exception:
        return set()
