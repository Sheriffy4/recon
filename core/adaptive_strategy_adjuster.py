"""
Adaptive Strategy Adjustment Module

This module adjusts strategy parameters based on ClientHello size to ensure
strategies work correctly in both testing mode (small ClientHello) and
production mode (large ClientHello).

Requirements: 18.1, 18.2, 18.3
"""

import logging
from typing import Dict, Any

LOG = logging.getLogger(__name__)


class AdaptiveStrategyAdjuster:
    """
    Adjusts strategy parameters based on ClientHello size.

    This ensures strategies work correctly regardless of ClientHello size,
    preventing false negatives in testing mode.
    """

    # ClientHello size thresholds
    SMALL_CLIENTHELLO = 500  # bytes
    MEDIUM_CLIENTHELLO = 1000  # bytes

    def __init__(self):
        self.logger = LOG
        self._adjustment_count = 0

    def adjust_strategy(self, strategy: Dict[str, Any], clienthello_size: int) -> Dict[str, Any]:
        """
        Adjust strategy parameters based on ClientHello size.

        Args:
            strategy: Strategy configuration dict
            clienthello_size: Size of ClientHello in bytes

        Returns:
            Adjusted strategy configuration
        """
        if clienthello_size <= 0:
            self.logger.warning(
                f"Invalid ClientHello size: {clienthello_size}, skipping adjustment"
            )
            return strategy

        original_strategy = strategy.copy()
        params = strategy.get("params", {})

        # Determine size category
        if clienthello_size < self.SMALL_CLIENTHELLO:
            category = "small"
            self._adjust_for_small_clienthello(params, clienthello_size)
        elif clienthello_size < self.MEDIUM_CLIENTHELLO:
            category = "medium"
            self._adjust_for_medium_clienthello(params, clienthello_size)
        else:
            category = "large"
            # No adjustment needed for large ClientHello
            self.logger.debug(f"Large ClientHello ({clienthello_size} bytes), no adjustment needed")
            return strategy

        strategy["params"] = params
        self._adjustment_count += 1

        self.logger.info(
            f"[OK] Adjusted strategy for {category} ClientHello ({clienthello_size} bytes)"
        )
        self.logger.debug(f"   Original params: {original_strategy.get('params', {})}")
        self.logger.debug(f"   Adjusted params: {params}")

        return strategy

    def _adjust_for_small_clienthello(self, params: Dict[str, Any], size: int):
        """
        Adjust parameters for small ClientHello (<500 bytes).

        Small ClientHello requires minimal splitting to avoid creating
        segments too small for DPI bypass.
        """
        self.logger.info(f"Adjusting for small ClientHello ({size} bytes)")

        # Reduce split count
        if "split_count" in params:
            original = params["split_count"]
            params["split_count"] = min(2, original)
            if original != params["split_count"]:
                self.logger.info(f"   split_count: {original} → {params['split_count']}")

        # Adjust split position
        if "split_pos" in params:
            original = params["split_pos"]
            # For small ClientHello, split at position 1 to create 2 segments
            params["split_pos"] = 1
            if original != params["split_pos"]:
                self.logger.info(f"   split_pos: {original} → {params['split_pos']}")

        # Reduce disorder complexity
        if "disorder_method" in params and params["disorder_method"] == "reverse":
            # Keep reverse for small packets, it's simple
            pass

    def _adjust_for_medium_clienthello(self, params: Dict[str, Any], size: int):
        """
        Adjust parameters for medium ClientHello (500-1000 bytes).

        Medium ClientHello can handle moderate splitting.
        """
        self.logger.info(f"Adjusting for medium ClientHello ({size} bytes)")

        # Moderate split count
        if "split_count" in params:
            original = params["split_count"]
            params["split_count"] = min(4, original)
            if original != params["split_count"]:
                self.logger.info(f"   split_count: {original} → {params['split_count']}")

        # Adjust split position
        if "split_pos" in params:
            original = params["split_pos"]
            # For medium ClientHello, split at position 2
            params["split_pos"] = 2
            if original != params["split_pos"]:
                self.logger.info(f"   split_pos: {original} → {params['split_pos']}")

    def get_stats(self) -> Dict[str, int]:
        """Get adjustment statistics"""
        return {"total_adjustments": self._adjustment_count}
