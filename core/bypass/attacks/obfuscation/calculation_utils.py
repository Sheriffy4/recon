"""
Obfuscation Calculation Utilities

Helper functions for calculating chunk sizes, delays, jitter, and padding
for traffic obfuscation attacks.
"""

import random
from typing import Literal


IntensityLevel = Literal["low", "medium", "high"]


class ObfuscationCalculator:
    """Static utility class for obfuscation calculations."""

    _CHUNK_SIZE_RANGES = {
        "low": (200, 500),
        "medium": (100, 300),
        "high": (50, 150),
    }
    _BASE_DELAY_RANGES = {
        "low": (10, 50),
        "medium": (20, 100),
        "high": (50, 200),
    }
    _JITTER_RANGES = {"low": (-5, 5), "medium": (-20, 20), "high": (-50, 50)}
    _PADDING_RATIOS = {"low": 0.1, "medium": 0.3, "high": 0.5}

    @staticmethod
    def _pick_range(ranges: dict, intensity: str, default: tuple) -> tuple:
        lo, hi = ranges.get(intensity, default)
        lo = int(lo)
        hi = int(hi)
        if hi < lo:
            lo, hi = hi, lo
        # randint requires hi>=lo
        return lo, hi

    @staticmethod
    def get_chunk_size(intensity: IntensityLevel) -> int:
        """
        Get chunk size based on intensity level.

        Args:
            intensity: Intensity level (low, medium, high)

        Returns:
            Random chunk size appropriate for the intensity level
        """
        lo, hi = ObfuscationCalculator._pick_range(
            ObfuscationCalculator._CHUNK_SIZE_RANGES, str(intensity), (200, 500)
        )
        return random.randint(lo, hi)

    @staticmethod
    def get_base_delay(intensity: IntensityLevel) -> int:
        """
        Get base delay in milliseconds based on intensity level.

        Args:
            intensity: Intensity level (low, medium, high)

        Returns:
            Random base delay in milliseconds
        """
        lo, hi = ObfuscationCalculator._pick_range(
            ObfuscationCalculator._BASE_DELAY_RANGES, str(intensity), (10, 50)
        )
        return random.randint(lo, hi)

    @staticmethod
    def calculate_jitter(intensity: IntensityLevel) -> int:
        """
        Calculate timing jitter based on intensity level.

        Args:
            intensity: Intensity level (low, medium, high)

        Returns:
            Random jitter value (can be negative)
        """
        min_jitter, max_jitter = ObfuscationCalculator._pick_range(
            ObfuscationCalculator._JITTER_RANGES, str(intensity), (-10, 10)
        )
        return random.randint(min_jitter, max_jitter)

    @staticmethod
    def calculate_padding_size(original_size: int, intensity: IntensityLevel) -> int:
        """
        Calculate padding size based on original size and intensity.

        Args:
            original_size: Original data size in bytes
            intensity: Intensity level (low, medium, high)

        Returns:
            Padding size in bytes
        """
        size = max(0, int(original_size))
        ratio = ObfuscationCalculator._PADDING_RATIOS.get(str(intensity), 0.2)
        # Keep a small random pad floor to avoid trivially-detectable patterns.
        return int(size * ratio) + random.randint(10, 50)
