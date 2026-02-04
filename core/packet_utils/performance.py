"""Performance monitoring for packet building."""

from typing import Dict, Any
from core.packet_utils.checksum import ChecksumCache


class PerformanceMonitor:
    """Monitors packet building performance metrics."""

    _packets_built = 0
    _total_build_time_ms = 0.0

    @classmethod
    def record_packet_build(cls, build_time_ms: float):
        """
        Record a packet build operation.

        Args:
            build_time_ms: Build time in milliseconds
        """
        cls._packets_built += 1
        cls._total_build_time_ms += build_time_ms

    @classmethod
    def get_performance_stats(cls) -> Dict[str, Any]:
        """
        Get performance statistics.

        Returns:
            Dictionary with performance metrics
        """
        cache_stats = ChecksumCache.get_cache_stats()
        avg_build_time = (
            cls._total_build_time_ms / cls._packets_built if cls._packets_built > 0 else 0.0
        )

        return {
            "checksum_cache_size": cache_stats["cache_size"],
            "checksum_cache_hits": cache_stats["hits"],
            "checksum_cache_misses": cache_stats["misses"],
            "checksum_hit_rate": cache_stats["hit_rate"],
            "packets_built": cls._packets_built,
            "total_build_time_ms": cls._total_build_time_ms,
            "avg_build_time_ms": avg_build_time,
        }

    @classmethod
    def reset_performance_stats(cls):
        """Reset performance statistics."""
        ChecksumCache.clear_cache()
        cls._packets_built = 0
        cls._total_build_time_ms = 0.0
