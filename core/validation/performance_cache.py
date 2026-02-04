"""
Performance Cache for False Positive Validation Fix

This module implements caching for repeated validation decisions to optimize
performance in high-throughput scenarios.

Requirements: All requirements - Performance optimization
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Union
from threading import RLock
from collections import OrderedDict

from core.bypass.validation.validator import ValidationResult
from core.validation.unified_validation_system import UnifiedValidationResult


@dataclass
class CacheEntry:
    """Cache entry for validation results."""

    result: Union[ValidationResult, UnifiedValidationResult]
    timestamp: float
    access_count: int = 0
    last_access: float = field(default_factory=time.time)


class ValidationCache:
    """
    Thread-safe LRU cache for validation results.

    This cache optimizes performance by storing validation decisions for
    repeated HTTP code + telemetry combinations, reducing computational
    overhead in high-throughput scenarios.
    """

    def __init__(
        self,
        max_size: int = 1000,
        ttl_seconds: float = 300.0,  # 5 minutes default TTL
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize the validation cache.

        Args:
            max_size: Maximum number of entries to cache
            ttl_seconds: Time-to-live for cache entries in seconds
            logger: Optional logger instance
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.logger = logger or logging.getLogger("ValidationCache")

        # Thread-safe cache storage
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = RLock()

        # Performance metrics
        self._hits = 0
        self._misses = 0
        self._evictions = 0

        self.logger.info(
            "ValidationCache initialized: max_size=%d, ttl=%.1fs", max_size, ttl_seconds
        )

    def get(
        self, http_code: int, telemetry: Dict[str, Any], strategy_name: str
    ) -> Optional[Union[ValidationResult, UnifiedValidationResult]]:
        """
        Get cached validation result if available and valid.

        Args:
            http_code: HTTP response code
            telemetry: Network telemetry data
            strategy_name: Name of bypass strategy

        Returns:
            Cached validation result if available, None otherwise
        """
        cache_key = self._generate_cache_key(http_code, telemetry, strategy_name)

        with self._lock:
            entry = self._cache.get(cache_key)

            if entry is None:
                self._misses += 1
                return None

            # Check if entry has expired
            if self._is_expired(entry):
                del self._cache[cache_key]
                self._misses += 1
                return None

            # Update access statistics
            entry.access_count += 1
            entry.last_access = time.time()

            # Move to end (most recently used)
            self._cache.move_to_end(cache_key)

            self._hits += 1
            return entry.result

    def put(
        self,
        http_code: int,
        telemetry: Dict[str, Any],
        strategy_name: str,
        result: Union[ValidationResult, UnifiedValidationResult],
    ) -> None:
        """
        Store validation result in cache.

        Args:
            http_code: HTTP response code
            telemetry: Network telemetry data
            strategy_name: Name of bypass strategy
            result: Validation result to cache
        """
        cache_key = self._generate_cache_key(http_code, telemetry, strategy_name)

        with self._lock:
            # Create new cache entry
            entry = CacheEntry(result=result, timestamp=time.time())

            # Add to cache
            self._cache[cache_key] = entry

            # Enforce size limit
            while len(self._cache) > self.max_size:
                # Remove least recently used entry
                oldest_key, _ = self._cache.popitem(last=False)
                self._evictions += 1
                self.logger.debug("Evicted cache entry: %s", oldest_key[:16] + "...")

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            cleared_count = len(self._cache)
            self._cache.clear()
            self.logger.info("Cache cleared: %d entries removed", cleared_count)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics."""
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests) if total_requests > 0 else 0.0

            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "hit_rate": hit_rate,
                "total_requests": total_requests,
            }

    def cleanup_expired(self) -> int:
        """Remove expired entries from cache."""
        with self._lock:
            current_time = time.time()
            expired_keys = []

            for key, entry in self._cache.items():
                if current_time - entry.timestamp > self.ttl_seconds:
                    expired_keys.append(key)

            for key in expired_keys:
                del self._cache[key]

            if expired_keys:
                self.logger.debug("Cleaned up %d expired cache entries", len(expired_keys))

            return len(expired_keys)

    def _generate_cache_key(
        self, http_code: int, telemetry: Dict[str, Any], strategy_name: str
    ) -> str:
        """
        Generate cache key from validation parameters.

        The key includes HTTP code, relevant telemetry metrics, and strategy name
        to ensure cache hits only occur for equivalent validation scenarios.
        """
        # Extract only the relevant telemetry fields for caching
        relevant_telemetry = {
            "server_hellos": telemetry.get("server_hellos", 0),
            "client_hellos": telemetry.get("client_hellos", 0),
            "retransmissions": telemetry.get("retransmissions", 0),
            "total_packets": telemetry.get("total_packets", 0),
        }

        # Create deterministic string representation
        key_data = {
            "http_code": http_code,
            "telemetry": relevant_telemetry,
            "strategy": strategy_name,
        }

        # Generate hash for efficient key comparison
        key_string = str(sorted(key_data.items()))
        return hashlib.md5(key_string.encode(), usedforsecurity=False).hexdigest()

    def _is_expired(self, entry: CacheEntry) -> bool:
        """Check if cache entry has expired."""
        return time.time() - entry.timestamp > self.ttl_seconds


class PerformanceOptimizedValidator:
    """
    Performance-optimized wrapper for validation systems with caching.

    This class provides a high-performance interface to validation systems
    by implementing intelligent caching, batch processing, and optimization
    strategies for high-throughput scenarios.
    """

    def __init__(
        self,
        validator,  # Can be StrategyResultValidator or UnifiedValidationSystem
        cache_size: int = 1000,
        cache_ttl: float = 300.0,
        enable_batch_processing: bool = True,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize performance-optimized validator.

        Args:
            validator: Underlying validation system
            cache_size: Maximum cache size
            cache_ttl: Cache time-to-live in seconds
            enable_batch_processing: Whether to enable batch processing
            logger: Optional logger instance
        """
        self.validator = validator
        self.cache = ValidationCache(cache_size, cache_ttl, logger)
        self.enable_batch_processing = enable_batch_processing
        self.logger = logger or logging.getLogger("PerformanceOptimizedValidator")

        # Performance tracking
        self._validation_times = []
        self._batch_sizes = []

        self.logger.info(
            "PerformanceOptimizedValidator initialized with cache_size=%d, ttl=%.1fs",
            cache_size,
            cache_ttl,
        )

    def validate(
        self,
        http_success: bool,
        http_code: int,
        telemetry: Dict[str, Any],
        strategy_name: str = "unknown",
        **kwargs,
    ) -> Union[ValidationResult, UnifiedValidationResult]:
        """
        Perform cached validation with performance optimization.

        Args:
            http_success: Whether HTTP request succeeded
            http_code: HTTP response code
            telemetry: Network telemetry data
            strategy_name: Name of bypass strategy
            **kwargs: Additional arguments for validation

        Returns:
            Validation result (cached or computed)
        """
        start_time = time.time()

        # Try cache first
        cached_result = self.cache.get(http_code, telemetry, strategy_name)
        if cached_result is not None:
            self.logger.debug("Cache hit for strategy '%s', HTTP %d", strategy_name, http_code)
            return cached_result

        # Cache miss - perform validation
        self.logger.debug("Cache miss for strategy '%s', HTTP %d", strategy_name, http_code)

        # Call appropriate validation method based on validator type
        if hasattr(self.validator, "validate_enhanced"):
            # UnifiedValidationSystem
            result = self.validator.validate_enhanced(
                http_success, http_code, telemetry, strategy_name, **kwargs
            )
        else:
            # StrategyResultValidator
            result = self.validator.validate(
                http_success, http_code, telemetry, strategy_name, **kwargs
            )

        # Cache the result
        self.cache.put(http_code, telemetry, strategy_name, result)

        # Track performance
        validation_time = time.time() - start_time
        self._validation_times.append(validation_time)

        # Keep only recent performance data
        if len(self._validation_times) > 1000:
            self._validation_times = self._validation_times[-500:]

        return result

    def validate_batch(self, validation_requests: list) -> list:
        """
        Perform batch validation with optimizations.

        Args:
            validation_requests: List of validation request dictionaries

        Returns:
            List of validation results
        """
        if not self.enable_batch_processing:
            # Fall back to individual validations
            return [self.validate(**request) for request in validation_requests]

        start_time = time.time()
        results = []
        cache_hits = 0

        # Process batch with cache optimization
        for request in validation_requests:
            http_code = request["http_code"]
            telemetry = request["telemetry"]
            strategy_name = request.get("strategy_name", "unknown")

            # Check cache first
            cached_result = self.cache.get(http_code, telemetry, strategy_name)
            if cached_result is not None:
                results.append(cached_result)
                cache_hits += 1
            else:
                # Perform validation
                result = self.validate(**request)
                results.append(result)

        # Track batch performance
        batch_time = time.time() - start_time
        batch_size = len(validation_requests)
        self._batch_sizes.append(batch_size)

        self.logger.info(
            "Batch validation completed: %d requests, %d cache hits (%.1f%%), %.3fs total",
            batch_size,
            cache_hits,
            (cache_hits / batch_size) * 100,
            batch_time,
        )

        return results

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        cache_stats = self.cache.get_stats()

        # Calculate validation timing statistics
        if self._validation_times:
            avg_time = sum(self._validation_times) / len(self._validation_times)
            min_time = min(self._validation_times)
            max_time = max(self._validation_times)
        else:
            avg_time = min_time = max_time = 0.0

        # Calculate batch statistics
        if self._batch_sizes:
            avg_batch_size = sum(self._batch_sizes) / len(self._batch_sizes)
            total_batches = len(self._batch_sizes)
        else:
            avg_batch_size = 0.0
            total_batches = 0

        return {
            "cache": cache_stats,
            "validation_timing": {
                "average_ms": avg_time * 1000,
                "min_ms": min_time * 1000,
                "max_ms": max_time * 1000,
                "total_validations": len(self._validation_times),
            },
            "batch_processing": {
                "average_batch_size": avg_batch_size,
                "total_batches": total_batches,
                "enabled": self.enable_batch_processing,
            },
        }

    def optimize_cache(self) -> Dict[str, Any]:
        """
        Perform cache optimization and cleanup.

        Returns:
            Optimization results and recommendations
        """
        # Clean up expired entries
        expired_count = self.cache.cleanup_expired()

        # Get current stats
        stats = self.cache.get_stats()

        # Generate optimization recommendations
        recommendations = []

        if stats["hit_rate"] < 0.3:
            recommendations.append("Low cache hit rate - consider increasing cache size or TTL")

        if stats["evictions"] > stats["hits"]:
            recommendations.append("High eviction rate - consider increasing cache size")

        if expired_count > stats["size"] * 0.1:
            recommendations.append("Many expired entries - consider reducing TTL")

        return {
            "expired_cleaned": expired_count,
            "current_stats": stats,
            "recommendations": recommendations,
        }


def create_performance_optimized_validator(
    validator,
    cache_size: int = 1000,
    cache_ttl: float = 300.0,
    enable_batch_processing: bool = True,
    logger: Optional[logging.Logger] = None,
) -> PerformanceOptimizedValidator:
    """
    Factory function for creating performance-optimized validators.

    Args:
        validator: Underlying validation system
        cache_size: Maximum cache size
        cache_ttl: Cache time-to-live in seconds
        enable_batch_processing: Whether to enable batch processing
        logger: Optional logger instance

    Returns:
        Configured PerformanceOptimizedValidator instance
    """
    return PerformanceOptimizedValidator(
        validator, cache_size, cache_ttl, enable_batch_processing, logger
    )
