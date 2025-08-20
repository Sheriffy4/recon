#!/usr/bin/env python3
"""
Segment Performance Optimizer for Native Attack Orchestration.

This module provides comprehensive performance optimization for segment-based
attack execution, including profiling, caching, memory optimization, and
performance monitoring.
"""

import asyncio
import logging
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Callable, Union
from concurrent.futures import ThreadPoolExecutor
import weakref
import gc

from core.bypass.attacks.base import AttackResult, AttackContext

# Optional import to avoid circular dependencies
try:
    from core.bypass.attacks.segment_packet_builder import SegmentPacketBuilder
except ImportError:
    SegmentPacketBuilder = None


@dataclass
class PerformanceMetrics:
    """Performance metrics for segment execution."""
    execution_time: float = 0.0
    packet_construction_time: float = 0.0
    transmission_time: float = 0.0
    memory_usage: int = 0
    segment_count: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    optimization_applied: List[str] = field(default_factory=list)


@dataclass
class OptimizationConfig:
    """Configuration for performance optimizations."""
    enable_packet_caching: bool = True
    enable_memory_pooling: bool = True
    enable_async_execution: bool = True
    enable_batch_processing: bool = True
    max_cache_size: int = 1000
    max_memory_pool_size: int = 10000
    batch_size: int = 10
    profiling_enabled: bool = False
    performance_threshold_ms: float = 100.0


class PacketCache:
    """High-performance cache for packet construction."""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._cache: Dict[str, bytes] = {}
        self._access_order = deque()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
    
    def _generate_key(self, payload: bytes, options: Dict[str, Any]) -> str:
        """Generate cache key from payload and options."""
        # Create a deterministic key from payload and options
        options_str = str(sorted(options.items()))
        payload_hash = hash(payload)
        return f"{payload_hash}:{hash(options_str)}"
    
    def get(self, payload: bytes, options: Dict[str, Any]) -> Optional[bytes]:
        """Get cached packet if available."""
        key = self._generate_key(payload, options)
        
        with self._lock:
            if key in self._cache:
                # Move to end (most recently used)
                self._access_order.remove(key)
                self._access_order.append(key)
                self._hits += 1
                return self._cache[key]
            
            self._misses += 1
            return None
    
    def put(self, payload: bytes, options: Dict[str, Any], packet: bytes):
        """Cache a constructed packet."""
        key = self._generate_key(payload, options)
        
        with self._lock:
            # Remove oldest if at capacity
            if len(self._cache) >= self.max_size and key not in self._cache:
                oldest_key = self._access_order.popleft()
                del self._cache[oldest_key]
            
            self._cache[key] = packet
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = self._hits / total_requests if total_requests > 0 else 0.0
            
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'hits': self._hits,
                'misses': self._misses,
                'hit_rate': hit_rate
            }
    
    def clear(self):
        """Clear the cache."""
        with self._lock:
            self._cache.clear()
            self._access_order.clear()
            self._hits = 0
            self._misses = 0


class MemoryPool:
    """Memory pool for reducing allocation overhead."""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self._pools: Dict[int, deque] = defaultdict(deque)
        self._lock = threading.RLock()
        self._allocated = 0
        self._reused = 0
    
    def get_buffer(self, size: int) -> bytearray:
        """Get a buffer of specified size."""
        # Round up to nearest power of 2 for better pooling
        pool_size = 1 << (size - 1).bit_length()
        
        with self._lock:
            pool = self._pools[pool_size]
            if pool:
                buffer = pool.popleft()
                self._reused += 1
                # Clear the buffer
                buffer[:] = b'\x00' * len(buffer)
                return buffer
            
            # Create new buffer
            self._allocated += 1
            return bytearray(pool_size)
    
    def return_buffer(self, buffer: bytearray):
        """Return buffer to pool."""
        size = len(buffer)
        
        with self._lock:
            pool = self._pools[size]
            if len(pool) < self.max_size // len(self._pools) if self._pools else self.max_size:
                pool.append(buffer)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get memory pool statistics."""
        with self._lock:
            total_buffers = sum(len(pool) for pool in self._pools.values())
            return {
                'total_buffers': total_buffers,
                'pool_sizes': {size: len(pool) for size, pool in self._pools.items()},
                'allocated': self._allocated,
                'reused': self._reused,
                'reuse_rate': self._reused / (self._allocated + self._reused) if (self._allocated + self._reused) > 0 else 0.0
            }


class PerformanceProfiler:
    """Performance profiler for segment execution."""
    
    def __init__(self):
        self._profiles: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.RLock()
        self._enabled = False
    
    def enable(self):
        """Enable profiling."""
        self._enabled = True
    
    def disable(self):
        """Disable profiling."""
        self._enabled = False
    
    def profile(self, operation: str):
        """Context manager for profiling operations."""
        return self._ProfileContext(self, operation)
    
    class _ProfileContext:
        def __init__(self, profiler, operation: str):
            self.profiler = profiler
            self.operation = operation
            self.start_time = None
        
        def __enter__(self):
            if self.profiler._enabled:
                self.start_time = time.perf_counter()
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            if self.profiler._enabled and self.start_time is not None:
                duration = time.perf_counter() - self.start_time
                with self.profiler._lock:
                    self.profiler._profiles[self.operation].append(duration)
    
    def get_stats(self) -> Dict[str, Dict[str, float]]:
        """Get profiling statistics."""
        with self._lock:
            stats = {}
            for operation, times in self._profiles.items():
                if times:
                    stats[operation] = {
                        'count': len(times),
                        'total_time': sum(times),
                        'avg_time': sum(times) / len(times),
                        'min_time': min(times),
                        'max_time': max(times)
                    }
            return stats
    
    def clear(self):
        """Clear profiling data."""
        with self._lock:
            self._profiles.clear()


class SegmentPerformanceOptimizer:
    """
    Main performance optimizer for segment-based attack execution.
    
    Provides:
    - Packet construction caching
    - Memory pooling for reduced allocations
    - Asynchronous execution optimization
    - Batch processing for multiple segments
    - Performance profiling and monitoring
    """
    
    def __init__(self, config: Optional[OptimizationConfig] = None):
        self.config = config or OptimizationConfig()
        self.logger = logging.getLogger(__name__)
        
        # Performance components
        self.packet_cache = PacketCache(self.config.max_cache_size) if self.config.enable_packet_caching else None
        self.memory_pool = MemoryPool(self.config.max_memory_pool_size) if self.config.enable_memory_pooling else None
        self.profiler = PerformanceProfiler()
        
        # Thread pool for async operations
        self._thread_pool = ThreadPoolExecutor(max_workers=4) if self.config.enable_async_execution else None
        
        # Performance monitoring
        self._performance_history: deque = deque(maxlen=1000)
        self._optimization_stats = defaultdict(int)
        
        # Enable profiling if configured
        if self.config.profiling_enabled:
            self.profiler.enable()
    
    def optimize_packet_construction(self, segments: List[Tuple[bytes, int, Dict[str, Any]]], 
                                   packet_builder: Any) -> List[bytes]:
        """
        Optimize packet construction for segments.
        
        Args:
            segments: List of (payload, seq_offset, options) tuples
            packet_builder: Packet builder instance
            
        Returns:
            List of constructed packets
        """
        with self.profiler.profile("packet_construction"):
            packets = []
            cache_hits = 0
            cache_misses = 0
            
            for payload, seq_offset, options in segments:
                # Try cache first if enabled
                if self.packet_cache:
                    cached_packet = self.packet_cache.get(payload, options)
                    if cached_packet:
                        packets.append(cached_packet)
                        cache_hits += 1
                        continue
                    cache_misses += 1
                
                # Construct packet
                if self.config.enable_memory_pooling and self.memory_pool:
                    # Use memory pool for buffer allocation
                    buffer = self.memory_pool.get_buffer(len(payload) + 100)  # Extra space for headers
                    try:
                        packet = packet_builder.build_segment_packet(payload, seq_offset, options, buffer)
                    finally:
                        self.memory_pool.return_buffer(buffer)
                else:
                    packet = packet_builder.build_segment_packet(payload, seq_offset, options)
                
                packets.append(packet)
                
                # Cache the result if enabled
                if self.packet_cache:
                    self.packet_cache.put(payload, options, packet)
            
            # Update optimization stats
            self._optimization_stats['cache_hits'] += cache_hits
            self._optimization_stats['cache_misses'] += cache_misses
            
            return packets
    
    def optimize_segment_execution(self, segments: List[Tuple[bytes, int, Dict[str, Any]]], 
                                 execution_func: Callable) -> PerformanceMetrics:
        """
        Optimize execution of segments with various performance enhancements.
        
        Args:
            segments: List of segments to execute
            execution_func: Function to execute segments
            
        Returns:
            Performance metrics for the execution
        """
        start_time = time.perf_counter()
        metrics = PerformanceMetrics()
        
        try:
            with self.profiler.profile("segment_execution"):
                if self.config.enable_batch_processing and len(segments) > self.config.batch_size:
                    # Process in batches for better performance
                    metrics = self._execute_batched(segments, execution_func)
                elif self.config.enable_async_execution and self._thread_pool:
                    # Async execution for I/O bound operations
                    metrics = self._execute_async(segments, execution_func)
                else:
                    # Standard sequential execution
                    metrics = self._execute_sequential(segments, execution_func)
            
            # Record performance metrics
            execution_time = time.perf_counter() - start_time
            metrics.execution_time = execution_time
            metrics.segment_count = len(segments)
            
            # Add cache statistics if available
            if self.packet_cache:
                cache_stats = self.packet_cache.get_stats()
                metrics.cache_hits = cache_stats['hits']
                metrics.cache_misses = cache_stats['misses']
            
            # Record performance history
            self._performance_history.append(execution_time)
            
            # Check if performance threshold exceeded
            if execution_time * 1000 > self.config.performance_threshold_ms:
                self.logger.warning(f"Segment execution exceeded threshold: {execution_time*1000:.2f}ms")
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error in optimized segment execution: {e}")
            raise
    
    def _execute_sequential(self, segments: List[Tuple[bytes, int, Dict[str, Any]]], 
                          execution_func: Callable) -> PerformanceMetrics:
        """Execute segments sequentially."""
        metrics = PerformanceMetrics()
        
        for segment in segments:
            execution_func(segment)
        
        metrics.optimization_applied.append("sequential")
        return metrics
    
    def _execute_batched(self, segments: List[Tuple[bytes, int, Dict[str, Any]]], 
                        execution_func: Callable) -> PerformanceMetrics:
        """Execute segments in batches."""
        metrics = PerformanceMetrics()
        batch_size = self.config.batch_size
        
        for i in range(0, len(segments), batch_size):
            batch = segments[i:i + batch_size]
            
            # Process batch
            for segment in batch:
                execution_func(segment)
            
            # Small delay between batches to prevent overwhelming
            if i + batch_size < len(segments):
                time.sleep(0.001)  # 1ms delay
        
        metrics.optimization_applied.append("batched")
        self._optimization_stats['batches_processed'] += (len(segments) + batch_size - 1) // batch_size
        return metrics
    
    def _execute_async(self, segments: List[Tuple[bytes, int, Dict[str, Any]]], 
                      execution_func: Callable) -> PerformanceMetrics:
        """Execute segments asynchronously."""
        metrics = PerformanceMetrics()
        
        # Submit all segments to thread pool
        futures = []
        for segment in segments:
            future = self._thread_pool.submit(execution_func, segment)
            futures.append(future)
        
        # Wait for completion
        for future in futures:
            future.result()  # This will raise any exceptions
        
        metrics.optimization_applied.append("async")
        self._optimization_stats['async_executions'] += len(segments)
        return metrics
    
    def optimize_memory_usage(self):
        """Optimize memory usage by cleaning up caches and pools."""
        with self.profiler.profile("memory_optimization"):
            # Clear old cache entries
            if self.packet_cache:
                cache_stats = self.packet_cache.get_stats()
                if cache_stats['size'] > self.config.max_cache_size * 0.8:
                    # Clear 25% of cache when 80% full
                    self.packet_cache.clear()
                    self._optimization_stats['cache_clears'] += 1
            
            # Force garbage collection
            collected = gc.collect()
            self._optimization_stats['gc_collections'] += 1
            self._optimization_stats['objects_collected'] += collected
            
            self.logger.debug(f"Memory optimization: collected {collected} objects")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        stats = {
            'optimization_config': {
                'packet_caching': self.config.enable_packet_caching,
                'memory_pooling': self.config.enable_memory_pooling,
                'async_execution': self.config.enable_async_execution,
                'batch_processing': self.config.enable_batch_processing,
                'profiling': self.config.profiling_enabled
            },
            'optimization_stats': dict(self._optimization_stats),
            'profiler_stats': self.profiler.get_stats()
        }
        
        # Add cache stats if available
        if self.packet_cache:
            stats['cache_stats'] = self.packet_cache.get_stats()
        
        # Add memory pool stats if available
        if self.memory_pool:
            stats['memory_pool_stats'] = self.memory_pool.get_stats()
        
        # Add performance history
        if self._performance_history:
            history = list(self._performance_history)
            stats['performance_history'] = {
                'count': len(history),
                'avg_time': sum(history) / len(history),
                'min_time': min(history),
                'max_time': max(history),
                'recent_times': history[-10:]  # Last 10 executions
            }
        
        return stats
    
    def benchmark_performance(self, segments: List[Tuple[bytes, int, Dict[str, Any]]], 
                            execution_func: Callable, iterations: int = 10) -> Dict[str, Any]:
        """
        Benchmark segment execution performance.
        
        Args:
            segments: Test segments
            execution_func: Execution function
            iterations: Number of benchmark iterations
            
        Returns:
            Benchmark results
        """
        self.logger.info(f"Starting performance benchmark with {iterations} iterations")
        
        # Clear caches and stats for clean benchmark
        if self.packet_cache:
            self.packet_cache.clear()
        if self.memory_pool:
            self.memory_pool.get_stats()  # Reset counters
        self.profiler.clear()
        
        # Run benchmark
        times = []
        for i in range(iterations):
            start_time = time.perf_counter()
            metrics = self.optimize_segment_execution(segments, execution_func)
            execution_time = time.perf_counter() - start_time
            times.append(execution_time)
            
            # Small delay between iterations
            time.sleep(0.01)
        
        # Calculate statistics
        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)
        
        # Calculate throughput
        total_segments = len(segments) * iterations
        total_time = sum(times)
        throughput = total_segments / total_time if total_time > 0 else 0
        
        benchmark_results = {
            'iterations': iterations,
            'segment_count': len(segments),
            'total_segments_processed': total_segments,
            'execution_times': times,
            'avg_time': avg_time,
            'min_time': min_time,
            'max_time': max_time,
            'throughput_segments_per_sec': throughput,
            'performance_stats': self.get_performance_stats()
        }
        
        self.logger.info(f"Benchmark completed: {throughput:.1f} segments/sec average")
        return benchmark_results
    
    def suggest_optimizations(self, performance_stats: Dict[str, Any]) -> List[str]:
        """
        Suggest performance optimizations based on current statistics.
        
        Args:
            performance_stats: Current performance statistics
            
        Returns:
            List of optimization suggestions
        """
        suggestions = []
        
        # Check cache performance
        if 'cache_stats' in performance_stats:
            cache_stats = performance_stats['cache_stats']
            if cache_stats['hit_rate'] < 0.5:
                suggestions.append("Consider increasing cache size - low hit rate detected")
            if cache_stats['size'] < cache_stats['max_size'] * 0.1:
                suggestions.append("Cache is underutilized - consider reducing cache size")
        
        # Check memory pool performance
        if 'memory_pool_stats' in performance_stats:
            pool_stats = performance_stats['memory_pool_stats']
            if pool_stats['reuse_rate'] < 0.3:
                suggestions.append("Memory pool has low reuse rate - consider adjusting pool sizes")
        
        # Check execution times
        if 'performance_history' in performance_stats:
            history = performance_stats['performance_history']
            if history['avg_time'] > self.config.performance_threshold_ms / 1000:
                suggestions.append("Average execution time exceeds threshold - consider enabling more optimizations")
            if history['max_time'] > history['avg_time'] * 3:
                suggestions.append("High variance in execution times - investigate performance bottlenecks")
        
        # Check optimization usage
        opt_stats = performance_stats.get('optimization_stats', {})
        if not self.config.enable_async_execution and opt_stats.get('async_executions', 0) == 0:
            suggestions.append("Consider enabling async execution for I/O bound operations")
        
        if not self.config.enable_batch_processing and len(suggestions) == 0:
            suggestions.append("Consider enabling batch processing for large segment counts")
        
        return suggestions
    
    def cleanup(self):
        """Clean up resources."""
        if self._thread_pool:
            self._thread_pool.shutdown(wait=True)
        
        if self.packet_cache:
            self.packet_cache.clear()
        
        self.profiler.clear()
        self.logger.info("Performance optimizer cleaned up")


# Global optimizer instance
_global_optimizer: Optional[SegmentPerformanceOptimizer] = None


def get_global_optimizer() -> SegmentPerformanceOptimizer:
    """Get or create global performance optimizer instance."""
    global _global_optimizer
    if _global_optimizer is None:
        _global_optimizer = SegmentPerformanceOptimizer()
    return _global_optimizer


def optimize_segments(
    segments: List[Tuple[bytes, int, Dict[str, Any]]],
    execution_func: Callable
) -> PerformanceMetrics:
    """
    Convenience function to optimize segment execution using global optimizer.
    """
    optimizer = get_global_optimizer()
    return optimizer.optimize_segment_execution(segments, execution_func)
# Export main class
__all__ = [
    "SegmentPerformanceOptimizer",
    "PerformanceMetrics",
    "OptimizationConfig",
    "get_global_optimizer",
    "optimize_segments",
]
           