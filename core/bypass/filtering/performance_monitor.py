"""
Performance monitoring for runtime packet filtering.

This module provides comprehensive performance monitoring including:
- Packet processing latency metrics
- Cache hit/miss statistics
- Domain extraction success rates
- Memory usage monitoring
- Performance alerting
"""

import time
import threading
import logging
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from collections import deque, defaultdict
import psutil
import os


logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """Container for performance metrics."""
    
    # Timing metrics (in milliseconds)
    packet_processing_latency: List[float] = field(default_factory=list)
    domain_extraction_latency: List[float] = field(default_factory=list)
    pattern_matching_latency: List[float] = field(default_factory=list)
    
    # Counter metrics
    packets_processed: int = 0
    domains_extracted: int = 0
    extraction_failures: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    
    # Success rates
    sni_extraction_success: int = 0
    sni_extraction_attempts: int = 0
    host_extraction_success: int = 0
    host_extraction_attempts: int = 0
    
    # Memory metrics (in MB)
    memory_usage_samples: List[float] = field(default_factory=list)
    
    # Performance degradation alerts
    alert_count: int = 0
    last_alert_time: Optional[float] = None


class PerformanceMonitor:
    """
    Comprehensive performance monitoring for packet filtering.
    
    This class provides:
    - Real-time performance metrics collection
    - Statistical analysis and alerting
    - Memory usage monitoring
    - Performance dashboard data
    """
    
    def __init__(self, 
                 max_samples: int = 1000,
                 alert_threshold_ms: float = 10.0,
                 memory_alert_threshold_mb: float = 500.0):
        """
        Initialize Performance Monitor.
        
        Args:
            max_samples: Maximum number of latency samples to keep
            alert_threshold_ms: Alert if processing takes longer than this (ms)
            memory_alert_threshold_mb: Alert if memory usage exceeds this (MB)
            
        Requirements: 6.3, 6.4
        """
        self.max_samples = max_samples
        self.alert_threshold_ms = alert_threshold_ms
        self.memory_alert_threshold_mb = memory_alert_threshold_mb
        
        self.metrics = PerformanceMetrics()
        self._lock = threading.RLock()
        
        # Sliding window for recent metrics
        self._recent_latencies = deque(maxlen=max_samples)
        self._recent_memory = deque(maxlen=100)  # Keep last 100 memory samples
        
        # Alert callbacks
        self._alert_callbacks: List[Callable[[str, Dict[str, Any]], None]] = []
        
        # Process info for memory monitoring
        self._process = psutil.Process(os.getpid())
        
        logger.info(f"PerformanceMonitor initialized with alert_threshold={alert_threshold_ms}ms")
    
    def start_packet_processing(self) -> 'PerformanceTimer':
        """
        Start timing packet processing.
        
        Returns:
            Timer context manager for packet processing
            
        Requirements: 6.3
        """
        return PerformanceTimer(self, 'packet_processing')
    
    def start_domain_extraction(self) -> 'PerformanceTimer':
        """
        Start timing domain extraction.
        
        Returns:
            Timer context manager for domain extraction
            
        Requirements: 6.3
        """
        return PerformanceTimer(self, 'domain_extraction')
    
    def start_pattern_matching(self) -> 'PerformanceTimer':
        """
        Start timing pattern matching.
        
        Returns:
            Timer context manager for pattern matching
            
        Requirements: 6.3
        """
        return PerformanceTimer(self, 'pattern_matching')
    
    def record_packet_processed(self) -> None:
        """Record that a packet was processed."""
        with self._lock:
            self.metrics.packets_processed += 1
    
    def record_domain_extracted(self, success: bool = True) -> None:
        """
        Record domain extraction attempt.
        
        Args:
            success: Whether extraction was successful
        """
        with self._lock:
            if success:
                self.metrics.domains_extracted += 1
            else:
                self.metrics.extraction_failures += 1
    
    def record_sni_extraction(self, success: bool) -> None:
        """
        Record SNI extraction attempt.
        
        Args:
            success: Whether SNI extraction was successful
        """
        with self._lock:
            self.metrics.sni_extraction_attempts += 1
            if success:
                self.metrics.sni_extraction_success += 1
    
    def record_host_extraction(self, success: bool) -> None:
        """
        Record Host header extraction attempt.
        
        Args:
            success: Whether Host extraction was successful
        """
        with self._lock:
            self.metrics.host_extraction_attempts += 1
            if success:
                self.metrics.host_extraction_success += 1
    
    def record_cache_hit(self) -> None:
        """Record cache hit."""
        with self._lock:
            self.metrics.cache_hits += 1
    
    def record_cache_miss(self) -> None:
        """Record cache miss."""
        with self._lock:
            self.metrics.cache_misses += 1
    
    def record_latency(self, operation: str, latency_ms: float) -> None:
        """
        Record operation latency.
        
        Args:
            operation: Operation name ('packet_processing', 'domain_extraction', 'pattern_matching')
            latency_ms: Latency in milliseconds
            
        Requirements: 6.3, 6.4
        """
        with self._lock:
            # Add to appropriate metric list
            if operation == 'packet_processing':
                self.metrics.packet_processing_latency.append(latency_ms)
                # Keep only recent samples
                if len(self.metrics.packet_processing_latency) > self.max_samples:
                    self.metrics.packet_processing_latency.pop(0)
            elif operation == 'domain_extraction':
                self.metrics.domain_extraction_latency.append(latency_ms)
                if len(self.metrics.domain_extraction_latency) > self.max_samples:
                    self.metrics.domain_extraction_latency.pop(0)
            elif operation == 'pattern_matching':
                self.metrics.pattern_matching_latency.append(latency_ms)
                if len(self.metrics.pattern_matching_latency) > self.max_samples:
                    self.metrics.pattern_matching_latency.pop(0)
            
            # Add to recent latencies for alerting
            self._recent_latencies.append(latency_ms)
            
            # Check for performance alerts
            if latency_ms > self.alert_threshold_ms:
                self._trigger_alert('high_latency', {
                    'operation': operation,
                    'latency_ms': latency_ms,
                    'threshold_ms': self.alert_threshold_ms
                })
    
    def sample_memory_usage(self) -> float:
        """
        Sample current memory usage.
        
        Returns:
            Memory usage in MB
            
        Requirements: 6.4
        """
        try:
            memory_info = self._process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)  # Convert to MB
            
            with self._lock:
                self.metrics.memory_usage_samples.append(memory_mb)
                # Keep only recent samples
                if len(self.metrics.memory_usage_samples) > self.max_samples:
                    self.metrics.memory_usage_samples.pop(0)
                
                self._recent_memory.append(memory_mb)
            
            # Check for memory alerts
            if memory_mb > self.memory_alert_threshold_mb:
                self._trigger_alert('high_memory', {
                    'memory_mb': memory_mb,
                    'threshold_mb': self.memory_alert_threshold_mb
                })
            
            return memory_mb
            
        except Exception as e:
            logger.warning(f"Error sampling memory usage: {e}")
            return 0.0
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive performance statistics.
        
        Returns:
            Dictionary with performance statistics
            
        Requirements: 6.3, 6.4
        """
        with self._lock:
            stats = {
                # Basic counters
                'packets_processed': self.metrics.packets_processed,
                'domains_extracted': self.metrics.domains_extracted,
                'extraction_failures': self.metrics.extraction_failures,
                'cache_hits': self.metrics.cache_hits,
                'cache_misses': self.metrics.cache_misses,
                
                # Success rates
                'sni_success_rate': self._calculate_success_rate(
                    self.metrics.sni_extraction_success,
                    self.metrics.sni_extraction_attempts
                ),
                'host_success_rate': self._calculate_success_rate(
                    self.metrics.host_extraction_success,
                    self.metrics.host_extraction_attempts
                ),
                'cache_hit_rate': self._calculate_success_rate(
                    self.metrics.cache_hits,
                    self.metrics.cache_hits + self.metrics.cache_misses
                ),
                
                # Latency statistics
                'packet_processing_latency': self._calculate_latency_stats(
                    self.metrics.packet_processing_latency
                ),
                'domain_extraction_latency': self._calculate_latency_stats(
                    self.metrics.domain_extraction_latency
                ),
                'pattern_matching_latency': self._calculate_latency_stats(
                    self.metrics.pattern_matching_latency
                ),
                
                # Memory statistics
                'memory_usage': self._calculate_memory_stats(),
                
                # Alert information
                'alert_count': self.metrics.alert_count,
                'last_alert_time': self.metrics.last_alert_time,
                
                # Configuration
                'alert_threshold_ms': self.alert_threshold_ms,
                'memory_alert_threshold_mb': self.memory_alert_threshold_mb,
                'max_samples': self.max_samples
            }
        
        return stats
    
    def _calculate_success_rate(self, successes: int, total: int) -> float:
        """Calculate success rate as percentage."""
        if total == 0:
            return 0.0
        return (successes / total) * 100.0
    
    def _calculate_latency_stats(self, latencies: List[float]) -> Dict[str, float]:
        """Calculate latency statistics."""
        if not latencies:
            return {
                'count': 0,
                'min_ms': 0.0,
                'max_ms': 0.0,
                'avg_ms': 0.0,
                'p95_ms': 0.0,
                'p99_ms': 0.0
            }
        
        sorted_latencies = sorted(latencies)
        count = len(sorted_latencies)
        
        return {
            'count': count,
            'min_ms': sorted_latencies[0],
            'max_ms': sorted_latencies[-1],
            'avg_ms': sum(sorted_latencies) / count,
            'p95_ms': sorted_latencies[int(count * 0.95)] if count > 0 else 0.0,
            'p99_ms': sorted_latencies[int(count * 0.99)] if count > 0 else 0.0
        }
    
    def _calculate_memory_stats(self) -> Dict[str, float]:
        """Calculate memory usage statistics."""
        if not self.metrics.memory_usage_samples:
            return {
                'current_mb': 0.0,
                'min_mb': 0.0,
                'max_mb': 0.0,
                'avg_mb': 0.0
            }
        
        current_mb = self.sample_memory_usage()
        samples = self.metrics.memory_usage_samples
        
        return {
            'current_mb': current_mb,
            'min_mb': min(samples),
            'max_mb': max(samples),
            'avg_mb': sum(samples) / len(samples)
        }
    
    def add_alert_callback(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """
        Add callback for performance alerts.
        
        Args:
            callback: Function to call when alerts are triggered
        """
        self._alert_callbacks.append(callback)
    
    def _trigger_alert(self, alert_type: str, alert_data: Dict[str, Any]) -> None:
        """
        Trigger performance alert.
        
        Args:
            alert_type: Type of alert ('high_latency', 'high_memory')
            alert_data: Alert details
        """
        current_time = time.time()
        
        # Rate limit alerts (max 1 per minute per type)
        if (self.metrics.last_alert_time and 
            current_time - self.metrics.last_alert_time < 60):
            return
        
        with self._lock:
            self.metrics.alert_count += 1
            self.metrics.last_alert_time = current_time
        
        # Log alert
        logger.warning(f"Performance alert: {alert_type} - {alert_data}")
        
        # Call alert callbacks
        for callback in self._alert_callbacks:
            try:
                callback(alert_type, alert_data)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def reset_metrics(self) -> None:
        """Reset all performance metrics."""
        with self._lock:
            self.metrics = PerformanceMetrics()
            self._recent_latencies.clear()
            self._recent_memory.clear()
        
        logger.info("Performance metrics reset")
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """
        Get data formatted for performance dashboard.
        
        Returns:
            Dictionary with dashboard-ready performance data
        """
        stats = self.get_statistics()
        
        return {
            'summary': {
                'packets_processed': stats['packets_processed'],
                'avg_latency_ms': stats['packet_processing_latency']['avg_ms'],
                'cache_hit_rate': stats['cache_hit_rate'],
                'memory_usage_mb': stats['memory_usage']['current_mb']
            },
            'latency_trends': {
                'packet_processing': list(self._recent_latencies)[-50:],  # Last 50 samples
                'memory_usage': list(self._recent_memory)[-50:]
            },
            'alerts': {
                'total_count': stats['alert_count'],
                'last_alert': stats['last_alert_time']
            },
            'detailed_stats': stats
        }


class PerformanceTimer:
    """
    Context manager for timing operations.
    
    Usage:
        with monitor.start_packet_processing():
            # Process packet
            pass
    """
    
    def __init__(self, monitor: PerformanceMonitor, operation: str):
        """
        Initialize Performance Timer.
        
        Args:
            monitor: PerformanceMonitor instance
            operation: Operation name to time
        """
        self.monitor = monitor
        self.operation = operation
        self.start_time = None
    
    def __enter__(self):
        """Start timing."""
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop timing and record latency."""
        if self.start_time is not None:
            end_time = time.perf_counter()
            latency_ms = (end_time - self.start_time) * 1000.0
            self.monitor.record_latency(self.operation, latency_ms)


# Global performance monitor instance
_global_monitor: Optional[PerformanceMonitor] = None


def get_global_monitor() -> PerformanceMonitor:
    """
    Get or create global performance monitor instance.
    
    Returns:
        Global PerformanceMonitor instance
    """
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = PerformanceMonitor()
    return _global_monitor


def configure_global_monitor(**kwargs) -> PerformanceMonitor:
    """
    Configure global performance monitor with custom settings.
    
    Args:
        **kwargs: Configuration parameters for PerformanceMonitor
        
    Returns:
        Configured global PerformanceMonitor instance
    """
    global _global_monitor
    _global_monitor = PerformanceMonitor(**kwargs)
    return _global_monitor