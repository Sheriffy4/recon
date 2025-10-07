"""
Performance Profiler for Attack Validation Suite

This module provides profiling and optimization utilities for the validation suite,
including baseline manager, real domain tester, and CLI validation orchestrator.

Part of Phase 8: Performance Optimization
"""

import time
import cProfile
import pstats
import io
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Callable, List
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from contextlib import contextmanager


logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """Performance metrics for a profiled operation."""
    operation_name: str
    execution_time: float
    call_count: int = 1
    memory_usage: Optional[float] = None
    cpu_time: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'operation_name': self.operation_name,
            'execution_time': self.execution_time,
            'call_count': self.call_count,
            'memory_usage': self.memory_usage,
            'cpu_time': self.cpu_time,
            'details': self.details
        }


@dataclass
class ProfileReport:
    """Complete profiling report."""
    timestamp: str
    component: str
    metrics: List[PerformanceMetrics] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp,
            'component': self.component,
            'metrics': [m.to_dict() for m in self.metrics],
            'summary': self.summary,
            'recommendations': self.recommendations
        }
    
    def save_to_file(self, output_path: Path):
        """Save report to JSON file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2)


class PerformanceProfiler:
    """
    Performance profiler for validation suite components.
    
    Features:
    - Execution time measurement
    - Memory usage tracking
    - CPU profiling
    - Bottleneck identification
    - Optimization recommendations
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize performance profiler.
        
        Args:
            output_dir: Directory for profiling reports
        """
        if output_dir is None:
            output_dir = Path.cwd() / "profiling_results"
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
        self.metrics: List[PerformanceMetrics] = []
    
    @contextmanager
    def profile_operation(self, operation_name: str):
        """
        Context manager for profiling an operation.
        
        Args:
            operation_name: Name of the operation being profiled
        
        Yields:
            PerformanceMetrics object that will be populated
        """
        metrics = PerformanceMetrics(
            operation_name=operation_name,
            execution_time=0.0
        )
        
        start_time = time.time()
        
        try:
            yield metrics
        finally:
            metrics.execution_time = time.time() - start_time
            self.metrics.append(metrics)
            
            self.logger.info(
                f"Operation '{operation_name}' completed in {metrics.execution_time:.4f}s"
            )
    
    def profile_function(self, func: Callable, *args, **kwargs) -> tuple[Any, PerformanceMetrics]:
        """
        Profile a function execution.
        
        Args:
            func: Function to profile
            *args: Function arguments
            **kwargs: Function keyword arguments
        
        Returns:
            Tuple of (function result, performance metrics)
        """
        operation_name = f"{func.__module__}.{func.__name__}"
        
        with self.profile_operation(operation_name) as metrics:
            result = func(*args, **kwargs)
        
        return result, metrics
    
    def profile_with_cprofile(
        self,
        func: Callable,
        *args,
        **kwargs
    ) -> tuple[Any, str]:
        """
        Profile a function using cProfile for detailed analysis.
        
        Args:
            func: Function to profile
            *args: Function arguments
            **kwargs: Function keyword arguments
        
        Returns:
            Tuple of (function result, profiling stats string)
        """
        profiler = cProfile.Profile()
        profiler.enable()
        
        result = func(*args, **kwargs)
        
        profiler.disable()
        
        # Get stats
        stats_stream = io.StringIO()
        stats = pstats.Stats(profiler, stream=stats_stream)
        stats.strip_dirs()
        stats.sort_stats('cumulative')
        stats.print_stats(20)  # Top 20 functions
        
        return result, stats_stream.getvalue()
    
    def measure_memory_usage(self) -> Optional[float]:
        """
        Measure current memory usage in MB.
        
        Returns:
            Memory usage in MB or None if psutil not available
        """
        try:
            import psutil
            import os
            
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()
            return memory_info.rss / (1024 * 1024)  # Convert to MB
        except ImportError:
            self.logger.warning("psutil not available, cannot measure memory usage")
            return None
    
    def generate_report(
        self,
        component: str,
        include_recommendations: bool = True
    ) -> ProfileReport:
        """
        Generate profiling report.
        
        Args:
            component: Name of component being profiled
            include_recommendations: Whether to include optimization recommendations
        
        Returns:
            Profile report
        """
        report = ProfileReport(
            timestamp=datetime.now().isoformat(),
            component=component,
            metrics=self.metrics.copy()
        )
        
        # Calculate summary statistics
        if self.metrics:
            total_time = sum(m.execution_time for m in self.metrics)
            avg_time = total_time / len(self.metrics)
            max_time = max(m.execution_time for m in self.metrics)
            min_time = min(m.execution_time for m in self.metrics)
            
            report.summary = {
                'total_operations': len(self.metrics),
                'total_time': total_time,
                'average_time': avg_time,
                'max_time': max_time,
                'min_time': min_time,
                'slowest_operation': max(self.metrics, key=lambda m: m.execution_time).operation_name
            }
        
        # Generate recommendations
        if include_recommendations:
            report.recommendations = self._generate_recommendations(report)
        
        return report
    
    def save_report(self, report: ProfileReport, filename: Optional[str] = None) -> Path:
        """
        Save profiling report to file.
        
        Args:
            report: Profile report to save
            filename: Optional custom filename
        
        Returns:
            Path to saved report file
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"profile_report_{report.component}_{timestamp}.json"
        
        output_path = self.output_dir / filename
        report.save_to_file(output_path)
        
        self.logger.info(f"Profile report saved to: {output_path}")
        
        return output_path
    
    def clear_metrics(self):
        """Clear collected metrics."""
        self.metrics.clear()
    
    def _generate_recommendations(self, report: ProfileReport) -> List[str]:
        """Generate optimization recommendations based on metrics."""
        recommendations = []
        
        # Check for slow operations
        if report.summary.get('max_time', 0) > 1.0:
            slowest = report.summary.get('slowest_operation', 'unknown')
            recommendations.append(
                f"Operation '{slowest}' took {report.summary['max_time']:.2f}s. "
                "Consider optimization or caching."
            )
        
        # Check for repeated operations
        operation_counts = {}
        for metric in report.metrics:
            operation_counts[metric.operation_name] = operation_counts.get(metric.operation_name, 0) + 1
        
        for op_name, count in operation_counts.items():
            if count > 10:
                recommendations.append(
                    f"Operation '{op_name}' called {count} times. "
                    "Consider batching or caching."
                )
        
        # Check average time
        if report.summary.get('average_time', 0) > 0.5:
            recommendations.append(
                f"Average operation time is {report.summary['average_time']:.2f}s. "
                "Consider parallel execution or optimization."
            )
        
        return recommendations


def profile_decorator(profiler: PerformanceProfiler):
    """
    Decorator for profiling functions.
    
    Args:
        profiler: PerformanceProfiler instance
    
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            operation_name = f"{func.__module__}.{func.__name__}"
            
            with profiler.profile_operation(operation_name):
                return func(*args, **kwargs)
        
        return wrapper
    
    return decorator
