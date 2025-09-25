#!/usr/bin/env python3
"""
Integrated Performance Optimizer
Combines monitoring, caching, async optimization, and configuration management
to provide comprehensive performance optimization for the recon system.
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional, List, Callable
from pathlib import Path
import threading

# Import our performance components
from core.monitoring.performance_monitor import PerformanceMonitor, get_global_monitor, monitor_operation
from core.caching.smart_cache import get_fingerprint_cache, get_strategy_cache
from core.async.async_optimizer import AsyncOptimizer, get_global_optimizer
from core.config.performance_config import (
    PerformanceConfigManager, 
    get_global_config_manager,
    apply_environment_overrides,
    apply_performance_preset
)

class IntegratedPerformanceOptimizer:
    """
    Integrated performance optimizer that coordinates all performance components.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.config_manager = PerformanceConfigManager(config_path)
        self.config = self.config_manager.get_config()
        
        # Apply environment overrides
        self.config = apply_environment_overrides(self.config)
        
        # Initialize monitoring
        self.monitor = get_global_monitor() if self.config.monitoring.enabled else None
        
        # Initialize caching
        self.fingerprint_cache = get_fingerprint_cache() if self.config.caching.enabled else None
        self.strategy_cache = get_strategy_cache() if self.config.caching.enabled else None
        
        # Initialize async optimizer
        self.async_optimizer = get_global_optimizer() if self.config.async_ops.enabled else None
        
        # Performance tracking
        self.optimization_stats = {
            "cache_optimizations": 0,
            "async_optimizations": 0,
            "monitoring_alerts": 0,
            "config_reloads": 0
        }
        
        # Register config change callback
        self.config_manager.add_change_callback(self._on_config_change)
        
        self.logger.info("Integrated Performance Optimizer initialized")
    
    def _on_config_change(self, new_config):
        """Handle configuration changes."""
        self.config = new_config
        self.optimization_stats["config_reloads"] += 1
        self.logger.info("Configuration reloaded")
        
        # Reconfigure components based on new config
        self._reconfigure_components()
    
    def _reconfigure_components(self):
        """Reconfigure components based on current configuration."""
        # Reconfigure monitoring
        if self.config.monitoring.enabled and not self.monitor:
            self.monitor = get_global_monitor()
            self.monitor.start_monitoring(self.config.monitoring.interval_seconds)
        elif not self.config.monitoring.enabled and self.monitor:
            self.monitor.stop_monitoring()
            self.monitor = None
        
        # Reconfigure caching
        if self.config.caching.enabled:
            if not self.fingerprint_cache:
                self.fingerprint_cache = get_fingerprint_cache()
            if not self.strategy_cache:
                self.strategy_cache = get_strategy_cache()
        
        # Reconfigure async optimizer
        if self.config.async_ops.enabled and not self.async_optimizer:
            self.async_optimizer = get_global_optimizer()
    
    @monitor_operation("optimizer", "fingerprint_with_cache")
    def optimize_fingerprinting(self, domain: str, port: int, fingerprint_func: Callable) -> Dict[str, Any]:
        """
        Optimize fingerprinting with caching and monitoring.
        
        Args:
            domain: Target domain
            port: Target port
            fingerprint_func: Function to perform fingerprinting
            
        Returns:
            Fingerprint result
        """
        if not self.config.fingerprinting.enabled:
            return fingerprint_func()
        
        # Check cache first
        if self.fingerprint_cache and self.config.fingerprinting.cache_results:
            cached_result = self.fingerprint_cache.get_fingerprint(domain, port)
            if cached_result and self.config.fingerprinting.skip_on_cache_hit:
                if self.monitor:
                    self.monitor.record_cache_hit()
                self.optimization_stats["cache_optimizations"] += 1
                return cached_result
        
        # Perform fingerprinting
        start_time = time.time()
        try:
            result = fingerprint_func()
            
            # Cache result if successful
            if (self.fingerprint_cache and 
                self.config.fingerprinting.cache_results and 
                result.get("confidence", 0) > 0.3):
                
                self.fingerprint_cache.put_fingerprint(
                    domain, port, result, result.get("confidence", 1.0)
                )
            
            # Record metrics
            if self.monitor:
                duration_ms = (time.time() - start_time) * 1000
                self.monitor.record_operation(
                    "fingerprinter", "fingerprint", duration_ms, True
                )
                if not cached_result:
                    self.monitor.record_cache_miss()
            
            return result
            
        except Exception as e:
            # Record failure
            if self.monitor:
                duration_ms = (time.time() - start_time) * 1000
                self.monitor.record_operation(
                    "fingerprinter", "fingerprint", duration_ms, False, str(e)
                )
            raise
    
    @monitor_operation("optimizer", "bypass_with_cache")
    def optimize_bypass_strategy(self, domain: str, strategy_hash: str, bypass_func: Callable) -> Dict[str, Any]:
        """
        Optimize bypass strategy execution with caching and monitoring.
        
        Args:
            domain: Target domain
            strategy_hash: Hash of the strategy
            bypass_func: Function to execute bypass
            
        Returns:
            Bypass result
        """
        if not self.config.bypass_engine.enabled:
            return bypass_func()
        
        # Check cache first
        if self.strategy_cache:
            cached_result = self.strategy_cache.get_strategy_result(domain, strategy_hash)
            if cached_result:
                if self.monitor:
                    self.monitor.record_cache_hit()
                self.optimization_stats["cache_optimizations"] += 1
                return cached_result
        
        # Execute bypass
        start_time = time.time()
        try:
            result = bypass_func()
            
            # Cache result
            if self.strategy_cache:
                self.strategy_cache.put_strategy_result(domain, strategy_hash, result)
            
            # Record metrics
            if self.monitor:
                duration_ms = (time.time() - start_time) * 1000
                success = result.get("success_rate", 0) > 0
                self.monitor.record_operation(
                    "bypass_engine", "execute_strategy", duration_ms, success
                )
                self.monitor.record_cache_miss()
            
            return result
            
        except Exception as e:
            # Record failure
            if self.monitor:
                duration_ms = (time.time() - start_time) * 1000
                self.monitor.record_operation(
                    "bypass_engine", "execute_strategy", duration_ms, False, str(e)
                )
            raise
    
    async def optimize_async_operation(self, operation: Callable, *args, **kwargs) -> Any:
        """
        Optimize an async operation with proper resource management.
        
        Args:
            operation: Async operation to execute
            *args: Operation arguments
            **kwargs: Operation keyword arguments
            
        Returns:
            Operation result
        """
        if not self.async_optimizer:
            return await operation(*args, **kwargs)
        
        # Use async optimizer for better resource management
        if asyncio.iscoroutinefunction(operation):
            return await operation(*args, **kwargs)
        else:
            # Convert blocking operation to async
            return await self.async_optimizer.run_in_thread(operation, *args, **kwargs)
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report."""
        report = {
            "timestamp": time.time(),
            "config": self.config.to_dict(),
            "optimization_stats": self.optimization_stats.copy()
        }
        
        # Add monitoring data
        if self.monitor:
            current_metrics = self.monitor.get_current_metrics()
            if current_metrics:
                report["current_metrics"] = {
                    "bypass_success_rate": current_metrics.bypass_success_rate,
                    "fingerprint_success_rate": current_metrics.fingerprint_success_rate,
                    "cache_hit_rate": current_metrics.cache_hit_rate,
                    "memory_usage_mb": current_metrics.memory_usage_mb,
                    "cpu_usage_percent": current_metrics.cpu_usage_percent
                }
            
            report["component_summary"] = self.monitor.get_component_summary()
        
        # Add cache statistics
        if self.fingerprint_cache:
            report["fingerprint_cache"] = self.fingerprint_cache.get_info()
        
        if self.strategy_cache:
            report["strategy_cache"] = self.strategy_cache.get_info()
        
        # Add async optimizer stats
        if self.async_optimizer:
            report["async_stats"] = {
                "operation_stats": self.async_optimizer.get_operation_stats(),
                "active_operations": self.async_optimizer.get_active_operations()
            }
        
        return report
    
    def apply_performance_preset(self, preset_name: str):
        """Apply a performance preset."""
        try:
            new_config = apply_performance_preset(self.config, preset_name)
            self.config_manager.update_config(new_config.to_dict())
            self.logger.info(f"Applied performance preset: {preset_name}")
        except Exception as e:
            self.logger.error(f"Error applying preset {preset_name}: {e}")
    
    def optimize_for_regression_fix(self):
        """
        Apply specific optimizations to fix the performance regression
        identified in the analysis.
        """
        self.logger.info("Applying regression fix optimizations...")
        
        # Apply fast preset to reduce timeouts and improve success rates
        regression_fix_config = {
            "fingerprinting": {
                "timeout_seconds": 20.0,  # Reduced from 30s
                "max_concurrent_fingerprints": 3,  # Reduced concurrency
                "analysis_levels": {
                    "basic": True,
                    "advanced": True,
                    "deep": False,  # Disable deep analysis
                    "behavioral": False,  # Disable behavioral analysis
                    "timing": False  # Disable timing analysis
                }
            },
            "bypass_engine": {
                "max_concurrent_bypasses": 10,  # Reduced concurrency
                "strategy_timeout_seconds": 45.0,  # Reduced timeout
                "packet_injection_timeout_seconds": 3.0,  # Reduced injection timeout
                "tcp_retransmission_mitigation": True,  # Enable mitigation
                "packet_validation": True,  # Enable validation
                "performance_mode": "balanced"
            },
            "caching": {
                "enabled": True,
                "max_memory_mb": 150,
                "default_ttl_seconds": 3600
            },
            "monitoring": {
                "enabled": True,
                "interval_seconds": 60.0  # Reduced monitoring frequency
            }
        }
        
        # Update configuration
        self.config_manager.update_config(regression_fix_config)
        
        # Clear caches to ensure fresh data
        if self.fingerprint_cache:
            self.fingerprint_cache.clear()
        if self.strategy_cache:
            self.strategy_cache.clear()
        
        self.logger.info("Regression fix optimizations applied")
    
    def export_performance_data(self, filepath: str):
        """Export performance data for analysis."""
        try:
            report = self.get_performance_report()
            
            # Ensure directory exists
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            
            import json
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            self.logger.info(f"Performance data exported to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error exporting performance data: {e}")
    
    async def cleanup(self):
        """Cleanup all resources."""
        if self.async_optimizer:
            await self.async_optimizer.cleanup()
        
        if self.monitor:
            self.monitor.stop_monitoring()
        
        if self.fingerprint_cache:
            self.fingerprint_cache.stop_cleanup_thread()
        
        if self.strategy_cache:
            self.strategy_cache.stop_cleanup_thread()

# Global optimizer instance
_global_integrated_optimizer: Optional[IntegratedPerformanceOptimizer] = None

def get_integrated_optimizer() -> IntegratedPerformanceOptimizer:
    """Get or create global integrated performance optimizer."""
    global _global_integrated_optimizer
    if _global_integrated_optimizer is None:
        _global_integrated_optimizer = IntegratedPerformanceOptimizer()
    return _global_integrated_optimizer

def optimize_fingerprinting(domain: str, port: int, fingerprint_func: Callable) -> Dict[str, Any]:
    """Global function to optimize fingerprinting."""
    optimizer = get_integrated_optimizer()
    return optimizer.optimize_fingerprinting(domain, port, fingerprint_func)

def optimize_bypass_strategy(domain: str, strategy_hash: str, bypass_func: Callable) -> Dict[str, Any]:
    """Global function to optimize bypass strategy."""
    optimizer = get_integrated_optimizer()
    return optimizer.optimize_bypass_strategy(domain, strategy_hash, bypass_func)

async def optimize_async_operation(operation: Callable, *args, **kwargs) -> Any:
    """Global function to optimize async operations."""
    optimizer = get_integrated_optimizer()
    return await optimizer.optimize_async_operation(operation, *args, **kwargs)

def apply_regression_fix():
    """Apply regression fix optimizations."""
    optimizer = get_integrated_optimizer()
    optimizer.optimize_for_regression_fix()

def get_performance_report() -> Dict[str, Any]:
    """Get global performance report."""
    optimizer = get_integrated_optimizer()
    return optimizer.get_performance_report()

# Context manager for performance optimization
class PerformanceOptimizationContext:
    """Context manager for performance optimization."""
    
    def __init__(self, preset: Optional[str] = None):
        self.preset = preset
        self.optimizer = None
    
    async def __aenter__(self):
        self.optimizer = get_integrated_optimizer()
        
        if self.preset:
            self.optimizer.apply_performance_preset(self.preset)
        
        return self.optimizer
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.optimizer:
            await self.optimizer.cleanup()

# Decorator for automatic performance optimization
def with_performance_optimization(preset: Optional[str] = None):
    """Decorator to apply performance optimization to functions."""
    def decorator(func):
        if asyncio.iscoroutinefunction(func):
            async def async_wrapper(*args, **kwargs):
                async with PerformanceOptimizationContext(preset):
                    return await func(*args, **kwargs)
            return async_wrapper
        else:
            def sync_wrapper(*args, **kwargs):
                optimizer = get_integrated_optimizer()
                if preset:
                    optimizer.apply_performance_preset(preset)
                return func(*args, **kwargs)
            return sync_wrapper
    
    return decorator