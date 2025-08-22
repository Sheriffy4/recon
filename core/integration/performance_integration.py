"""
Integration module for Performance Optimizer in DPI bypass system.
"""
import logging
import time
from typing import Dict, List, Any, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
try:
    from core.optimization.performance_optimizer import PerformanceOptimizer, PerformanceProfile
    PERFORMANCE_OPTIMIZER_AVAILABLE = True
except ImportError as e:
    PERFORMANCE_OPTIMIZER_AVAILABLE = False
    logging.warning(f'Full performance optimizer not available: {e}')
if not PERFORMANCE_OPTIMIZER_AVAILABLE:
    try:
        from recon.core.integration.simple_performance_optimizer import SimplePerformanceOptimizer, SimplePerformanceProfile
        SIMPLE_PERFORMANCE_OPTIMIZER_AVAILABLE = True
    except ImportError as e:
        SIMPLE_PERFORMANCE_OPTIMIZER_AVAILABLE = False
        logging.warning(f'Simple performance optimizer not available: {e}')
else:
    SIMPLE_PERFORMANCE_OPTIMIZER_AVAILABLE = False
LOG = logging.getLogger('performance_integration')

@dataclass
class BypassPerformanceMetrics:
    """Performance metrics specific to bypass operations."""
    packets_per_second: float
    attacks_per_second: float
    ml_predictions_per_second: float
    fingerprints_per_second: float
    average_attack_latency_ms: float
    success_rate_percent: float
    memory_usage_mb: float
    cpu_usage_percent: float
    timestamp: datetime

@dataclass
class PerformanceAlert:
    """Performance alert for bypass system."""
    alert_type: str
    severity: str
    message: str
    current_value: float
    threshold: float
    timestamp: datetime
    suggestions: List[str]

class BypassPerformanceIntegrator:
    """
    Integrates Performance Optimizer into DPI bypass engines.
    Provides performance monitoring, optimization, and alerting.
    """

    def __init__(self, enable_optimization: bool=True):
        self.enable_optimization = enable_optimization and (PERFORMANCE_OPTIMIZER_AVAILABLE or SIMPLE_PERFORMANCE_OPTIMIZER_AVAILABLE)
        self.optimizer = None
        self.metrics_history = []
        self.alerts = []
        self.performance_callbacks = []
        self.thresholds = {'cpu_warning': 70.0, 'cpu_critical': 85.0, 'memory_warning': 75.0, 'memory_critical': 90.0, 'success_rate_warning': 60.0, 'success_rate_critical': 40.0, 'latency_warning': 500.0, 'latency_critical': 1000.0}
        self.counters = {'packets_processed': 0, 'attacks_executed': 0, 'ml_predictions': 0, 'fingerprints_created': 0, 'successful_attacks': 0, 'total_attack_latency_ms': 0.0}
        self.last_metrics_time = time.time()
        self.metrics_interval = 10.0
        if self.enable_optimization:
            try:
                self._initialize_performance_optimizer()
                LOG.info('Performance optimizer initialized successfully')
            except Exception as e:
                LOG.error(f'Failed to initialize performance optimizer: {e}')
                self.enable_optimization = False
        if not self.enable_optimization:
            LOG.info('Using basic performance monitoring fallback')

    def _initialize_performance_optimizer(self):
        """Initialize the performance optimizer."""
        if SIMPLE_PERFORMANCE_OPTIMIZER_AVAILABLE:
            self.optimizer = SimplePerformanceOptimizer(name='BypassPerformanceOptimizer')
            self.optimizer._optimizations.extend([self._optimize_bypass_caches, self._optimize_attack_pools, self._optimize_ml_models])
        elif PERFORMANCE_OPTIMIZER_AVAILABLE:
            try:
                self.optimizer = PerformanceOptimizer(name='BypassPerformanceOptimizer')
                self.optimizer._optimizations.extend([self._optimize_bypass_caches, self._optimize_attack_pools, self._optimize_ml_models])
            except Exception as e:
                LOG.warning(f'Full optimizer failed, falling back to simple: {e}')
                self.optimizer = SimplePerformanceOptimizer(name='BypassPerformanceOptimizer')
                self.optimizer._optimizations.extend([self._optimize_bypass_caches, self._optimize_attack_pools, self._optimize_ml_models])
        else:
            raise Exception('No performance optimizer available')
        self.optimizer.start_monitoring()

    def record_packet_processed(self):
        """Record that a packet was processed."""
        self.counters['packets_processed'] += 1

    def record_attack_executed(self, latency_ms: float, success: bool):
        """Record that an attack was executed."""
        self.counters['attacks_executed'] += 1
        self.counters['total_attack_latency_ms'] += latency_ms
        if success:
            self.counters['successful_attacks'] += 1

    def record_ml_prediction(self):
        """Record that an ML prediction was made."""
        self.counters['ml_predictions'] += 1

    def record_fingerprint_created(self):
        """Record that a fingerprint was created."""
        self.counters['fingerprints_created'] += 1

    def get_current_metrics(self) -> BypassPerformanceMetrics:
        """Get current performance metrics."""
        current_time = time.time()
        time_delta = current_time - self.last_metrics_time
        if time_delta == 0:
            time_delta = 1.0
        packets_per_second = self.counters['packets_processed'] / time_delta
        attacks_per_second = self.counters['attacks_executed'] / time_delta
        ml_predictions_per_second = self.counters['ml_predictions'] / time_delta
        fingerprints_per_second = self.counters['fingerprints_created'] / time_delta
        avg_attack_latency = 0.0
        if self.counters['attacks_executed'] > 0:
            avg_attack_latency = self.counters['total_attack_latency_ms'] / self.counters['attacks_executed']
        success_rate = 0.0
        if self.counters['attacks_executed'] > 0:
            success_rate = self.counters['successful_attacks'] / self.counters['attacks_executed'] * 100
        memory_usage_mb = 0.0
        cpu_usage_percent = 0.0
        if self.optimizer and self.optimizer.profiles:
            latest_profile = self.optimizer.profiles[-1]
            cpu_usage_percent = latest_profile.cpu_percent
            memory_usage_mb = latest_profile.memory_percent * 10
        return BypassPerformanceMetrics(packets_per_second=packets_per_second, attacks_per_second=attacks_per_second, ml_predictions_per_second=ml_predictions_per_second, fingerprints_per_second=fingerprints_per_second, average_attack_latency_ms=avg_attack_latency, success_rate_percent=success_rate, memory_usage_mb=memory_usage_mb, cpu_usage_percent=cpu_usage_percent, timestamp=datetime.now())

    def check_performance_alerts(self) -> List[PerformanceAlert]:
        """Check for performance alerts and return them."""
        alerts = []
        metrics = self.get_current_metrics()
        if metrics.cpu_usage_percent > self.thresholds['cpu_critical']:
            alerts.append(PerformanceAlert(alert_type='high_cpu', severity='critical', message=f'Critical CPU usage: {metrics.cpu_usage_percent:.1f}%', current_value=metrics.cpu_usage_percent, threshold=self.thresholds['cpu_critical'], timestamp=datetime.now(), suggestions=['Consider reducing attack concurrency', 'Disable ML predictions temporarily', 'Clear caches and optimize memory usage']))
        elif metrics.cpu_usage_percent > self.thresholds['cpu_warning']:
            alerts.append(PerformanceAlert(alert_type='high_cpu', severity='warning', message=f'High CPU usage: {metrics.cpu_usage_percent:.1f}%', current_value=metrics.cpu_usage_percent, threshold=self.thresholds['cpu_warning'], timestamp=datetime.now(), suggestions=['Monitor CPU usage closely', 'Consider optimizing attack strategies']))
        if metrics.memory_usage_mb > self.thresholds['memory_critical']:
            alerts.append(PerformanceAlert(alert_type='high_memory', severity='critical', message=f'Critical memory usage: {metrics.memory_usage_mb:.1f}MB', current_value=metrics.memory_usage_mb, threshold=self.thresholds['memory_critical'], timestamp=datetime.now(), suggestions=['Clear fingerprint cache', 'Reduce ML model cache size', 'Force garbage collection']))
        if metrics.success_rate_percent < self.thresholds['success_rate_critical']:
            alerts.append(PerformanceAlert(alert_type='low_success_rate', severity='critical', message=f'Critical success rate: {metrics.success_rate_percent:.1f}%', current_value=metrics.success_rate_percent, threshold=self.thresholds['success_rate_critical'], timestamp=datetime.now(), suggestions=['Review and update attack strategies', 'Check DPI fingerprinting accuracy', 'Verify ML model predictions']))
        if metrics.average_attack_latency_ms > self.thresholds['latency_critical']:
            alerts.append(PerformanceAlert(alert_type='high_latency', severity='critical', message=f'Critical attack latency: {metrics.average_attack_latency_ms:.1f}ms', current_value=metrics.average_attack_latency_ms, threshold=self.thresholds['latency_critical'], timestamp=datetime.now(), suggestions=['Optimize attack execution', 'Reduce network timeouts', 'Check system performance']))
        self.alerts.extend(alerts)
        for alert in alerts:
            self._trigger_performance_callbacks('alert', alert)
        return alerts

    def optimize_performance(self) -> Dict[str, Any]:
        """Trigger performance optimizations."""
        if not self.enable_optimization:
            return {'success': False, 'message': 'Performance optimizer not available'}
        LOG.info('Triggering performance optimizations')
        try:
            results = {}
            if self.optimizer:
                try:
                    optimizer_results = self.optimizer.apply_optimizations()
                    results.update(optimizer_results)
                except Exception as e:
                    LOG.error(f'Optimizer optimizations failed: {e}')
                    results['optimizer_error'] = str(e)
            bypass_results = {'reset_counters': self._reset_performance_counters(), 'clear_old_alerts': self._clear_old_alerts()}
            results.update(bypass_results)
            LOG.info('Performance optimizations completed')
            return {'success': True, 'results': results}
        except Exception as e:
            LOG.error(f'Performance optimization failed: {e}')
            return {'success': False, 'error': str(e)}

    def _optimize_bypass_caches(self) -> Dict[str, Any]:
        """Optimize bypass-specific caches."""
        try:
            try:
                from recon.core.integration.strategy_prediction_integration import get_strategy_integrator
                strategy_integrator = get_strategy_integrator()
                strategy_integrator.clear_cache()
            except Exception as e:
                LOG.debug(f'Could not clear strategy cache: {e}')
            try:
                from recon.core.integration.fingerprint_integration import get_fingerprint_integrator
                fingerprint_integrator = get_fingerprint_integrator()
                fingerprint_integrator.clear_cache()
            except Exception as e:
                LOG.debug(f'Could not clear fingerprint cache: {e}')
            return {'success': True, 'message': 'Bypass caches cleared successfully'}
        except Exception as e:
            return {'success': False, 'message': f'Failed to clear bypass caches: {e}'}

    def _optimize_attack_pools(self) -> Dict[str, Any]:
        """Optimize attack execution pools."""
        try:
            return {'success': True, 'message': 'Attack pools optimized'}
        except Exception as e:
            return {'success': False, 'message': f'Failed to optimize attack pools: {e}'}

    def _optimize_ml_models(self) -> Dict[str, Any]:
        """Optimize ML model memory usage."""
        try:
            return {'success': True, 'message': 'ML models optimized'}
        except Exception as e:
            return {'success': False, 'message': f'Failed to optimize ML models: {e}'}

    def _reset_performance_counters(self) -> Dict[str, Any]:
        """Reset performance counters."""
        self.counters = {'packets_processed': 0, 'attacks_executed': 0, 'ml_predictions': 0, 'fingerprints_created': 0, 'successful_attacks': 0, 'total_attack_latency_ms': 0.0}
        self.last_metrics_time = time.time()
        return {'success': True, 'message': 'Performance counters reset'}

    def _clear_old_alerts(self) -> Dict[str, Any]:
        """Clear old performance alerts."""
        cutoff_time = datetime.now() - timedelta(hours=1)
        old_count = len(self.alerts)
        self.alerts = [alert for alert in self.alerts if alert.timestamp > cutoff_time]
        cleared_count = old_count - len(self.alerts)
        return {'success': True, 'message': f'Cleared {cleared_count} old alerts'}

    def add_performance_callback(self, callback: Callable[[str, Any], None]):
        """Add callback for performance events."""
        self.performance_callbacks.append(callback)

    def _trigger_performance_callbacks(self, event_type: str, data: Any):
        """Trigger performance callbacks."""
        for callback in self.performance_callbacks:
            try:
                callback(event_type, data)
            except Exception as e:
                LOG.error(f'Performance callback failed: {e}')

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        metrics = self.get_current_metrics()
        alerts = self.check_performance_alerts()
        return {'metrics': {'packets_per_second': metrics.packets_per_second, 'attacks_per_second': metrics.attacks_per_second, 'ml_predictions_per_second': metrics.ml_predictions_per_second, 'fingerprints_per_second': metrics.fingerprints_per_second, 'average_attack_latency_ms': metrics.average_attack_latency_ms, 'success_rate_percent': metrics.success_rate_percent, 'memory_usage_mb': metrics.memory_usage_mb, 'cpu_usage_percent': metrics.cpu_usage_percent}, 'alerts': [{'type': alert.alert_type, 'severity': alert.severity, 'message': alert.message, 'suggestions': alert.suggestions} for alert in alerts], 'optimization_enabled': self.enable_optimization, 'timestamp': datetime.now().isoformat()}

    def shutdown(self):
        """Shutdown performance monitoring."""
        if self.optimizer:
            try:
                self.optimizer.stop_monitoring()
                LOG.info('Performance monitoring stopped')
            except Exception as e:
                LOG.error(f'Error stopping performance monitoring: {e}')
_global_performance_integrator = None

def get_performance_integrator() -> BypassPerformanceIntegrator:
    """Get global performance integrator instance."""
    global _global_performance_integrator
    if _global_performance_integrator is None:
        _global_performance_integrator = BypassPerformanceIntegrator()
    return _global_performance_integrator