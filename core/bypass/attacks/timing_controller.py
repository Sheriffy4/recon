#!/usr/bin/env python3
"""
Precise timing control system for segments orchestration.

Provides microsecond-level timing control for packet transmission,
essential for implementing zapret-level effectiveness.
"""

import time
import asyncio
import threading
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import statistics


class TimingStrategy(Enum):
    """Timing strategies for packet transmission."""
    
    SLEEP = "sleep"                    # Standard time.sleep()
    ASYNCIO = "asyncio"               # asyncio.sleep() for async contexts
    BUSY_WAIT = "busy_wait"           # Busy waiting for high precision
    HYBRID = "hybrid"                 # Combination of sleep + busy wait
    ADAPTIVE = "adaptive"             # Adaptive based on delay requirements


@dataclass
class TimingMeasurement:
    """Measurement of timing accuracy."""
    
    requested_delay_ms: float
    actual_delay_ms: float
    accuracy_error_ms: float
    strategy_used: TimingStrategy
    timestamp: float = field(default_factory=time.time)
    
    @property
    def accuracy_percentage(self) -> float:
        """Calculate timing accuracy as percentage."""
        if self.requested_delay_ms == 0:
            return 100.0 if self.actual_delay_ms < 0.1 else 0.0
        
        error_ratio = abs(self.accuracy_error_ms) / self.requested_delay_ms
        return max(0.0, (1.0 - error_ratio) * 100.0)


@dataclass
class TimingStatistics:
    """Statistics for timing performance."""
    
    measurements: List[TimingMeasurement] = field(default_factory=list)
    total_delays: int = 0
    total_requested_time_ms: float = 0.0
    total_actual_time_ms: float = 0.0
    
    def add_measurement(self, measurement: TimingMeasurement):
        """Add a timing measurement."""
        self.measurements.append(measurement)
        self.total_delays += 1
        self.total_requested_time_ms += measurement.requested_delay_ms
        self.total_actual_time_ms += measurement.actual_delay_ms
    
    def get_average_accuracy(self) -> float:
        """Get average timing accuracy percentage."""
        if not self.measurements:
            return 0.0
        
        accuracies = [m.accuracy_percentage for m in self.measurements]
        return statistics.mean(accuracies)
    
    def get_average_error_ms(self) -> float:
        """Get average timing error in milliseconds."""
        if not self.measurements:
            return 0.0
        
        errors = [abs(m.accuracy_error_ms) for m in self.measurements]
        return statistics.mean(errors)
    
    def get_strategy_performance(self) -> Dict[TimingStrategy, Dict[str, float]]:
        """Get performance breakdown by strategy."""
        strategy_stats = {}
        
        for strategy in TimingStrategy:
            strategy_measurements = [m for m in self.measurements if m.strategy_used == strategy]
            
            if strategy_measurements:
                accuracies = [m.accuracy_percentage for m in strategy_measurements]
                errors = [abs(m.accuracy_error_ms) for m in strategy_measurements]
                
                strategy_stats[strategy] = {
                    "count": len(strategy_measurements),
                    "avg_accuracy": statistics.mean(accuracies),
                    "avg_error_ms": statistics.mean(errors),
                    "max_error_ms": max(errors),
                    "min_error_ms": min(errors)
                }
        
        return strategy_stats


class PreciseTimingController:
    """
    Precise timing controller for segments orchestration.
    
    Provides microsecond-level timing control with multiple strategies
    and automatic accuracy measurement.
    """
    
    def __init__(self, default_strategy: TimingStrategy = TimingStrategy.ADAPTIVE):
        """
        Initialize timing controller.
        
        Args:
            default_strategy: Default timing strategy to use
        """
        self.default_strategy = default_strategy
        self.logger = logging.getLogger(__name__)
        self.statistics = TimingStatistics()
        
        # Calibration data for different strategies
        self.calibration_data = {
            TimingStrategy.SLEEP: {"overhead_ms": 1.0, "min_precision_ms": 1.0},
            TimingStrategy.ASYNCIO: {"overhead_ms": 0.5, "min_precision_ms": 0.5},
            TimingStrategy.BUSY_WAIT: {"overhead_ms": 0.01, "min_precision_ms": 0.001},
            TimingStrategy.HYBRID: {"overhead_ms": 0.1, "min_precision_ms": 0.01}
        }
        
        # Performance thresholds
        self.thresholds = {
            "high_precision_ms": 1.0,      # Use high precision for delays < 1ms
            "busy_wait_threshold_ms": 5.0,  # Use busy wait for delays < 5ms
            "hybrid_threshold_ms": 10.0     # Use hybrid for delays < 10ms
        }
        
        # Calibrate timing overhead on initialization
        self._calibrate_timing_overhead()
    
    def _calibrate_timing_overhead(self):
        """Calibrate timing overhead for different strategies."""
        self.logger.debug("Calibrating timing overhead...")
        
        # Calibrate sleep overhead
        sleep_times = []
        for _ in range(10):
            start = time.perf_counter()
            time.sleep(0.001)  # 1ms
            end = time.perf_counter()
            sleep_times.append((end - start) * 1000)
        
        sleep_overhead = statistics.mean(sleep_times) - 1.0  # Subtract requested 1ms
        self.calibration_data[TimingStrategy.SLEEP]["overhead_ms"] = max(0.1, sleep_overhead)
        
        # Calibrate busy wait precision
        busy_wait_times = []
        for _ in range(10):
            start = time.perf_counter()
            target = start + 0.001  # 1ms
            while time.perf_counter() < target:
                pass
            end = time.perf_counter()
            busy_wait_times.append((end - start) * 1000)
        
        busy_wait_error = statistics.stdev(busy_wait_times) if len(busy_wait_times) > 1 else 0.01
        self.calibration_data[TimingStrategy.BUSY_WAIT]["min_precision_ms"] = busy_wait_error
        
        self.logger.debug(f"Timing calibration complete: sleep_overhead={sleep_overhead:.3f}ms, "
                         f"busy_wait_precision={busy_wait_error:.3f}ms")
    
    def select_optimal_strategy(self, delay_ms: float) -> TimingStrategy:
        """
        Select optimal timing strategy based on delay requirements.
        
        Args:
            delay_ms: Requested delay in milliseconds
            
        Returns:
            Optimal timing strategy
        """
        if self.default_strategy != TimingStrategy.ADAPTIVE:
            return self.default_strategy
        
        # Select strategy based on delay requirements
        if delay_ms <= 0:
            return TimingStrategy.BUSY_WAIT  # No delay, just return immediately
        elif delay_ms < self.thresholds["high_precision_ms"]:
            return TimingStrategy.BUSY_WAIT  # High precision needed
        elif delay_ms < self.thresholds["busy_wait_threshold_ms"]:
            return TimingStrategy.HYBRID     # Medium precision
        elif delay_ms < self.thresholds["hybrid_threshold_ms"]:
            return TimingStrategy.ASYNCIO    # Good precision with efficiency
        else:
            return TimingStrategy.SLEEP      # Standard precision is sufficient
    
    def delay(self, delay_ms: float, strategy: Optional[TimingStrategy] = None) -> TimingMeasurement:
        """
        Execute precise delay with timing measurement.
        
        Args:
            delay_ms: Delay in milliseconds
            strategy: Optional timing strategy override
            
        Returns:
            TimingMeasurement with accuracy information
        """
        if delay_ms <= 0:
            return TimingMeasurement(
                requested_delay_ms=delay_ms,
                actual_delay_ms=0.0,
                accuracy_error_ms=0.0,
                strategy_used=TimingStrategy.BUSY_WAIT
            )
        
        # Select strategy
        selected_strategy = strategy or self.select_optimal_strategy(delay_ms)
        
        # Execute delay with measurement
        start_time = time.perf_counter()
        
        if selected_strategy == TimingStrategy.SLEEP:
            self._sleep_delay(delay_ms)
        elif selected_strategy == TimingStrategy.ASYNCIO:
            # Note: This is synchronous version, async version available separately
            self._sleep_delay(delay_ms)
        elif selected_strategy == TimingStrategy.BUSY_WAIT:
            self._busy_wait_delay(delay_ms)
        elif selected_strategy == TimingStrategy.HYBRID:
            self._hybrid_delay(delay_ms)
        else:
            self._sleep_delay(delay_ms)  # Fallback
        
        end_time = time.perf_counter()
        actual_delay_ms = (end_time - start_time) * 1000
        
        # Create measurement
        measurement = TimingMeasurement(
            requested_delay_ms=delay_ms,
            actual_delay_ms=actual_delay_ms,
            accuracy_error_ms=actual_delay_ms - delay_ms,
            strategy_used=selected_strategy
        )
        
        # Add to statistics
        self.statistics.add_measurement(measurement)
        
        # Log if debug enabled
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"Timing: requested={delay_ms:.3f}ms, actual={actual_delay_ms:.3f}ms, "
                            f"error={measurement.accuracy_error_ms:.3f}ms, "
                            f"accuracy={measurement.accuracy_percentage:.1f}%, strategy={selected_strategy.value}")
        
        return measurement
    
    async def async_delay(self, delay_ms: float, strategy: Optional[TimingStrategy] = None) -> TimingMeasurement:
        """
        Execute precise async delay with timing measurement.
        
        Args:
            delay_ms: Delay in milliseconds
            strategy: Optional timing strategy override
            
        Returns:
            TimingMeasurement with accuracy information
        """
        if delay_ms <= 0:
            return TimingMeasurement(
                requested_delay_ms=delay_ms,
                actual_delay_ms=0.0,
                accuracy_error_ms=0.0,
                strategy_used=TimingStrategy.ASYNCIO
            )
        
        # Select strategy (prefer asyncio for async context)
        selected_strategy = strategy or TimingStrategy.ASYNCIO
        if selected_strategy == TimingStrategy.SLEEP:
            selected_strategy = TimingStrategy.ASYNCIO
        
        # Execute delay with measurement
        start_time = time.perf_counter()
        
        if selected_strategy == TimingStrategy.ASYNCIO:
            await asyncio.sleep(delay_ms / 1000.0)
        elif selected_strategy == TimingStrategy.BUSY_WAIT:
            # Busy wait in async context (not recommended for long delays)
            target_time = start_time + (delay_ms / 1000.0)
            while time.perf_counter() < target_time:
                await asyncio.sleep(0)  # Yield control
        elif selected_strategy == TimingStrategy.HYBRID:
            # Hybrid: asyncio sleep + busy wait
            if delay_ms > 1.0:
                await asyncio.sleep((delay_ms - 0.5) / 1000.0)  # Sleep most of the time
                # Busy wait for the remainder
                target_time = start_time + (delay_ms / 1000.0)
                while time.perf_counter() < target_time:
                    await asyncio.sleep(0)
            else:
                await asyncio.sleep(delay_ms / 1000.0)
        else:
            await asyncio.sleep(delay_ms / 1000.0)  # Fallback
        
        end_time = time.perf_counter()
        actual_delay_ms = (end_time - start_time) * 1000
        
        # Create measurement
        measurement = TimingMeasurement(
            requested_delay_ms=delay_ms,
            actual_delay_ms=actual_delay_ms,
            accuracy_error_ms=actual_delay_ms - delay_ms,
            strategy_used=selected_strategy
        )
        
        # Add to statistics
        self.statistics.add_measurement(measurement)
        
        return measurement
    
    def _sleep_delay(self, delay_ms: float):
        """Standard sleep delay."""
        time.sleep(delay_ms / 1000.0)
    
    def _busy_wait_delay(self, delay_ms: float):
        """High-precision busy wait delay."""
        target_time = time.perf_counter() + (delay_ms / 1000.0)
        while time.perf_counter() < target_time:
            pass  # Busy wait
    
    def _hybrid_delay(self, delay_ms: float):
        """Hybrid delay: sleep + busy wait for precision."""
        if delay_ms <= 1.0:
            # For very short delays, use busy wait only
            self._busy_wait_delay(delay_ms)
        else:
            # Sleep for most of the time, busy wait for precision
            sleep_time = delay_ms - 0.5  # Leave 0.5ms for busy wait
            time.sleep(sleep_time / 1000.0)
            
            # Busy wait for the remainder
            target_time = time.perf_counter() + (0.5 / 1000.0)
            while time.perf_counter() < target_time:
                pass
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive timing statistics.
        
        Returns:
            Dictionary with timing statistics
        """
        stats = {
            "total_delays": self.statistics.total_delays,
            "total_requested_time_ms": self.statistics.total_requested_time_ms,
            "total_actual_time_ms": self.statistics.total_actual_time_ms,
            "average_accuracy_percentage": self.statistics.get_average_accuracy(),
            "average_error_ms": self.statistics.get_average_error_ms(),
            "strategy_performance": self.statistics.get_strategy_performance(),
            "calibration_data": self.calibration_data,
            "thresholds": self.thresholds
        }
        
        if self.statistics.measurements:
            recent_measurements = self.statistics.measurements[-10:]  # Last 10 measurements
            stats["recent_accuracy"] = statistics.mean([m.accuracy_percentage for m in recent_measurements])
            stats["recent_error_ms"] = statistics.mean([abs(m.accuracy_error_ms) for m in recent_measurements])
        
        return stats
    
    def reset_statistics(self):
        """Reset timing statistics."""
        self.statistics = TimingStatistics()
        self.logger.debug("Timing statistics reset")
    
    def configure_thresholds(self, **kwargs):
        """
        Configure timing strategy thresholds.
        
        Args:
            high_precision_ms: Threshold for high precision timing
            busy_wait_threshold_ms: Threshold for busy wait strategy
            hybrid_threshold_ms: Threshold for hybrid strategy
        """
        for key, value in kwargs.items():
            if key in self.thresholds:
                self.thresholds[key] = value
                self.logger.debug(f"Updated threshold {key} to {value}")
    
    def benchmark_strategies(self, test_delays: List[float]) -> Dict[TimingStrategy, Dict[str, float]]:
        """
        Benchmark different timing strategies with test delays.
        
        Args:
            test_delays: List of delays to test (in milliseconds)
            
        Returns:
            Performance comparison of strategies
        """
        self.logger.info(f"Benchmarking timing strategies with {len(test_delays)} test delays")
        
        # Save current statistics
        original_stats = self.statistics
        
        results = {}
        
        for strategy in TimingStrategy:
            if strategy == TimingStrategy.ADAPTIVE:
                continue  # Skip adaptive as it selects other strategies
            
            self.statistics = TimingStatistics()  # Fresh stats for this strategy
            
            self.logger.debug(f"Testing strategy: {strategy.value}")
            
            for delay_ms in test_delays:
                try:
                    self.delay(delay_ms, strategy=strategy)
                except Exception as e:
                    self.logger.warning(f"Strategy {strategy.value} failed for delay {delay_ms}ms: {e}")
            
            # Collect results
            if self.statistics.measurements:
                accuracies = [m.accuracy_percentage for m in self.statistics.measurements]
                errors = [abs(m.accuracy_error_ms) for m in self.statistics.measurements]
                
                results[strategy] = {
                    "avg_accuracy": statistics.mean(accuracies),
                    "avg_error_ms": statistics.mean(errors),
                    "max_error_ms": max(errors),
                    "min_error_ms": min(errors),
                    "std_error_ms": statistics.stdev(errors) if len(errors) > 1 else 0.0,
                    "test_count": len(self.statistics.measurements)
                }
        
        # Restore original statistics
        self.statistics = original_stats
        
        self.logger.info("Timing strategy benchmark complete")
        return results


# Global timing controller instance
_global_timing_controller: Optional[PreciseTimingController] = None


def get_timing_controller() -> PreciseTimingController:
    """Get global timing controller instance."""
    global _global_timing_controller
    if _global_timing_controller is None:
        _global_timing_controller = PreciseTimingController()
    return _global_timing_controller


def precise_delay(delay_ms: float, strategy: Optional[TimingStrategy] = None) -> TimingMeasurement:
    """
    Convenience function for precise delay.
    
    Args:
        delay_ms: Delay in milliseconds
        strategy: Optional timing strategy
        
    Returns:
        TimingMeasurement with accuracy information
    """
    controller = get_timing_controller()
    return controller.delay(delay_ms, strategy)


async def precise_async_delay(delay_ms: float, strategy: Optional[TimingStrategy] = None) -> TimingMeasurement:
    """
    Convenience function for precise async delay.
    
    Args:
        delay_ms: Delay in milliseconds
        strategy: Optional timing strategy
        
    Returns:
        TimingMeasurement with accuracy information
    """
    controller = get_timing_controller()
    return await controller.async_delay(delay_ms, strategy)


def get_timing_statistics() -> Dict[str, Any]:
    """Get global timing statistics."""
    controller = get_timing_controller()
    return controller.get_statistics()


def reset_timing_statistics():
    """Reset global timing statistics."""
    controller = get_timing_controller()
    controller.reset_statistics()