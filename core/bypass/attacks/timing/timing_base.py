# recon/core/bypass/attacks/timing/timing_base.py

"""
Base class for timing-based DPI bypass attacks.
Provides common functionality for all timing attack implementations.
"""

import time
import random
import logging
from abc import abstractmethod
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..timing_controller import PreciseTimingController, TimingStrategy, TimingMeasurement


class TimingPattern(Enum):
    """Types of timing patterns for attacks."""
    CONSTANT = "constant"           # Fixed delay between packets
    LINEAR = "linear"               # Linearly increasing/decreasing delays
    EXPONENTIAL = "exponential"     # Exponentially changing delays
    RANDOM = "random"               # Random delays within range
    JITTER = "jitter"              # Base delay with random jitter
    BURST = "burst"                # Burst patterns with gaps
    ADAPTIVE = "adaptive"          # Adaptive based on response times


@dataclass
class TimingConfiguration:
    """Configuration for timing attacks."""
    
    # Basic timing parameters
    base_delay_ms: float = 0.0
    min_delay_ms: float = 0.0
    max_delay_ms: float = 1000.0
    
    # Pattern configuration
    pattern: TimingPattern = TimingPattern.CONSTANT
    jitter_percentage: float = 10.0  # Percentage of base delay for jitter
    
    # Burst configuration
    burst_size: int = 3
    burst_gap_ms: float = 100.0
    
    # Adaptive configuration
    adaptation_factor: float = 1.2
    response_timeout_ms: float = 5000.0
    
    # Precision configuration
    timing_strategy: TimingStrategy = TimingStrategy.ADAPTIVE
    precision_required: bool = True
    
    # Validation
    def __post_init__(self):
        """Validate configuration parameters."""
        if self.min_delay_ms < 0:
            self.min_delay_ms = 0.0
        if self.max_delay_ms < self.min_delay_ms:
            self.max_delay_ms = self.min_delay_ms + 1.0
        if self.base_delay_ms < self.min_delay_ms:
            self.base_delay_ms = self.min_delay_ms
        if self.base_delay_ms > self.max_delay_ms:
            self.base_delay_ms = self.max_delay_ms
        if self.jitter_percentage < 0:
            self.jitter_percentage = 0.0
        if self.jitter_percentage > 100:
            self.jitter_percentage = 100.0


@dataclass
class TimingResult:
    """Result of timing attack execution."""
    
    # Basic result information
    success: bool = False
    error_message: Optional[str] = None
    
    # Timing measurements
    timing_measurements: List[TimingMeasurement] = field(default_factory=list)
    total_execution_time_ms: float = 0.0
    
    # Pattern statistics
    delays_executed: int = 0
    average_delay_ms: float = 0.0
    delay_accuracy_percentage: float = 0.0
    
    # Performance metrics
    packets_sent: int = 0
    bytes_sent: int = 0
    response_received: bool = False
    
    # Metadata
    pattern_used: Optional[TimingPattern] = None
    configuration: Optional[TimingConfiguration] = None
    
    def add_timing_measurement(self, measurement: TimingMeasurement):
        """Add a timing measurement to the result."""
        self.timing_measurements.append(measurement)
        self.delays_executed += 1
        
        # Update statistics
        if self.timing_measurements:
            total_requested = sum(m.requested_delay_ms for m in self.timing_measurements)
            total_actual = sum(m.actual_delay_ms for m in self.timing_measurements)
            
            self.average_delay_ms = total_actual / len(self.timing_measurements)
            
            # Calculate accuracy
            if total_requested > 0:
                accuracy_sum = sum(m.accuracy_percentage for m in self.timing_measurements)
                self.delay_accuracy_percentage = accuracy_sum / len(self.timing_measurements)
    
    def get_timing_statistics(self) -> Dict[str, Any]:
        """Get comprehensive timing statistics."""
        if not self.timing_measurements:
            return {}
        
        accuracies = [m.accuracy_percentage for m in self.timing_measurements]
        errors = [abs(m.accuracy_error_ms) for m in self.timing_measurements]
        
        return {
            "total_delays": len(self.timing_measurements),
            "average_accuracy": sum(accuracies) / len(accuracies),
            "min_accuracy": min(accuracies),
            "max_accuracy": max(accuracies),
            "average_error_ms": sum(errors) / len(errors),
            "max_error_ms": max(errors),
            "min_error_ms": min(errors),
            "total_requested_time_ms": sum(m.requested_delay_ms for m in self.timing_measurements),
            "total_actual_time_ms": sum(m.actual_delay_ms for m in self.timing_measurements)
        }


class TimingAttackBase(BaseAttack):
    """
    Base class for all timing-based DPI bypass attacks.
    
    Provides common functionality for timing manipulation, pattern generation,
    and precision control.
    """
    
    def __init__(self, config: Optional[TimingConfiguration] = None):
        """
        Initialize timing attack base.
        
        Args:
            config: Timing configuration (uses defaults if None)
        """
        super().__init__()
        self.config = config or TimingConfiguration()
        self.timing_controller = PreciseTimingController(self.config.timing_strategy)
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # State tracking
        self.current_delay_index = 0
        self.pattern_state = {}
        self.last_response_time = None
        
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute timing attack with comprehensive measurement.
        
        Args:
            context: Attack execution context
            
        Returns:
            AttackResult with timing information
        """
        start_time = time.perf_counter()
        timing_result = TimingResult(
            pattern_used=self.config.pattern,
            configuration=self.config
        )
        
        try:
            # Execute the specific timing attack
            attack_result = self._execute_timing_attack(context, timing_result)
            
            # Measure total execution time
            end_time = time.perf_counter()
            timing_result.total_execution_time_ms = (end_time - start_time) * 1000
            
            # Convert timing result to attack result
            result = self._convert_timing_result_to_attack_result(attack_result, timing_result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Timing attack failed: {e}")
            timing_result.success = False
            timing_result.error_message = str(e)
            
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                metadata={"timing_result": timing_result}
            )
    
    @abstractmethod
    def _execute_timing_attack(self, context: AttackContext, timing_result: TimingResult) -> AttackResult:
        """
        Execute the specific timing attack implementation.
        
        Args:
            context: Attack execution context
            timing_result: Timing result to populate
            
        Returns:
            AttackResult from the specific attack
        """
        pass
    
    def generate_delay_sequence(self, count: int) -> List[float]:
        """
        Generate sequence of delays based on configured pattern.
        
        Args:
            count: Number of delays to generate
            
        Returns:
            List of delay values in milliseconds
        """
        delays = []
        
        for i in range(count):
            if self.config.pattern == TimingPattern.CONSTANT:
                delay = self.config.base_delay_ms
                
            elif self.config.pattern == TimingPattern.LINEAR:
                # Linear progression from min to max
                if count > 1:
                    progress = i / (count - 1)
                    delay = self.config.min_delay_ms + progress * (self.config.max_delay_ms - self.config.min_delay_ms)
                else:
                    delay = self.config.base_delay_ms
                    
            elif self.config.pattern == TimingPattern.EXPONENTIAL:
                # Exponential progression
                if count > 1:
                    progress = i / (count - 1)
                    delay = self.config.min_delay_ms * (self.config.max_delay_ms / self.config.min_delay_ms) ** progress
                else:
                    delay = self.config.base_delay_ms
                    
            elif self.config.pattern == TimingPattern.RANDOM:
                delay = random.uniform(self.config.min_delay_ms, self.config.max_delay_ms)
                
            elif self.config.pattern == TimingPattern.JITTER:
                jitter_amount = self.config.base_delay_ms * (self.config.jitter_percentage / 100.0)
                jitter = random.uniform(-jitter_amount, jitter_amount)
                delay = max(0, self.config.base_delay_ms + jitter)
                
            elif self.config.pattern == TimingPattern.BURST:
                # Burst pattern: short delays within burst, long gap between bursts
                burst_position = i % (self.config.burst_size + 1)
                if burst_position < self.config.burst_size:
                    delay = self.config.min_delay_ms  # Short delay within burst
                else:
                    delay = self.config.burst_gap_ms  # Gap between bursts
                    
            elif self.config.pattern == TimingPattern.ADAPTIVE:
                # Adaptive delays based on response times
                delay = self._calculate_adaptive_delay(i)
                
            else:
                delay = self.config.base_delay_ms
            
            # Ensure delay is within bounds
            delay = max(self.config.min_delay_ms, min(self.config.max_delay_ms, delay))
            delays.append(delay)
        
        return delays
    
    def _calculate_adaptive_delay(self, index: int) -> float:
        """
        Calculate adaptive delay based on previous response times.
        
        Args:
            index: Current delay index
            
        Returns:
            Calculated delay in milliseconds
        """
        if self.last_response_time is None or index == 0:
            return self.config.base_delay_ms
        
        # Adapt based on last response time
        if self.last_response_time > self.config.response_timeout_ms:
            # Slow response, reduce delay
            return max(self.config.min_delay_ms, self.config.base_delay_ms / self.config.adaptation_factor)
        else:
            # Fast response, can increase delay
            return min(self.config.max_delay_ms, self.config.base_delay_ms * self.config.adaptation_factor)
    
    def execute_delay(self, delay_ms: float, timing_result: TimingResult) -> TimingMeasurement:
        """
        Execute a single delay with measurement.
        
        Args:
            delay_ms: Delay to execute in milliseconds
            timing_result: Timing result to update
            
        Returns:
            TimingMeasurement for this delay
        """
        measurement = self.timing_controller.delay(delay_ms, self.config.timing_strategy)
        timing_result.add_timing_measurement(measurement)
        
        self.logger.debug(f"Executed delay: {delay_ms:.3f}ms, "
                         f"actual: {measurement.actual_delay_ms:.3f}ms, "
                         f"accuracy: {measurement.accuracy_percentage:.1f}%")
        
        return measurement
    
    def execute_timed_packet_sequence(self, context: AttackContext, 
                                    payloads: List[bytes], 
                                    delays: List[float],
                                    timing_result: TimingResult) -> List[AttackResult]:
        """
        Execute sequence of packets with precise timing.
        
        Args:
            context: Attack execution context
            payloads: List of payloads to send
            delays: List of delays between packets
            timing_result: Timing result to update
            
        Returns:
            List of AttackResults for each packet
        """
        results = []
        
        for i, (payload, delay) in enumerate(zip(payloads, delays)):
            # Create context for this packet
            packet_context = context.copy()
            packet_context.payload = payload
            
            # Send packet (implemented by subclass)
            packet_result = self._send_packet(packet_context)
            results.append(packet_result)
            
            # Update timing result
            timing_result.packets_sent += 1
            timing_result.bytes_sent += len(payload)
            
            # Execute delay before next packet (except for last packet)
            if i < len(delays) - 1:
                self.execute_delay(delay, timing_result)
        
        return results
    
    def _send_packet(self, context: AttackContext) -> AttackResult:
        """
        Send a single packet. To be implemented by subclasses.
        
        Args:
            context: Attack execution context
            
        Returns:
            AttackResult for the packet transmission
        """
        # Default implementation - subclasses should override
        return AttackResult(
            status=AttackStatus.SUCCESS,
            packets_sent=1,
            bytes_sent=len(context.payload)
        )
    
    def _convert_timing_result_to_attack_result(self, attack_result: AttackResult, 
                                              timing_result: TimingResult) -> AttackResult:
        """
        Convert timing result to standard attack result.
        
        Args:
            attack_result: Original attack result
            timing_result: Timing result with measurements
            
        Returns:
            Enhanced AttackResult with timing information
        """
        # Update attack result with timing information
        attack_result.processing_time_ms = timing_result.total_execution_time_ms
        attack_result.packets_sent = timing_result.packets_sent
        attack_result.bytes_sent = timing_result.bytes_sent
        
        # Add timing metadata
        if not attack_result.metadata:
            attack_result.metadata = {}
        
        attack_result.metadata.update({
            "timing_result": timing_result,
            "timing_statistics": timing_result.get_timing_statistics(),
            "pattern_used": timing_result.pattern_used.value if timing_result.pattern_used else None,
            "delays_executed": timing_result.delays_executed,
            "average_delay_ms": timing_result.average_delay_ms,
            "delay_accuracy_percentage": timing_result.delay_accuracy_percentage
        })
        
        return attack_result
    
    def get_timing_statistics(self) -> Dict[str, Any]:
        """Get timing controller statistics."""
        return self.timing_controller.get_statistics()
    
    def reset_timing_statistics(self):
        """Reset timing controller statistics."""
        self.timing_controller.reset_statistics()
    
    def configure_timing(self, **kwargs):
        """
        Configure timing parameters.
        
        Args:
            **kwargs: Timing configuration parameters
        """
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                self.logger.debug(f"Updated timing config {key} to {value}")
    
    def benchmark_timing_accuracy(self, test_delays: List[float]) -> Dict[str, Any]:
        """
        Benchmark timing accuracy with test delays.
        
        Args:
            test_delays: List of delays to test
            
        Returns:
            Benchmark results
        """
        return self.timing_controller.benchmark_strategies(test_delays)