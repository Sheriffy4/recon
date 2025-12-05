"""
Jitter injection attacks for DPI bypass.

Implements various jitter patterns to disrupt DPI timing analysis:
- Random jitter injection with configurable variance
- Gaussian distribution for jitter
- Uniform distribution support
- Periodic jitter variations
- Adaptive jitter based on network conditions
- Actual jitter measurement
"""

import random
import math
import time
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.timing.timing_base import (
    TimingAttackBase,
    TimingConfiguration,
    TimingResult,
)
from core.bypass.attacks.metadata import AttackCategories, RegistrationPriority
from core.bypass.attacks.attack_registry import register_attack

logger = logging.getLogger(__name__)


class JitterType:
    """Types of jitter patterns."""

    UNIFORM = "uniform"
    GAUSSIAN = "gaussian"
    EXPONENTIAL = "exponential"
    PERIODIC = "periodic"
    SAWTOOTH = "sawtooth"
    TRIANGLE = "triangle"
    ADAPTIVE = "adaptive"


@dataclass
class JitterConfiguration(TimingConfiguration):
    """Configuration for jitter injection attacks."""

    jitter_type: str = JitterType.UNIFORM
    jitter_variance_ms: float = 10.0
    jitter_amplitude_ms: float = 10.0
    jitter_frequency: float = 1.0
    jitter_phase: float = 0.0
    gaussian_mean_ms: float = 0.0
    gaussian_stddev_ms: float = 5.0
    exponential_lambda: float = 0.1
    adaptive_sensitivity: float = 0.5
    adaptive_memory: int = 10
    packets_per_burst: int = 5
    inter_packet_base_delay_ms: float = 1.0
    measure_jitter: bool = True

    def __post_init__(self):
        """Validate jitter configuration."""
        super().__post_init__()
        if self.jitter_variance_ms < 0:
            self.jitter_variance_ms = 0.0
        if self.jitter_amplitude_ms < 0:
            self.jitter_amplitude_ms = 0.0
        if self.gaussian_stddev_ms <= 0:
            self.gaussian_stddev_ms = 1.0
        if self.exponential_lambda <= 0:
            self.exponential_lambda = 0.1
        if self.packets_per_burst < 1:
            self.packets_per_burst = 1


@register_attack(
    name="timing_jitter",
    category=AttackCategories.TIMING,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={
        "jitter_type": "uniform",
        "jitter_variance_ms": 10.0,
        "gaussian_mean_ms": 0.0,
        "gaussian_stddev_ms": 5.0,
        "measure_jitter": True
    },
    aliases=["jitter_injection", "timing_jitter_attack"],
    description="Adds random jitter to packet timing with configurable variance and distributions"
)
class TimingJitterAttack(TimingAttackBase):
    """
    Timing Jitter Attack.
    
    Adds random jitter to packet timing to evade temporal DPI analysis.
    Supports uniform and Gaussian distributions with configurable variance
    and actual jitter measurement.
    
    Parameters:
        jitter_type (str): Type of jitter - "uniform" or "gaussian" (default: "uniform")
        jitter_variance_ms (float): Maximum jitter variance in milliseconds (default: 10.0)
        gaussian_mean_ms (float): Mean for Gaussian distribution (default: 0.0)
        gaussian_stddev_ms (float): Standard deviation for Gaussian (default: 5.0)
        measure_jitter (bool): Measure actual jitter applied (default: True)
    
    Examples:
        # Example 1: Uniform random jitter
        attack = TimingJitterAttack()
        context = AttackContext(
            payload=b"GET /path HTTP/1.1",
            params={"jitter_type": "uniform", "jitter_variance_ms": 15.0}
        )
        result = attack.execute(context)
        # Result: Random jitter between -15ms and +15ms
        
        # Example 2: Gaussian jitter for natural timing variation
        context = AttackContext(
            payload=b"sensitive data",
            params={
                "jitter_type": "gaussian",
                "gaussian_mean_ms": 0.0,
                "gaussian_stddev_ms": 10.0
            }
        )
        result = attack.execute(context)
        # Result: Gaussian-distributed jitter centered at 0ms
        
        # Example 3: Measured jitter with variance tracking
        context = AttackContext(
            payload=b"HTTP request",
            params={
                "jitter_type": "uniform",
                "jitter_variance_ms": 20.0,
                "measure_jitter": True
            }
        )
        result = attack.execute(context)
        # Result: Jitter applied and measured for analysis
    
    Known Limitations:
        - Large jitter may cause packet reordering
        - Gaussian jitter may occasionally exceed variance bounds
        - System timer resolution limits precision
        - High jitter may trigger timeout detection
    
    Workarounds:
        - Keep jitter within reasonable bounds
        - Use Gaussian distribution for more natural patterns
        - Combine with other timing attacks
        - Monitor actual jitter to tune parameters
    
    Performance Characteristics:
        - Execution time: O(n) where n is packet count
        - Memory usage: O(n) for jitter history
        - Timer precision: Microsecond level
        - Typical overhead: < 1ms per packet
        - CPU usage: Minimal
    """

    def __init__(self, config: Optional[JitterConfiguration] = None):
        """
        Initialize timing jitter attack.

        Args:
            config: Jitter configuration (uses defaults if None)
        """
        if config is None:
            config = JitterConfiguration()
        super().__init__(config)
        self.jitter_config = config
        self.response_times = []
        self.jitter_history = []
        self.jitter_measurements = []
        self.periodic_time = 0.0

    @property
    def name(self) -> str:
        """Unique name for this attack."""
        return "timing_jitter"
    
    @property
    def category(self) -> str:
        """Attack category."""
        return AttackCategories.TIMING
    
    @property
    def required_params(self) -> list:
        """Required parameters."""
        return []
    
    @property
    def optional_params(self) -> dict:
        """Optional parameters with defaults."""
        return {
            "jitter_type": "uniform",
            "jitter_variance_ms": 10.0,
            "gaussian_mean_ms": 0.0,
            "gaussian_stddev_ms": 5.0,
            "measure_jitter": True
        }

    def _execute_timing_attack(
        self, context: AttackContext, timing_result: TimingResult
    ) -> AttackResult:
        """
        Execute timing jitter attack with measurement.

        Args:
            context: Attack execution context
            timing_result: Timing result to populate

        Returns:
            AttackResult from jitter injection
        """
        try:
            # Extract parameters from context
            jitter_type = context.params.get("jitter_type", "uniform")
            self.jitter_config.jitter_type = jitter_type
            
            # Update configuration from context params
            for param in ["jitter_variance_ms", "gaussian_mean_ms", "gaussian_stddev_ms", "measure_jitter"]:
                if param in context.params:
                    setattr(self.jitter_config, param, context.params[param])
            
            # Update amplitude from variance for compatibility
            self.jitter_config.jitter_amplitude_ms = self.jitter_config.jitter_variance_ms
            
            payloads = self._generate_packet_payloads(context)
            jitter_delays = self._generate_jitter_sequence(len(payloads))
            
            # Execute packets with jitter measurement
            packet_results = []
            for i, (payload, base_delay) in enumerate(zip(payloads, jitter_delays)):
                packet_context = context.copy()
                packet_context.payload = payload
                
                # Calculate jitter for this packet
                jitter_ms = self._calculate_jitter(i)
                total_delay = max(0.0, base_delay + jitter_ms)
                
                # Send packet
                packet_result = self._send_packet(packet_context)
                packet_results.append(packet_result)
                timing_result.packets_sent += 1
                timing_result.bytes_sent += len(payload)
                
                # Measure actual jitter if enabled
                if self.jitter_config.measure_jitter and i < len(jitter_delays) - 1:
                    start_time = time.perf_counter()
                    self.execute_delay(total_delay, timing_result)
                    end_time = time.perf_counter()
                    actual_delay = (end_time - start_time) * 1000.0
                    actual_jitter = actual_delay - base_delay
                    
                    self.jitter_measurements.append({
                        "requested_jitter_ms": jitter_ms,
                        "actual_jitter_ms": actual_jitter,
                        "base_delay_ms": base_delay,
                        "total_delay_ms": total_delay,
                        "actual_total_ms": actual_delay
                    })
                    
                    logger.debug(
                        f"Jitter: requested={jitter_ms:.3f}ms, actual={actual_jitter:.3f}ms, "
                        f"base={base_delay:.3f}ms"
                    )
                elif i < len(jitter_delays) - 1:
                    self.execute_delay(total_delay, timing_result)
            
            success = any(
                (result.status == AttackStatus.SUCCESS for result in packet_results)
            )
            timing_result.success = success
            timing_result.response_received = any(
                (
                    getattr(result, "response_received", False)
                    for result in packet_results
                )
            )
            
            # Calculate jitter statistics
            avg_jitter = 0.0
            jitter_variance = 0.0
            if self.jitter_measurements:
                jitters = [m["actual_jitter_ms"] for m in self.jitter_measurements]
                avg_jitter = sum(jitters) / len(jitters)
                jitter_variance = sum((j - avg_jitter) ** 2 for j in jitters) / len(jitters)
            
            result = AttackResult(
                status=AttackStatus.SUCCESS if success else AttackStatus.FAILURE,
                technique_used=f"timing_jitter_{self.jitter_config.jitter_type}",
                packets_sent=len(payloads),
                bytes_sent=sum((len(p) for p in payloads)),
                response_received=timing_result.response_received,
                metadata={
                    "jitter_type": self.jitter_config.jitter_type,
                    "avg_jitter_ms": avg_jitter,
                    "jitter_variance": jitter_variance,
                    "jitter_measurements": self.jitter_measurements[-10:] if self.jitter_measurements else []
                }
            )
            return result
        except Exception as e:
            logger.error(f"Timing jitter attack failed: {e}")
            timing_result.success = False
            timing_result.error_message = str(e)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used="timing_jitter_error",
            )

    def _generate_packet_payloads(self, context: AttackContext) -> List[bytes]:
        """
        Generate packet payloads for jitter injection.

        Args:
            context: Attack execution context

        Returns:
            List of packet payloads
        """
        payloads = []
        original_payload = context.payload
        if not original_payload:
            original_payload = f"GET / HTTP/1.1\r\nHost: {context.domain or context.dst_ip}\r\n\r\n".encode()
        if len(original_payload) > 100:
            chunk_size = len(original_payload) // self.jitter_config.packets_per_burst
            for i in range(0, len(original_payload), chunk_size):
                chunk = original_payload[i : i + chunk_size]
                if chunk:
                    payloads.append(chunk)
        else:
            for i in range(self.jitter_config.packets_per_burst):
                if i == 0:
                    payloads.append(original_payload)
                else:
                    varied_payload = original_payload + f" # Packet {i}".encode()
                    payloads.append(varied_payload)
        return payloads

    def _generate_jitter_sequence(self, count: int) -> List[float]:
        """
        Generate sequence of jittered delays.

        Args:
            count: Number of delays to generate

        Returns:
            List of jittered delay values in milliseconds
        """
        delays = []
        base_delay = self.jitter_config.inter_packet_base_delay_ms
        for i in range(count):
            jitter = self._calculate_jitter(i)
            delay = max(0.0, base_delay + jitter)
            delays.append(delay)
            if self.jitter_config.jitter_type in [
                JitterType.PERIODIC,
                JitterType.SAWTOOTH,
                JitterType.TRIANGLE,
            ]:
                self.periodic_time += 1.0 / self.jitter_config.jitter_frequency
        return delays

    def _calculate_jitter(self, index: int) -> float:
        """
        Calculate jitter value based on configured type.

        Args:
            index: Current packet index

        Returns:
            Jitter value in milliseconds
        """
        jitter_type = self.jitter_config.jitter_type
        variance = self.jitter_config.jitter_variance_ms
        amplitude = self.jitter_config.jitter_amplitude_ms
        
        if jitter_type == JitterType.UNIFORM or jitter_type == "uniform":
            jitter = random.uniform(-variance, variance)
        elif jitter_type == JitterType.GAUSSIAN or jitter_type == "gaussian":
            jitter = random.gauss(
                self.jitter_config.gaussian_mean_ms,
                self.jitter_config.gaussian_stddev_ms,
            )
            # Clip to variance bounds
            jitter = max(-variance, min(variance, jitter))
        elif jitter_type == JitterType.EXPONENTIAL:
            exp_jitter = random.expovariate(self.jitter_config.exponential_lambda)
            exp_jitter = min(amplitude, exp_jitter)
            jitter = exp_jitter if random.random() > 0.5 else -exp_jitter
        elif jitter_type == JitterType.PERIODIC:
            phase = self.jitter_config.jitter_phase
            freq = self.jitter_config.jitter_frequency
            jitter = amplitude * math.sin(2 * math.pi * freq * self.periodic_time + phase)
        elif jitter_type == JitterType.SAWTOOTH:
            freq = self.jitter_config.jitter_frequency
            period = 1.0 / freq
            t_in_period = self.periodic_time % period
            jitter = amplitude * (2 * (t_in_period / period) - 1)
        elif jitter_type == JitterType.TRIANGLE:
            freq = self.jitter_config.jitter_frequency
            period = 1.0 / freq
            t_in_period = self.periodic_time % period
            if t_in_period < period / 2:
                jitter = amplitude * (4 * t_in_period / period - 1)
            else:
                jitter = amplitude * (3 - 4 * t_in_period / period)
        elif jitter_type == JitterType.ADAPTIVE:
            jitter = self._calculate_adaptive_jitter(index)
        else:
            jitter = random.uniform(-variance, variance)
        
        # Store jitter in history
        self.jitter_history.append(jitter)
        if len(self.jitter_history) > self.jitter_config.adaptive_memory * 2:
            self.jitter_history.pop(0)
        
        return jitter

    def _calculate_adaptive_jitter(self, index: int) -> float:
        """
        Calculate adaptive jitter based on response time history.

        Args:
            index: Current packet index

        Returns:
            Adaptive jitter value in milliseconds
        """
        if not self.response_times or len(self.response_times) < 2:
            return random.uniform(
                -self.jitter_config.jitter_amplitude_ms,
                self.jitter_config.jitter_amplitude_ms,
            )
        recent_times = self.response_times[-self.jitter_config.adaptive_memory :]
        if len(recent_times) < 2:
            return 0.0
        trend = (recent_times[-1] - recent_times[0]) / len(recent_times)
        sensitivity = self.jitter_config.adaptive_sensitivity
        amplitude = self.jitter_config.jitter_amplitude_ms
        if trend > 0:
            adaptive_amplitude = amplitude * (
                1.0 - sensitivity * min(1.0, trend / 100.0)
            )
        else:
            adaptive_amplitude = amplitude * (
                1.0 + sensitivity * min(1.0, abs(trend) / 100.0)
            )
        base_jitter = random.uniform(-adaptive_amplitude, adaptive_amplitude)
        self.jitter_history.append(base_jitter)
        if len(self.jitter_history) > self.jitter_config.adaptive_memory:
            self.jitter_history.pop(0)
        return base_jitter

    def _send_packet(self, context: AttackContext) -> AttackResult:
        """
        Send a single packet with jitter timing.

        Args:
            context: Attack execution context

        Returns:
            AttackResult for the packet transmission
        """
        start_time = time.perf_counter()
        try:
            simulated_network_delay = random.uniform(1.0, 50.0)
            time.sleep(simulated_network_delay / 1000.0)
            end_time = time.perf_counter()
            response_time = (end_time - start_time) * 1000
            self.response_times.append(response_time)
            if len(self.response_times) > self.jitter_config.adaptive_memory * 2:
                self.response_times.pop(0)
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=response_time,
                packets_sent=1,
                bytes_sent=len(context.payload),
                response_received=True,
                technique_used=f"jitter_packet_{self.jitter_config.jitter_type}",
            )
        except Exception as e:
            self.logger.error(f"Failed to send jittered packet: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used="jitter_packet_error",
            )

    def get_jitter_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive jitter statistics.

        Returns:
            Dictionary with jitter statistics
        """
        stats = {
            "jitter_type": self.jitter_config.jitter_type,
            "jitter_amplitude_ms": self.jitter_config.jitter_amplitude_ms,
            "packets_per_burst": self.jitter_config.packets_per_burst,
            "response_times_count": len(self.response_times),
            "jitter_history_count": len(self.jitter_history),
        }
        if self.response_times:
            stats.update(
                {
                    "avg_response_time_ms": sum(self.response_times)
                    / len(self.response_times),
                    "min_response_time_ms": min(self.response_times),
                    "max_response_time_ms": max(self.response_times),
                }
            )
        if self.jitter_history:
            stats.update(
                {
                    "avg_jitter_ms": sum(self.jitter_history)
                    / len(self.jitter_history),
                    "min_jitter_ms": min(self.jitter_history),
                    "max_jitter_ms": max(self.jitter_history),
                }
            )
        stats.update(self.get_timing_statistics())
        return stats

    def configure_jitter(
        self,
        jitter_type: str = None,
        amplitude_ms: float = None,
        frequency: float = None,
        **kwargs,
    ):
        """
        Configure jitter parameters.

        Args:
            jitter_type: Type of jitter pattern
            amplitude_ms: Maximum jitter amplitude
            frequency: Frequency for periodic jitter
            **kwargs: Additional configuration parameters
        """
        if jitter_type is not None:
            self.jitter_config.jitter_type = jitter_type
        if amplitude_ms is not None:
            self.jitter_config.jitter_amplitude_ms = amplitude_ms
        if frequency is not None:
            self.jitter_config.jitter_frequency = frequency
        for key, value in kwargs.items():
            if hasattr(self.jitter_config, key):
                setattr(self.jitter_config, key, value)
                self.logger.debug(f"Updated jitter config {key} to {value}")

    def reset_adaptive_state(self):
        """Reset adaptive jitter state."""
        self.response_times.clear()
        self.jitter_history.clear()
        self.periodic_time = 0.0
        self.logger.debug("Reset adaptive jitter state")

    def benchmark_jitter_patterns(
        self, test_count: int = 100
    ) -> Dict[str, Dict[str, Any]]:
        """
        Benchmark different jitter patterns.

        Args:
            test_count: Number of jitter values to generate for each pattern

        Returns:
            Benchmark results for each jitter pattern
        """
        results = {}
        original_type = self.jitter_config.jitter_type
        for jitter_type in [
            JitterType.UNIFORM,
            JitterType.GAUSSIAN,
            JitterType.EXPONENTIAL,
            JitterType.PERIODIC,
            JitterType.SAWTOOTH,
            JitterType.TRIANGLE,
        ]:
            self.jitter_config.jitter_type = jitter_type
            self.periodic_time = 0.0
            jitter_values = []
            generation_times = []
            for i in range(test_count):
                start_time = time.perf_counter()
                jitter = self._calculate_jitter(i)
                end_time = time.perf_counter()
                jitter_values.append(jitter)
                generation_times.append((end_time - start_time) * 1000)
            results[jitter_type] = {
                "avg_jitter_ms": sum(jitter_values) / len(jitter_values),
                "min_jitter_ms": min(jitter_values),
                "max_jitter_ms": max(jitter_values),
                "jitter_range_ms": max(jitter_values) - min(jitter_values),
                "avg_generation_time_ms": sum(generation_times) / len(generation_times),
                "max_generation_time_ms": max(generation_times),
                "values_generated": len(jitter_values),
            }
        self.jitter_config.jitter_type = original_type
        return results
