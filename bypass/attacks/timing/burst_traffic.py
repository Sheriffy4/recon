# recon/core/bypass/attacks/timing/burst_traffic.py

"""
Burst traffic generation attacks for DPI bypass.

Implements various burst patterns to overwhelm DPI analysis:
- High-frequency packet bursts
- Variable burst sizes and intervals
- Coordinated multi-stream bursts
- Adaptive burst patterns based on network conditions
"""

import time
import random
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..base import AttackContext, AttackResult, AttackStatus
from .timing_base import (
    TimingAttackBase,
    TimingConfiguration,
    TimingResult,
)


class BurstType(Enum):
    """Types of burst patterns."""

    FIXED_SIZE = "fixed_size"  # Fixed number of packets per burst
    VARIABLE_SIZE = "variable_size"  # Variable burst sizes
    EXPONENTIAL = "exponential"  # Exponentially increasing burst sizes
    FIBONACCI = "fibonacci"  # Fibonacci sequence burst sizes
    RANDOM = "random"  # Random burst sizes within range
    ADAPTIVE = "adaptive"  # Adaptive based on network response


class BurstTiming(Enum):
    """Timing patterns for bursts."""

    FIXED_INTERVAL = "fixed_interval"  # Fixed time between bursts
    VARIABLE_INTERVAL = "variable"  # Variable intervals
    EXPONENTIAL_BACKOFF = "exp_backoff"  # Exponential backoff between bursts
    RANDOM_INTERVAL = "random"  # Random intervals within range
    RESPONSE_BASED = "response_based"  # Based on response times


@dataclass
class BurstConfiguration(TimingConfiguration):
    """Configuration for burst traffic attacks."""

    # Burst size configuration
    burst_type: BurstType = BurstType.FIXED_SIZE
    min_burst_size: int = 5  # Minimum packets per burst
    max_burst_size: int = 20  # Maximum packets per burst
    default_burst_size: int = 10  # Default burst size

    # Burst timing configuration
    burst_timing: BurstTiming = BurstTiming.FIXED_INTERVAL
    burst_interval_ms: float = 100.0  # Time between bursts
    min_interval_ms: float = 10.0  # Minimum interval between bursts
    max_interval_ms: float = 1000.0  # Maximum interval between bursts

    # Packet timing within burst
    intra_burst_delay_ms: float = 1.0  # Delay between packets within burst
    intra_burst_jitter_ms: float = 0.5  # Jitter for intra-burst delays

    # Multi-stream configuration
    concurrent_streams: int = 1  # Number of concurrent burst streams
    stream_offset_ms: float = 0.0  # Time offset between streams

    # Adaptive configuration
    adaptation_threshold_ms: float = 100.0  # Response time threshold for adaptation
    adaptation_factor: float = 1.2  # Factor for adaptive adjustments

    # Burst sequence configuration
    total_bursts: int = 5  # Total number of bursts to send
    burst_payload_size: int = 1024  # Size of each packet in burst

    # Performance limits
    max_packets_per_second: int = 1000  # Rate limiting
    max_concurrent_packets: int = 50  # Concurrency limit

    def __post_init__(self):
        """Validate burst configuration."""
        super().__post_init__()

        if self.min_burst_size < 1:
            self.min_burst_size = 1
        if self.max_burst_size < self.min_burst_size:
            self.max_burst_size = self.min_burst_size
        if self.default_burst_size < self.min_burst_size:
            self.default_burst_size = self.min_burst_size
        if self.default_burst_size > self.max_burst_size:
            self.default_burst_size = self.max_burst_size
        if self.min_interval_ms <= 0:
            self.min_interval_ms = 1.0
        if self.max_interval_ms < self.min_interval_ms:
            self.max_interval_ms = self.min_interval_ms
        if self.concurrent_streams < 1:
            self.concurrent_streams = 1
        if self.total_bursts < 1:
            self.total_bursts = 1
        if self.burst_payload_size < 1:
            self.burst_payload_size = 1


@dataclass
class BurstMetrics:
    """Metrics for burst traffic analysis."""

    bursts_sent: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    avg_burst_size: float = 0.0
    avg_burst_interval_ms: float = 0.0
    successful_bursts: int = 0
    failed_bursts: int = 0
    avg_response_time_ms: float = 0.0
    peak_throughput_pps: float = 0.0  # Packets per second
    peak_throughput_bps: float = 0.0  # Bytes per second

    # Timing statistics
    burst_timings: List[float] = field(default_factory=list)
    response_times: List[float] = field(default_factory=list)

    def update_burst_metrics(
        self,
        burst_size: int,
        interval_ms: float,
        success: bool,
        response_time_ms: float,
    ):
        """Update metrics with burst results."""
        self.bursts_sent += 1
        self.total_packets += burst_size

        if success:
            self.successful_bursts += 1
        else:
            self.failed_bursts += 1

        # Update averages
        self.avg_burst_size = self.total_packets / self.bursts_sent

        self.burst_timings.append(interval_ms)
        self.response_times.append(response_time_ms)

        if self.burst_timings:
            self.avg_burst_interval_ms = sum(self.burst_timings) / len(
                self.burst_timings
            )
        if self.response_times:
            self.avg_response_time_ms = sum(self.response_times) / len(
                self.response_times
            )


class BurstTrafficAttack(TimingAttackBase):
    """
    Burst traffic generation attack implementation.

    Generates high-intensity packet bursts to overwhelm DPI analysis
    and create traffic patterns that are difficult to classify.
    """

    def __init__(self, config: Optional[BurstConfiguration] = None):
        """
        Initialize burst traffic attack.

        Args:
            config: Burst configuration (uses defaults if None)
        """
        if config is None:
            config = BurstConfiguration()

        super().__init__(config)
        self.burst_config = config

        # Metrics and state tracking
        self.metrics = BurstMetrics()
        self.fibonacci_cache = [1, 1]
        self.current_burst_size = config.default_burst_size
        self.last_response_time = 0.0

        # Thread pool for concurrent bursts
        self.executor = ThreadPoolExecutor(max_workers=config.concurrent_streams)

    @property
    def name(self) -> str:
        """Unique name for this attack."""
        return f"burst_traffic_{self.burst_config.burst_type.value}"

    def _execute_timing_attack(
        self, context: AttackContext, timing_result: TimingResult
    ) -> AttackResult:
        """
        Execute burst traffic attack.

        Args:
            context: Attack execution context
            timing_result: Timing result to populate

        Returns:
            AttackResult from burst traffic generation
        """
        try:
            # Reset metrics for this attack
            self.metrics = BurstMetrics()

            # Generate burst sequence
            burst_sequence = self._generate_burst_sequence()

            # Execute bursts
            if self.burst_config.concurrent_streams > 1:
                # Multi-stream concurrent bursts
                results = self._execute_concurrent_bursts(
                    context, burst_sequence, timing_result
                )
            else:
                # Single stream sequential bursts
                results = self._execute_sequential_bursts(
                    context, burst_sequence, timing_result
                )

            # Analyze results
            success = any(result.status == AttackStatus.SUCCESS for result in results)

            timing_result.success = success
            timing_result.packets_sent = self.metrics.total_packets
            timing_result.bytes_sent = self.metrics.total_bytes
            timing_result.response_received = any(
                getattr(result, "response_received", False) for result in results
            )

            # Create final result
            result = AttackResult(
                status=AttackStatus.SUCCESS if success else AttackStatus.FAILURE,
                technique_used=f"burst_traffic_{self.burst_config.burst_type.value}",
                packets_sent=self.metrics.total_packets,
                bytes_sent=self.metrics.total_bytes,
                response_received=timing_result.response_received,
                latency_ms=self.metrics.avg_response_time_ms,
            )

            return result

        except Exception as e:
            self.logger.error(f"Burst traffic attack failed: {e}")
            timing_result.success = False
            timing_result.error_message = str(e)

            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used="burst_traffic_error",
            )

    def _generate_burst_sequence(self) -> List[Tuple[int, float]]:
        """
        Generate sequence of (burst_size, interval) tuples.

        Returns:
            List of (burst_size, interval_ms) tuples
        """
        sequence = []

        for i in range(self.burst_config.total_bursts):
            # Generate burst size
            burst_size = self._calculate_burst_size(i)

            # Generate interval (except for last burst)
            if i < self.burst_config.total_bursts - 1:
                interval_ms = self._calculate_burst_interval(i)
            else:
                interval_ms = 0.0  # No interval after last burst

            sequence.append((burst_size, interval_ms))

        return sequence

    def _calculate_burst_size(self, burst_index: int) -> int:
        """
        Calculate burst size based on configuration.

        Args:
            burst_index: Index of current burst

        Returns:
            Number of packets in this burst
        """
        burst_type = self.burst_config.burst_type

        if burst_type == BurstType.FIXED_SIZE:
            return self.burst_config.default_burst_size

        elif burst_type == BurstType.VARIABLE_SIZE:
            # Alternate between min and max
            if burst_index % 2 == 0:
                return self.burst_config.min_burst_size
            else:
                return self.burst_config.max_burst_size

        elif burst_type == BurstType.EXPONENTIAL:
            # Exponentially increasing burst sizes
            base_size = self.burst_config.min_burst_size
            size = int(base_size * (2**burst_index))
            return min(size, self.burst_config.max_burst_size)

        elif burst_type == BurstType.FIBONACCI:
            # Fibonacci sequence burst sizes
            while len(self.fibonacci_cache) <= burst_index:
                next_fib = self.fibonacci_cache[-1] + self.fibonacci_cache[-2]
                self.fibonacci_cache.append(next_fib)

            fib_size = self.fibonacci_cache[burst_index]
            # Scale to fit within bounds
            scaled_size = self.burst_config.min_burst_size + (
                fib_size
                % (
                    self.burst_config.max_burst_size
                    - self.burst_config.min_burst_size
                    + 1
                )
            )
            return scaled_size

        elif burst_type == BurstType.RANDOM:
            return random.randint(
                self.burst_config.min_burst_size, self.burst_config.max_burst_size
            )

        elif burst_type == BurstType.ADAPTIVE:
            # Adapt based on previous response times
            if self.last_response_time > self.burst_config.adaptation_threshold_ms:
                # Slow response, reduce burst size
                self.current_burst_size = max(
                    self.burst_config.min_burst_size,
                    int(self.current_burst_size / self.burst_config.adaptation_factor),
                )
            else:
                # Fast response, can increase burst size
                self.current_burst_size = min(
                    self.burst_config.max_burst_size,
                    int(self.current_burst_size * self.burst_config.adaptation_factor),
                )
            return self.current_burst_size

        else:
            return self.burst_config.default_burst_size

    def _calculate_burst_interval(self, burst_index: int) -> float:
        """
        Calculate interval before next burst.

        Args:
            burst_index: Index of current burst

        Returns:
            Interval in milliseconds before next burst
        """
        timing = self.burst_config.burst_timing

        if timing == BurstTiming.FIXED_INTERVAL:
            return self.burst_config.burst_interval_ms

        elif timing == BurstTiming.VARIABLE_INTERVAL:
            # Alternate between min and max intervals
            if burst_index % 2 == 0:
                return self.burst_config.min_interval_ms
            else:
                return self.burst_config.max_interval_ms

        elif timing == BurstTiming.EXPONENTIAL_BACKOFF:
            # Exponential backoff
            base_interval = self.burst_config.burst_interval_ms
            interval = base_interval * (2**burst_index)
            return min(interval, self.burst_config.max_interval_ms)

        elif timing == BurstTiming.RANDOM_INTERVAL:
            return random.uniform(
                self.burst_config.min_interval_ms, self.burst_config.max_interval_ms
            )

        elif timing == BurstTiming.RESPONSE_BASED:
            # Base interval on last response time
            if self.last_response_time > 0:
                # Use response time as base, with some variation
                base = self.last_response_time * 0.5  # Half of response time
                variation = base * 0.2  # 20% variation
                interval = base + random.uniform(-variation, variation)
                return max(
                    self.burst_config.min_interval_ms,
                    min(interval, self.burst_config.max_interval_ms),
                )
            else:
                return self.burst_config.burst_interval_ms

        else:
            return self.burst_config.burst_interval_ms

    def _execute_sequential_bursts(
        self,
        context: AttackContext,
        burst_sequence: List[Tuple[int, float]],
        timing_result: TimingResult,
    ) -> List[AttackResult]:
        """
        Execute bursts sequentially in single stream.

        Args:
            context: Attack execution context
            burst_sequence: Sequence of (burst_size, interval) tuples
            timing_result: Timing result to update

        Returns:
            List of AttackResults for each burst
        """
        results = []

        for i, (burst_size, interval_ms) in enumerate(burst_sequence):
            # Execute single burst
            burst_result = self._execute_single_burst(context, burst_size, i)
            results.append(burst_result)

            # Update metrics
            self.metrics.update_burst_metrics(
                burst_size,
                interval_ms,
                burst_result.status == AttackStatus.SUCCESS,
                getattr(burst_result, "latency_ms", 0.0),
            )

            # Update timing result
            timing_result.packets_sent += burst_size
            timing_result.bytes_sent += (
                burst_size * self.burst_config.burst_payload_size
            )

            # Wait for interval before next burst (except for last burst)
            if i < len(burst_sequence) - 1 and interval_ms > 0:
                self.execute_delay(interval_ms, timing_result)

        return results

    def _execute_concurrent_bursts(
        self,
        context: AttackContext,
        burst_sequence: List[Tuple[int, float]],
        timing_result: TimingResult,
    ) -> List[AttackResult]:
        """
        Execute bursts concurrently across multiple streams.

        Args:
            context: Attack execution context
            burst_sequence: Sequence of (burst_size, interval) tuples
            timing_result: Timing result to update

        Returns:
            List of AttackResults for all bursts
        """
        results = []
        futures = []

        # Submit burst tasks to thread pool
        for stream_id in range(self.burst_config.concurrent_streams):
            # Calculate stream offset
            stream_offset = stream_id * self.burst_config.stream_offset_ms

            # Submit stream execution
            future = self.executor.submit(
                self._execute_stream_bursts,
                context,
                burst_sequence,
                stream_id,
                stream_offset,
            )
            futures.append(future)

        # Collect results from all streams
        for future in as_completed(futures):
            try:
                stream_results = future.result()
                results.extend(stream_results)

                # Update timing result with stream results
                for result in stream_results:
                    timing_result.packets_sent += getattr(result, "packets_sent", 0)
                    timing_result.bytes_sent += getattr(result, "bytes_sent", 0)

            except Exception as e:
                self.logger.error(f"Stream execution failed: {e}")
                results.append(
                    AttackResult(
                        status=AttackStatus.ERROR,
                        error_message=str(e),
                        technique_used="burst_stream_error",
                    )
                )

        return results

    def _execute_stream_bursts(
        self,
        context: AttackContext,
        burst_sequence: List[Tuple[int, float]],
        stream_id: int,
        offset_ms: float,
    ) -> List[AttackResult]:
        """
        Execute burst sequence for a single stream.

        Args:
            context: Attack execution context
            burst_sequence: Sequence of (burst_size, interval) tuples
            stream_id: Stream identifier
            offset_ms: Initial offset for this stream

        Returns:
            List of AttackResults for this stream
        """
        results = []

        # Initial offset delay
        if offset_ms > 0:
            time.sleep(offset_ms / 1000.0)

        for i, (burst_size, interval_ms) in enumerate(burst_sequence):
            # Execute burst for this stream
            burst_result = self._execute_single_burst(context, burst_size, i, stream_id)
            results.append(burst_result)

            # Wait for interval (except for last burst)
            if i < len(burst_sequence) - 1 and interval_ms > 0:
                time.sleep(interval_ms / 1000.0)

        return results

    def _execute_single_burst(
        self,
        context: AttackContext,
        burst_size: int,
        burst_index: int,
        stream_id: int = 0,
    ) -> AttackResult:
        """
        Execute a single burst of packets.

        Args:
            context: Attack execution context
            burst_size: Number of packets in this burst
            burst_index: Index of this burst
            stream_id: Stream identifier

        Returns:
            AttackResult for this burst
        """
        start_time = time.perf_counter()
        packets_sent = 0
        bytes_sent = 0

        try:
            # Generate burst payload
            burst_payload = self._generate_burst_payload(context, burst_size)

            # Send packets in rapid succession
            for packet_idx in range(burst_size):
                # Create packet context
                packet_context = context.copy()
                packet_context.payload = burst_payload

                # Send packet (simulated)
                packet_result = self._send_burst_packet(
                    packet_context, burst_index, packet_idx, stream_id
                )

                packets_sent += 1
                bytes_sent += len(burst_payload)

                # Small intra-burst delay
                if packet_idx < burst_size - 1:
                    intra_delay = self.burst_config.intra_burst_delay_ms
                    if self.burst_config.intra_burst_jitter_ms > 0:
                        jitter = random.uniform(
                            -self.burst_config.intra_burst_jitter_ms,
                            self.burst_config.intra_burst_jitter_ms,
                        )
                        intra_delay = max(0, intra_delay + jitter)

                    if intra_delay > 0:
                        time.sleep(intra_delay / 1000.0)

            end_time = time.perf_counter()
            burst_duration_ms = (end_time - start_time) * 1000

            # Update last response time for adaptive behavior
            self.last_response_time = burst_duration_ms

            # Update metrics
            self.metrics.total_bytes += bytes_sent

            return AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used=f"burst_traffic_burst_{burst_index}_stream_{stream_id}",
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                latency_ms=burst_duration_ms,
                response_received=True,
            )

        except Exception as e:
            self.logger.error(f"Failed to execute burst {burst_index}: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used=f"burst_traffic_error_{burst_index}",
            )

    def _generate_burst_payload(self, context: AttackContext, burst_size: int) -> bytes:
        """
        Generate payload for burst packets.

        Args:
            context: Attack execution context
            burst_size: Number of packets in burst

        Returns:
            Payload bytes for burst packets
        """
        if context.payload:
            base_payload = context.payload
        else:
            # Create default HTTP request
            base_payload = f"GET / HTTP/1.1\r\nHost: {context.domain or context.dst_ip}\r\n\r\n".encode()

        # Adjust payload size to configured burst payload size
        target_size = self.burst_config.burst_payload_size

        if len(base_payload) > target_size:
            # Truncate if too large
            return base_payload[:target_size]
        elif len(base_payload) < target_size:
            # Pad if too small
            padding_needed = target_size - len(base_payload)
            padding = b"X" * padding_needed
            return base_payload + padding
        else:
            return base_payload

    def _send_burst_packet(
        self,
        context: AttackContext,
        burst_index: int,
        packet_index: int,
        stream_id: int,
    ) -> AttackResult:
        """
        Send a single packet within a burst.

        Args:
            context: Attack execution context
            burst_index: Index of the burst
            packet_index: Index of packet within burst
            stream_id: Stream identifier

        Returns:
            AttackResult for the packet
        """
        # Simulate high-speed packet transmission
        # In a real implementation, this would use PyDivert or similar
        # to send packets with minimal delay

        # Simulate very small network delay for burst packets
        network_delay = random.uniform(0.1, 2.0)  # 0.1-2ms
        time.sleep(network_delay / 1000.0)

        return AttackResult(
            status=AttackStatus.SUCCESS,
            packets_sent=1,
            bytes_sent=len(context.payload),
            latency_ms=network_delay,
            technique_used=f"burst_packet_b{burst_index}_p{packet_index}_s{stream_id}",
        )

    def get_burst_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive burst traffic statistics.

        Returns:
            Dictionary with burst statistics
        """
        stats = {
            "burst_type": self.burst_config.burst_type.value,
            "burst_timing": self.burst_config.burst_timing.value,
            "concurrent_streams": self.burst_config.concurrent_streams,
            "total_bursts_configured": self.burst_config.total_bursts,
            "metrics": {
                "bursts_sent": self.metrics.bursts_sent,
                "total_packets": self.metrics.total_packets,
                "total_bytes": self.metrics.total_bytes,
                "successful_bursts": self.metrics.successful_bursts,
                "failed_bursts": self.metrics.failed_bursts,
                "success_rate": (
                    self.metrics.successful_bursts / max(1, self.metrics.bursts_sent)
                )
                * 100,
                "avg_burst_size": self.metrics.avg_burst_size,
                "avg_burst_interval_ms": self.metrics.avg_burst_interval_ms,
                "avg_response_time_ms": self.metrics.avg_response_time_ms,
            },
        }

        # Calculate throughput statistics
        if self.metrics.burst_timings:
            total_time_s = sum(self.metrics.burst_timings) / 1000.0
            if total_time_s > 0:
                stats["metrics"]["peak_throughput_pps"] = (
                    self.metrics.total_packets / total_time_s
                )
                stats["metrics"]["peak_throughput_bps"] = (
                    self.metrics.total_bytes / total_time_s
                )

        # Add timing controller statistics
        stats.update(self.get_timing_statistics())

        return stats

    def configure_burst_pattern(
        self, burst_type: BurstType = None, burst_timing: BurstTiming = None, **kwargs
    ):
        """
        Configure burst pattern and parameters.

        Args:
            burst_type: Type of burst size pattern
            burst_timing: Type of burst timing pattern
            **kwargs: Additional configuration parameters
        """
        if burst_type is not None:
            self.burst_config.burst_type = burst_type
        if burst_timing is not None:
            self.burst_config.burst_timing = burst_timing

        # Update other parameters
        for key, value in kwargs.items():
            if hasattr(self.burst_config, key):
                setattr(self.burst_config, key, value)
                self.logger.debug(f"Updated burst config {key} to {value}")

    def reset_burst_state(self):
        """Reset burst generation state."""
        self.metrics = BurstMetrics()
        self.fibonacci_cache = [1, 1]
        self.current_burst_size = self.burst_config.default_burst_size
        self.last_response_time = 0.0
        self.logger.debug("Reset burst traffic state")

    def benchmark_burst_patterns(
        self, test_bursts: int = 5
    ) -> Dict[str, Dict[str, Any]]:
        """
        Benchmark different burst patterns.

        Args:
            test_bursts: Number of bursts to generate for each pattern

        Returns:
            Benchmark results for each burst pattern
        """
        results = {}
        original_type = self.burst_config.burst_type
        original_timing = self.burst_config.burst_timing
        original_total = self.burst_config.total_bursts

        # Test each burst type
        for burst_type in BurstType:
            self.burst_config.burst_type = burst_type
            self.burst_config.total_bursts = test_bursts

            start_time = time.perf_counter()
            burst_sequence = self._generate_burst_sequence()
            end_time = time.perf_counter()

            generation_time_ms = (end_time - start_time) * 1000

            # Calculate statistics
            burst_sizes = [size for size, _ in burst_sequence]
            intervals = [interval for _, interval in burst_sequence if interval > 0]

            results[burst_type.value] = {
                "sequence_length": len(burst_sequence),
                "total_packets": sum(burst_sizes),
                "avg_burst_size": (
                    sum(burst_sizes) / len(burst_sizes) if burst_sizes else 0
                ),
                "min_burst_size": min(burst_sizes) if burst_sizes else 0,
                "max_burst_size": max(burst_sizes) if burst_sizes else 0,
                "avg_interval_ms": sum(intervals) / len(intervals) if intervals else 0,
                "generation_time_ms": generation_time_ms,
                "burst_sizes_preview": burst_sizes[:5],  # First 5 burst sizes
            }

        # Restore original configuration
        self.burst_config.burst_type = original_type
        self.burst_config.burst_timing = original_timing
        self.burst_config.total_bursts = original_total

        return results

    def __del__(self):
        """Cleanup thread pool on destruction."""
        if hasattr(self, "executor"):
            self.executor.shutdown(wait=False)
