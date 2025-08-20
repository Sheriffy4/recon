#!/usr/bin/env python3
"""
Demo script for timing-based DPI bypass attacks.

Demonstrates all timing attack implementations:
- Jitter injection attacks
- Delay-based evasion attacks
- Burst traffic generation attacks
- Performance benchmarking
"""

import asyncio
import time
import logging

from ..base import AttackContext
from .jitter_injection import JitterInjectionAttack, JitterConfiguration, JitterType
from .delay_evasion import DelayEvasionAttack, DelayEvasionConfiguration, DelayPattern
from .burst_traffic import (
    BurstTrafficAttack,
    BurstConfiguration,
    BurstType,
    BurstTiming,
)
from ..timing_controller import TimingStrategy, get_timing_controller


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def create_demo_context() -> AttackContext:
    """Create demo attack context."""
    return AttackContext(
        dst_ip="93.184.216.34",  # example.com IP
        dst_port=443,
        domain="example.com",
        payload=b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    )


def demo_jitter_injection():
    """Demonstrate jitter injection attacks."""
    print("\n" + "=" * 60)
    print("JITTER INJECTION ATTACK DEMONSTRATION")
    print("=" * 60)

    context = create_demo_context()

    # Test different jitter types
    jitter_types = [
        (JitterType.UNIFORM, "Uniform Random Jitter"),
        (JitterType.GAUSSIAN, "Gaussian Distribution Jitter"),
        (JitterType.PERIODIC, "Periodic Sine Wave Jitter"),
        (JitterType.SAWTOOTH, "Sawtooth Wave Jitter"),
        (JitterType.ADAPTIVE, "Adaptive Response-Based Jitter"),
    ]

    for jitter_type, description in jitter_types:
        print(f"\n--- {description} ---")

        config = JitterConfiguration(
            jitter_type=jitter_type,
            jitter_amplitude_ms=15.0,
            packets_per_burst=4,
            inter_packet_base_delay_ms=2.0,
        )

        attack = JitterInjectionAttack(config)

        start_time = time.perf_counter()
        result = attack.execute(context)
        end_time = time.perf_counter()

        execution_time = (end_time - start_time) * 1000

        print(f"Status: {result.status.value}")
        print(f"Technique: {result.technique_used}")
        print(f"Packets sent: {result.packets_sent}")
        print(f"Bytes sent: {result.bytes_sent}")
        print(f"Execution time: {execution_time:.2f}ms")

        # Get jitter statistics
        stats = attack.get_jitter_statistics()
        print(f"Jitter amplitude: {stats['jitter_amplitude_ms']}ms")
        if "avg_response_time_ms" in stats:
            print(f"Average response time: {stats['avg_response_time_ms']:.2f}ms")

    # Benchmark jitter patterns
    print("\n--- Jitter Pattern Benchmark ---")
    attack = JitterInjectionAttack()
    benchmark_results = attack.benchmark_jitter_patterns(test_count=100)

    for pattern, results in benchmark_results.items():
        print(
            f"{pattern}: avg={results['avg_jitter_ms']:.2f}ms, "
            f"range={results['jitter_range_ms']:.2f}ms, "
            f"gen_time={results['avg_generation_time_ms']:.4f}ms"
        )


def demo_delay_evasion():
    """Demonstrate delay-based evasion attacks."""
    print("\n" + "=" * 60)
    print("DELAY-BASED EVASION ATTACK DEMONSTRATION")
    print("=" * 60)

    context = create_demo_context()

    # Test different delay patterns
    delay_patterns = [
        (DelayPattern.PROGRESSIVE, "Progressive Increasing Delays"),
        (DelayPattern.EXPONENTIAL, "Exponential Backoff Delays"),
        (DelayPattern.FIBONACCI, "Fibonacci Sequence Delays"),
        (DelayPattern.SINE_WAVE, "Sine Wave Pattern Delays"),
        (DelayPattern.RANDOM_WALK, "Random Walk Delays"),
    ]

    for pattern, description in delay_patterns:
        print(f"\n--- {description} ---")

        config = DelayEvasionConfiguration(
            delay_pattern=pattern,
            base_delay_ms=5.0,
            max_progression_steps=6,
            progression_factor=1.8,
            packets_per_delay=2,
        )

        attack = DelayEvasionAttack(config)

        start_time = time.perf_counter()
        result = attack.execute(context)
        end_time = time.perf_counter()

        execution_time = (end_time - start_time) * 1000

        print(f"Status: {result.status.value}")
        print(f"Technique: {result.technique_used}")
        print(f"Packets sent: {result.packets_sent}")
        print(f"Bytes sent: {result.bytes_sent}")
        print(f"Execution time: {execution_time:.2f}ms")

        # Get delay statistics
        stats = attack.get_delay_evasion_statistics()
        print(f"Max progression steps: {stats['max_progression_steps']}")
        print(f"Packets per delay: {stats['packets_per_delay']}")
        if "avg_response_time_ms" in stats:
            print(f"Average response time: {stats['avg_response_time_ms']:.2f}ms")

    # Test custom delay sequence
    print("\n--- Custom Delay Sequence ---")
    custom_delays = [2.0, 5.0, 10.0, 20.0, 15.0, 8.0, 3.0]

    attack = DelayEvasionAttack()
    attack.set_custom_sequence(custom_delays)

    result = attack.execute(context)
    print(f"Custom sequence result: {result.status.value}")
    print(f"Packets sent: {result.packets_sent}")

    # Benchmark delay patterns
    print("\n--- Delay Pattern Benchmark ---")
    benchmark_results = attack.benchmark_delay_patterns(test_steps=8)

    for pattern, results in benchmark_results.items():
        print(
            f"{pattern}: total_delay={results['total_delay_ms']:.1f}ms, "
            f"avg={results['avg_delay_ms']:.2f}ms, "
            f"gen_time={results['generation_time_ms']:.4f}ms"
        )


def demo_burst_traffic():
    """Demonstrate burst traffic generation attacks."""
    print("\n" + "=" * 60)
    print("BURST TRAFFIC GENERATION ATTACK DEMONSTRATION")
    print("=" * 60)

    context = create_demo_context()

    # Test different burst types
    burst_configs = [
        (
            BurstType.FIXED_SIZE,
            BurstTiming.FIXED_INTERVAL,
            "Fixed Size, Fixed Interval",
        ),
        (
            BurstType.EXPONENTIAL,
            BurstTiming.EXPONENTIAL_BACKOFF,
            "Exponential Size, Exponential Timing",
        ),
        (
            BurstType.FIBONACCI,
            BurstTiming.RANDOM_INTERVAL,
            "Fibonacci Size, Random Timing",
        ),
        (
            BurstType.RANDOM,
            BurstTiming.RESPONSE_BASED,
            "Random Size, Response-Based Timing",
        ),
        (
            BurstType.ADAPTIVE,
            BurstTiming.VARIABLE_INTERVAL,
            "Adaptive Size, Variable Timing",
        ),
    ]

    for burst_type, burst_timing, description in burst_configs:
        print(f"\n--- {description} ---")

        config = BurstConfiguration(
            burst_type=burst_type,
            burst_timing=burst_timing,
            min_burst_size=3,
            max_burst_size=12,
            default_burst_size=6,
            total_bursts=4,
            burst_interval_ms=25.0,
            min_interval_ms=10.0,
            max_interval_ms=50.0,
            intra_burst_delay_ms=0.5,
        )

        attack = BurstTrafficAttack(config)

        start_time = time.perf_counter()
        result = attack.execute(context)
        end_time = time.perf_counter()

        execution_time = (end_time - start_time) * 1000

        print(f"Status: {result.status.value}")
        print(f"Technique: {result.technique_used}")
        print(f"Packets sent: {result.packets_sent}")
        print(f"Bytes sent: {result.bytes_sent}")
        print(f"Execution time: {execution_time:.2f}ms")

        # Get burst statistics
        stats = attack.get_burst_statistics()
        metrics = stats["metrics"]
        print(f"Bursts sent: {metrics['bursts_sent']}")
        print(f"Success rate: {metrics['success_rate']:.1f}%")
        print(f"Average burst size: {metrics['avg_burst_size']:.1f}")
        if metrics["avg_burst_interval_ms"] > 0:
            print(f"Average interval: {metrics['avg_burst_interval_ms']:.2f}ms")

    # Test concurrent streams
    print("\n--- Concurrent Multi-Stream Bursts ---")
    config = BurstConfiguration(
        burst_type=BurstType.VARIABLE_SIZE,
        concurrent_streams=3,
        stream_offset_ms=5.0,
        total_bursts=3,
        default_burst_size=4,
    )

    attack = BurstTrafficAttack(config)
    result = attack.execute(context)

    print(f"Multi-stream result: {result.status.value}")
    print(f"Total packets sent: {result.packets_sent}")
    print(f"Concurrent streams: {config.concurrent_streams}")

    # Benchmark burst patterns
    print("\n--- Burst Pattern Benchmark ---")
    benchmark_results = attack.benchmark_burst_patterns(test_bursts=4)

    for pattern, results in benchmark_results.items():
        print(
            f"{pattern}: total_packets={results['total_packets']}, "
            f"avg_size={results['avg_burst_size']:.1f}, "
            f"gen_time={results['generation_time_ms']:.4f}ms"
        )


def demo_timing_controller():
    """Demonstrate timing controller functionality."""
    print("\n" + "=" * 60)
    print("TIMING CONTROLLER DEMONSTRATION")
    print("=" * 60)

    controller = get_timing_controller()

    # Test different timing strategies
    test_delays = [0.5, 1.0, 5.0, 10.0, 25.0]

    print("\n--- Timing Strategy Comparison ---")
    for delay_ms in test_delays:
        print(f"\nTesting {delay_ms}ms delay:")

        for strategy in [
            TimingStrategy.SLEEP,
            TimingStrategy.BUSY_WAIT,
            TimingStrategy.HYBRID,
        ]:
            measurement = controller.delay(delay_ms, strategy)

            print(
                f"  {strategy.value}: "
                f"actual={measurement.actual_delay_ms:.3f}ms, "
                f"error={measurement.accuracy_error_ms:.3f}ms, "
                f"accuracy={measurement.accuracy_percentage:.1f}%"
            )

    # Benchmark timing strategies
    print("\n--- Timing Strategy Benchmark ---")
    benchmark_delays = [0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
    benchmark_results = controller.benchmark_strategies(benchmark_delays)

    for strategy, results in benchmark_results.items():
        print(
            f"{strategy.value}: "
            f"avg_accuracy={results['avg_accuracy']:.1f}%, "
            f"avg_error={results['avg_error_ms']:.3f}ms, "
            f"max_error={results['max_error_ms']:.3f}ms"
        )

    # Get overall statistics
    print("\n--- Overall Timing Statistics ---")
    stats = controller.get_statistics()
    print(f"Total delays executed: {stats['total_delays']}")
    print(f"Average accuracy: {stats['average_accuracy_percentage']:.1f}%")
    print(f"Average error: {stats['average_error_ms']:.3f}ms")


def demo_performance_comparison():
    """Compare performance of different timing attacks."""
    print("\n" + "=" * 60)
    print("TIMING ATTACK PERFORMANCE COMPARISON")
    print("=" * 60)

    context = create_demo_context()

    # Create different attack configurations
    attacks = [
        (
            "Jitter Injection (Uniform)",
            JitterInjectionAttack(
                JitterConfiguration(
                    jitter_type=JitterType.UNIFORM,
                    jitter_amplitude_ms=10.0,
                    packets_per_burst=5,
                )
            ),
        ),
        (
            "Delay Evasion (Progressive)",
            DelayEvasionAttack(
                DelayEvasionConfiguration(
                    delay_pattern=DelayPattern.PROGRESSIVE,
                    max_progression_steps=5,
                    progression_factor=1.5,
                )
            ),
        ),
        (
            "Burst Traffic (Fixed)",
            BurstTrafficAttack(
                BurstConfiguration(
                    burst_type=BurstType.FIXED_SIZE,
                    default_burst_size=8,
                    total_bursts=3,
                )
            ),
        ),
    ]

    results = []

    for name, attack in attacks:
        print(f"\n--- Testing {name} ---")

        # Run multiple iterations for average
        execution_times = []
        packets_sent_list = []
        bytes_sent_list = []

        for i in range(3):
            start_time = time.perf_counter()
            result = attack.execute(context)
            end_time = time.perf_counter()

            execution_time = (end_time - start_time) * 1000
            execution_times.append(execution_time)
            packets_sent_list.append(result.packets_sent)
            bytes_sent_list.append(result.bytes_sent)

        avg_execution_time = sum(execution_times) / len(execution_times)
        avg_packets_sent = sum(packets_sent_list) / len(packets_sent_list)
        avg_bytes_sent = sum(bytes_sent_list) / len(bytes_sent_list)

        print(f"Average execution time: {avg_execution_time:.2f}ms")
        print(f"Average packets sent: {avg_packets_sent:.1f}")
        print(f"Average bytes sent: {avg_bytes_sent:.1f}")

        # Calculate packets per second
        if avg_execution_time > 0:
            pps = (avg_packets_sent / avg_execution_time) * 1000
            print(f"Packets per second: {pps:.1f}")

        results.append(
            {
                "name": name,
                "avg_time_ms": avg_execution_time,
                "avg_packets": avg_packets_sent,
                "avg_bytes": avg_bytes_sent,
            }
        )

    # Summary comparison
    print("\n--- Performance Summary ---")
    print(f"{'Attack Type':<30} {'Time (ms)':<12} {'Packets':<10} {'Bytes':<10}")
    print("-" * 62)

    for result in results:
        print(
            f"{result['name']:<30} {result['avg_time_ms']:<12.2f} "
            f"{result['avg_packets']:<10.1f} {result['avg_bytes']:<10.1f}"
        )


async def demo_async_timing():
    """Demonstrate asynchronous timing functionality."""
    print("\n" + "=" * 60)
    print("ASYNCHRONOUS TIMING DEMONSTRATION")
    print("=" * 60)

    controller = get_timing_controller()

    # Test async delays
    print("\n--- Async Delay Testing ---")
    test_delays = [1.0, 5.0, 10.0]

    for delay_ms in test_delays:
        start_time = time.perf_counter()
        measurement = await controller.async_delay(delay_ms)
        end_time = time.perf_counter()

        actual_time = (end_time - start_time) * 1000

        print(
            f"Async delay {delay_ms}ms: "
            f"measured={measurement.actual_delay_ms:.3f}ms, "
            f"wall_time={actual_time:.3f}ms, "
            f"accuracy={measurement.accuracy_percentage:.1f}%"
        )

    # Test concurrent async delays
    print("\n--- Concurrent Async Delays ---")

    async def concurrent_delay(delay_ms, delay_id):
        start_time = time.perf_counter()
        measurement = await controller.async_delay(delay_ms)
        end_time = time.perf_counter()
        return delay_id, measurement, (end_time - start_time) * 1000

    # Run multiple delays concurrently
    tasks = [
        concurrent_delay(5.0, 1),
        concurrent_delay(10.0, 2),
        concurrent_delay(15.0, 3),
    ]

    start_time = time.perf_counter()
    results = await asyncio.gather(*tasks)
    end_time = time.perf_counter()

    total_time = (end_time - start_time) * 1000

    print(f"Concurrent execution total time: {total_time:.2f}ms")
    for delay_id, measurement, wall_time in results:
        print(
            f"  Delay {delay_id}: {measurement.requested_delay_ms}ms -> "
            f"{measurement.actual_delay_ms:.3f}ms (wall: {wall_time:.3f}ms)"
        )


def main():
    """Run all timing attack demonstrations."""
    print("TIMING-BASED DPI BYPASS ATTACKS DEMONSTRATION")
    print("=" * 80)
    print("This demo showcases advanced packet timing manipulation techniques")
    print("for evading Deep Packet Inspection (DPI) systems.")
    print("=" * 80)

    try:
        # Demonstrate individual attack types
        demo_jitter_injection()
        demo_delay_evasion()
        demo_burst_traffic()

        # Demonstrate timing controller
        demo_timing_controller()

        # Performance comparison
        demo_performance_comparison()

        # Async timing demo
        print("\nRunning async timing demonstration...")
        asyncio.run(demo_async_timing())

        print("\n" + "=" * 60)
        print("DEMONSTRATION COMPLETE")
        print("=" * 60)
        print("All timing attack implementations have been demonstrated.")
        print("Key features showcased:")
        print("- Jitter injection with multiple patterns")
        print("- Delay-based evasion with sophisticated sequences")
        print("- Burst traffic generation with concurrent streams")
        print("- High-precision timing control")
        print("- Performance benchmarking and comparison")
        print("- Asynchronous timing support")

    except KeyboardInterrupt:
        print("\nDemo interrupted by user.")
    except Exception as e:
        logger.error(f"Demo failed with error: {e}")
        raise


if __name__ == "__main__":
    main()
