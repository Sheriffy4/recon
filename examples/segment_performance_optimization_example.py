#!/usr/bin/env python3
"""
Segment Performance Optimization Example.

Demonstrates the usage of the segment performance optimizer for improving
attack execution performance through caching, memory pooling, async execution,
and other optimization techniques.
"""

import time
import random
from typing import List, Tuple, Dict, Any

from core.bypass.performance.segment_performance_optimizer import (
    SegmentPerformanceOptimizer,
    OptimizationConfig,
    PerformanceMetrics,
    get_global_optimizer,
    optimize_segments
)
from core.bypass.attacks.segment_packet_builder import SegmentPacketBuilder
from core.bypass.attacks.base import AttackContext


def create_test_segments(count: int = 50) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """Create test segments for demonstration."""
    segments = []
    
    for i in range(count):
        # Create varied payloads
        payload_size = random.randint(50, 500)
        payload = f"HTTP/1.1 GET /path{i} ".encode() + b"X" * (payload_size - 20)
        
        # Sequence offset
        seq_offset = i * payload_size
        
        # Options with some variation
        options = {
            "ttl": random.randint(32, 64),
            "delay_ms": random.randint(0, 100),
            "flags": 0x18,  # PSH+ACK
            "window_size": random.choice([1024, 2048, 4096, 8192])
        }
        
        segments.append((payload, seq_offset, options))
    
    return segments


def simulate_packet_construction(segments: List[Tuple[bytes, int, Dict[str, Any]]]) -> List[bytes]:
    """Simulate packet construction (normally done by SegmentPacketBuilder)."""
    packets = []
    
    for payload, seq_offset, options in segments:
        # Simulate construction time
        time.sleep(0.001)  # 1ms per packet
        
        # Create mock packet
        packet = f"PACKET[{len(payload)}bytes,seq={seq_offset},ttl={options.get('ttl', 64)}]".encode()
        packets.append(packet)
    
    return packets


def simulate_packet_transmission(packet: bytes):
    """Simulate packet transmission."""
    # Simulate network transmission time
    time.sleep(0.0005)  # 0.5ms per packet
    
    # Simulate some processing
    _ = len(packet)


def demonstrate_basic_optimization():
    """Demonstrate basic performance optimization."""
    print("=== Basic Performance Optimization ===")
    
    # Create test segments
    segments = create_test_segments(20)
    print(f"Created {len(segments)} test segments")
    
    # Create optimizer with default configuration
    optimizer = SegmentPerformanceOptimizer()
    
    # Define execution function
    def execution_func(segment):
        payload, seq_offset, options = segment
        packet = simulate_packet_construction([segment])[0]
        simulate_packet_transmission(packet)
    
    # Execute with optimization
    print("Executing segments with optimization...")
    start_time = time.time()
    metrics = optimizer.optimize_segment_execution(segments, execution_func)
    execution_time = time.time() - start_time
    
    print(f"Execution completed in {execution_time:.3f}s")
    print(f"Segments processed: {metrics.segment_count}")
    print(f"Optimizations applied: {', '.join(metrics.optimization_applied)}")
    
    # Get performance stats
    stats = optimizer.get_performance_stats()
    print(f"Cache hit rate: {stats.get('cache_stats', {}).get('hit_rate', 0):.1%}")
    
    optimizer.cleanup()


def demonstrate_configuration_options():
    """Demonstrate different optimization configurations."""
    print("\n=== Configuration Options ===")
    
    segments = create_test_segments(15)
    
    # Test different configurations
    configs = [
        ("Default", OptimizationConfig()),
        ("Cache Only", OptimizationConfig(
            enable_packet_caching=True,
            enable_memory_pooling=False,
            enable_async_execution=False,
            enable_batch_processing=False
        )),
        ("Async Only", OptimizationConfig(
            enable_packet_caching=False,
            enable_memory_pooling=False,
            enable_async_execution=True,
            enable_batch_processing=False
        )),
        ("Batch Only", OptimizationConfig(
            enable_packet_caching=False,
            enable_memory_pooling=False,
            enable_async_execution=False,
            enable_batch_processing=True,
            batch_size=5
        )),
        ("All Optimizations", OptimizationConfig(
            enable_packet_caching=True,
            enable_memory_pooling=True,
            enable_async_execution=True,
            enable_batch_processing=True,
            batch_size=3,
            profiling_enabled=True
        ))
    ]
    
    def execution_func(segment):
        simulate_packet_transmission(b"mock_packet")
    
    results = []
    
    for config_name, config in configs:
        optimizer = SegmentPerformanceOptimizer(config)
        
        start_time = time.time()
        metrics = optimizer.optimize_segment_execution(segments, execution_func)
        execution_time = time.time() - start_time
        
        results.append((config_name, execution_time, metrics.optimization_applied))
        optimizer.cleanup()
    
    # Display results
    print(f"{'Configuration':<20} {'Time (ms)':<10} {'Optimizations'}")
    print("-" * 60)
    for config_name, exec_time, optimizations in results:
        print(f"{config_name:<20} {exec_time*1000:<10.1f} {', '.join(optimizations)}")


def demonstrate_caching_benefits():
    """Demonstrate packet caching benefits."""
    print("\n=== Caching Benefits ===")
    
    # Create segments with repeated patterns (good for caching)
    base_segments = create_test_segments(5)
    repeated_segments = base_segments * 4  # Repeat 4 times
    random.shuffle(repeated_segments)  # Shuffle to simulate real usage
    
    print(f"Testing with {len(repeated_segments)} segments ({len(base_segments)} unique)")
    
    # Test without caching
    config_no_cache = OptimizationConfig(enable_packet_caching=False)
    optimizer_no_cache = SegmentPerformanceOptimizer(config_no_cache)
    
    def execution_func_no_cache(segment):
        # Simulate expensive packet construction
        time.sleep(0.002)  # 2ms per construction
    
    start_time = time.time()
    metrics_no_cache = optimizer_no_cache.optimize_segment_execution(repeated_segments, execution_func_no_cache)
    time_no_cache = time.time() - start_time
    
    # Test with caching
    config_with_cache = OptimizationConfig(enable_packet_caching=True, max_cache_size=10)
    optimizer_with_cache = SegmentPerformanceOptimizer(config_with_cache)
    
    def execution_func_with_cache(segment):
        # Simulate packet construction (will be cached)
        time.sleep(0.002)  # 2ms per construction
    
    start_time = time.time()
    metrics_with_cache = optimizer_with_cache.optimize_segment_execution(repeated_segments, execution_func_with_cache)
    time_with_cache = time.time() - start_time
    
    # Compare results
    print(f"Without caching: {time_no_cache:.3f}s")
    print(f"With caching:    {time_with_cache:.3f}s")
    print(f"Speedup:         {time_no_cache/time_with_cache:.1f}x")
    
    # Show cache stats
    cache_stats = optimizer_with_cache.get_performance_stats().get('cache_stats', {})
    print(f"Cache hit rate:  {cache_stats.get('hit_rate', 0):.1%}")
    print(f"Cache hits:      {cache_stats.get('hits', 0)}")
    print(f"Cache misses:    {cache_stats.get('misses', 0)}")
    
    optimizer_no_cache.cleanup()
    optimizer_with_cache.cleanup()


def demonstrate_memory_pooling():
    """Demonstrate memory pooling benefits."""
    print("\n=== Memory Pooling Benefits ===")
    
    segments = create_test_segments(30)
    
    # Test without memory pooling
    config_no_pool = OptimizationConfig(enable_memory_pooling=False)
    optimizer_no_pool = SegmentPerformanceOptimizer(config_no_pool)
    
    allocations_no_pool = []
    
    def execution_func_no_pool(segment):
        # Simulate memory allocation
        buffer = bytearray(1024)  # New allocation each time
        allocations_no_pool.append(buffer)
        time.sleep(0.0001)
    
    start_time = time.time()
    optimizer_no_pool.optimize_segment_execution(segments, execution_func_no_pool)
    time_no_pool = time.time() - start_time
    
    # Test with memory pooling
    config_with_pool = OptimizationConfig(enable_memory_pooling=True)
    optimizer_with_pool = SegmentPerformanceOptimizer(config_with_pool)
    
    def execution_func_with_pool(segment):
        # Simulate using memory pool
        buffer = optimizer_with_pool.memory_pool.get_buffer(1024)
        optimizer_with_pool.memory_pool.return_buffer(buffer)
        time.sleep(0.0001)
    
    start_time = time.time()
    optimizer_with_pool.optimize_segment_execution(segments, execution_func_with_pool)
    time_with_pool = time.time() - start_time
    
    # Compare results
    print(f"Without pooling: {time_no_pool:.3f}s")
    print(f"With pooling:    {time_with_pool:.3f}s")
    
    # Show memory pool stats
    pool_stats = optimizer_with_pool.get_performance_stats().get('memory_pool_stats', {})
    print(f"Buffer reuse rate: {pool_stats.get('reuse_rate', 0):.1%}")
    print(f"Buffers allocated: {pool_stats.get('allocated', 0)}")
    print(f"Buffers reused:    {pool_stats.get('reused', 0)}")
    
    optimizer_no_pool.cleanup()
    optimizer_with_pool.cleanup()


def demonstrate_performance_benchmarking():
    """Demonstrate performance benchmarking."""
    print("\n=== Performance Benchmarking ===")
    
    segments = create_test_segments(10)
    
    # Create optimizer with profiling enabled
    config = OptimizationConfig(
        enable_packet_caching=True,
        enable_memory_pooling=True,
        enable_async_execution=True,
        profiling_enabled=True
    )
    optimizer = SegmentPerformanceOptimizer(config)
    
    def execution_func(segment):
        # Simulate variable execution time
        time.sleep(random.uniform(0.001, 0.005))
    
    # Run benchmark
    print("Running performance benchmark...")
    benchmark_results = optimizer.benchmark_performance(segments, execution_func, iterations=5)
    
    # Display results
    print(f"Benchmark Results:")
    print(f"  Iterations: {benchmark_results['iterations']}")
    print(f"  Segments per iteration: {benchmark_results['segment_count']}")
    print(f"  Total segments processed: {benchmark_results['total_segments_processed']}")
    print(f"  Average execution time: {benchmark_results['avg_time']*1000:.2f}ms")
    print(f"  Min execution time: {benchmark_results['min_time']*1000:.2f}ms")
    print(f"  Max execution time: {benchmark_results['max_time']*1000:.2f}ms")
    print(f"  Throughput: {benchmark_results['throughput_segments_per_sec']:.1f} segments/sec")
    
    # Show profiler stats
    profiler_stats = benchmark_results['performance_stats'].get('profiler_stats', {})
    if profiler_stats:
        print(f"  Profiler data:")
        for operation, stats in profiler_stats.items():
            print(f"    {operation}: {stats['avg_time']*1000:.2f}ms avg ({stats['count']} calls)")
    
    optimizer.cleanup()


def demonstrate_optimization_suggestions():
    """Demonstrate optimization suggestions."""
    print("\n=== Optimization Suggestions ===")
    
    segments = create_test_segments(25)
    
    # Create optimizer with suboptimal configuration
    config = OptimizationConfig(
        enable_packet_caching=True,
        max_cache_size=5,  # Very small cache
        enable_memory_pooling=False,
        enable_async_execution=False,
        enable_batch_processing=False
    )
    optimizer = SegmentPerformanceOptimizer(config)
    
    def execution_func(segment):
        time.sleep(0.002)  # Slow execution
    
    # Execute segments
    optimizer.optimize_segment_execution(segments, execution_func)
    
    # Get performance stats and suggestions
    stats = optimizer.get_performance_stats()
    suggestions = optimizer.suggest_optimizations(stats)
    
    print("Current Performance Stats:")
    if 'cache_stats' in stats:
        cache_stats = stats['cache_stats']
        print(f"  Cache hit rate: {cache_stats.get('hit_rate', 0):.1%}")
        print(f"  Cache size: {cache_stats.get('size', 0)}/{cache_stats.get('max_size', 0)}")
    
    if 'performance_history' in stats:
        history = stats['performance_history']
        print(f"  Average execution time: {history.get('avg_time', 0)*1000:.2f}ms")
    
    print("\nOptimization Suggestions:")
    if suggestions:
        for i, suggestion in enumerate(suggestions, 1):
            print(f"  {i}. {suggestion}")
    else:
        print("  No suggestions - performance looks good!")
    
    optimizer.cleanup()


def demonstrate_global_optimizer():
    """Demonstrate global optimizer usage."""
    print("\n=== Global Optimizer ===")
    
    segments = create_test_segments(15)
    
    def execution_func(segment):
        time.sleep(0.001)
    
    # Use global optimizer (convenience function)
    print("Using global optimizer...")
    start_time = time.time()
    metrics = optimize_segments(segments, execution_func)
    execution_time = time.time() - start_time
    
    print(f"Execution time: {execution_time:.3f}s")
    print(f"Segments processed: {metrics.segment_count}")
    print(f"Optimizations: {', '.join(metrics.optimization_applied)}")
    
    # Get global optimizer stats
    global_optimizer = get_global_optimizer()
    stats = global_optimizer.get_performance_stats()
    
    print("Global optimizer stats:")
    print(f"  Optimization calls: {stats.get('optimization_stats', {})}")
    
    # The global optimizer persists across calls
    print("\nUsing global optimizer again...")
    metrics2 = optimize_segments(segments[:5], execution_func)
    print(f"Second call processed: {metrics2.segment_count} segments")


def demonstrate_real_world_scenario():
    """Demonstrate real-world attack scenario optimization."""
    print("\n=== Real-World Attack Scenario ===")
    
    # Simulate a real attack with multiple types of segments
    http_segments = []
    
    # HTTP request segments
    for i in range(10):
        payload = f"GET /api/endpoint{i} HTTP/1.1\r\nHost: target.com\r\nUser-Agent: Browser\r\n\r\n".encode()
        http_segments.append((payload, i * len(payload), {"ttl": 64, "delay_ms": i * 10}))
    
    # HTTP response segments (simulated)
    for i in range(5):
        payload = f"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{'X' * 100}".encode()
        http_segments.append((payload, 1000 + i * len(payload), {"ttl": 63, "delay_ms": 50}))
    
    print(f"Simulating attack with {len(http_segments)} HTTP segments")
    
    # Create production-like optimizer configuration
    config = OptimizationConfig(
        enable_packet_caching=True,
        enable_memory_pooling=True,
        enable_async_execution=True,
        enable_batch_processing=True,
        max_cache_size=100,
        batch_size=5,
        profiling_enabled=True,
        performance_threshold_ms=50.0
    )
    
    optimizer = SegmentPerformanceOptimizer(config)
    
    def attack_execution_func(segment):
        payload, seq_offset, options = segment
        
        # Simulate packet construction
        time.sleep(0.001)
        
        # Simulate timing delay
        delay_ms = options.get("delay_ms", 0)
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        
        # Simulate transmission
        time.sleep(0.0005)
    
    # Execute attack
    print("Executing optimized attack...")
    start_time = time.time()
    metrics = optimizer.optimize_segment_execution(http_segments, attack_execution_func)
    execution_time = time.time() - start_time
    
    print(f"Attack completed in {execution_time:.3f}s")
    print(f"Segments processed: {metrics.segment_count}")
    print(f"Optimizations applied: {', '.join(metrics.optimization_applied)}")
    
    # Show detailed stats
    stats = optimizer.get_performance_stats()
    print("\nDetailed Performance Stats:")
    
    if 'cache_stats' in stats:
        cache = stats['cache_stats']
        print(f"  Cache: {cache['hits']} hits, {cache['misses']} misses ({cache['hit_rate']:.1%} hit rate)")
    
    if 'memory_pool_stats' in stats:
        pool = stats['memory_pool_stats']
        print(f"  Memory Pool: {pool['reused']} reused, {pool['allocated']} allocated ({pool['reuse_rate']:.1%} reuse rate)")
    
    if 'profiler_stats' in stats:
        print("  Profiler Data:")
        for operation, op_stats in stats['profiler_stats'].items():
            print(f"    {operation}: {op_stats['avg_time']*1000:.2f}ms avg ({op_stats['count']} calls)")
    
    # Get optimization suggestions
    suggestions = optimizer.suggest_optimizations(stats)
    if suggestions:
        print("\nOptimization Suggestions:")
        for suggestion in suggestions:
            print(f"  - {suggestion}")
    
    optimizer.cleanup()


def main():
    """Run all performance optimization demonstrations."""
    print("Segment Performance Optimization Examples")
    print("=" * 50)
    
    try:
        demonstrate_basic_optimization()
        demonstrate_configuration_options()
        demonstrate_caching_benefits()
        demonstrate_memory_pooling()
        demonstrate_performance_benchmarking()
        demonstrate_optimization_suggestions()
        demonstrate_global_optimizer()
        demonstrate_real_world_scenario()
        
        print("\n" + "=" * 50)
        print("All performance optimization examples completed!")
        
    except Exception as e:
        print(f"\nError during demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()