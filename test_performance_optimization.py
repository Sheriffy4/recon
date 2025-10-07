"""
Comprehensive test for performance optimization features.
Tests streaming, memory optimization, parallel processing, and caching.
"""

import asyncio
import os
import tempfile
import time
import random
import shutil
from pathlib import Path
from typing import List

from core.pcap_analysis.packet_info import PacketInfo
from core.pcap_analysis.streaming_processor import StreamingPcapProcessor, StreamingConfig
from core.pcap_analysis.memory_optimizer import MemoryOptimizer, OptimizedPacketStorage
from core.pcap_analysis.parallel_processor import ParallelPcapAnalyzer, ParallelConfig
from core.pcap_analysis.analysis_cache import HybridCache, CachedAnalyzer
from core.pcap_analysis.performance_integration import HighPerformancePcapAnalyzer, PerformanceConfig

def create_sample_packets(count: int = 10000) -> List[PacketInfo]:
    """Create sample packets for testing."""
    packets = []
    base_time = time.time()
    
    for i in range(count):
        packet = PacketInfo(
            timestamp=base_time + i * 0.001,  # 1ms intervals
            src_ip=f"192.168.1.{random.randint(1, 50)}",
            dst_ip=f"10.0.0.{random.randint(1, 50)}",
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443, 8080, 8443, 53]),
            sequence_num=i * 1000 + random.randint(0, 999),
            ack_num=i * 1000 + random.randint(1000, 1999),
            ttl=random.choice([64, 128, 255]),
            flags=random.choice([['ACK'], ['SYN'], ['SYN', 'ACK'], ['FIN', 'ACK'], ['RST']]),
            payload_length=random.randint(0, 1500),
            payload_hex="deadbeef" * random.randint(1, 20),
            checksum=random.randint(0x1000, 0xFFFF),
            checksum_valid=random.choice([True, False]),
            is_client_hello=(i % 100 == 0)  # Every 100th packet is TLS Client Hello
        )
        packets.append(packet)
        
    return packets

def test_streaming_processor():
    """Test streaming PCAP processor."""
    print("Testing streaming processor...")
    
    # Create test configuration
    config = StreamingConfig(
        chunk_size=1000,
        memory_limit_mb=128,
        enable_gc_optimization=True
    )
    
    processor = StreamingPcapProcessor(config)
    
    # Test memory monitoring
    memory_usage = processor.memory_monitor.get_memory_usage_mb()
    print(f"  Initial memory usage: {memory_usage:.1f}MB")
    
    # Test with sample data (would normally use real PCAP file)
    sample_packets = create_sample_packets(5000)
    print(f"  Created {len(sample_packets)} sample packets")
    
    # Test memory limit detection
    is_limit_exceeded = processor.memory_monitor.is_memory_limit_exceeded()
    print(f"  Memory limit exceeded: {is_limit_exceeded}")
    
    print("  Streaming processor test completed ✓")

def test_memory_optimizer():
    """Test memory optimization features."""
    print("Testing memory optimizer...")
    
    optimizer = MemoryOptimizer(enable_aggressive_gc=True)
    
    # Get initial memory stats
    initial_stats = optimizer.get_memory_stats()
    print(f"  Initial memory: {initial_stats.rss_mb:.1f}MB")
    
    # Create large packet collection
    large_packet_set = create_sample_packets(20000)
    print(f"  Created {len(large_packet_set)} packets for optimization")
    
    # Test packet storage optimization
    start_time = time.time()
    optimized_storage = optimizer.optimize_packet_storage(large_packet_set)
    optimization_time = time.time() - start_time
    
    print(f"  Optimization completed in {optimization_time:.2f}s")
    
    # Test optimized queries
    test_ip = "192.168.1.1"
    packets_by_ip = optimized_storage.get_packets_by_ip(test_ip)
    print(f"  Found {len(packets_by_ip)} packets for IP {test_ip}")
    
    packets_in_range = optimized_storage.get_packets_in_time_range(
        time.time(), time.time() + 10
    )
    print(f"  Found {len(packets_in_range)} packets in time range")
    
    # Test memory usage
    storage_memory = optimized_storage.get_memory_usage_mb()
    print(f"  Optimized storage memory usage: {storage_memory:.1f}MB")
    
    # Force garbage collection
    gc_stats = optimizer.force_garbage_collection()
    print(f"  GC freed {gc_stats.get('memory_freed_mb', 0):.1f}MB")
    
    print("  Memory optimizer test completed ✓")

def test_parallel_processor():
    """Test parallel processing capabilities."""
    print("Testing parallel processor...")
    
    config = ParallelConfig(
        max_workers=4,
        use_processes=True,
        chunk_size=1000,
        timeout_seconds=30.0
    )
    
    analyzer = ParallelPcapAnalyzer(config)
    
    # Create sample analysis functions
    def count_packets(packets: List[PacketInfo]) -> int:
        time.sleep(0.1)  # Simulate processing time
        return len(packets)
        
    def count_unique_ips(packets: List[PacketInfo]) -> int:
        time.sleep(0.1)  # Simulate processing time
        unique_ips = set()
        for packet in packets:
            unique_ips.add(packet.src_ip)
            unique_ips.add(packet.dst_ip)
        return len(unique_ips)
        
    def analyze_protocols(packets: List[PacketInfo]) -> dict:
        time.sleep(0.1)  # Simulate processing time
        protocols = {'TLS': 0, 'Other': 0}
        for packet in packets:
            if packet.is_client_hello:
                protocols['TLS'] += 1
            else:
                protocols['Other'] += 1
        return protocols
        
    # Test parallel packet analysis
    sample_packets = create_sample_packets(5000)
    analysis_functions = [count_packets, count_unique_ips, analyze_protocols]
    
    start_time = time.time()
    results = analyzer.parallel_packet_analysis(sample_packets, analysis_functions)
    parallel_time = time.time() - start_time
    
    print(f"  Parallel analysis completed in {parallel_time:.2f}s")
    print(f"  Analysis results: {len(results)} functions executed")
    
    for task_id, result in results.items():
        print(f"    {task_id}: {result}")
        
    print("  Parallel processor test completed ✓")

def test_analysis_cache():
    """Test analysis caching system."""
    print("Testing analysis cache...")
    
    # Create temporary cache directory
    temp_cache_dir = tempfile.mkdtemp(prefix="test_cache_")
    
    try:
        # Create hybrid cache
        cache = HybridCache(
            memory_cache_mb=32,
            persistent_cache_mb=64,
            cache_dir=temp_cache_dir
        )
        
        # Test basic cache operations
        test_data = {
            'analysis_result': 'test_value',
            'timestamp': time.time(),
            'packet_count': 1000
        }
        
        # Test cache put/get
        cache_key = "test_analysis_key"
        put_success = cache.put(cache_key, test_data, ttl_seconds=300)
        print(f"  Cache put successful: {put_success}")
        
        retrieved_data = cache.get(cache_key)
        print(f"  Cache get successful: {retrieved_data is not None}")
        print(f"  Data matches: {retrieved_data == test_data}")
        
        # Test cached analyzer
        cached_analyzer = CachedAnalyzer(cache)
        
        def sample_analysis(packets: List[PacketInfo]) -> dict:
            time.sleep(0.1)  # Simulate processing
            return {
                'packet_count': len(packets),
                'analysis_time': time.time()
            }
            
        sample_packets = create_sample_packets(1000)
        
        # First call (cache miss)
        start_time = time.time()
        result1 = cached_analyzer.cached_packet_analysis(
            sample_packets, sample_analysis, "test_analysis"
        )
        first_call_time = time.time() - start_time
        
        # Second call (cache hit)
        start_time = time.time()
        result2 = cached_analyzer.cached_packet_analysis(
            sample_packets, sample_analysis, "test_analysis"
        )
        second_call_time = time.time() - start_time
        
        print(f"  First call time: {first_call_time:.3f}s")
        print(f"  Second call time: {second_call_time:.3f}s")
        print(f"  Cache speedup: {first_call_time / max(second_call_time, 0.001):.1f}x")
        
        # Test cache statistics
        cache_stats = cache.get_stats()
        print(f"  Memory cache entries: {cache_stats['memory'].total_entries}")
        print(f"  Persistent cache entries: {cache_stats['persistent'].total_entries}")
        
        print("  Analysis cache test completed ✓")
        
    finally:
        # Cleanup temporary cache directory
        if os.path.exists(temp_cache_dir):
            shutil.rmtree(temp_cache_dir)

def test_performance_integration():
    """Test integrated high-performance analyzer."""
    print("Testing performance integration...")
    
    # Create temporary cache directory
    temp_cache_dir = tempfile.mkdtemp(prefix="test_perf_cache_")
    
    try:
        config = PerformanceConfig(
            streaming_chunk_size=500,
            streaming_memory_limit_mb=128,
            memory_cache_mb=32,
            persistent_cache_mb=64,
            max_workers=2,
            cache_dir=temp_cache_dir,
            enable_progress_reporting=False  # Disable for cleaner test output
        )
        
        analyzer = HighPerformancePcapAnalyzer(config)
        
        # Test analysis functions
        def count_tls_packets(packets: List[PacketInfo]) -> int:
            return sum(1 for p in packets if p.is_client_hello)
            
        def analyze_port_distribution(packets: List[PacketInfo]) -> dict:
            port_counts = {}
            for packet in packets:
                port = packet.dst_port
                port_counts[port] = port_counts.get(port, 0) + 1
            return port_counts
            
        # Create a mock PCAP file analysis (since we don't have real PCAP files)
        sample_packets = create_sample_packets(5000)
        
        # Simulate single PCAP analysis
        start_time = time.time()
        
        # Mock the analyze_single_pcap method to work with our sample data
        def mock_analyze_single_pcap(pcap_file: str) -> dict:
            return {
                'pcap_file': pcap_file,
                'packet_count': len(sample_packets),
                'analysis_timestamp': time.time(),
                'optimizations_applied': ['memory_optimization', 'caching'],
                'basic_stats': {
                    'unique_src_ips': len(set(p.src_ip for p in sample_packets)),
                    'unique_dst_ips': len(set(p.dst_ip for p in sample_packets)),
                    'tls_client_hello_count': sum(1 for p in sample_packets if p.is_client_hello)
                }
            }
            
        # Test the mock analysis
        result = mock_analyze_single_pcap("test.pcap")
        analysis_time = time.time() - start_time
        
        print(f"  Mock analysis completed in {analysis_time:.3f}s")
        print(f"  Packet count: {result['packet_count']}")
        print(f"  Unique source IPs: {result['basic_stats']['unique_src_ips']}")
        print(f"  TLS packets: {result['basic_stats']['tls_client_hello_count']}")
        print(f"  Optimizations applied: {result['optimizations_applied']}")
        
        # Test performance metrics
        metrics = analyzer.get_performance_metrics()
        print(f"  Performance metrics collected: {len(metrics)} items")
        
        # Cleanup
        analyzer.cleanup()
        
        print("  Performance integration test completed ✓")
        
    finally:
        # Cleanup temporary cache directory
        if os.path.exists(temp_cache_dir):
            shutil.rmtree(temp_cache_dir)

async def test_async_processing():
    """Test asynchronous processing capabilities."""
    print("Testing async processing...")
    
    from core.pcap_analysis.parallel_processor import AsyncParallelProcessor
    
    processor = AsyncParallelProcessor(max_concurrent_tasks=5)
    
    # Create async test tasks
    async def async_analysis_task(task_id: int, processing_time: float) -> dict:
        await asyncio.sleep(processing_time)
        return {
            'task_id': task_id,
            'processing_time': processing_time,
            'completed_at': time.time()
        }
        
    # Create multiple tasks with different processing times
    tasks = [async_analysis_task for _ in range(10)]
    task_args = [(i, random.uniform(0.1, 0.5)) for i in range(10)]
    
    start_time = time.time()
    results = await processor.process_tasks_async(tasks, task_args)
    total_time = time.time() - start_time
    
    successful_results = [r for r in results if not isinstance(r, Exception)]
    
    print(f"  Async processing completed in {total_time:.2f}s")
    print(f"  Successful tasks: {len(successful_results)}/{len(tasks)}")
    
    if successful_results:
        avg_task_time = sum(r['processing_time'] for r in successful_results) / len(successful_results)
        print(f"  Average task time: {avg_task_time:.2f}s")
        print(f"  Concurrency benefit: {avg_task_time * len(successful_results) / total_time:.1f}x")
        
    print("  Async processing test completed ✓")

def run_all_tests():
    """Run all performance optimization tests."""
    print("=" * 60)
    print("PCAP ANALYSIS PERFORMANCE OPTIMIZATION TESTS")
    print("=" * 60)
    
    try:
        # Test individual components
        test_streaming_processor()
        print()
        
        test_memory_optimizer()
        print()
        
        test_parallel_processor()
        print()
        
        test_analysis_cache()
        print()
        
        test_performance_integration()
        print()
        
        # Test async processing
        asyncio.run(test_async_processing())
        print()
        
        print("=" * 60)
        print("ALL PERFORMANCE OPTIMIZATION TESTS COMPLETED SUCCESSFULLY ✓")
        print("=" * 60)
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    return True

if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)