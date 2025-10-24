"""
Performance integration module that combines all optimization techniques.
Provides a unified interface for high-performance PCAP analysis.
"""

import asyncio
import logging
import time
from typing import List, Dict, Any, Optional, Callable, Tuple
from dataclasses import dataclass
from pathlib import Path

from .streaming_processor import (
    StreamingPcapProcessor,
    StreamingConfig,
    AsyncStreamingProcessor,
)
from .memory_optimizer import (
    MemoryOptimizer,
    MemoryEfficientComparator,
)
from .parallel_processor import (
    ParallelPcapAnalyzer,
    ParallelConfig,
    AsyncParallelProcessor,
)
from .analysis_cache import HybridCache, CachedAnalyzer
from .packet_info import PacketInfo
from .comparison_result import ComparisonResult

logger = logging.getLogger(__name__)


@dataclass
class PerformanceConfig:
    """Unified configuration for performance optimizations."""

    # Streaming configuration
    streaming_chunk_size: int = 1000
    streaming_memory_limit_mb: int = 512
    enable_streaming: bool = True

    # Memory optimization configuration
    memory_cache_mb: int = 128
    persistent_cache_mb: int = 512
    enable_memory_optimization: bool = True
    enable_aggressive_gc: bool = True

    # Parallel processing configuration
    max_workers: Optional[int] = None
    use_processes: bool = True
    parallel_chunk_size: int = 500
    enable_parallel_processing: bool = True

    # Caching configuration
    cache_dir: str = ".pcap_analysis_cache"
    default_cache_ttl_seconds: float = 3600
    enable_caching: bool = True

    # General performance settings
    enable_progress_reporting: bool = True
    performance_monitoring: bool = True


class HighPerformancePcapAnalyzer:
    """
    High-performance PCAP analyzer that combines all optimization techniques.
    Provides the best performance for large-scale PCAP analysis tasks.
    """

    def __init__(self, config: Optional[PerformanceConfig] = None):
        self.config = config or PerformanceConfig()

        # Initialize components based on configuration
        self._init_components()

        # Performance metrics
        self.metrics = {
            "total_analyses": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "total_processing_time": 0.0,
            "memory_optimizations": 0,
            "parallel_tasks_executed": 0,
        }

        logger.info("Initialized high-performance PCAP analyzer")

    def _init_components(self):
        """Initialize performance optimization components."""
        # Memory optimizer
        if self.config.enable_memory_optimization:
            self.memory_optimizer = MemoryOptimizer(
                enable_aggressive_gc=self.config.enable_aggressive_gc
            )
        else:
            self.memory_optimizer = None

        # Streaming processor
        if self.config.enable_streaming:
            streaming_config = StreamingConfig(
                chunk_size=self.config.streaming_chunk_size,
                memory_limit_mb=self.config.streaming_memory_limit_mb,
                enable_gc_optimization=self.config.enable_aggressive_gc,
                progress_callback=(
                    self._progress_callback
                    if self.config.enable_progress_reporting
                    else None
                ),
            )
            self.streaming_processor = StreamingPcapProcessor(streaming_config)
            self.async_streaming_processor = AsyncStreamingProcessor(streaming_config)
        else:
            self.streaming_processor = None
            self.async_streaming_processor = None

        # Parallel processor
        if self.config.enable_parallel_processing:
            parallel_config = ParallelConfig(
                max_workers=self.config.max_workers,
                use_processes=self.config.use_processes,
                chunk_size=self.config.parallel_chunk_size,
                enable_progress_tracking=self.config.enable_progress_reporting,
                memory_limit_per_worker_mb=self.config.streaming_memory_limit_mb // 2,
            )
            self.parallel_analyzer = ParallelPcapAnalyzer(parallel_config)
            self.async_parallel_processor = AsyncParallelProcessor(
                max_concurrent_tasks=self.config.max_workers or 8
            )
        else:
            self.parallel_analyzer = None
            self.async_parallel_processor = None

        # Cache
        if self.config.enable_caching:
            self.cache = HybridCache(
                memory_cache_mb=self.config.memory_cache_mb,
                persistent_cache_mb=self.config.persistent_cache_mb,
                cache_dir=self.config.cache_dir,
            )
            self.cached_analyzer = CachedAnalyzer(self.cache)
        else:
            self.cache = None
            self.cached_analyzer = None

    def _progress_callback(self, processed: int, total: int):
        """Progress callback for reporting."""
        if self.config.enable_progress_reporting:
            percent = (processed / total) * 100 if total > 0 else 0
            logger.info(f"Processing progress: {processed}/{total} ({percent:.1f}%)")

    def analyze_single_pcap(
        self, pcap_file: str, analysis_functions: Optional[List[Callable]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a single PCAP file with all optimizations enabled.

        Args:
            pcap_file: Path to PCAP file
            analysis_functions: Optional list of analysis functions to apply

        Returns:
            Analysis results dictionary
        """
        start_time = time.time()
        self.metrics["total_analyses"] += 1

        logger.info(f"Starting high-performance analysis of {pcap_file}")

        try:
            # Check cache first
            if self.cached_analyzer:
                cache_key = f"single_pcap_analysis_{pcap_file}"
                cached_result = self.cache.get(cache_key)
                if cached_result is not None:
                    self.metrics["cache_hits"] += 1
                    logger.info(f"Cache hit for {pcap_file}")
                    return cached_result
                else:
                    self.metrics["cache_misses"] += 1

            # Stream packets efficiently
            if self.streaming_processor:
                packets = list(self.streaming_processor.stream_packets(pcap_file))
            else:
                # Fallback to basic loading
                from .pcap_comparator import PCAPComparator

                comparator = PCAPComparator()
                packets = comparator.extract_packet_sequences(pcap_file)

            logger.info(f"Loaded {len(packets)} packets from {pcap_file}")

            # Optimize packet storage
            if self.memory_optimizer and len(packets) > 1000:
                optimized_storage = self.memory_optimizer.optimize_packet_storage(
                    packets
                )
                packets = optimized_storage.get_all_packets()
                self.metrics["memory_optimizations"] += 1
                logger.debug("Applied memory optimization to packet storage")

            # Perform analysis
            results = {
                "pcap_file": pcap_file,
                "packet_count": len(packets),
                "analysis_timestamp": time.time(),
                "optimizations_applied": [],
            }

            # Apply analysis functions
            if analysis_functions:
                if self.parallel_analyzer and len(analysis_functions) > 1:
                    # Parallel analysis
                    parallel_results = self.parallel_analyzer.parallel_packet_analysis(
                        packets, analysis_functions
                    )
                    results["parallel_analysis"] = parallel_results
                    results["optimizations_applied"].append("parallel_processing")
                    self.metrics["parallel_tasks_executed"] += len(analysis_functions)
                else:
                    # Sequential analysis
                    for func in analysis_functions:
                        func_name = func.__name__
                        results[func_name] = func(packets)

            # Basic packet statistics
            results.update(self._calculate_basic_stats(packets))

            # Cache results
            if self.cached_analyzer:
                self.cache.put(
                    cache_key, results, self.config.default_cache_ttl_seconds
                )

            # Record optimizations applied
            if self.streaming_processor:
                results["optimizations_applied"].append("streaming_processing")
            if self.memory_optimizer:
                results["optimizations_applied"].append("memory_optimization")
            if self.cache:
                results["optimizations_applied"].append("caching")

            processing_time = time.time() - start_time
            self.metrics["total_processing_time"] += processing_time
            results["processing_time_seconds"] = processing_time

            logger.info(f"Completed analysis of {pcap_file} in {processing_time:.2f}s")
            return results

        except Exception as e:
            logger.error(f"Error analyzing PCAP {pcap_file}: {e}")
            raise

    def compare_pcaps_optimized(
        self, recon_pcap: str, zapret_pcap: str
    ) -> ComparisonResult:
        """
        Compare two PCAP files with all optimizations enabled.

        Args:
            recon_pcap: Path to recon PCAP file
            zapret_pcap: Path to zapret PCAP file

        Returns:
            Optimized comparison result
        """
        start_time = time.time()

        logger.info(
            f"Starting optimized PCAP comparison: {recon_pcap} vs {zapret_pcap}"
        )

        try:
            # Check cache first
            if self.cached_analyzer:

                def comparison_func(r_pcap, z_pcap):
                    if self.memory_optimizer:
                        comparator = MemoryEfficientComparator(
                            memory_limit_mb=self.config.streaming_memory_limit_mb
                        )
                        return comparator.compare_large_pcaps(r_pcap, z_pcap)
                    else:
                        from .pcap_comparator import PCAPComparator

                        comparator = PCAPComparator()
                        return comparator.compare_pcaps(r_pcap, z_pcap)

                result = self.cached_analyzer.cached_comparison(
                    recon_pcap,
                    zapret_pcap,
                    comparison_func,
                    ttl_seconds=self.config.default_cache_ttl_seconds,
                )
            else:
                # Direct comparison
                if self.memory_optimizer:
                    comparator = MemoryEfficientComparator(
                        memory_limit_mb=self.config.streaming_memory_limit_mb
                    )
                    result = comparator.compare_large_pcaps(recon_pcap, zapret_pcap)
                else:
                    from .pcap_comparator import PCAPComparator

                    comparator = PCAPComparator()
                    result = comparator.compare_pcaps(recon_pcap, zapret_pcap)

            # Add performance metadata
            processing_time = time.time() - start_time
            result.analysis_metadata.update(
                {
                    "optimized_comparison": True,
                    "processing_time_seconds": processing_time,
                    "optimizations_enabled": {
                        "streaming": self.config.enable_streaming,
                        "memory_optimization": self.config.enable_memory_optimization,
                        "parallel_processing": self.config.enable_parallel_processing,
                        "caching": self.config.enable_caching,
                    },
                }
            )

            logger.info(f"Completed optimized comparison in {processing_time:.2f}s")
            return result

        except Exception as e:
            logger.error(f"Error comparing PCAPs: {e}")
            raise

    async def analyze_multiple_pcaps_async(
        self, pcap_files: List[str]
    ) -> Dict[str, Any]:
        """
        Analyze multiple PCAP files asynchronously with optimizations.

        Args:
            pcap_files: List of PCAP file paths

        Returns:
            Dictionary of analysis results
        """
        logger.info(f"Starting async analysis of {len(pcap_files)} PCAP files")

        if not self.async_parallel_processor:
            raise RuntimeError("Async parallel processing not enabled")

        # Create analysis tasks
        async def analyze_single_async(pcap_file: str) -> Tuple[str, Dict[str, Any]]:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, self.analyze_single_pcap, pcap_file
            )
            return pcap_file, result

        # Execute all analyses concurrently
        tasks = [analyze_single_async(pcap_file) for pcap_file in pcap_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        analysis_results = {}
        successful_analyses = 0

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Async analysis failed: {result}")
            else:
                pcap_file, analysis_result = result
                analysis_results[pcap_file] = analysis_result
                successful_analyses += 1

        logger.info(
            f"Completed async analysis: {successful_analyses}/{len(pcap_files)} successful"
        )

        return {
            "results": analysis_results,
            "summary": {
                "total_files": len(pcap_files),
                "successful_analyses": successful_analyses,
                "failed_analyses": len(pcap_files) - successful_analyses,
                "async_processing": True,
            },
        }

    def batch_analyze_with_optimization(
        self, pcap_files: List[str], batch_size: int = 50
    ) -> Dict[str, Any]:
        """
        Analyze large batches of PCAP files with memory management.

        Args:
            pcap_files: List of PCAP file paths
            batch_size: Size of processing batches

        Returns:
            Batch analysis results
        """
        logger.info(
            f"Starting batch analysis of {len(pcap_files)} files (batch size: {batch_size})"
        )

        all_results = {}
        batch_count = 0

        for i in range(0, len(pcap_files), batch_size):
            batch = pcap_files[i : i + batch_size]
            batch_count += 1

            logger.info(f"Processing batch {batch_count} ({len(batch)} files)")

            try:
                if self.parallel_analyzer:
                    batch_results = self.parallel_analyzer.analyze_multiple_pcaps(batch)
                else:
                    # Sequential processing
                    batch_results = {}
                    for pcap_file in batch:
                        batch_results[pcap_file] = self.analyze_single_pcap(pcap_file)

                all_results[f"batch_{batch_count}"] = batch_results

                # Force memory cleanup between batches
                if self.memory_optimizer:
                    self.memory_optimizer.force_garbage_collection()

            except Exception as e:
                logger.error(f"Error processing batch {batch_count}: {e}")
                all_results[f"batch_{batch_count}"] = {"error": str(e)}

        return {
            "batch_results": all_results,
            "total_batches": batch_count,
            "total_files": len(pcap_files),
            "batch_size": batch_size,
        }

    def _calculate_basic_stats(self, packets: List[PacketInfo]) -> Dict[str, Any]:
        """Calculate basic packet statistics."""
        if not packets:
            return {"basic_stats": {}}

        # Calculate statistics
        unique_src_ips = set(p.src_ip for p in packets)
        unique_dst_ips = set(p.dst_ip for p in packets)
        unique_ports = set(p.dst_port for p in packets)

        tls_packets = sum(1 for p in packets if p.is_client_hello)

        time_span = max(p.timestamp for p in packets) - min(
            p.timestamp for p in packets
        )

        return {
            "basic_stats": {
                "unique_src_ips": len(unique_src_ips),
                "unique_dst_ips": len(unique_dst_ips),
                "unique_dst_ports": len(unique_ports),
                "tls_client_hello_count": tls_packets,
                "time_span_seconds": time_span,
                "packets_per_second": len(packets) / max(time_span, 0.001),
            }
        }

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics and statistics."""
        metrics = self.metrics.copy()

        # Add cache statistics if available
        if self.cache:
            cache_stats = self.cache.get_stats()
            metrics["cache_stats"] = {
                "memory": cache_stats["memory"].__dict__,
                "persistent": cache_stats["persistent"].__dict__,
            }

        # Add memory statistics if available
        if self.memory_optimizer:
            memory_stats = self.memory_optimizer.get_memory_stats()
            metrics["memory_stats"] = memory_stats.__dict__

        # Calculate derived metrics
        if metrics["total_analyses"] > 0:
            metrics["average_processing_time"] = (
                metrics["total_processing_time"] / metrics["total_analyses"]
            )
            metrics["cache_hit_rate"] = (
                metrics["cache_hits"]
                / (metrics["cache_hits"] + metrics["cache_misses"])
                if (metrics["cache_hits"] + metrics["cache_misses"]) > 0
                else 0.0
            )

        return metrics

    def cleanup(self):
        """Clean up resources and temporary files."""
        if self.memory_optimizer:
            self.memory_optimizer.cleanup_temp_files()

        logger.info("Cleaned up high-performance PCAP analyzer resources")


# Example usage and testing
if __name__ == "__main__":

    # Test high-performance analyzer
    config = PerformanceConfig(
        streaming_chunk_size=500,
        streaming_memory_limit_mb=256,
        memory_cache_mb=64,
        persistent_cache_mb=256,
        max_workers=4,
        enable_progress_reporting=True,
    )

    analyzer = HighPerformancePcapAnalyzer(config)

    # Create sample analysis functions
    def count_packets(packets: List[PacketInfo]) -> int:
        return len(packets)

    def analyze_protocols(packets: List[PacketInfo]) -> Dict[str, int]:
        protocol_counts = {}
        for packet in packets:
            if packet.is_client_hello:
                protocol_counts["TLS"] = protocol_counts.get("TLS", 0) + 1
            else:
                protocol_counts["Other"] = protocol_counts.get("Other", 0) + 1
        return protocol_counts

    # Test with sample PCAP files (if they exist)
    test_pcaps = ["test1.pcap", "test2.pcap"]  # Replace with actual test files
    existing_pcaps = [pcap for pcap in test_pcaps if Path(pcap).exists()]

    if existing_pcaps:
        print(f"Testing with {len(existing_pcaps)} PCAP files")

        # Test single PCAP analysis
        for pcap_file in existing_pcaps[:1]:  # Test with first file
            result = analyzer.analyze_single_pcap(
                pcap_file, analysis_functions=[count_packets, analyze_protocols]
            )
            print(f"Analysis result for {pcap_file}:")
            print(f"  Packet count: {result.get('packet_count', 0)}")
            print(f"  Processing time: {result.get('processing_time_seconds', 0):.2f}s")
            print(f"  Optimizations: {result.get('optimizations_applied', [])}")

        # Test batch analysis
        if len(existing_pcaps) > 1:
            batch_results = analyzer.batch_analyze_with_optimization(
                existing_pcaps, batch_size=2
            )
            print(f"Batch analysis completed: {batch_results['total_batches']} batches")

    else:
        print("No test PCAP files found, skipping file-based tests")

    # Show performance metrics
    metrics = analyzer.get_performance_metrics()
    print("Performance metrics:")
    for key, value in metrics.items():
        if not isinstance(value, dict):
            print(f"  {key}: {value}")

    # Cleanup
    analyzer.cleanup()
