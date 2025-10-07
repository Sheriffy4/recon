"""
Parallel processing utilities for PCAP analysis.
Implements concurrent and parallel processing for independent analysis tasks.
"""

import asyncio
import concurrent.futures
import multiprocessing as mp
import threading
import logging
import time
from typing import List, Dict, Any, Optional, Callable, Tuple, Union
from dataclasses import dataclass, field
from functools import partial
import queue
import os
import pickle
import tempfile

from .packet_info import PacketInfo
from .comparison_result import ComparisonResult
from .memory_optimizer import MemoryOptimizer

logger = logging.getLogger(__name__)

@dataclass
class ParallelConfig:
    """Configuration for parallel processing."""
    max_workers: Optional[int] = None  # None = auto-detect
    use_processes: bool = True  # True for CPU-bound, False for I/O-bound
    chunk_size: int = 1000  # Size of work chunks
    timeout_seconds: float = 300.0  # Timeout for individual tasks
    enable_progress_tracking: bool = True
    memory_limit_per_worker_mb: int = 256

@dataclass
class TaskResult:
    """Result of a parallel task."""
    task_id: str
    success: bool
    result: Any = None
    error: Optional[str] = None
    execution_time: float = 0.0
    memory_used_mb: float = 0.0

class ParallelTaskManager:
    """
    Manager for parallel task execution.
    Handles both process-based and thread-based parallelism.
    """
    
    def __init__(self, config: Optional[ParallelConfig] = None):
        self.config = config or ParallelConfig()
        self.memory_optimizer = MemoryOptimizer()
        
        # Auto-detect worker count if not specified
        if self.config.max_workers is None:
            self.config.max_workers = min(mp.cpu_count(), 8)  # Cap at 8 for memory reasons
            
        logger.info(f"Initialized parallel task manager with {self.config.max_workers} workers")
        
    def execute_parallel_tasks(self, tasks: List[Tuple[Callable, tuple]], 
                             task_ids: Optional[List[str]] = None) -> List[TaskResult]:
        """
        Execute multiple tasks in parallel.
        
        Args:
            tasks: List of (function, args) tuples
            task_ids: Optional list of task IDs for tracking
            
        Returns:
            List of TaskResult objects
        """
        if not tasks:
            return []
            
        if task_ids is None:
            task_ids = [f"task_{i}" for i in range(len(tasks))]
            
        if len(tasks) != len(task_ids):
            raise ValueError("Number of tasks must match number of task IDs")
            
        logger.info(f"Executing {len(tasks)} tasks in parallel")
        
        if self.config.use_processes:
            return self._execute_with_processes(tasks, task_ids)
        else:
            return self._execute_with_threads(tasks, task_ids)
            
    def _execute_with_processes(self, tasks: List[Tuple[Callable, tuple]], 
                               task_ids: List[str]) -> List[TaskResult]:
        """Execute tasks using process pool."""
        results = []
        
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=self.config.max_workers,
            mp_context=mp.get_context('spawn')  # More reliable on Windows
        ) as executor:
            
            # Submit all tasks
            future_to_task = {}
            for i, (func, args) in enumerate(tasks):
                future = executor.submit(self._execute_single_task, func, args, task_ids[i])
                future_to_task[future] = task_ids[i]
                
            # Collect results
            for future in concurrent.futures.as_completed(
                future_to_task.keys(), 
                timeout=self.config.timeout_seconds
            ):
                task_id = future_to_task[future]
                try:
                    result = future.result()
                    results.append(result)
                    if result.success:
                        logger.debug(f"Task {task_id} completed successfully")
                    else:
                        logger.warning(f"Task {task_id} failed: {result.error}")
                except Exception as e:
                    logger.error(f"Task {task_id} raised exception: {e}")
                    results.append(TaskResult(
                        task_id=task_id,
                        success=False,
                        error=str(e)
                    ))
                    
        return results
        
    def _execute_with_threads(self, tasks: List[Tuple[Callable, tuple]], 
                             task_ids: List[str]) -> List[TaskResult]:
        """Execute tasks using thread pool."""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.max_workers
        ) as executor:
            
            # Submit all tasks
            future_to_task = {}
            for i, (func, args) in enumerate(tasks):
                future = executor.submit(self._execute_single_task, func, args, task_ids[i])
                future_to_task[future] = task_ids[i]
                
            # Collect results
            for future in concurrent.futures.as_completed(
                future_to_task.keys(),
                timeout=self.config.timeout_seconds
            ):
                task_id = future_to_task[future]
                try:
                    result = future.result()
                    results.append(result)
                    if result.success:
                        logger.debug(f"Task {task_id} completed successfully")
                    else:
                        logger.warning(f"Task {task_id} failed: {result.error}")
                except Exception as e:
                    logger.error(f"Task {task_id} raised exception: {e}")
                    results.append(TaskResult(
                        task_id=task_id,
                        success=False,
                        error=str(e)
                    ))
                    
        return results
        
    @staticmethod
    def _execute_single_task(func: Callable, args: tuple, task_id: str) -> TaskResult:
        """Execute a single task and return result."""
        start_time = time.time()
        
        try:
            # Monitor memory usage
            import psutil
            process = psutil.Process(os.getpid())
            start_memory = process.memory_info().rss / 1024 / 1024
            
            # Execute the task
            result = func(*args)
            
            # Calculate metrics
            end_time = time.time()
            end_memory = process.memory_info().rss / 1024 / 1024
            
            return TaskResult(
                task_id=task_id,
                success=True,
                result=result,
                execution_time=end_time - start_time,
                memory_used_mb=end_memory - start_memory
            )
            
        except Exception as e:
            end_time = time.time()
            return TaskResult(
                task_id=task_id,
                success=False,
                error=str(e),
                execution_time=end_time - start_time
            )

class ParallelPcapAnalyzer:
    """
    Parallel PCAP analyzer that processes multiple files or analysis tasks concurrently.
    """
    
    def __init__(self, config: Optional[ParallelConfig] = None):
        self.config = config or ParallelConfig()
        self.task_manager = ParallelTaskManager(config)
        
    def analyze_multiple_pcaps(self, pcap_files: List[str]) -> Dict[str, Any]:
        """Analyze multiple PCAP files in parallel."""
        logger.info(f"Starting parallel analysis of {len(pcap_files)} PCAP files")
        
        # Create analysis tasks
        tasks = []
        task_ids = []
        
        for pcap_file in pcap_files:
            tasks.append((self._analyze_single_pcap, (pcap_file,)))
            task_ids.append(f"analyze_{os.path.basename(pcap_file)}")
            
        # Execute tasks in parallel
        results = self.task_manager.execute_parallel_tasks(tasks, task_ids)
        
        # Aggregate results
        analysis_results = {}
        successful_analyses = 0
        total_execution_time = 0.0
        
        for result in results:
            if result.success:
                successful_analyses += 1
                analysis_results[result.task_id] = result.result
            else:
                logger.error(f"Analysis failed for {result.task_id}: {result.error}")
                analysis_results[result.task_id] = {'error': result.error}
                
            total_execution_time += result.execution_time
            
        logger.info(f"Parallel analysis completed: {successful_analyses}/{len(pcap_files)} successful")
        
        return {
            'results': analysis_results,
            'summary': {
                'total_files': len(pcap_files),
                'successful_analyses': successful_analyses,
                'failed_analyses': len(pcap_files) - successful_analyses,
                'total_execution_time': total_execution_time,
                'parallel_speedup': sum(r.execution_time for r in results) / max(total_execution_time, 0.001)
            }
        }
        
    def compare_pcap_pairs(self, pcap_pairs: List[Tuple[str, str]]) -> Dict[str, ComparisonResult]:
        """Compare multiple PCAP file pairs in parallel."""
        logger.info(f"Starting parallel comparison of {len(pcap_pairs)} PCAP pairs")
        
        # Create comparison tasks
        tasks = []
        task_ids = []
        
        for i, (recon_pcap, zapret_pcap) in enumerate(pcap_pairs):
            tasks.append((self._compare_pcap_pair, (recon_pcap, zapret_pcap)))
            task_ids.append(f"compare_pair_{i}")
            
        # Execute tasks in parallel
        results = self.task_manager.execute_parallel_tasks(tasks, task_ids)
        
        # Aggregate results
        comparison_results = {}
        for result in results:
            if result.success:
                comparison_results[result.task_id] = result.result
            else:
                logger.error(f"Comparison failed for {result.task_id}: {result.error}")
                
        return comparison_results
        
    def parallel_packet_analysis(self, packets: List[PacketInfo], 
                                analysis_functions: List[Callable]) -> Dict[str, Any]:
        """Perform multiple analysis functions on packets in parallel."""
        logger.info(f"Starting parallel packet analysis with {len(analysis_functions)} functions")
        
        # Create analysis tasks
        tasks = []
        task_ids = []
        
        for i, analysis_func in enumerate(analysis_functions):
            tasks.append((analysis_func, (packets,)))
            task_ids.append(f"analysis_{analysis_func.__name__}_{i}")
            
        # Execute tasks in parallel
        results = self.task_manager.execute_parallel_tasks(tasks, task_ids)
        
        # Aggregate results
        analysis_results = {}
        for result in results:
            if result.success:
                analysis_results[result.task_id] = result.result
            else:
                logger.error(f"Analysis failed for {result.task_id}: {result.error}")
                
        return analysis_results
        
    @staticmethod
    def _analyze_single_pcap(pcap_file: str) -> Dict[str, Any]:
        """Analyze a single PCAP file."""
        from .streaming_processor import StreamingPcapProcessor
        from .packet_sequence_analyzer import PacketSequenceAnalyzer
        
        try:
            # Stream packets from file
            processor = StreamingPcapProcessor()
            packets = list(processor.stream_packets(pcap_file))
            
            # Perform basic analysis
            analyzer = PacketSequenceAnalyzer()
            sequence_analysis = analyzer.analyze_packet_sequence(packets)
            
            return {
                'pcap_file': pcap_file,
                'packet_count': len(packets),
                'sequence_analysis': sequence_analysis,
                'analysis_timestamp': time.time()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing PCAP {pcap_file}: {e}")
            raise
            
    @staticmethod
    def _compare_pcap_pair(recon_pcap: str, zapret_pcap: str) -> ComparisonResult:
        """Compare a pair of PCAP files."""
        from .pcap_comparator import PCAPComparator
        
        try:
            comparator = PCAPComparator()
            return comparator.compare_pcaps(recon_pcap, zapret_pcap)
            
        except Exception as e:
            logger.error(f"Error comparing PCAPs {recon_pcap} vs {zapret_pcap}: {e}")
            raise

class AsyncParallelProcessor:
    """
    Asynchronous parallel processor for I/O-bound tasks.
    Uses asyncio for concurrent processing of network operations.
    """
    
    def __init__(self, max_concurrent_tasks: int = 10):
        self.max_concurrent_tasks = max_concurrent_tasks
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)
        
    async def process_tasks_async(self, tasks: List[Callable], 
                                 task_args: List[tuple]) -> List[Any]:
        """Process multiple async tasks concurrently."""
        if len(tasks) != len(task_args):
            raise ValueError("Number of tasks must match number of argument tuples")
            
        async def _execute_with_semaphore(task, args):
            async with self.semaphore:
                if asyncio.iscoroutinefunction(task):
                    return await task(*args)
                else:
                    # Run sync function in executor
                    loop = asyncio.get_event_loop()
                    return await loop.run_in_executor(None, task, *args)
                    
        # Execute all tasks concurrently
        results = await asyncio.gather(
            *[_execute_with_semaphore(task, args) 
              for task, args in zip(tasks, task_args)],
            return_exceptions=True
        )
        
        return results
        
    async def stream_multiple_pcaps_async(self, pcap_files: List[str]) -> Dict[str, List[PacketInfo]]:
        """Stream multiple PCAP files concurrently."""
        from .streaming_processor import AsyncStreamingProcessor
        
        async def _stream_single_pcap(pcap_file: str) -> Tuple[str, List[PacketInfo]]:
            processor = AsyncStreamingProcessor()
            packets = []
            async for packet in processor.stream_packets_async(pcap_file):
                packets.append(packet)
            return pcap_file, packets
            
        # Create tasks for all PCAP files
        tasks = [_stream_single_pcap(pcap_file) for pcap_file in pcap_files]
        
        # Execute concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        pcap_data = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Error streaming PCAP: {result}")
            else:
                pcap_file, packets = result
                pcap_data[pcap_file] = packets
                
        return pcap_data

class BatchProcessor:
    """
    Batch processor for handling large numbers of analysis tasks.
    Processes tasks in batches to manage memory and system resources.
    """
    
    def __init__(self, batch_size: int = 100, config: Optional[ParallelConfig] = None):
        self.batch_size = batch_size
        self.config = config or ParallelConfig()
        self.parallel_analyzer = ParallelPcapAnalyzer(config)
        
    def process_pcap_batch(self, pcap_files: List[str]) -> Dict[str, Any]:
        """Process a large batch of PCAP files in smaller chunks."""
        logger.info(f"Processing batch of {len(pcap_files)} PCAP files")
        
        all_results = {}
        batch_count = 0
        
        # Process in batches
        for i in range(0, len(pcap_files), self.batch_size):
            batch = pcap_files[i:i + self.batch_size]
            batch_count += 1
            
            logger.info(f"Processing batch {batch_count} ({len(batch)} files)")
            
            try:
                batch_results = self.parallel_analyzer.analyze_multiple_pcaps(batch)
                all_results[f'batch_{batch_count}'] = batch_results
                
                # Force garbage collection between batches
                import gc
                gc.collect()
                
            except Exception as e:
                logger.error(f"Error processing batch {batch_count}: {e}")
                all_results[f'batch_{batch_count}'] = {'error': str(e)}
                
        return {
            'batch_results': all_results,
            'total_batches': batch_count,
            'total_files': len(pcap_files)
        }

# Example usage and testing
if __name__ == "__main__":
    import tempfile
    import random
    
    # Test parallel processing
    config = ParallelConfig(max_workers=4, use_processes=True)
    analyzer = ParallelPcapAnalyzer(config)
    
    # Create sample analysis functions
    def analyze_packet_count(packets: List[PacketInfo]) -> int:
        return len(packets)
        
    def analyze_unique_ips(packets: List[PacketInfo]) -> int:
        unique_ips = set()
        for packet in packets:
            unique_ips.add(packet.src_ip)
            unique_ips.add(packet.dst_ip)
        return len(unique_ips)
        
    def analyze_port_distribution(packets: List[PacketInfo]) -> Dict[int, int]:
        port_counts = {}
        for packet in packets:
            port_counts[packet.dst_port] = port_counts.get(packet.dst_port, 0) + 1
        return port_counts
        
    # Create sample packets
    sample_packets = []
    for i in range(1000):
        packet = PacketInfo(
            timestamp=float(i),
            src_ip=f"192.168.1.{random.randint(1, 10)}",
            dst_ip=f"10.0.0.{random.randint(1, 10)}",
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443, 8080, 8443]),
            sequence_num=i * 1000,
            ack_num=i * 1000 + 1,
            ttl=64,
            flags=['ACK'],
            payload_length=random.randint(50, 1500),
            payload_hex="deadbeef" * random.randint(1, 10),
            checksum=0x1234,
            checksum_valid=True,
            is_client_hello=False
        )
        sample_packets.append(packet)
        
    print(f"Created {len(sample_packets)} sample packets")
    
    # Test parallel packet analysis
    analysis_functions = [analyze_packet_count, analyze_unique_ips, analyze_port_distribution]
    
    start_time = time.time()
    results = analyzer.parallel_packet_analysis(sample_packets, analysis_functions)
    end_time = time.time()
    
    print(f"Parallel analysis completed in {end_time - start_time:.2f}s")
    print("Results:")
    for task_id, result in results.items():
        print(f"  {task_id}: {result}")
        
    # Test async processing
    async def test_async_processing():
        async_processor = AsyncParallelProcessor(max_concurrent_tasks=5)
        
        # Create async tasks
        async def async_task(task_id: int, delay: float) -> str:
            await asyncio.sleep(delay)
            return f"Task {task_id} completed after {delay}s"
            
        tasks = [async_task for _ in range(10)]
        task_args = [(i, random.uniform(0.1, 1.0)) for i in range(10)]
        
        start_time = time.time()
        results = await async_processor.process_tasks_async(tasks, task_args)
        end_time = time.time()
        
        print(f"Async processing completed in {end_time - start_time:.2f}s")
        for result in results:
            print(f"  {result}")
            
    # Run async test
    asyncio.run(test_async_processing())