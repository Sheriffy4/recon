"""
Memory optimization utilities for PCAP analysis.
Implements various memory optimization techniques to reduce memory footprint.
"""

import gc
import sys
import logging
from typing import List, Dict
from dataclasses import dataclass
import psutil
import os
from functools import lru_cache
import pickle
import tempfile
import mmap

from .packet_info import PacketInfo
from .comparison_result import ComparisonResult

logger = logging.getLogger(__name__)


@dataclass
class MemoryStats:
    """Memory usage statistics."""

    rss_mb: float  # Resident Set Size in MB
    vms_mb: float  # Virtual Memory Size in MB
    percent: float  # Memory usage percentage
    available_mb: float  # Available memory in MB


class MemoryOptimizer:
    """
    Memory optimization utilities for PCAP analysis.
    Provides various techniques to minimize memory usage during analysis.
    """

    def __init__(self, enable_aggressive_gc: bool = True):
        self.enable_aggressive_gc = enable_aggressive_gc
        self.process = psutil.Process(os.getpid())
        self._temp_files = []  # Track temporary files for cleanup

    def get_memory_stats(self) -> MemoryStats:
        """Get current memory usage statistics."""
        memory_info = self.process.memory_info()
        virtual_memory = psutil.virtual_memory()

        return MemoryStats(
            rss_mb=memory_info.rss / 1024 / 1024,
            vms_mb=memory_info.vms / 1024 / 1024,
            percent=self.process.memory_percent(),
            available_mb=virtual_memory.available / 1024 / 1024,
        )

    def force_garbage_collection(self) -> Dict[str, int]:
        """Force garbage collection and return collection stats."""
        if not self.enable_aggressive_gc:
            return {}

        # Collect statistics before GC
        before_stats = self.get_memory_stats()

        # Force garbage collection for all generations
        collected = {}
        for generation in range(3):
            collected[f"gen_{generation}"] = gc.collect(generation)

        # Get statistics after GC
        after_stats = self.get_memory_stats()

        memory_freed = before_stats.rss_mb - after_stats.rss_mb

        logger.debug(f"GC freed {memory_freed:.1f}MB memory")

        return {
            **collected,
            "memory_freed_mb": memory_freed,
            "before_rss_mb": before_stats.rss_mb,
            "after_rss_mb": after_stats.rss_mb,
        }

    def optimize_packet_storage(
        self, packets: List[PacketInfo]
    ) -> "OptimizedPacketStorage":
        """Optimize packet storage to reduce memory usage."""
        return OptimizedPacketStorage(packets, self)

    def create_memory_mapped_storage(
        self, packets: List[PacketInfo]
    ) -> "MemoryMappedStorage":
        """Create memory-mapped storage for large packet collections."""
        return MemoryMappedStorage(packets, self)

    def cleanup_temp_files(self):
        """Clean up temporary files created during optimization."""
        for temp_file in self._temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                    logger.debug(f"Cleaned up temp file: {temp_file}")
            except Exception as e:
                logger.warning(f"Failed to cleanup temp file {temp_file}: {e}")
        self._temp_files.clear()

    def __del__(self):
        """Cleanup on destruction."""
        self.cleanup_temp_files()


class OptimizedPacketStorage:
    """
    Optimized storage for packet collections that minimizes memory usage.
    Uses various techniques like deduplication, compression, and lazy loading.
    """

    def __init__(self, packets: List[PacketInfo], optimizer: MemoryOptimizer):
        self.optimizer = optimizer
        self._original_count = len(packets)

        # Optimize storage
        self._deduplicated_packets = self._deduplicate_packets(packets)
        self._compressed_payloads = self._compress_payloads(self._deduplicated_packets)
        self._indexed_packets = self._create_index(self._deduplicated_packets)

        # Force GC after optimization
        self.optimizer.force_garbage_collection()

        logger.info(
            f"Optimized packet storage: {self._original_count} -> {len(self._deduplicated_packets)} packets"
        )

    def _deduplicate_packets(self, packets: List[PacketInfo]) -> List[PacketInfo]:
        """Remove duplicate packets to save memory."""
        seen = set()
        deduplicated = []

        for packet in packets:
            # Create a hash key based on packet characteristics
            key = (
                packet.src_ip,
                packet.dst_ip,
                packet.src_port,
                packet.dst_port,
                packet.sequence_num,
                packet.ack_num,
                packet.timestamp,
            )

            if key not in seen:
                seen.add(key)
                deduplicated.append(packet)

        logger.debug(f"Deduplication: {len(packets)} -> {len(deduplicated)} packets")
        return deduplicated

    def _compress_payloads(self, packets: List[PacketInfo]) -> Dict[str, bytes]:
        """Compress packet payloads to save memory."""
        import zlib

        compressed_payloads = {}
        total_original = 0
        total_compressed = 0

        for i, packet in enumerate(packets):
            if packet.payload_hex:
                original_data = bytes.fromhex(packet.payload_hex)
                total_original += len(original_data)

                if len(original_data) > 100:  # Only compress larger payloads
                    compressed = zlib.compress(original_data, level=9)
                    total_compressed += len(compressed)
                    compressed_payloads[f"packet_{i}"] = compressed
                    # Clear original payload to save memory
                    packet.payload_hex = ""
                else:
                    total_compressed += len(original_data)

        compression_ratio = (
            (total_compressed / total_original) if total_original > 0 else 1.0
        )
        logger.debug(f"Payload compression ratio: {compression_ratio:.2f}")

        return compressed_payloads

    def _create_index(self, packets: List[PacketInfo]) -> Dict[str, List[int]]:
        """Create indexes for fast packet lookup."""
        indexes = {
            "by_src_ip": {},
            "by_dst_ip": {},
            "by_port_pair": {},
            "by_timestamp_range": {},
        }

        for i, packet in enumerate(packets):
            # Index by source IP
            if packet.src_ip not in indexes["by_src_ip"]:
                indexes["by_src_ip"][packet.src_ip] = []
            indexes["by_src_ip"][packet.src_ip].append(i)

            # Index by destination IP
            if packet.dst_ip not in indexes["by_dst_ip"]:
                indexes["by_dst_ip"][packet.dst_ip] = []
            indexes["by_dst_ip"][packet.dst_ip].append(i)

            # Index by port pair
            port_pair = f"{packet.src_port}-{packet.dst_port}"
            if port_pair not in indexes["by_port_pair"]:
                indexes["by_port_pair"][port_pair] = []
            indexes["by_port_pair"][port_pair].append(i)

            # Index by timestamp range (1-second buckets)
            timestamp_bucket = int(packet.timestamp)
            if timestamp_bucket not in indexes["by_timestamp_range"]:
                indexes["by_timestamp_range"][timestamp_bucket] = []
            indexes["by_timestamp_range"][timestamp_bucket].append(i)

        return indexes

    def get_packets_by_ip(self, ip: str, is_source: bool = True) -> List[PacketInfo]:
        """Get packets by IP address."""
        index_key = "by_src_ip" if is_source else "by_dst_ip"
        packet_indices = self._indexed_packets[index_key].get(ip, [])
        return [self._deduplicated_packets[i] for i in packet_indices]

    def get_packets_by_port_pair(
        self, src_port: int, dst_port: int
    ) -> List[PacketInfo]:
        """Get packets by port pair."""
        port_pair = f"{src_port}-{dst_port}"
        packet_indices = self._indexed_packets["by_port_pair"].get(port_pair, [])
        return [self._deduplicated_packets[i] for i in packet_indices]

    def get_packets_in_time_range(
        self, start_time: float, end_time: float
    ) -> List[PacketInfo]:
        """Get packets within a time range."""
        result = []
        start_bucket = int(start_time)
        end_bucket = int(end_time)

        for bucket in range(start_bucket, end_bucket + 1):
            packet_indices = self._indexed_packets["by_timestamp_range"].get(bucket, [])
            for i in packet_indices:
                packet = self._deduplicated_packets[i]
                if start_time <= packet.timestamp <= end_time:
                    result.append(packet)

        return result

    def get_all_packets(self) -> List[PacketInfo]:
        """Get all packets."""
        return self._deduplicated_packets.copy()

    def get_memory_usage_mb(self) -> float:
        """Get estimated memory usage of this storage."""
        return sys.getsizeof(self._deduplicated_packets) / 1024 / 1024


class MemoryMappedStorage:
    """
    Memory-mapped storage for very large packet collections.
    Stores packets on disk and maps them into memory as needed.
    """

    def __init__(self, packets: List[PacketInfo], optimizer: MemoryOptimizer):
        self.optimizer = optimizer
        self._packet_count = len(packets)

        # Create temporary file for storage
        self._temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pkl")
        self._temp_file_path = self._temp_file.name
        optimizer._temp_files.append(self._temp_file_path)

        # Serialize packets to file
        with open(self._temp_file_path, "wb") as f:
            pickle.dump(packets, f, protocol=pickle.HIGHEST_PROTOCOL)

        self._temp_file.close()

        # Memory map the file
        self._file_handle = open(self._temp_file_path, "rb")
        self._mmap = mmap.mmap(self._file_handle.fileno(), 0, access=mmap.ACCESS_READ)

        logger.info(f"Created memory-mapped storage for {self._packet_count} packets")

    def load_packets(self) -> List[PacketInfo]:
        """Load all packets from memory-mapped storage."""
        self._mmap.seek(0)
        return pickle.loads(self._mmap.read())

    def load_packet_range(self, start_idx: int, end_idx: int) -> List[PacketInfo]:
        """Load a range of packets (not implemented for pickle format)."""
        # For pickle format, we need to load all packets
        # In a production system, you might use a different serialization format
        all_packets = self.load_packets()
        return all_packets[start_idx:end_idx]

    def get_packet_count(self) -> int:
        """Get total packet count."""
        return self._packet_count

    def close(self):
        """Close memory-mapped storage."""
        if hasattr(self, "_mmap"):
            self._mmap.close()
        if hasattr(self, "_file_handle"):
            self._file_handle.close()

    def __del__(self):
        """Cleanup on destruction."""
        self.close()


class LazyPacketLoader:
    """
    Lazy loader for packet collections that loads packets on demand.
    Useful for very large datasets where only subsets are needed.
    """

    def __init__(self, pcap_file: str, optimizer: MemoryOptimizer):
        self.pcap_file = pcap_file
        self.optimizer = optimizer
        self._packet_cache = {}
        self._cache_size_limit = 1000  # Maximum packets to keep in cache

    @lru_cache(maxsize=128)
    def get_packet_count(self) -> int:
        """Get total packet count (cached)."""
        from .streaming_processor import StreamingPcapProcessor

        processor = StreamingPcapProcessor()
        return processor.estimate_packet_count(self.pcap_file)

    def load_packet_range(self, start_idx: int, end_idx: int) -> List[PacketInfo]:
        """Load a specific range of packets."""
        cache_key = f"{start_idx}_{end_idx}"

        if cache_key in self._packet_cache:
            return self._packet_cache[cache_key]

        # Load packets from file
        from .streaming_processor import StreamingPcapProcessor

        processor = StreamingPcapProcessor()

        packets = []
        current_idx = 0

        for packet in processor.stream_packets(self.pcap_file):
            if start_idx <= current_idx < end_idx:
                packets.append(packet)
            current_idx += 1

            if current_idx >= end_idx:
                break

        # Cache the result (with size limit)
        if len(self._packet_cache) < self._cache_size_limit:
            self._packet_cache[cache_key] = packets
        else:
            # Remove oldest cache entry
            oldest_key = next(iter(self._packet_cache))
            del self._packet_cache[oldest_key]
            self._packet_cache[cache_key] = packets

        return packets

    def clear_cache(self):
        """Clear packet cache to free memory."""
        self._packet_cache.clear()
        self.optimizer.force_garbage_collection()


class MemoryEfficientComparator:
    """
    Memory-efficient PCAP comparator that uses optimization techniques.
    Designed to handle large PCAP files without excessive memory usage.
    """

    def __init__(self, memory_limit_mb: int = 512):
        self.optimizer = MemoryOptimizer(enable_aggressive_gc=True)
        self.memory_limit_mb = memory_limit_mb

    def compare_large_pcaps(
        self, recon_pcap: str, zapret_pcap: str
    ) -> ComparisonResult:
        """Compare large PCAP files using memory optimization."""
        logger.info("Starting memory-efficient PCAP comparison")

        # Use lazy loading for very large files
        recon_loader = LazyPacketLoader(recon_pcap, self.optimizer)
        zapret_loader = LazyPacketLoader(zapret_pcap, self.optimizer)

        recon_count = recon_loader.get_packet_count()
        zapret_count = zapret_loader.get_packet_count()

        logger.info(f"Comparing {recon_count} vs {zapret_count} packets")

        # Process in chunks to manage memory
        chunk_size = 1000
        recon_packets = []
        zapret_packets = []

        # Load recon packets in chunks
        for start_idx in range(0, recon_count, chunk_size):
            end_idx = min(start_idx + chunk_size, recon_count)
            chunk = recon_loader.load_packet_range(start_idx, end_idx)
            recon_packets.extend(chunk)

            # Check memory usage
            stats = self.optimizer.get_memory_stats()
            if stats.rss_mb > self.memory_limit_mb:
                logger.warning(
                    f"Memory limit exceeded ({stats.rss_mb:.1f}MB), forcing GC"
                )
                self.optimizer.force_garbage_collection()

        # Load zapret packets in chunks
        for start_idx in range(0, zapret_count, chunk_size):
            end_idx = min(start_idx + chunk_size, zapret_count)
            chunk = zapret_loader.load_packet_range(start_idx, end_idx)
            zapret_packets.extend(chunk)

            # Check memory usage
            stats = self.optimizer.get_memory_stats()
            if stats.rss_mb > self.memory_limit_mb:
                logger.warning(
                    f"Memory limit exceeded ({stats.rss_mb:.1f}MB), forcing GC"
                )
                self.optimizer.force_garbage_collection()

        # Optimize storage
        recon_storage = self.optimizer.optimize_packet_storage(recon_packets)
        zapret_storage = self.optimizer.optimize_packet_storage(zapret_packets)

        # Clear original lists to free memory
        del recon_packets
        del zapret_packets
        self.optimizer.force_garbage_collection()

        # Create comparison result
        result = ComparisonResult(
            recon_packets=recon_storage.get_all_packets(),
            zapret_packets=zapret_storage.get_all_packets(),
            differences=[],  # Will be populated by difference detector
            similarity_score=0.0,  # Will be calculated by comparator
            analysis_metadata={
                "memory_optimized": True,
                "memory_limit_mb": self.memory_limit_mb,
                "recon_optimized_count": len(recon_storage.get_all_packets()),
                "zapret_optimized_count": len(zapret_storage.get_all_packets()),
            },
        )

        logger.info("Memory-efficient PCAP comparison completed")
        return result


# Example usage and testing
if __name__ == "__main__":
    # Test memory optimization
    optimizer = MemoryOptimizer()

    # Create sample packets for testing
    sample_packets = []
    for i in range(10000):
        packet = PacketInfo(
            timestamp=float(i),
            src_ip=f"192.168.1.{i % 255}",
            dst_ip=f"10.0.0.{i % 255}",
            src_port=80 + (i % 1000),
            dst_port=443,
            sequence_num=i * 1000,
            ack_num=i * 1000 + 1,
            ttl=64,
            flags=["ACK"],
            payload_length=100 + (i % 500),
            payload_hex="deadbeef" * (10 + i % 20),
            checksum=0x1234,
            checksum_valid=True,
            is_client_hello=(i % 100 == 0),
        )
        sample_packets.append(packet)

    print(f"Created {len(sample_packets)} sample packets")

    # Test optimization
    before_stats = optimizer.get_memory_stats()
    print(f"Memory before optimization: {before_stats.rss_mb:.1f}MB")

    optimized_storage = optimizer.optimize_packet_storage(sample_packets)

    after_stats = optimizer.get_memory_stats()
    print(f"Memory after optimization: {after_stats.rss_mb:.1f}MB")

    # Test queries
    packets_by_ip = optimized_storage.get_packets_by_ip("192.168.1.1")
    print(f"Found {len(packets_by_ip)} packets for IP 192.168.1.1")

    packets_in_range = optimized_storage.get_packets_in_time_range(100.0, 200.0)
    print(f"Found {len(packets_in_range)} packets in time range 100-200")

    # Test memory-mapped storage
    mmap_storage = optimizer.create_memory_mapped_storage(sample_packets[:1000])
    loaded_packets = mmap_storage.load_packets()
    print(f"Memory-mapped storage loaded {len(loaded_packets)} packets")

    mmap_storage.close()
    optimizer.cleanup_temp_files()
