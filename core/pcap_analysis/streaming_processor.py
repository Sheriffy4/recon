"""
Streaming PCAP processor for handling large files efficiently.
Implements memory-efficient streaming processing to avoid loading entire PCAP files into memory.
"""

import asyncio
import logging
from typing import Iterator, Optional, Callable, List
from dataclasses import dataclass
from pathlib import Path
import gc
import psutil
import os

try:
    import dpkt
    import pcap

    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

try:
    from scapy.all import PcapReader, Packet

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .packet_info import PacketInfo
from .comparison_result import ComparisonResult

logger = logging.getLogger(__name__)


@dataclass
class StreamingConfig:
    """Configuration for streaming PCAP processing."""

    chunk_size: int = 1000  # Number of packets to process in each chunk
    memory_limit_mb: int = 512  # Memory limit in MB before forcing garbage collection
    buffer_size: int = 8192  # Buffer size for file reading
    enable_gc_optimization: bool = True  # Enable aggressive garbage collection
    progress_callback: Optional[Callable[[int, int], None]] = None  # Progress callback


class MemoryMonitor:
    """Monitor memory usage during streaming processing."""

    def __init__(self, limit_mb: int = 512):
        self.limit_mb = limit_mb
        self.process = psutil.Process(os.getpid())

    def get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB."""
        return self.process.memory_info().rss / 1024 / 1024

    def is_memory_limit_exceeded(self) -> bool:
        """Check if memory limit is exceeded."""
        return self.get_memory_usage_mb() > self.limit_mb

    def force_gc_if_needed(self) -> bool:
        """Force garbage collection if memory limit exceeded."""
        if self.is_memory_limit_exceeded():
            logger.debug(f"Memory limit exceeded ({self.get_memory_usage_mb():.1f}MB), forcing GC")
            gc.collect()
            return True
        return False


class StreamingPcapProcessor:
    """
    Streaming PCAP processor that handles large files efficiently.
    Processes packets in chunks to minimize memory usage.
    """

    def __init__(self, config: Optional[StreamingConfig] = None):
        self.config = config or StreamingConfig()
        self.memory_monitor = MemoryMonitor(self.config.memory_limit_mb)
        self._processed_packets = 0
        self._total_packets = 0

    def estimate_packet_count(self, pcap_file: str) -> int:
        """Estimate total packet count for progress reporting."""
        try:
            file_size = Path(pcap_file).stat().st_size
            # Rough estimate: average packet size ~100 bytes
            estimated_packets = file_size // 100
            return max(estimated_packets, 1)
        except Exception as e:
            logger.warning(f"Could not estimate packet count: {e}")
            return 1

    def _report_progress(self):
        """Report processing progress."""
        if self.config.progress_callback and self._total_packets > 0:
            self.config.progress_callback(self._processed_packets, self._total_packets)

    def stream_packets_dpkt(self, pcap_file: str) -> Iterator[PacketInfo]:
        """Stream packets using dpkt library."""
        if not DPKT_AVAILABLE:
            raise ImportError("dpkt library not available")

        try:
            with open(pcap_file, "rb") as f:
                pcap_reader = dpkt.pcap.Reader(f)

                packet_buffer = []
                for timestamp, buf in pcap_reader:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, dpkt.ip.IP):
                            ip = eth.data
                            if isinstance(ip.data, dpkt.tcp.TCP):
                                tcp = ip.data

                                packet_info = PacketInfo(
                                    timestamp=float(timestamp),
                                    src_ip=f"{ip.src[0]}.{ip.src[1]}.{ip.src[2]}.{ip.src[3]}",
                                    dst_ip=f"{ip.dst[0]}.{ip.dst[1]}.{ip.dst[2]}.{ip.dst[3]}",
                                    src_port=tcp.sport,
                                    dst_port=tcp.dport,
                                    sequence_num=tcp.seq,
                                    ack_num=tcp.ack,
                                    ttl=ip.ttl,
                                    flags=[],  # Will be populated based on TCP flags
                                    payload_length=len(tcp.data),
                                    payload_hex=tcp.data.hex() if tcp.data else "",
                                    checksum=tcp.sum,
                                    checksum_valid=True,  # dpkt doesn't validate by default
                                    is_client_hello=self._is_tls_client_hello(tcp.data),
                                )

                                packet_buffer.append(packet_info)
                                self._processed_packets += 1

                                # Process in chunks
                                if len(packet_buffer) >= self.config.chunk_size:
                                    for packet in packet_buffer:
                                        yield packet
                                    packet_buffer.clear()

                                    # Memory management
                                    if self.config.enable_gc_optimization:
                                        self.memory_monitor.force_gc_if_needed()

                                    self._report_progress()

                    except Exception as e:
                        logger.warning(f"Error processing packet: {e}")
                        continue

                # Yield remaining packets
                for packet in packet_buffer:
                    yield packet

        except Exception as e:
            logger.error(f"Error reading PCAP file {pcap_file}: {e}")
            raise

    def stream_packets_scapy(self, pcap_file: str) -> Iterator[PacketInfo]:
        """Stream packets using scapy library."""
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy library not available")

        try:
            packet_buffer = []

            with PcapReader(pcap_file) as pcap_reader:
                for packet in pcap_reader:
                    try:
                        if packet.haslayer("TCP") and packet.haslayer("IP"):
                            ip_layer = packet["IP"]
                            tcp_layer = packet["TCP"]

                            packet_info = PacketInfo(
                                timestamp=float(packet.time),
                                src_ip=ip_layer.src,
                                dst_ip=ip_layer.dst,
                                src_port=tcp_layer.sport,
                                dst_port=tcp_layer.dport,
                                sequence_num=tcp_layer.seq,
                                ack_num=tcp_layer.ack,
                                ttl=ip_layer.ttl,
                                flags=self._extract_tcp_flags(tcp_layer),
                                payload_length=len(tcp_layer.payload),
                                payload_hex=(
                                    bytes(tcp_layer.payload).hex() if tcp_layer.payload else ""
                                ),
                                checksum=tcp_layer.chksum,
                                checksum_valid=packet.haslayer("TCP") and tcp_layer.chksum != 0,
                                is_client_hello=self._is_tls_client_hello(bytes(tcp_layer.payload)),
                            )

                            packet_buffer.append(packet_info)
                            self._processed_packets += 1

                            # Process in chunks
                            if len(packet_buffer) >= self.config.chunk_size:
                                for pkt in packet_buffer:
                                    yield pkt
                                packet_buffer.clear()

                                # Memory management
                                if self.config.enable_gc_optimization:
                                    self.memory_monitor.force_gc_if_needed()

                                self._report_progress()

                    except Exception as e:
                        logger.warning(f"Error processing packet: {e}")
                        continue

                # Yield remaining packets
                for packet in packet_buffer:
                    yield packet

        except Exception as e:
            logger.error(f"Error reading PCAP file {pcap_file}: {e}")
            raise

    def stream_packets(self, pcap_file: str, prefer_dpkt: bool = True) -> Iterator[PacketInfo]:
        """
        Stream packets from PCAP file using available library.

        Args:
            pcap_file: Path to PCAP file
            prefer_dpkt: Whether to prefer dpkt over scapy (dpkt is faster)

        Yields:
            PacketInfo objects for each packet
        """
        self._processed_packets = 0
        self._total_packets = self.estimate_packet_count(pcap_file)

        logger.info(f"Starting streaming processing of {pcap_file}")
        logger.info(f"Estimated packets: {self._total_packets}")

        try:
            if prefer_dpkt and DPKT_AVAILABLE:
                logger.debug("Using dpkt for streaming processing")
                yield from self.stream_packets_dpkt(pcap_file)
            elif SCAPY_AVAILABLE:
                logger.debug("Using scapy for streaming processing")
                yield from self.stream_packets_scapy(pcap_file)
            else:
                raise ImportError("Neither dpkt nor scapy libraries are available")

        finally:
            logger.info(
                f"Completed streaming processing. Processed {self._processed_packets} packets"
            )
            if self.config.enable_gc_optimization:
                gc.collect()

    def _extract_tcp_flags(self, tcp_layer) -> List[str]:
        """Extract TCP flags from scapy TCP layer."""
        flags = []
        if hasattr(tcp_layer, "flags"):
            flag_value = tcp_layer.flags
            if flag_value & 0x01:
                flags.append("FIN")
            if flag_value & 0x02:
                flags.append("SYN")
            if flag_value & 0x04:
                flags.append("RST")
            if flag_value & 0x08:
                flags.append("PSH")
            if flag_value & 0x10:
                flags.append("ACK")
            if flag_value & 0x20:
                flags.append("URG")
        return flags

    def _is_tls_client_hello(self, payload: bytes) -> bool:
        """Check if payload contains TLS Client Hello."""
        if not payload or len(payload) < 6:
            return False

        # TLS record header: type(1) + version(2) + length(2) + handshake_type(1)
        try:
            return payload[0] == 0x16 and payload[5] == 0x01  # TLS Handshake  # Client Hello
        except IndexError:
            return False


class AsyncStreamingProcessor:
    """Asynchronous streaming PCAP processor for better performance."""

    def __init__(self, config: Optional[StreamingConfig] = None):
        self.config = config or StreamingConfig()
        self.processor = StreamingPcapProcessor(config)

    async def stream_packets_async(self, pcap_file: str) -> Iterator[PacketInfo]:
        """Asynchronously stream packets from PCAP file."""
        loop = asyncio.get_event_loop()

        # Run streaming in executor to avoid blocking
        def _stream_sync():
            return list(self.processor.stream_packets(pcap_file))

        packets = await loop.run_in_executor(None, _stream_sync)

        # Yield packets in chunks to allow other coroutines to run
        for i in range(0, len(packets), self.config.chunk_size):
            chunk = packets[i : i + self.config.chunk_size]
            for packet in chunk:
                yield packet
            await asyncio.sleep(0)  # Allow other coroutines to run

    async def compare_pcaps_streaming(self, recon_pcap: str, zapret_pcap: str) -> ComparisonResult:
        """Compare two PCAP files using streaming processing."""
        recon_packets = []
        zapret_packets = []

        # Stream both files concurrently
        async def stream_recon():
            async for packet in self.stream_packets_async(recon_pcap):
                recon_packets.append(packet)

        async def stream_zapret():
            async for packet in self.stream_packets_async(zapret_pcap):
                zapret_packets.append(packet)

        # Process both files concurrently
        await asyncio.gather(stream_recon(), stream_zapret())

        # Create comparison result
        return ComparisonResult(
            recon_packets=recon_packets,
            zapret_packets=zapret_packets,
            differences=[],  # Will be populated by difference detector
            similarity_score=0.0,  # Will be calculated by comparator
            analysis_metadata={
                "recon_packet_count": len(recon_packets),
                "zapret_packet_count": len(zapret_packets),
                "streaming_enabled": True,
                "memory_limit_mb": self.config.memory_limit_mb,
            },
        )


# Example usage and testing
if __name__ == "__main__":
    import time

    def progress_callback(processed: int, total: int):
        percent = (processed / total) * 100 if total > 0 else 0
        print(f"Progress: {processed}/{total} ({percent:.1f}%)")

    config = StreamingConfig(
        chunk_size=500, memory_limit_mb=256, progress_callback=progress_callback
    )

    processor = StreamingPcapProcessor(config)

    # Test with a sample PCAP file
    test_pcap = "test.pcap"  # Replace with actual test file
    if Path(test_pcap).exists():
        start_time = time.time()
        packet_count = 0

        for packet in processor.stream_packets(test_pcap):
            packet_count += 1
            if packet_count % 1000 == 0:
                memory_mb = processor.memory_monitor.get_memory_usage_mb()
                print(f"Processed {packet_count} packets, Memory: {memory_mb:.1f}MB")

        end_time = time.time()
        print(
            f"Streaming processing completed: {packet_count} packets in {end_time - start_time:.2f}s"
        )
    else:
        print(f"Test PCAP file {test_pcap} not found")
