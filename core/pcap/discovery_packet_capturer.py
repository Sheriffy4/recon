"""
Discovery Mode Packet Capturer

This module provides an enhanced packet capturer that integrates with the domain filter
to capture only target domain traffic during auto strategy discovery sessions.

Requirements: 3.4 from auto-strategy-discovery spec
"""

import logging
import threading
import time
import os
from typing import Optional, Callable, Any
from pathlib import Path

try:
    from scapy.all import sniff, PcapWriter, Packet

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    sniff = None
    PcapWriter = None
    Packet = Any

from core.pcap.discovery_pcap_filter import DiscoveryPCAPFilter
from core.domain_filter import DomainFilter

LOG = logging.getLogger(__name__)


class DiscoveryPacketCapturer:
    """
    Enhanced packet capturer for auto strategy discovery mode.

    This class extends the basic packet capture functionality with domain filtering
    to ensure only target domain traffic is captured during discovery sessions.

    Key features:
    - Integration with DiscoveryPCAPFilter for domain-based filtering
    - Streaming capture without accumulating packets in memory
    - Configurable capture limits (packets, time)
    - Statistics collection and reporting
    """

    def __init__(
        self,
        filename: str,
        target_domain: Optional[str] = None,
        domain_filter: Optional[DomainFilter] = None,
        iface: Optional[str] = None,
        max_packets: Optional[int] = None,
        max_seconds: Optional[int] = None,
    ):
        """
        Initialize the discovery packet capturer.

        Args:
            filename: Output PCAP file path
            target_domain: Target domain for filtering (if None, no filtering)
            domain_filter: Existing DomainFilter instance (if None, creates new one)
            iface: Network interface to capture on (None for default)
            max_packets: Maximum number of packets to capture (None for unlimited)
            max_seconds: Maximum capture duration in seconds (None for unlimited)
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for packet capturing. pip install scapy")

        self.filename = filename
        self.target_domain = target_domain
        self.iface = iface
        self.max_packets = max_packets
        self.max_seconds = max_seconds

        # Initialize filtering components
        self._pcap_filter = DiscoveryPCAPFilter(domain_filter)
        if target_domain:
            self._pcap_filter.configure_for_discovery(target_domain)

        # Capture state
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._writer: Optional[PcapWriter] = None
        self._counter = 0
        self._start_ts: Optional[float] = None

        LOG.info(f"DiscoveryPacketCapturer initialized for file: {filename}")
        if target_domain:
            LOG.info(f"  Target domain: {target_domain}")
        if max_packets:
            LOG.info(f"  Max packets: {max_packets}")
        if max_seconds:
            LOG.info(f"  Max duration: {max_seconds}s")

    def start(self) -> None:
        """
        Start packet capture with domain filtering.

        Requirements: 3.4
        """
        if self._thread and self._thread.is_alive():
            LOG.warning("Capture already running")
            return

        self._start_ts = time.time()
        self._counter = 0
        self._stop.clear()

        # Ensure output directory exists
        output_path = Path(self.filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize PCAP writer
        self._writer = PcapWriter(self.filename, append=True, sync=True)

        # Start capture thread
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

        target_info = f" (target: {self.target_domain})" if self.target_domain else ""
        bpf_filter = self._pcap_filter.create_bpf_filter(self.target_domain)

        LOG.info(f"PCAP capture started -> {self.filename}{target_info}")
        LOG.info(f"  BPF filter: {bpf_filter}")
        LOG.info(f"  Interface: {self.iface or 'default'}")

    def stop(self) -> None:
        """
        Stop packet capture and finalize output file.

        Requirements: 3.4
        """
        if not self._thread or not self._thread.is_alive():
            LOG.warning("Capture not running")
            return

        LOG.info("Stopping PCAP capture...")
        self._stop.set()

        # Wait for capture thread to finish
        if self._thread:
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                LOG.warning("Capture thread did not stop gracefully")

        # Close PCAP writer
        if self._writer:
            try:
                self._writer.close()
                self._writer = None
            except Exception as e:
                LOG.error(f"Error closing PCAP writer: {e}")

        # Log capture summary
        duration = time.time() - self._start_ts if self._start_ts else 0
        LOG.info(f"PCAP capture stopped. Total packets written: {self._counter}")
        LOG.info(f"  Duration: {duration:.1f}s")
        LOG.info(f"  File: {self.filename}")

        # Log filtering statistics
        self._pcap_filter.log_filtering_summary()

    def _capture_loop(self) -> None:
        """
        Main capture loop that runs in a separate thread.
        """
        LOG.info(f"Starting packet capture loop (iface={self.iface})")

        # Create BPF filter for coarse filtering
        bpf_filter = self._pcap_filter.create_bpf_filter(self.target_domain)

        # Create packet filter function for fine-grained filtering
        packet_filter = self._pcap_filter.create_packet_filter_function()

        while not self._stop.is_set():
            try:
                # Use Scapy's sniff with both BPF and packet filters
                sniff(
                    iface=self.iface,
                    filter=bpf_filter,  # Coarse BPF filtering at network level
                    lfilter=packet_filter,  # Fine-grained SNI-based filtering
                    prn=self._on_packet,
                    store=False,
                    timeout=1,
                    stop_filter=lambda x: self._stop.is_set(),
                )
            except PermissionError as e:
                LOG.error(f"Permission denied: {e}")
                LOG.error("On Windows install Npcap and run as Admin; on Linux run with sudo.")
                self._stop.set()
                break
            except Exception as e:
                LOG.error(f"Capture error: {e}")
                import traceback

                LOG.debug(traceback.format_exc())

                # Brief pause before retrying
                if not self._stop.is_set():
                    time.sleep(0.5)

        LOG.info("Packet capture loop stopped")

    def _on_packet(self, packet: Packet) -> None:
        """
        Handle captured packet - write to PCAP file and update counters.

        Args:
            packet: Captured packet that passed filtering
        """
        try:
            if self._writer and not self._stop.is_set():
                self._writer.write(packet)
                self._counter += 1

                # Log progress for target domain packets
                if self._counter % 100 == 0:
                    LOG.debug(f"Captured {self._counter} target domain packets")

        except Exception as e:
            LOG.error(f"Failed to write packet: {e}")

        # Check capture limits
        if self.max_packets and self._counter >= self.max_packets:
            LOG.info(f"Reached packet limit ({self.max_packets}), stopping capture")
            self._stop.set()

        if self.max_seconds and self._start_ts:
            elapsed = time.time() - self._start_ts
            if elapsed >= self.max_seconds:
                LOG.info(f"Reached time limit ({self.max_seconds}s), stopping capture")
                self._stop.set()

    def is_running(self) -> bool:
        """
        Check if capture is currently running.

        Returns:
            True if capture is active, False otherwise
        """
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def get_packet_count(self) -> int:
        """
        Get the number of packets captured so far.

        Returns:
            Number of packets written to PCAP file
        """
        return self._counter

    def get_capture_duration(self) -> float:
        """
        Get the current capture duration in seconds.

        Returns:
            Capture duration in seconds, or 0 if not started
        """
        if not self._start_ts:
            return 0.0
        return time.time() - self._start_ts

    def get_pcap_filter(self) -> DiscoveryPCAPFilter:
        """
        Get the PCAP filter instance used by this capturer.

        Returns:
            DiscoveryPCAPFilter instance
        """
        return self._pcap_filter

    def get_current_target(self) -> Optional[str]:
        """
        Get the current target domain.

        Returns:
            Current target domain or None if not set
        """
        return self.target_domain

    def is_discovery_mode(self) -> bool:
        """
        Check if currently in discovery mode.

        Returns:
            True if in discovery mode, False otherwise
        """
        return self._pcap_filter.is_discovery_mode()

    def get_stats(self) -> dict:
        """
        Get comprehensive capture and filtering statistics.

        Returns:
            Dictionary containing capture and filtering statistics
        """
        pcap_stats = self._pcap_filter.get_stats()

        return {
            "filename": self.filename,
            "target_domain": self.target_domain,
            "is_running": self.is_running(),
            "packets_written": self._counter,
            "capture_duration": self.get_capture_duration(),
            "pcap_filter_stats": {
                "total_packets": pcap_stats.total_packets,
                "processed_packets": pcap_stats.processed_packets,
                "filtered_packets": pcap_stats.filtered_packets,
                "target_domain_packets": pcap_stats.target_domain_packets,
                "non_tls_packets": pcap_stats.non_tls_packets,
                "extraction_errors": pcap_stats.extraction_errors,
                "filter_rate": pcap_stats.filter_rate,
                "target_rate": pcap_stats.target_rate,
            },
        }

    def configure_target_domain(self, target_domain: str) -> None:
        """
        Configure or change the target domain for filtering.

        Args:
            target_domain: New target domain to filter for

        Requirements: 3.4
        """
        if self.is_running():
            raise RuntimeError("Cannot change target domain while capture is running")

        self.target_domain = target_domain
        self._pcap_filter.configure_for_discovery(target_domain)

        LOG.info(f"Target domain configured: {target_domain}")

    def add_packet_callback(self, callback: Callable[[Packet], None]) -> None:
        """
        Add a callback function to be called for each captured packet.

        Args:
            callback: Function to call with each captured packet
        """
        self._pcap_filter.add_packet_callback(callback)

    def remove_packet_callback(self, callback: Callable[[Packet], None]) -> None:
        """
        Remove a packet callback function.

        Args:
            callback: Function to remove from callbacks
        """
        self._pcap_filter.remove_packet_callback(callback)


def create_discovery_capturer(
    filename: str,
    target_domain: str,
    max_packets: Optional[int] = None,
    max_seconds: Optional[int] = None,
    iface: Optional[str] = None,
) -> DiscoveryPacketCapturer:
    """
    Convenience function to create a discovery packet capturer.

    Args:
        filename: Output PCAP file path
        target_domain: Target domain for filtering
        max_packets: Maximum number of packets to capture
        max_seconds: Maximum capture duration in seconds
        iface: Network interface to capture on

    Returns:
        Configured DiscoveryPacketCapturer instance

    Requirements: 3.4
    """
    return DiscoveryPacketCapturer(
        filename=filename,
        target_domain=target_domain,
        max_packets=max_packets,
        max_seconds=max_seconds,
        iface=iface,
    )
