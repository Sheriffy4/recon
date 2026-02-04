"""
Discovery Mode PCAP Filter

This module provides PCAP filtering functionality specifically for auto strategy discovery mode.
It integrates with the domain filter to ensure only target domain traffic is captured and analyzed.

Requirements: 3.4 from auto-strategy-discovery spec
"""

import logging
from typing import Optional, Callable, Any, Dict, List
from dataclasses import dataclass
import time

try:
    from scapy.all import Packet, Raw, IP, IPv6, TCP
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.handshake import TLSClientHello

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = Any
    Raw = Any
    IP = Any
    IPv6 = Any
    TCP = Any
    TLS = Any
    TLSClientHello = Any

from core.domain_filter import DomainFilter, FilterMode
from core.bypass.filtering.sni_extractor import SNIExtractor

LOG = logging.getLogger(__name__)


@dataclass
class PCAPFilterStats:
    """Statistics for PCAP filtering operations"""

    total_packets: int = 0
    processed_packets: int = 0
    filtered_packets: int = 0
    target_domain_packets: int = 0
    non_tls_packets: int = 0
    extraction_errors: int = 0

    @property
    def filter_rate(self) -> float:
        """Calculate the filtering rate (filtered/total)"""
        return self.filtered_packets / self.total_packets if self.total_packets > 0 else 0.0

    @property
    def target_rate(self) -> float:
        """Calculate the target domain rate (target/processed)"""
        return (
            self.target_domain_packets / self.processed_packets
            if self.processed_packets > 0
            else 0.0
        )


class DiscoveryPCAPFilter:
    """
    PCAP filter for auto strategy discovery mode.

    This class provides packet filtering functionality that integrates with the domain filter
    to ensure only target domain traffic is captured during discovery sessions.

    Key features:
    - Integration with DomainFilter for consistent filtering logic
    - SNI-based packet filtering for TLS traffic
    - Statistics collection for monitoring effectiveness
    - Support for both real-time and offline PCAP analysis
    """

    def __init__(self, domain_filter: Optional[DomainFilter] = None):
        """
        Initialize the PCAP filter.

        Args:
            domain_filter: DomainFilter instance to use for filtering logic.
                          If None, creates a new instance.
        """
        self._domain_filter = domain_filter or DomainFilter()
        self._sni_extractor = SNIExtractor()
        self._stats = PCAPFilterStats()
        self._packet_callbacks: List[Callable[[Packet], None]] = []

        LOG.info("DiscoveryPCAPFilter initialized")

    def configure_for_discovery(self, target_domain: str) -> None:
        """
        Configure the filter for discovery mode with a specific target domain.

        Args:
            target_domain: The domain to filter for during discovery

        Requirements: 3.4
        """
        if not target_domain:
            raise ValueError("Target domain cannot be empty")

        # Configure the domain filter for discovery mode
        self._domain_filter.configure_filter(target_domain, FilterMode.DISCOVERY)

        # Reset statistics for new discovery session
        self._reset_stats()

        LOG.info(f"PCAP filter configured for discovery mode with target domain: {target_domain}")

    def should_capture_packet(self, packet: Packet) -> bool:
        """
        Determine if a packet should be captured based on domain filtering rules.

        Args:
            packet: Scapy packet object to evaluate

        Returns:
            True if packet should be captured, False if it should be filtered out

        Requirements: 3.4
        """
        if not SCAPY_AVAILABLE:
            LOG.warning("Scapy not available, cannot filter packets")
            return True

        self._stats.total_packets += 1

        try:
            # Extract payload from packet
            payload = self._extract_payload_from_packet(packet)
            if not payload:
                # No payload - likely not TLS traffic
                self._stats.non_tls_packets += 1
                self._stats.filtered_packets += 1
                LOG.debug("Filtered packet: no TLS payload found")
                return False

            # Use domain filter to determine if packet should be processed
            should_process = self._domain_filter.should_process_packet(payload)

            if should_process:
                self._stats.processed_packets += 1
                self._stats.target_domain_packets += 1
                LOG.debug("Packet approved for capture (target domain)")

                # Notify callbacks about captured packet
                self._notify_packet_callbacks(packet)

                return True
            else:
                self._stats.filtered_packets += 1
                LOG.debug("Packet filtered out (non-target domain)")
                return False

        except Exception as e:
            self._stats.extraction_errors += 1
            self._stats.filtered_packets += 1
            LOG.warning(f"Error evaluating packet for capture: {e}")
            return False

    def _extract_payload_from_packet(self, packet: Packet) -> Optional[bytes]:
        """
        Extract TLS payload from a Scapy packet.

        Args:
            packet: Scapy packet object

        Returns:
            TLS payload bytes if found, None otherwise
        """
        try:
            # Look for TLS layer first
            if packet.haslayer(TLS):
                tls_layer = packet[TLS]
                return bytes(tls_layer)

            # Look for TLS ClientHello specifically
            if packet.haslayer(TLSClientHello):
                clienthello_layer = packet[TLSClientHello]
                return bytes(clienthello_layer)

            # Fallback: look for Raw layer in TCP packets (common for TLS)
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                tcp_layer = packet[TCP]
                raw_layer = packet[Raw]

                # Check if this looks like TLS traffic (port 443 or TLS record type)
                if (
                    tcp_layer.dport == 443
                    or tcp_layer.sport == 443
                    or (len(raw_layer.load) > 0 and raw_layer.load[0] == 0x16)
                ):  # TLS Handshake
                    return bytes(raw_layer.load)

            return None

        except Exception as e:
            LOG.debug(f"Error extracting payload from packet: {e}")
            return None

    def create_packet_filter_function(self) -> Callable[[Packet], bool]:
        """
        Create a packet filter function for use with Scapy's sniff() function.

        Returns:
            Function that can be used as the 'lfilter' parameter in sniff()

        Requirements: 3.4
        """

        def packet_filter(packet: Packet) -> bool:
            """Filter function for Scapy sniff()"""
            return self.should_capture_packet(packet)

        return packet_filter

    def create_bpf_filter(self, target_domain: Optional[str] = None) -> str:
        """
        Create a BPF (Berkeley Packet Filter) string for basic traffic filtering.

        This provides a coarse filter that can be applied at the network level
        before packets reach the SNI-based filtering logic.

        Args:
            target_domain: Optional target domain for IP-based filtering

        Returns:
            BPF filter string

        Requirements: 3.4
        """
        # Basic filter for TLS traffic (ports 443 and 80 for potential redirects)
        base_filter = "tcp port 443 or tcp port 80"

        # TODO: Could be enhanced with IP-based filtering if we resolve target_domain to IPs
        # For now, keep it simple and rely on SNI-based filtering for domain specificity

        LOG.info(f"Created BPF filter: {base_filter}")
        return base_filter

    def add_packet_callback(self, callback: Callable[[Packet], None]) -> None:
        """
        Add a callback function to be called for each captured packet.

        Args:
            callback: Function to call with each captured packet
        """
        self._packet_callbacks.append(callback)
        LOG.debug(f"Added packet callback: {callback.__name__}")

    def remove_packet_callback(self, callback: Callable[[Packet], None]) -> None:
        """
        Remove a packet callback function.

        Args:
            callback: Function to remove from callbacks
        """
        if callback in self._packet_callbacks:
            self._packet_callbacks.remove(callback)
            LOG.debug(f"Removed packet callback: {callback.__name__}")

    def _notify_packet_callbacks(self, packet: Packet) -> None:
        """
        Notify all registered callbacks about a captured packet.

        Args:
            packet: Captured packet to notify about
        """
        for callback in self._packet_callbacks:
            try:
                callback(packet)
            except Exception as e:
                LOG.warning(f"Error in packet callback {callback.__name__}: {e}")

    def filter_pcap_file(self, input_file: str, output_file: str) -> int:
        """
        Filter an existing PCAP file to include only target domain traffic.

        Args:
            input_file: Path to input PCAP file
            output_file: Path to output filtered PCAP file

        Returns:
            Number of packets written to output file

        Requirements: 3.4
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for PCAP file filtering")

        from scapy.all import rdpcap, wrpcap

        LOG.info(f"Filtering PCAP file: {input_file} -> {output_file}")

        try:
            # Read input PCAP file
            packets = rdpcap(input_file)
            LOG.info(f"Read {len(packets)} packets from {input_file}")

            # Filter packets
            filtered_packets = []
            for packet in packets:
                if self.should_capture_packet(packet):
                    filtered_packets.append(packet)

            # Write filtered packets to output file
            if filtered_packets:
                wrpcap(output_file, filtered_packets)
                LOG.info(f"Wrote {len(filtered_packets)} filtered packets to {output_file}")
            else:
                LOG.warning(f"No packets matched filter criteria for {output_file}")

            return len(filtered_packets)

        except Exception as e:
            LOG.error(f"Error filtering PCAP file: {e}")
            raise

    def analyze_pcap_file(self, pcap_file: str) -> Dict[str, Any]:
        """
        Analyze a PCAP file and return statistics about domain distribution.

        Args:
            pcap_file: Path to PCAP file to analyze

        Returns:
            Dictionary containing analysis results

        Requirements: 3.4
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for PCAP file analysis")

        from scapy.all import rdpcap

        LOG.info(f"Analyzing PCAP file: {pcap_file}")

        try:
            packets = rdpcap(pcap_file)

            domain_counts = {}
            total_packets = len(packets)
            tls_packets = 0
            target_packets = 0

            current_target = self._domain_filter.get_current_target()

            for packet in packets:
                payload = self._extract_payload_from_packet(packet)
                if payload:
                    tls_packets += 1

                    # Extract domain using SNI extractor
                    domain = self._sni_extractor.extract_sni(payload)
                    if domain:
                        domain_counts[domain] = domain_counts.get(domain, 0) + 1

                        # Check if this is target domain traffic
                        if current_target and self._domain_filter._matches_target_domain(
                            domain, current_target
                        ):
                            target_packets += 1

            analysis = {
                "total_packets": total_packets,
                "tls_packets": tls_packets,
                "target_packets": target_packets,
                "current_target": current_target,
                "domain_distribution": domain_counts,
                "target_rate": target_packets / tls_packets if tls_packets > 0 else 0.0,
                "tls_rate": tls_packets / total_packets if total_packets > 0 else 0.0,
            }

            LOG.info(f"PCAP analysis complete: {target_packets}/{tls_packets} target packets")
            return analysis

        except Exception as e:
            LOG.error(f"Error analyzing PCAP file: {e}")
            raise

    def get_stats(self) -> PCAPFilterStats:
        """
        Get current PCAP filtering statistics.

        Returns:
            Current PCAPFilterStats object
        """
        return self._stats

    def get_domain_filter(self) -> DomainFilter:
        """
        Get the underlying domain filter instance.

        Returns:
            DomainFilter instance used by this PCAP filter
        """
        return self._domain_filter

    def is_discovery_mode(self) -> bool:
        """
        Check if currently in discovery mode.

        Returns:
            True if in discovery mode, False otherwise
        """
        return self._domain_filter.is_discovery_mode()

    def get_current_target(self) -> Optional[str]:
        """
        Get the current target domain.

        Returns:
            Current target domain or None if not set
        """
        return self._domain_filter.get_current_target()

    def _reset_stats(self) -> None:
        """Reset PCAP filtering statistics."""
        self._stats = PCAPFilterStats()

    def log_filtering_summary(self) -> None:
        """Log a summary of PCAP filtering statistics."""
        stats = self._stats
        LOG.info(f"PCAP Filtering Summary:")
        LOG.info(f"  Total packets: {stats.total_packets}")
        LOG.info(f"  Processed: {stats.processed_packets}")
        LOG.info(f"  Filtered: {stats.filtered_packets}")
        LOG.info(f"  Target domain: {stats.target_domain_packets}")
        LOG.info(f"  Non-TLS: {stats.non_tls_packets}")
        LOG.info(f"  Errors: {stats.extraction_errors}")
        LOG.info(f"  Filter rate: {stats.filter_rate:.2%}")
        LOG.info(f"  Target rate: {stats.target_rate:.2%}")

        current_target = self.get_current_target()
        if current_target:
            LOG.info(f"  Current target: {current_target}")
