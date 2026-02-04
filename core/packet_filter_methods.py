"""
Packet Filtering Methods for Domain Filter

This module provides packet-level filtering methods that integrate with
the existing packet processing infrastructure for domain-based filtering.

Requirements: 1.1, 1.2, 1.4 from auto-strategy-discovery spec
"""

import logging
from typing import Optional, Dict, Any, List, Tuple, Union
from dataclasses import dataclass
import struct

from core.domain_filter import DomainFilter, FilterMode
from core.bypass.engine.sni_domain_extractor import SNIDomainExtractor

LOG = logging.getLogger(__name__)


@dataclass
class PacketInfo:
    """Information extracted from a network packet"""

    # Basic packet info
    size: int
    protocol: str  # "tcp", "udp", "other"

    # Network layer info
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # Application layer info
    is_tls: bool = False
    is_http: bool = False
    extracted_domain: Optional[str] = None
    domain_source: Optional[str] = None  # "sni", "http_host", etc.

    # Filtering decision
    should_process: bool = True
    filter_reason: Optional[str] = None


class PacketFilterMethods:
    """
    Packet filtering methods for domain-based filtering.

    Provides methods to filter network packets based on domain extraction
    and filtering rules, integrating with the existing packet processing
    infrastructure.
    """

    def __init__(self, domain_filter: Optional[DomainFilter] = None):
        """
        Initialize packet filtering methods.

        Args:
            domain_filter: DomainFilter instance to use (creates new if None)
        """
        self.domain_filter = domain_filter or DomainFilter()
        self.domain_extractor = SNIDomainExtractor(enable_fast_sni=True)

        # Statistics
        self._packet_count = 0
        self._filtered_count = 0
        self._processed_count = 0

        LOG.info("PacketFilterMethods initialized")

    def filter_packet(
        self, packet_data: bytes, packet_info: Optional[Dict[str, Any]] = None
    ) -> PacketInfo:
        """
        Filter a single packet and extract relevant information.

        Args:
            packet_data: Raw packet data bytes
            packet_info: Optional additional packet information

        Returns:
            PacketInfo object with filtering decision and extracted data

        Requirements: 1.1, 1.2, 1.4
        """
        self._packet_count += 1

        # Create packet info object
        info = PacketInfo(size=len(packet_data), protocol="unknown")

        try:
            # Extract basic packet information
            self._extract_packet_info(packet_data, info, packet_info)

            # Extract domain information
            self._extract_domain_info(packet_data, info)

            # Apply domain filtering
            self._apply_domain_filter(info)

            # Update statistics
            if info.should_process:
                self._processed_count += 1
            else:
                self._filtered_count += 1

            LOG.debug(f"Packet filter result: {info.should_process} (reason: {info.filter_reason})")
            return info

        except Exception as e:
            LOG.error(f"Error filtering packet: {e}")
            # Default to not processing on error
            info.should_process = False
            info.filter_reason = f"filtering_error: {str(e)}"
            self._filtered_count += 1
            return info

    def filter_packet_batch(self, packets: List[bytes]) -> List[PacketInfo]:
        """
        Filter a batch of packets efficiently.

        Args:
            packets: List of raw packet data bytes

        Returns:
            List of PacketInfo objects with filtering decisions
        """
        results = []

        for packet_data in packets:
            info = self.filter_packet(packet_data)
            results.append(info)

        LOG.info(
            f"Filtered batch of {len(packets)} packets: {sum(1 for r in results if r.should_process)} processed"
        )
        return results

    def should_process_packet(self, packet_data: bytes) -> bool:
        """
        Simple boolean check if packet should be processed.

        Args:
            packet_data: Raw packet data bytes

        Returns:
            True if packet should be processed
        """
        return self.domain_filter.should_process_packet(packet_data)

    def _extract_packet_info(
        self, packet_data: bytes, info: PacketInfo, additional_info: Optional[Dict[str, Any]]
    ) -> None:
        """
        Extract basic packet information (protocol, ports, etc.).

        Args:
            packet_data: Raw packet data
            info: PacketInfo object to populate
            additional_info: Additional packet metadata
        """
        try:
            # Use additional info if provided
            if additional_info:
                info.src_ip = additional_info.get("src_ip")
                info.dst_ip = additional_info.get("dst_ip")
                info.src_port = additional_info.get("src_port")
                info.dst_port = additional_info.get("dst_port")
                info.protocol = additional_info.get("protocol", "unknown")

            # Try to extract protocol info from packet if not provided
            if info.protocol == "unknown" and len(packet_data) >= 20:
                # Basic heuristics for protocol detection
                if self._is_likely_tcp_packet(packet_data):
                    info.protocol = "tcp"
                    self._extract_tcp_info(packet_data, info)
                elif self._is_likely_udp_packet(packet_data):
                    info.protocol = "udp"
                    self._extract_udp_info(packet_data, info)

            # Detect application protocols
            if info.protocol == "tcp":
                info.is_tls = self._is_tls_packet(packet_data)
                info.is_http = self._is_http_packet(packet_data) if not info.is_tls else False

        except Exception as e:
            LOG.debug(f"Error extracting packet info: {e}")

    def _extract_domain_info(self, packet_data: bytes, info: PacketInfo) -> None:
        """
        Extract domain information from packet.

        Args:
            packet_data: Raw packet data
            info: PacketInfo object to populate
        """
        try:
            # Extract domain using the domain extractor
            result = self.domain_extractor.extract_from_payload(packet_data)

            if result.domain:
                info.extracted_domain = result.domain
                info.domain_source = result.source
                LOG.debug(f"Extracted domain: {result.domain} (source: {result.source})")

        except Exception as e:
            LOG.debug(f"Error extracting domain info: {e}")

    def _apply_domain_filter(self, info: PacketInfo) -> None:
        """
        Apply domain filtering logic to determine if packet should be processed.

        Args:
            info: PacketInfo object to update with filtering decision
        """
        try:
            # If domain filter is not in discovery mode, process all packets
            if not self.domain_filter.is_discovery_mode():
                info.should_process = True
                info.filter_reason = "not_in_discovery_mode"
                return

            # Get current target domain
            target_domain = self.domain_filter.get_current_target()
            if not target_domain:
                info.should_process = True
                info.filter_reason = "no_target_domain"
                return

            # If no domain was extracted, filter out in discovery mode
            if not info.extracted_domain:
                info.should_process = False
                info.filter_reason = "no_domain_extracted"
                return

            # Check if extracted domain matches target
            if self._matches_target_domain(info.extracted_domain, target_domain):
                info.should_process = True
                info.filter_reason = "target_domain_match"
            else:
                info.should_process = False
                info.filter_reason = f"non_target_domain: {info.extracted_domain}"

        except Exception as e:
            LOG.error(f"Error applying domain filter: {e}")
            info.should_process = False
            info.filter_reason = f"filter_error: {str(e)}"

    def _matches_target_domain(self, extracted_domain: str, target_domain: str) -> bool:
        """
        Check if extracted domain matches target domain.

        Args:
            extracted_domain: Domain extracted from packet
            target_domain: Target domain for filtering

        Returns:
            True if domains match
        """
        if not extracted_domain or not target_domain:
            return False

        # Normalize domains
        extracted = extracted_domain.strip().lower().rstrip(".")
        target = target_domain.strip().lower().rstrip(".")

        # Exact match
        if extracted == target:
            return True

        # Subdomain match
        if extracted.endswith(f".{target}"):
            return True

        return False

    def _is_likely_tcp_packet(self, packet_data: bytes) -> bool:
        """Check if packet is likely TCP."""
        # This is a simplified heuristic - in real implementation,
        # you'd parse IP headers properly
        return len(packet_data) >= 20

    def _is_likely_udp_packet(self, packet_data: bytes) -> bool:
        """Check if packet is likely UDP."""
        # This is a simplified heuristic
        return len(packet_data) >= 8

    def _extract_tcp_info(self, packet_data: bytes, info: PacketInfo) -> None:
        """Extract TCP-specific information."""
        try:
            # Simplified TCP header parsing
            # In real implementation, you'd need to handle IP header first
            if len(packet_data) >= 4:
                # Assume TCP header starts at beginning for simplicity
                info.src_port = struct.unpack("!H", packet_data[0:2])[0]
                info.dst_port = struct.unpack("!H", packet_data[2:4])[0]
        except Exception as e:
            LOG.debug(f"Error extracting TCP info: {e}")

    def _extract_udp_info(self, packet_data: bytes, info: PacketInfo) -> None:
        """Extract UDP-specific information."""
        try:
            # Simplified UDP header parsing
            if len(packet_data) >= 4:
                info.src_port = struct.unpack("!H", packet_data[0:2])[0]
                info.dst_port = struct.unpack("!H", packet_data[2:4])[0]
        except Exception as e:
            LOG.debug(f"Error extracting UDP info: {e}")

    def _is_tls_packet(self, packet_data: bytes) -> bool:
        """Check if packet contains TLS data."""
        try:
            # Look for TLS record header
            if len(packet_data) >= 6:
                # TLS record starts with 0x16 (handshake) and version 0x03xx
                return packet_data[0] == 0x16 and packet_data[1] == 0x03
            return False
        except Exception:
            return False

    def _is_http_packet(self, packet_data: bytes) -> bool:
        """Check if packet contains HTTP data."""
        try:
            # Look for HTTP method at start of packet
            http_methods = [
                b"GET ",
                b"POST ",
                b"HEAD ",
                b"PUT ",
                b"DELETE ",
                b"OPTIONS ",
                b"CONNECT ",
                b"TRACE ",
                b"PATCH ",
            ]

            for method in http_methods:
                if packet_data.startswith(method):
                    return True

            return False
        except Exception:
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get packet filtering statistics.

        Returns:
            Dictionary with filtering statistics
        """
        return {
            "total_packets": self._packet_count,
            "processed_packets": self._processed_count,
            "filtered_packets": self._filtered_count,
            "filter_rate": (
                self._filtered_count / self._packet_count if self._packet_count > 0 else 0.0
            ),
            "domain_filter_stats": self.domain_filter.get_stats(),
        }

    def reset_statistics(self) -> None:
        """Reset packet filtering statistics."""
        self._packet_count = 0
        self._filtered_count = 0
        self._processed_count = 0
        LOG.info("Reset packet filtering statistics")

    def configure_target_domain(self, target_domain: str) -> None:
        """
        Configure target domain for filtering.

        Args:
            target_domain: Domain to filter for
        """
        self.domain_filter.configure_filter(target_domain, FilterMode.DISCOVERY)
        LOG.info(f"Configured packet filtering for target domain: {target_domain}")

    def disable_filtering(self) -> None:
        """Disable packet filtering."""
        self.domain_filter.disable_filtering()
        LOG.info("Disabled packet filtering")

    def enable_filtering(self) -> None:
        """Enable packet filtering."""
        self.domain_filter.enable_filtering()
        LOG.info("Enabled packet filtering")


class PacketFilterIntegration:
    """
    Integration layer for packet filtering with existing systems.

    Provides integration points with existing packet processing pipelines,
    PCAP capture systems, and strategy testing frameworks.
    """

    def __init__(self, domain_filter: Optional[DomainFilter] = None):
        """
        Initialize packet filter integration.

        Args:
            domain_filter: DomainFilter instance to use
        """
        self.filter_methods = PacketFilterMethods(domain_filter)
        self._integration_hooks: Dict[str, List[callable]] = {}

        LOG.info("PacketFilterIntegration initialized")

    def register_hook(self, event: str, callback: callable) -> None:
        """
        Register a callback hook for filtering events.

        Args:
            event: Event name ("packet_filtered", "packet_processed", etc.)
            callback: Callback function to register
        """
        if event not in self._integration_hooks:
            self._integration_hooks[event] = []

        self._integration_hooks[event].append(callback)
        LOG.info(f"Registered hook for event: {event}")

    def _trigger_hooks(self, event: str, *args, **kwargs) -> None:
        """Trigger registered hooks for an event."""
        if event in self._integration_hooks:
            for callback in self._integration_hooks[event]:
                try:
                    callback(*args, **kwargs)
                except Exception as e:
                    LOG.error(f"Error in hook callback for {event}: {e}")

    def filter_pcap_packets(self, packets: List[bytes]) -> Tuple[List[bytes], List[bytes]]:
        """
        Filter PCAP packets for target domain isolation.

        Args:
            packets: List of raw packet data

        Returns:
            Tuple of (processed_packets, filtered_packets)

        Requirements: 3.4 (PCAP traffic filtering)
        """
        processed_packets = []
        filtered_packets = []

        for packet_data in packets:
            info = self.filter_methods.filter_packet(packet_data)

            if info.should_process:
                processed_packets.append(packet_data)
                self._trigger_hooks("packet_processed", packet_data, info)
            else:
                filtered_packets.append(packet_data)
                self._trigger_hooks("packet_filtered", packet_data, info)

        LOG.info(
            f"PCAP filtering: {len(processed_packets)} processed, {len(filtered_packets)} filtered"
        )
        return processed_packets, filtered_packets

    def create_filtered_pcap_writer(self, target_domain: str):
        """
        Create a PCAP writer that only writes target domain packets.

        Args:
            target_domain: Domain to filter for

        Returns:
            Filtered PCAP writer function
        """
        # Configure filtering for target domain
        self.filter_methods.configure_target_domain(target_domain)

        def write_filtered_packet(packet_data: bytes, writer_func: callable) -> bool:
            """
            Write packet only if it matches target domain.

            Args:
                packet_data: Raw packet data
                writer_func: Original PCAP writer function

            Returns:
                True if packet was written
            """
            if self.filter_methods.should_process_packet(packet_data):
                writer_func(packet_data)
                return True
            return False

        return write_filtered_packet

    def integrate_with_strategy_testing(self, strategy_test_func: callable):
        """
        Integrate domain filtering with strategy testing.

        Args:
            strategy_test_func: Original strategy testing function

        Returns:
            Wrapped strategy testing function with domain filtering
        """

        def filtered_strategy_test(*args, **kwargs):
            """Wrapped strategy test with domain filtering."""
            # Get target domain from test parameters
            target_domain = kwargs.get("target_domain") or kwargs.get("domain")

            if target_domain:
                # Configure filtering for this test
                self.filter_methods.configure_target_domain(target_domain)
                LOG.info(f"Configured domain filtering for strategy test: {target_domain}")

            try:
                # Run original test
                result = strategy_test_func(*args, **kwargs)

                # Filter results if domain filtering is active
                if hasattr(result, "packets") and target_domain:
                    processed_packets, _ = self.filter_pcap_packets(result.packets)
                    result.packets = processed_packets

                return result

            finally:
                # Clean up filtering after test
                if target_domain:
                    self.filter_methods.disable_filtering()

        return filtered_strategy_test
