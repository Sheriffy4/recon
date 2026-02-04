"""
Discovery Mode PCAP Integration

This module provides integration functions to seamlessly use discovery-mode PCAP filtering
in existing service and CLI code when auto strategy discovery is active.

Requirements: 3.4 from auto-strategy-discovery spec
"""

import logging
from typing import Optional, Union, Any
from pathlib import Path

try:
    from scapy.all import Packet

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = Any

from core.pcap.discovery_packet_capturer import DiscoveryPacketCapturer, create_discovery_capturer
from core.domain_filter import DomainFilter

LOG = logging.getLogger(__name__)


class PCAPCapturerFactory:
    """
    Factory class for creating appropriate PCAP capturers based on discovery mode.

    This factory automatically detects if auto strategy discovery is active and
    creates the appropriate capturer type with domain filtering when needed.
    """

    @staticmethod
    def create_capturer(
        filename: str,
        bpf: Optional[str] = None,
        iface: Optional[str] = None,
        max_packets: Optional[int] = None,
        max_seconds: Optional[int] = None,
        domain_filter: Optional[DomainFilter] = None,
        target_domain: Optional[str] = None,
    ) -> Union["PacketCapturer", DiscoveryPacketCapturer]:
        """
        Create an appropriate packet capturer based on discovery mode.

        Args:
            filename: Output PCAP file path
            bpf: BPF filter string (used for non-discovery mode)
            iface: Network interface to capture on
            max_packets: Maximum number of packets to capture
            max_seconds: Maximum capture duration in seconds
            domain_filter: DomainFilter instance (if None, checks for discovery mode)
            target_domain: Target domain for discovery mode

        Returns:
            DiscoveryPacketCapturer if in discovery mode, otherwise standard PacketCapturer

        Requirements: 3.4
        """
        # Check if we should use discovery mode
        use_discovery_mode = False
        discovered_target = None

        if domain_filter:
            # Use provided domain filter to check mode
            use_discovery_mode = domain_filter.is_discovery_mode()
            discovered_target = domain_filter.get_current_target()
        elif target_domain:
            # Explicit target domain provided
            use_discovery_mode = True
            discovered_target = target_domain
        else:
            # Try to detect discovery mode from global state
            try:
                # Check if there's an active discovery session
                discovered_target = PCAPCapturerFactory._detect_discovery_target()
                use_discovery_mode = discovered_target is not None
            except Exception as e:
                LOG.debug(f"Could not detect discovery mode: {e}")

        if use_discovery_mode and discovered_target:
            LOG.info(f"Creating discovery packet capturer for target: {discovered_target}")
            return DiscoveryPacketCapturer(
                filename=filename,
                target_domain=discovered_target,
                domain_filter=domain_filter,
                iface=iface,
                max_packets=max_packets,
                max_seconds=max_seconds,
            )
        else:
            LOG.info("Creating standard packet capturer")
            # Import here to avoid circular imports
            from cli import PacketCapturer

            return PacketCapturer(
                filename=filename,
                bpf=bpf,
                iface=iface,
                max_packets=max_packets,
                max_seconds=max_seconds,
            )

    @staticmethod
    def _detect_discovery_target() -> Optional[str]:
        """
        Attempt to detect if auto strategy discovery is active and get target domain.

        Returns:
            Target domain if discovery is active, None otherwise
        """
        # Try to import and check discovery controller state
        try:
            # This would be implemented when the discovery controller is created
            # For now, return None to use standard capturer
            return None
        except ImportError:
            return None


def create_integrated_capturer(
    filename: str,
    bpf: Optional[str] = None,
    iface: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_seconds: Optional[int] = None,
    target_domain: Optional[str] = None,
) -> Union["PacketCapturer", DiscoveryPacketCapturer]:
    """
    Convenience function to create an integrated packet capturer.

    This function automatically detects discovery mode and creates the appropriate
    capturer type. It's designed to be a drop-in replacement for PacketCapturer
    creation in existing code.

    Args:
        filename: Output PCAP file path
        bpf: BPF filter string (ignored in discovery mode)
        iface: Network interface to capture on
        max_packets: Maximum number of packets to capture
        max_seconds: Maximum capture duration in seconds
        target_domain: Target domain for discovery mode (optional)

    Returns:
        Appropriate capturer instance

    Requirements: 3.4
    """
    return PCAPCapturerFactory.create_capturer(
        filename=filename,
        bpf=bpf,
        iface=iface,
        max_packets=max_packets,
        max_seconds=max_seconds,
        target_domain=target_domain,
    )


def enhance_service_pcap_capture(
    service_instance: Any, target_domain: Optional[str] = None
) -> None:
    """
    Enhance an existing service instance with discovery-mode PCAP capture.

    This function modifies a service instance to use discovery-mode PCAP filtering
    when appropriate, while maintaining compatibility with existing code.

    Args:
        service_instance: Service instance to enhance (should have pcap_file attribute)
        target_domain: Target domain for discovery mode (optional)

    Requirements: 3.4
    """
    if not hasattr(service_instance, "pcap_file") or not service_instance.pcap_file:
        return

    if not SCAPY_AVAILABLE:
        LOG.warning("Scapy not available, cannot enhance PCAP capture")
        return

    try:
        # Check if service already has a capturer
        if hasattr(service_instance, "capturer") and service_instance.capturer:
            LOG.info("Service already has a capturer, skipping enhancement")
            return

        # Create discovery capturer if target domain is provided
        if target_domain:
            LOG.info(f"Enhancing service with discovery PCAP capture for: {target_domain}")
            service_instance.capturer = create_discovery_capturer(
                filename=service_instance.pcap_file,
                target_domain=target_domain,
                max_seconds=getattr(service_instance, "pcap_max_seconds", None),
                max_packets=getattr(service_instance, "pcap_max_packets", None),
            )

            # Add logging callback if service has logger
            if hasattr(service_instance, "logger"):

                def log_captured_packet(packet: Packet) -> None:
                    """Log captured packets for debugging"""
                    service_instance.logger.debug(
                        f"Captured target domain packet: {len(packet)} bytes"
                    )

                service_instance.capturer.add_packet_callback(log_captured_packet)

            LOG.info("Service enhanced with discovery PCAP capture")
        else:
            LOG.debug("No target domain provided, using standard PCAP capture")

    except Exception as e:
        LOG.error(f"Failed to enhance service PCAP capture: {e}")
        import traceback

        LOG.debug(traceback.format_exc())


def filter_existing_pcap_for_discovery(
    input_pcap: str, output_pcap: str, target_domain: str
) -> int:
    """
    Filter an existing PCAP file to include only target domain traffic.

    This function can be used to post-process PCAP files captured without
    domain filtering to extract only the relevant traffic for analysis.

    Args:
        input_pcap: Path to input PCAP file
        output_pcap: Path to output filtered PCAP file
        target_domain: Target domain to filter for

    Returns:
        Number of packets written to output file

    Requirements: 3.4
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy is required for PCAP filtering")

    LOG.info(f"Filtering PCAP for discovery: {input_pcap} -> {output_pcap}")
    LOG.info(f"Target domain: {target_domain}")

    # Create discovery filter
    from core.pcap.discovery_pcap_filter import DiscoveryPCAPFilter

    pcap_filter = DiscoveryPCAPFilter()
    pcap_filter.configure_for_discovery(target_domain)

    # Filter the PCAP file
    packet_count = pcap_filter.filter_pcap_file(input_pcap, output_pcap)

    # Log results
    pcap_filter.log_filtering_summary()
    LOG.info(f"Filtered PCAP created: {output_pcap} ({packet_count} packets)")

    return packet_count


def analyze_pcap_for_discovery(pcap_file: str, target_domain: Optional[str] = None) -> dict:
    """
    Analyze a PCAP file for discovery mode effectiveness.

    This function analyzes a PCAP file to determine how effective domain filtering
    would be and provides statistics about domain distribution.

    Args:
        pcap_file: Path to PCAP file to analyze
        target_domain: Target domain to analyze for (optional)

    Returns:
        Dictionary containing analysis results

    Requirements: 3.4
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy is required for PCAP analysis")

    LOG.info(f"Analyzing PCAP for discovery effectiveness: {pcap_file}")

    # Create discovery filter
    from core.pcap.discovery_pcap_filter import DiscoveryPCAPFilter

    pcap_filter = DiscoveryPCAPFilter()

    if target_domain:
        pcap_filter.configure_for_discovery(target_domain)

    # Analyze the PCAP file
    analysis = pcap_filter.analyze_pcap_file(pcap_file)

    LOG.info(f"PCAP analysis complete:")
    LOG.info(f"  Total packets: {analysis['total_packets']}")
    LOG.info(f"  TLS packets: {analysis['tls_packets']}")
    LOG.info(f"  Target packets: {analysis['target_packets']}")
    LOG.info(f"  Target rate: {analysis['target_rate']:.2%}")

    return analysis
