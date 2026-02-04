"""
DPI Blocking Detection

Detects DPI (Deep Packet Inspection) blocking patterns by analyzing
connection behavior and packet timing.

This module identifies characteristic DPI blocking signatures:
- RST packets sent shortly after ClientHello
- Connection resets during TLS handshake
- Timing-based blocking patterns
"""

import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from pathlib import Path

# Add parent directory to path for imports
import sys

_parent = Path(__file__).parent.parent
if str(_parent) not in sys.path:
    sys.path.insert(0, str(_parent))

from packet.pcap_analyzer import PCAPAnalyzer, PacketInfo

LOG = logging.getLogger(__name__)


@dataclass
class DPIBlockingPattern:
    """
    Represents a detected DPI blocking pattern.

    Attributes:
        pattern_type: Type of blocking pattern detected
        confidence: Confidence level (0.0 to 1.0)
        evidence: Description of evidence supporting detection
        timestamp: When the pattern was detected
        details: Additional pattern-specific details
    """

    pattern_type: str  # "rst_after_clienthello", "handshake_reset", "timeout_pattern"
    confidence: float  # 0.0 to 1.0
    evidence: str
    timestamp: float
    details: Dict[str, Any]


class DPIBlockingDetector:
    """
    Detects DPI blocking patterns in network traffic.

    This detector analyzes PCAP files and connection events to identify
    characteristic DPI blocking signatures:

    1. RST after ClientHello: RST packet within 100ms after ClientHello
    2. Handshake Reset: Connection reset during TLS handshake
    3. Timing Patterns: Suspicious timing that indicates active blocking

    The detector uses both PCAP analysis and real-time connection monitoring
    to identify blocking with high confidence.
    """

    # Detection thresholds
    RST_AFTER_CLIENTHELLO_WINDOW_MS = 100.0  # milliseconds
    HANDSHAKE_TIMEOUT_THRESHOLD_MS = 5000.0  # milliseconds

    def __init__(self, pcap_analyzer: Optional[PCAPAnalyzer] = None):
        """
        Initialize DPIBlockingDetector.

        Args:
            pcap_analyzer: Optional PCAPAnalyzer instance for PCAP analysis
        """
        self.pcap_analyzer = pcap_analyzer or PCAPAnalyzer()
        self.detected_patterns: List[DPIBlockingPattern] = []

    async def is_dpi_blocked(
        self,
        domain: str,
        pcap_file: Optional[str] = None,
        connection_events: Optional[List[Dict[str, Any]]] = None,
    ) -> bool:
        """
        Determine if a domain is being blocked by DPI.

        Analyzes available evidence (PCAP file and/or connection events)
        to detect DPI blocking patterns. Returns True if high-confidence
        blocking is detected.

        Args:
            domain: Domain name being checked
            pcap_file: Optional path to PCAP file for analysis
            connection_events: Optional list of connection event dicts

        Returns:
            True if DPI blocking is detected, False otherwise
        """
        self.detected_patterns.clear()

        # Analyze PCAP file if provided
        if pcap_file and Path(pcap_file).exists():
            await self._analyze_pcap_for_dpi(pcap_file, domain)

        # Analyze connection events if provided
        if connection_events:
            await self._analyze_connection_events(connection_events, domain)

        # Check if any high-confidence patterns were detected
        high_confidence_patterns = [p for p in self.detected_patterns if p.confidence >= 0.7]

        if high_confidence_patterns:
            LOG.info(
                f"DPI blocking detected for {domain}: "
                f"{len(high_confidence_patterns)} high-confidence pattern(s)"
            )
            for pattern in high_confidence_patterns:
                LOG.debug(
                    f"  - {pattern.pattern_type}: {pattern.evidence} "
                    f"(confidence: {pattern.confidence:.2f})"
                )
            return True

        return False

    async def _analyze_pcap_for_dpi(self, pcap_file: str, domain: str) -> None:
        """
        Analyze PCAP file for DPI blocking patterns.

        Looks for:
        - RST packets within 100ms after ClientHello
        - Connection resets during TLS handshake
        - Suspicious timing patterns

        Args:
            pcap_file: Path to PCAP file
            domain: Domain being analyzed
        """
        try:
            # Parse PCAP file
            packets = await self.pcap_analyzer.parse_pcap_simple(pcap_file)

            if not packets:
                LOG.debug(f"No packets found in {pcap_file}")
                return

            # Group packets by connection
            connections = self._group_packets_by_connection(packets)

            # Analyze each connection for DPI patterns
            for conn_key, conn_packets in connections.items():
                await self._analyze_connection_for_dpi(conn_key, conn_packets, domain)

        except Exception as e:
            LOG.warning(f"Error analyzing PCAP for DPI patterns: {e}")

    def _group_packets_by_connection(
        self, packets: List[PacketInfo]
    ) -> Dict[str, List[PacketInfo]]:
        """
        Group packets by connection (bidirectional flow).

        Groups packets into bidirectional flows by normalizing the connection
        key so that packets in both directions are grouped together.

        Args:
            packets: List of packet information

        Returns:
            Dictionary mapping connection key to list of packets
        """
        connections: Dict[str, List[PacketInfo]] = {}

        for packet in packets:
            # Create normalized connection key (bidirectional)
            # Sort IPs and ports to ensure both directions map to same key
            endpoints = sorted([(packet.src_ip, packet.src_port), (packet.dst_ip, packet.dst_port)])

            conn_key = (
                f"{endpoints[0][0]}:{endpoints[0][1]}<->" f"{endpoints[1][0]}:{endpoints[1][1]}"
            )

            if conn_key not in connections:
                connections[conn_key] = []

            connections[conn_key].append(packet)

        return connections

    async def _analyze_connection_for_dpi(
        self, conn_key: str, packets: List[PacketInfo], domain: str
    ) -> None:
        """
        Analyze a single connection for DPI blocking patterns.

        Args:
            conn_key: Connection identifier
            packets: List of packets in this connection
            domain: Domain being analyzed
        """
        # Sort packets by timestamp
        packets = sorted(packets, key=lambda p: p.timestamp)

        # Find ClientHello packet
        clienthello_packet = None
        clienthello_index = -1

        for i, packet in enumerate(packets):
            if packet.is_tls and packet.tls_type == "ClientHello":
                clienthello_packet = packet
                clienthello_index = i
                break

        if clienthello_packet is None:
            # No ClientHello found, can't detect RST-after-ClientHello pattern
            return

        # Check for RST packet after ClientHello
        for i in range(clienthello_index + 1, len(packets)):
            packet = packets[i]

            # Calculate time delta in milliseconds
            time_delta_ms = (packet.timestamp - clienthello_packet.timestamp) * 1000

            # Check if RST flag is set
            if "RST" in packet.flags:
                if time_delta_ms <= self.RST_AFTER_CLIENTHELLO_WINDOW_MS:
                    # RST within 100ms of ClientHello - strong DPI indicator
                    pattern = DPIBlockingPattern(
                        pattern_type="rst_after_clienthello",
                        confidence=0.95,
                        evidence=(
                            f"RST packet received {time_delta_ms:.1f}ms " f"after ClientHello"
                        ),
                        timestamp=packet.timestamp,
                        details={
                            "domain": domain,
                            "connection": conn_key,
                            "clienthello_time": clienthello_packet.timestamp,
                            "rst_time": packet.timestamp,
                            "time_delta_ms": time_delta_ms,
                        },
                    )
                    self.detected_patterns.append(pattern)
                    LOG.debug(f"Detected DPI pattern: {pattern.evidence}")
                    return
                else:
                    # RST after 100ms - less likely to be DPI
                    # Could be legitimate connection termination
                    break

            # Stop checking after 100ms window
            if time_delta_ms > self.RST_AFTER_CLIENTHELLO_WINDOW_MS:
                break

        # Check for handshake timeout pattern
        await self._check_handshake_timeout(conn_key, packets, clienthello_packet, domain)

    async def _check_handshake_timeout(
        self, conn_key: str, packets: List[PacketInfo], clienthello_packet: PacketInfo, domain: str
    ) -> None:
        """
        Check for TLS handshake timeout pattern.

        If ClientHello is sent but no ServerHello is received within
        a reasonable time, this may indicate blocking.

        Args:
            conn_key: Connection identifier
            packets: List of packets in connection
            clienthello_packet: The ClientHello packet
            domain: Domain being analyzed
        """
        # Look for ServerHello after ClientHello
        serverhello_found = False

        for packet in packets:
            if (
                packet.timestamp > clienthello_packet.timestamp
                and packet.is_tls
                and packet.tls_type == "ServerHello"
            ):
                serverhello_found = True
                break

        if not serverhello_found:
            # No ServerHello received
            # Check if connection ended with RST or timeout
            last_packet = packets[-1]
            time_delta_ms = (last_packet.timestamp - clienthello_packet.timestamp) * 1000

            if "RST" in last_packet.flags:
                # Connection reset without ServerHello
                pattern = DPIBlockingPattern(
                    pattern_type="handshake_reset",
                    confidence=0.85,
                    evidence=(
                        f"TLS handshake failed: RST without ServerHello "
                        f"({time_delta_ms:.1f}ms after ClientHello)"
                    ),
                    timestamp=last_packet.timestamp,
                    details={
                        "domain": domain,
                        "connection": conn_key,
                        "clienthello_time": clienthello_packet.timestamp,
                        "rst_time": last_packet.timestamp,
                        "time_delta_ms": time_delta_ms,
                    },
                )
                self.detected_patterns.append(pattern)
                LOG.debug(f"Detected DPI pattern: {pattern.evidence}")

    async def _analyze_connection_events(self, events: List[Dict[str, Any]], domain: str) -> None:
        """
        Analyze connection events for DPI patterns.

        Connection events are dictionaries with keys like:
        - timestamp: Event timestamp
        - event_type: "rst", "timeout", "success", etc.
        - details: Additional event information

        Args:
            events: List of connection event dictionaries
            domain: Domain being analyzed
        """
        # Sort events by timestamp
        events = sorted(events, key=lambda e: e.get("timestamp", 0))

        # Look for patterns in events
        for i, event in enumerate(events):
            event_type = event.get("event_type", "")

            if event_type == "rst_after_clienthello":
                # Direct RST-after-ClientHello event
                time_delta_ms = event.get("time_delta_ms", 0)

                if time_delta_ms <= self.RST_AFTER_CLIENTHELLO_WINDOW_MS:
                    pattern = DPIBlockingPattern(
                        pattern_type="rst_after_clienthello",
                        confidence=0.90,
                        evidence=(f"RST event {time_delta_ms:.1f}ms after ClientHello"),
                        timestamp=event.get("timestamp", 0),
                        details={
                            "domain": domain,
                            "event": event,
                        },
                    )
                    self.detected_patterns.append(pattern)

            elif event_type == "handshake_timeout":
                # Handshake timeout event
                pattern = DPIBlockingPattern(
                    pattern_type="handshake_timeout",
                    confidence=0.75,
                    evidence="TLS handshake timeout",
                    timestamp=event.get("timestamp", 0),
                    details={
                        "domain": domain,
                        "event": event,
                    },
                )
                self.detected_patterns.append(pattern)

    def get_detected_patterns(self) -> List[DPIBlockingPattern]:
        """
        Get list of detected DPI blocking patterns.

        Returns:
            List of DPIBlockingPattern objects
        """
        return self.detected_patterns.copy()

    def get_blocking_confidence(self) -> float:
        """
        Get overall confidence that DPI blocking is occurring.

        Returns:
            Confidence score from 0.0 to 1.0
        """
        if not self.detected_patterns:
            return 0.0

        # Return highest confidence pattern
        return max(p.confidence for p in self.detected_patterns)

    def get_blocking_summary(self) -> str:
        """
        Get human-readable summary of detected blocking.

        Returns:
            Summary string describing detected patterns
        """
        if not self.detected_patterns:
            return "No DPI blocking detected"

        pattern_counts = {}
        for pattern in self.detected_patterns:
            pattern_counts[pattern.pattern_type] = pattern_counts.get(pattern.pattern_type, 0) + 1

        summary_parts = []
        for pattern_type, count in pattern_counts.items():
            summary_parts.append(f"{count}x {pattern_type}")

        confidence = self.get_blocking_confidence()

        return (
            f"DPI blocking detected (confidence: {confidence:.0%}): " f"{', '.join(summary_parts)}"
        )
