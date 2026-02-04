"""
Performance Metrics Collector for Strategy Optimization

This module provides functionality to collect detailed performance metrics
during strategy testing, including retransmissions, latency, and packet counts.

Requirements: 2.1, 2.2, 2.3, 2.4
"""

import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, List
from collections import defaultdict

from core.optimization.models import PerformanceMetrics
from core.pcap.analyzer import PCAPAnalyzer
from core.packet.raw_pcap_reader import RawPCAPReader
from core.packet.raw_packet_engine import RawPacket, ProtocolType, IPHeader, TCPHeader

LOG = logging.getLogger(__name__)


class PerformanceMetricsCollector:
    """
    Collects performance metrics during strategy testing.

    Uses PCAP analysis to count retransmissions and timing measurements
    for latency. Integrates with existing PCAPAnalyzer for packet analysis.

    Requirements: 2.1, 2.2, 2.3, 2.4
    """

    def __init__(self, pcap_analyzer: Optional[PCAPAnalyzer] = None):
        """
        Initialize the metrics collector.

        Args:
            pcap_analyzer: Optional PCAPAnalyzer instance. If not provided,
                          a new one will be created.
        """
        self.pcap_analyzer = pcap_analyzer or PCAPAnalyzer()
        self.pcap_reader = RawPCAPReader()
        self.logger = LOG

    async def collect_metrics(
        self,
        domain: str,
        strategy: Dict,
        pcap_file: str,
        start_time: float,
        end_time: float,
    ) -> PerformanceMetrics:
        """
        Collect metrics from a strategy test.

        Analyzes PCAP for retransmissions and packet counts.
        Calculates timing metrics from timestamps.

        Args:
            domain: Target domain being tested
            strategy: Strategy configuration that was tested
            pcap_file: Path to PCAP file captured during test
            start_time: Unix timestamp when test started
            end_time: Unix timestamp when test ended

        Returns:
            PerformanceMetrics with collected data

        Requirements: 2.1, 2.2, 2.3, 2.4
        """
        self.logger.info(f"📊 Collecting metrics for {domain} from {pcap_file}")

        # Check if PCAP file exists
        if not Path(pcap_file).exists():
            self.logger.error(f"❌ PCAP file not found: {pcap_file}")
            return PerformanceMetrics(
                retransmission_count=0,
                ttfb_ms=0.0,
                total_time_ms=(end_time - start_time) * 1000,
                packets_sent=0,
                packets_received=0,
                success=False,
                error_message=f"PCAP file not found: {pcap_file}",
            )

        try:
            # Read PCAP file
            packets = self.pcap_reader.read_pcap_file(pcap_file)

            if not packets:
                self.logger.warning(f"⚠️ No packets found in {pcap_file}")
                return PerformanceMetrics(
                    retransmission_count=0,
                    ttfb_ms=0.0,
                    total_time_ms=(end_time - start_time) * 1000,
                    packets_sent=0,
                    packets_received=0,
                    success=False,
                    error_message="No packets in PCAP file",
                )

            # Extract the target flow (ClientHello flow)
            flow_packets = self._extract_target_flow(packets, domain)

            if not flow_packets:
                self.logger.warning(f"⚠️ No target flow found for {domain}")
                return PerformanceMetrics(
                    retransmission_count=0,
                    ttfb_ms=0.0,
                    total_time_ms=(end_time - start_time) * 1000,
                    packets_sent=0,
                    packets_received=0,
                    success=False,
                    error_message="No target flow found in PCAP",
                )

            # Count retransmissions
            flow_key = self._get_flow_key(flow_packets[0])
            retransmission_count = self.count_retransmissions(pcap_file, flow_key)

            # Count packets sent and received
            packets_sent, packets_received = self._count_packets(flow_packets)

            # Calculate timing metrics
            ttfb_ms, total_time_ms = self._calculate_timing(flow_packets, start_time, end_time)

            # Determine success (received response packets)
            success = packets_received > 0

            metrics = PerformanceMetrics(
                retransmission_count=retransmission_count,
                ttfb_ms=ttfb_ms,
                total_time_ms=total_time_ms,
                packets_sent=packets_sent,
                packets_received=packets_received,
                success=success,
                error_message=None if success else "No response received",
            )

            self.logger.info(
                f"✅ Metrics collected: retrans={retransmission_count}, "
                f"ttfb={ttfb_ms:.2f}ms, total={total_time_ms:.2f}ms, "
                f"sent={packets_sent}, recv={packets_received}, success={success}"
            )

            return metrics

        except Exception as e:
            self.logger.error(f"❌ Error collecting metrics: {e}", exc_info=True)
            return PerformanceMetrics(
                retransmission_count=0,
                ttfb_ms=0.0,
                total_time_ms=(end_time - start_time) * 1000,
                packets_sent=0,
                packets_received=0,
                success=False,
                error_message=f"Error collecting metrics: {str(e)}",
            )

    def count_retransmissions(self, pcap_file: str, flow_key: Tuple) -> int:
        """
        Count TCP retransmissions in PCAP for specific flow.

        A retransmission is detected when:
        - Same sequence number appears multiple times
        - With the same or similar payload length
        - In the same direction (client -> server)

        Args:
            pcap_file: Path to PCAP file
            flow_key: Flow identifier (src_ip, src_port, dst_ip, dst_port)

        Returns:
            Number of retransmissions detected

        Requirements: 2.1
        """
        try:
            packets = self.pcap_reader.read_pcap_file(pcap_file)

            if not packets:
                return 0

            # Filter packets for this specific flow
            flow_packets = [
                p
                for p in packets
                if p.protocol == ProtocolType.TCP and self._matches_flow(p, flow_key)
            ]

            if not flow_packets:
                return 0

            # Count sequence numbers (only for packets with payload)
            # Key: (seq_num, payload_len), Value: count
            seq_counts: Dict[Tuple[int, int], int] = defaultdict(int)

            for pkt in flow_packets:
                if not pkt.payload:
                    continue

                try:
                    # Extract TCP header
                    ip_header = IPHeader.unpack(pkt.data[:20])
                    ip_header_size = ip_header.ihl * 4
                    tcp_data = pkt.data[ip_header_size:]

                    if len(tcp_data) < 20:
                        continue

                    tcp_header = TCPHeader.unpack(tcp_data)

                    # Skip fake packets (low TTL)
                    if ip_header.ttl <= 5:
                        continue

                    # Count this (seq, payload_len) combination
                    seq_num = tcp_header.seq_num
                    payload_len = len(pkt.payload)
                    seq_counts[(seq_num, payload_len)] += 1

                except Exception as e:
                    self.logger.debug(f"⚠️ Error parsing packet: {e}")
                    continue

            # Count retransmissions (any seq+len that appears more than once)
            retransmission_count = sum(count - 1 for count in seq_counts.values() if count > 1)

            if retransmission_count > 0:
                self.logger.debug(f"🔍 Found {retransmission_count} retransmissions in flow")

            return retransmission_count

        except Exception as e:
            self.logger.error(f"❌ Error counting retransmissions: {e}", exc_info=True)
            return 0

    def _extract_target_flow(self, packets: List[RawPacket], domain: str) -> List[RawPacket]:
        """
        Extract the target TCP flow containing ClientHello.

        Args:
            packets: All packets from PCAP
            domain: Target domain (for validation)

        Returns:
            List of packets in the target flow
        """
        from core.packet.raw_packet_engine import RawPacketEngine

        packet_engine = RawPacketEngine()

        # Group packets by flow
        flows: Dict[Tuple, List[RawPacket]] = defaultdict(list)

        for pkt in packets:
            if pkt.protocol != ProtocolType.TCP:
                continue

            # Create flow key (bidirectional)
            flow_key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
            reverse_key = (pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)

            # Use consistent key (lower IP first)
            if flow_key < reverse_key:
                flows[flow_key].append(pkt)
            else:
                flows[reverse_key].append(pkt)

        # Find flow with ClientHello
        for flow_key, flow_packets in flows.items():
            for pkt in flow_packets:
                if pkt.payload and packet_engine.is_client_hello(pkt.payload):
                    self.logger.debug(
                        f"🌊 Found target flow: {flow_key[0]}:{flow_key[1]} -> "
                        f"{flow_key[2]}:{flow_key[3]}"
                    )
                    return flow_packets

        return []

    def _get_flow_key(self, packet: RawPacket) -> Tuple:
        """
        Get flow key from packet (src_ip, src_port, dst_ip, dst_port).

        Args:
            packet: Packet to extract flow key from

        Returns:
            Flow key tuple
        """
        return (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)

    def _matches_flow(self, packet: RawPacket, flow_key: Tuple) -> bool:
        """
        Check if packet belongs to the specified flow.

        Args:
            packet: Packet to check
            flow_key: Flow identifier

        Returns:
            True if packet is in this flow (either direction)
        """
        pkt_key = self._get_flow_key(packet)
        reverse_key = (flow_key[2], flow_key[3], flow_key[0], flow_key[1])

        return pkt_key == flow_key or pkt_key == reverse_key

    def _count_packets(self, flow_packets: List[RawPacket]) -> Tuple[int, int]:
        """
        Count packets sent and received in the flow.

        Args:
            flow_packets: Packets in the target flow

        Returns:
            Tuple of (packets_sent, packets_received)

        Requirements: 2.4
        """
        if not flow_packets:
            return 0, 0

        # Determine client and server based on first packet with payload
        client_ip = None
        server_ip = None

        for pkt in flow_packets:
            if pkt.payload:
                # Assume first packet with payload is from client
                client_ip = pkt.src_ip
                server_ip = pkt.dst_ip
                break

        if not client_ip:
            # Fallback: use first packet
            client_ip = flow_packets[0].src_ip
            server_ip = flow_packets[0].dst_ip

        packets_sent = 0
        packets_received = 0

        for pkt in flow_packets:
            if pkt.src_ip == client_ip:
                packets_sent += 1
            elif pkt.src_ip == server_ip:
                packets_received += 1

        return packets_sent, packets_received

    def _calculate_timing(
        self, flow_packets: List[RawPacket], start_time: float, end_time: float
    ) -> Tuple[float, float]:
        """
        Calculate timing metrics from flow packets.

        Args:
            flow_packets: Packets in the target flow
            start_time: Test start time (Unix timestamp)
            end_time: Test end time (Unix timestamp)

        Returns:
            Tuple of (ttfb_ms, total_time_ms)

        Requirements: 2.2, 2.3
        """
        # Calculate total time from start/end timestamps
        total_time_ms = (end_time - start_time) * 1000

        # Try to calculate TTFB from packet timestamps
        ttfb_ms = 0.0

        try:
            # Find first outgoing packet (ClientHello)
            first_sent_time = None
            for pkt in flow_packets:
                if pkt.payload and hasattr(pkt, "timestamp") and pkt.timestamp:
                    first_sent_time = pkt.timestamp
                    break

            # Find first incoming packet (ServerHello or response)
            first_recv_time = None
            if first_sent_time:
                # Determine client IP from first packet
                client_ip = flow_packets[0].src_ip if flow_packets[0].payload else None

                for pkt in flow_packets:
                    if (
                        hasattr(pkt, "timestamp")
                        and pkt.timestamp
                        and pkt.timestamp > first_sent_time
                        and pkt.src_ip != client_ip
                    ):
                        first_recv_time = pkt.timestamp
                        break

            if first_sent_time and first_recv_time:
                ttfb_ms = (first_recv_time - first_sent_time) * 1000
                self.logger.debug(f"⏱️ TTFB calculated from packets: {ttfb_ms:.2f}ms")
            else:
                # Fallback: use total time as TTFB estimate
                ttfb_ms = total_time_ms
                self.logger.debug(f"⏱️ TTFB fallback to total time: {ttfb_ms:.2f}ms")

        except Exception as e:
            self.logger.debug(f"⚠️ Error calculating TTFB: {e}")
            ttfb_ms = total_time_ms

        return ttfb_ms, total_time_ms
