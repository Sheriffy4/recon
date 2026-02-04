"""
Packet analysis utilities for comparing packet captures.

This module provides utilities for analyzing and comparing packet sequences
from discovery and service modes.
"""

from typing import List, Dict, Any


class PacketAnalyzer:
    """Analyzes packet sequences and timing for comparison."""

    @staticmethod
    def create_comparison(
        discovery_capture: Any,
        service_capture: Any,
        timestamp: str,
        discovery_packets: List[Any],
        service_packets: List[Any],
        differences: List[Any],
        timing_diffs: Dict[str, float],
        packets_match: bool,
    ) -> Any:
        """
        Create PacketComparison object from analysis results.

        Args:
            discovery_capture: Discovery mode capture
            service_capture: Service mode capture
            timestamp: Comparison timestamp
            discovery_packets: Loaded discovery packets
            service_packets: Loaded service packets
            differences: Found packet differences
            timing_diffs: Timing analysis results
            packets_match: Whether packets match

        Returns:
            PacketComparison object
        """
        # Import here to avoid circular dependency
        from core.strategy_comparator import PacketComparison

        return PacketComparison(
            domain=discovery_capture.domain,
            timestamp=timestamp,
            discovery_pcap=discovery_capture.pcap_file,
            service_pcap=service_capture.pcap_file,
            discovery_packet_count=len(discovery_packets),
            service_packet_count=len(service_packets),
            differences=differences,
            packets_match=packets_match,
            timing_differences=timing_diffs,
        )

    @staticmethod
    def analyze_timing(
        discovery_packets: List[Any], service_packets: List[Any]
    ) -> Dict[str, float]:
        """
        Analyze timing differences between packet sequences.

        Args:
            discovery_packets: Packets from discovery mode
            service_packets: Packets from service mode

        Returns:
            Dictionary with timing metrics (delays in milliseconds)
        """
        timing = {}

        if not discovery_packets or not service_packets:
            return timing

        # Calculate inter-packet delays
        disc_delays = []
        for i in range(1, len(discovery_packets)):
            delay = float(discovery_packets[i].time - discovery_packets[i - 1].time)
            disc_delays.append(delay)

        svc_delays = []
        for i in range(1, len(service_packets)):
            delay = float(service_packets[i].time - service_packets[i - 1].time)
            svc_delays.append(delay)

        if disc_delays and svc_delays:
            timing["avg_discovery_delay_ms"] = sum(disc_delays) / len(disc_delays) * 1000
            timing["avg_service_delay_ms"] = sum(svc_delays) / len(svc_delays) * 1000
            timing["max_discovery_delay_ms"] = max(disc_delays) * 1000
            timing["max_service_delay_ms"] = max(svc_delays) * 1000

        return timing

    @staticmethod
    def analyze_packet_differences_for_root_cause(comparison: Any, analysis: Any) -> None:
        """
        Analyze packet differences to identify root causes.

        Args:
            comparison: PacketComparison object
            analysis: RootCauseAnalysis object to populate

        Note:
            This method modifies the analysis object in-place.
        """
        # Group differences by field
        ttl_diffs = [d for d in comparison.differences if d.field == "ttl"]
        flag_diffs = [d for d in comparison.differences if d.field == "flags"]
        payload_diffs = [d for d in comparison.differences if d.field == "payload_len"]

        if ttl_diffs:
            analysis.root_causes.append(f"TTL values differ in {len(ttl_diffs)} packets")
            analysis.code_locations.append(
                "recon/core/bypass/engine/base_engine.py: calculate_autottl() or _build_packet()"
            )
            analysis.fix_recommendations.append(
                "Verify TTL calculation and application in packet building. "
                "Check if autottl is being calculated correctly at runtime."
            )

        if flag_diffs:
            analysis.root_causes.append(f"TCP flags differ in {len(flag_diffs)} packets")
            analysis.code_locations.append(
                "recon/core/bypass/packet/builder.py: build_tcp_packet()"
            )
            analysis.fix_recommendations.append(
                "Check TCP flag setting in packet builder. "
                "Verify fooling methods are being applied correctly."
            )

        if payload_diffs:
            analysis.root_causes.append(f"Payload lengths differ in {len(payload_diffs)} packets")
            analysis.code_locations.append("recon/core/bypass/attacks/: attack implementation")
            analysis.fix_recommendations.append(
                "Verify split position and overlap size are being applied correctly. "
                "Check packet segmentation logic."
            )

        # Check packet count mismatch
        if comparison.discovery_packet_count != comparison.service_packet_count:
            analysis.root_causes.append(
                f"Packet count mismatch: discovery sent {comparison.discovery_packet_count} "
                f"packets but service sent {comparison.service_packet_count}"
            )
            analysis.code_locations.append("recon/core/bypass/attacks/: attack implementation")
            analysis.fix_recommendations.append(
                "Check if repeats parameter is being applied. "
                "Verify attack sequence is complete."
            )
