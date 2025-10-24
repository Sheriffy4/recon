"""
PacketSequenceAnalyzer class for detailed sequence analysis.

This module implements comprehensive packet sequence analysis for DPI bypass
strategies, focusing on fake packet detection, split position analysis,
and timing patterns.
"""

import statistics
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from .packet_info import PacketInfo


@dataclass
class FakePacketAnalysis:
    """Analysis results for fake packet detection."""

    is_fake: bool
    confidence: float  # 0.0 to 1.0
    indicators: List[str] = field(default_factory=list)
    ttl_suspicious: bool = False
    checksum_invalid: bool = False
    timing_suspicious: bool = False
    payload_suspicious: bool = False

    def get_fake_score(self) -> float:
        """Calculate overall fake packet score."""
        score = 0.0
        if self.ttl_suspicious:
            score += 0.4
        if self.checksum_invalid:
            score += 0.3
        if self.timing_suspicious:
            score += 0.2
        if self.payload_suspicious:
            score += 0.1
        return min(score, 1.0)


@dataclass
class SplitPositionAnalysis:
    """Analysis results for split position detection."""

    detected_splits: List[int] = field(default_factory=list)
    split_method: str = "unknown"  # "fakeddisorder", "disorder", "multisplit"
    split_accuracy: float = 0.0
    expected_position: Optional[int] = None
    actual_positions: List[int] = field(default_factory=list)
    overlap_sizes: List[int] = field(default_factory=list)

    def is_split_correct(self) -> bool:
        """Check if split positions match expected values."""
        if self.expected_position is None:
            return True
        return self.expected_position in self.actual_positions


@dataclass
class OverlapAnalysis:
    """Analysis results for sequence overlap calculation."""

    overlaps_detected: List[Dict[str, Any]] = field(default_factory=list)
    total_overlap_bytes: int = 0
    overlap_accuracy: float = 0.0
    expected_overlap: Optional[int] = None

    def get_overlap_summary(self) -> Dict[str, Any]:
        """Get summary of overlap analysis."""
        return {
            "total_overlaps": len(self.overlaps_detected),
            "total_bytes": self.total_overlap_bytes,
            "accuracy": self.overlap_accuracy,
            "overlaps": self.overlaps_detected,
        }


@dataclass
class TimingAnalysis:
    """Analysis results for timing patterns."""

    inter_packet_delays: List[float] = field(default_factory=list)
    avg_delay: float = 0.0
    delay_variance: float = 0.0
    suspicious_delays: List[Dict[str, Any]] = field(default_factory=list)
    timing_pattern: str = "normal"  # "normal", "burst", "delayed", "irregular"

    def get_timing_summary(self) -> Dict[str, Any]:
        """Get summary of timing analysis."""
        return {
            "avg_delay": self.avg_delay,
            "variance": self.delay_variance,
            "pattern": self.timing_pattern,
            "suspicious_count": len(self.suspicious_delays),
            "total_packets": len(self.inter_packet_delays) + 1,
        }


@dataclass
class FakeDisorderAnalysis:
    """Comprehensive analysis results for fakeddisorder strategy."""

    fake_packet_detected: bool = False
    fake_packet_position: int = -1
    real_segments: List[PacketInfo] = field(default_factory=list)
    split_position: int = -1
    overlap_size: int = 0
    ttl_pattern: List[int] = field(default_factory=list)
    checksum_pattern: List[bool] = field(default_factory=list)
    timing_pattern: List[float] = field(default_factory=list)
    zapret_compliance: float = 0.0  # 0.0 to 1.0

    def is_compliant(self) -> bool:
        """Check if analysis shows zapret compliance."""
        return self.zapret_compliance >= 0.8


class PacketSequenceAnalyzer:
    """
    Advanced packet sequence analyzer for DPI bypass strategies.

    This class provides detailed analysis of packet sequences to identify
    fake packets, split positions, overlaps, and timing patterns used
    in DPI bypass techniques.
    """

    def __init__(self, debug_mode: bool = False):
        self.debug_mode = debug_mode
        self.fake_ttl_threshold = 10  # TTL values below this are suspicious
        self.timing_threshold = 0.1  # 100ms timing threshold
        self.split_size_threshold = 1000  # Packets larger than this might be split

    def analyze_fake_disorder_sequence(
        self, packets: List[PacketInfo]
    ) -> FakeDisorderAnalysis:
        """
        Analyze packet sequence for fakeddisorder strategy implementation.

        Args:
            packets: List of PacketInfo objects to analyze

        Returns:
            FakeDisorderAnalysis with comprehensive results
        """
        analysis = FakeDisorderAnalysis()

        if not packets:
            return analysis

        # Extract basic patterns
        analysis.ttl_pattern = [p.ttl for p in packets]
        analysis.checksum_pattern = [p.checksum_valid for p in packets]
        analysis.timing_pattern = self._calculate_inter_packet_delays(packets)

        # Detect fake packets
        fake_packets = []
        for i, packet in enumerate(packets):
            fake_analysis = self.detect_fake_packet(packet, packets, i)
            if fake_analysis.is_fake:
                fake_packets.append((i, packet, fake_analysis))

        if fake_packets:
            analysis.fake_packet_detected = True
            analysis.fake_packet_position = fake_packets[0][
                0
            ]  # First fake packet position

        # Detect split positions
        split_analysis = self.detect_split_positions(packets)
        if split_analysis.actual_positions:
            analysis.split_position = split_analysis.actual_positions[0]

        # Calculate overlap sizes
        overlap_analysis = self.calculate_overlap_sizes(packets)
        if overlap_analysis.overlaps_detected:
            analysis.overlap_size = overlap_analysis.total_overlap_bytes

        # Identify real segments (non-fake packets with payload)
        analysis.real_segments = [
            p
            for i, p in enumerate(packets)
            if not self.detect_fake_packet(p, packets, i).is_fake
            and p.payload_length > 0
        ]

        # Calculate zapret compliance score
        analysis.zapret_compliance = self._calculate_zapret_compliance(
            analysis, packets
        )

        return analysis

    def detect_fake_packet(
        self, packet: PacketInfo, context_packets: List[PacketInfo], position: int
    ) -> FakePacketAnalysis:
        """
        Detect if a packet is likely a fake packet used for DPI bypass.

        Args:
            packet: PacketInfo to analyze
            context_packets: Full packet sequence for context
            position: Position of packet in sequence

        Returns:
            FakePacketAnalysis with detection results
        """
        analysis = FakePacketAnalysis(is_fake=False, confidence=0.0)

        # TTL analysis
        if packet.ttl <= self.fake_ttl_threshold:
            analysis.ttl_suspicious = True
            analysis.indicators.append(f"Low TTL: {packet.ttl}")

        # Checksum analysis
        if not packet.checksum_valid or packet.checksum == 0:
            analysis.checksum_invalid = True
            analysis.indicators.append("Invalid checksum")

        # Payload analysis
        if packet.payload_length == 0 and "PSH" in packet.flags:
            analysis.payload_suspicious = True
            analysis.indicators.append("Empty PSH packet")

        # Timing analysis (if not first packet)
        if position > 0 and position < len(context_packets):
            prev_packet = context_packets[position - 1]
            time_diff = packet.timestamp - prev_packet.timestamp

            # Very short intervals might indicate fake packets
            if time_diff < 0.001:  # Less than 1ms
                analysis.timing_suspicious = True
                analysis.indicators.append(f"Suspicious timing: {time_diff:.6f}s")

        # Sequence number analysis
        if packet.sequence_num == 0 and position > 0:
            analysis.indicators.append("Zero sequence number")

        # Calculate confidence and final determination
        analysis.confidence = analysis.get_fake_score()
        analysis.is_fake = analysis.confidence >= 0.5

        if self.debug_mode and analysis.is_fake:
            print(f"Fake packet detected at position {position}: {analysis.indicators}")

        return analysis

    def detect_split_positions(
        self, packets: List[PacketInfo]
    ) -> SplitPositionAnalysis:
        """
        Detect split positions in packet sequence for disorder analysis.

        Args:
            packets: List of PacketInfo objects

        Returns:
            SplitPositionAnalysis with detected split information
        """
        analysis = SplitPositionAnalysis()

        # Find ClientHello packets as potential split targets
        client_hello_packets = [
            (i, p) for i, p in enumerate(packets) if p.is_client_hello
        ]

        for ch_index, ch_packet in client_hello_packets:
            # Look for subsequent packets that might be splits
            subsequent_packets = packets[
                ch_index + 1 : ch_index + 10
            ]  # Look ahead 10 packets

            # Detect potential splits based on payload size patterns
            small_segments = []
            for i, pkt in enumerate(subsequent_packets):
                if 0 < pkt.payload_length < 200:  # Small segments might be splits
                    small_segments.append((ch_index + 1 + i, pkt))

            if small_segments:
                # Calculate potential split positions
                for seg_index, seg_packet in small_segments:
                    # Estimate split position based on payload size
                    if ch_packet.payload_length > 0:
                        estimated_split = min(
                            seg_packet.payload_length, ch_packet.payload_length
                        )
                        analysis.actual_positions.append(estimated_split)
                        analysis.detected_splits.append(seg_index)

        # Determine split method
        if len(analysis.detected_splits) > 1:
            analysis.split_method = "multisplit"
        elif analysis.detected_splits:
            # Check if there are fake packets nearby
            fake_nearby = any(
                self.detect_fake_packet(packets[i], packets, i).is_fake
                for i in range(
                    max(0, analysis.detected_splits[0] - 2),
                    min(len(packets), analysis.detected_splits[0] + 3),
                )
            )
            analysis.split_method = "fakeddisorder" if fake_nearby else "disorder"

        # Set expected position for fakeddisorder (typically 3)
        if analysis.split_method == "fakeddisorder":
            analysis.expected_position = 3

        # Calculate split accuracy
        if analysis.expected_position and analysis.actual_positions:
            accuracy_scores = [
                1.0
                - abs(pos - analysis.expected_position)
                / max(analysis.expected_position, pos, 1)
                for pos in analysis.actual_positions
            ]
            analysis.split_accuracy = max(accuracy_scores) if accuracy_scores else 0.0

        return analysis

    def calculate_overlap_sizes(self, packets: List[PacketInfo]) -> OverlapAnalysis:
        """
        Calculate sequence overlap sizes for disorder analysis.

        Args:
            packets: List of PacketInfo objects

        Returns:
            OverlapAnalysis with overlap calculations
        """
        analysis = OverlapAnalysis()

        # Group packets by connection
        connections = {}
        for packet in packets:
            conn_key = packet.get_connection_key()
            if conn_key not in connections:
                connections[conn_key] = []
            connections[conn_key].append(packet)

        # Analyze overlaps within each connection
        for conn_key, conn_packets in connections.items():
            if len(conn_packets) < 2:
                continue

            # Sort by timestamp to analyze sequence
            conn_packets.sort(key=lambda p: p.timestamp)

            # Look for sequence number overlaps
            for i in range(len(conn_packets) - 1):
                current = conn_packets[i]
                next_pkt = conn_packets[i + 1]

                # Calculate expected next sequence number
                expected_seq = current.sequence_num + current.payload_length

                # Check for overlap (next packet starts before expected)
                if next_pkt.sequence_num < expected_seq:
                    overlap_size = expected_seq - next_pkt.sequence_num

                    overlap_info = {
                        "connection": conn_key,
                        "packet_index": i,
                        "overlap_bytes": overlap_size,
                        "current_seq": current.sequence_num,
                        "next_seq": next_pkt.sequence_num,
                        "expected_seq": expected_seq,
                    }

                    analysis.overlaps_detected.append(overlap_info)
                    analysis.total_overlap_bytes += overlap_size

        # Calculate overlap accuracy (simplified)
        if analysis.overlaps_detected:
            # For fakeddisorder, we typically expect small overlaps
            expected_overlap_range = (1, 10)  # 1-10 bytes typical
            accurate_overlaps = [
                o
                for o in analysis.overlaps_detected
                if expected_overlap_range[0]
                <= o["overlap_bytes"]
                <= expected_overlap_range[1]
            ]
            analysis.overlap_accuracy = len(accurate_overlaps) / len(
                analysis.overlaps_detected
            )

        return analysis

    def analyze_timing_patterns(self, packets: List[PacketInfo]) -> TimingAnalysis:
        """
        Analyze timing patterns between consecutive packets.

        Args:
            packets: List of PacketInfo objects

        Returns:
            TimingAnalysis with timing pattern analysis
        """
        analysis = TimingAnalysis()

        if len(packets) < 2:
            return analysis

        # Calculate inter-packet delays
        analysis.inter_packet_delays = self._calculate_inter_packet_delays(packets)

        if not analysis.inter_packet_delays:
            return analysis

        # Calculate statistics
        analysis.avg_delay = statistics.mean(analysis.inter_packet_delays)
        analysis.delay_variance = (
            statistics.variance(analysis.inter_packet_delays)
            if len(analysis.inter_packet_delays) > 1
            else 0.0
        )

        # Identify suspicious delays
        for i, delay in enumerate(analysis.inter_packet_delays):
            if delay > self.timing_threshold:
                analysis.suspicious_delays.append(
                    {
                        "position": i + 1,
                        "delay": delay,
                        "reason": "Excessive delay" if delay > 1.0 else "Notable delay",
                    }
                )
            elif delay < 0.0001:  # Less than 0.1ms
                analysis.suspicious_delays.append(
                    {"position": i + 1, "delay": delay, "reason": "Suspiciously fast"}
                )

        # Determine timing pattern
        if analysis.delay_variance > 0.1:
            analysis.timing_pattern = "irregular"
        elif analysis.avg_delay > 0.5:
            analysis.timing_pattern = "delayed"
        elif analysis.avg_delay < 0.01:
            analysis.timing_pattern = "burst"
        else:
            analysis.timing_pattern = "normal"

        return analysis

    def _calculate_inter_packet_delays(self, packets: List[PacketInfo]) -> List[float]:
        """Calculate delays between consecutive packets."""
        delays = []
        for i in range(1, len(packets)):
            delay = packets[i].timestamp - packets[i - 1].timestamp
            delays.append(delay)
        return delays

    def _calculate_zapret_compliance(
        self, analysis: FakeDisorderAnalysis, packets: List[PacketInfo]
    ) -> float:
        """
        Calculate how well the packet sequence complies with zapret patterns.

        Args:
            analysis: Current FakeDisorderAnalysis
            packets: Original packet list

        Returns:
            Compliance score from 0.0 to 1.0
        """
        score = 0.0
        total_checks = 0

        # Check 1: Fake packet detection
        total_checks += 1
        if analysis.fake_packet_detected:
            score += 0.3

        # Check 2: TTL pattern compliance
        total_checks += 1
        low_ttl_count = sum(1 for ttl in analysis.ttl_pattern if ttl <= 3)
        if low_ttl_count > 0:
            score += 0.3

        # Check 3: Split position accuracy
        total_checks += 1
        if analysis.split_position == 3:  # Expected for fakeddisorder
            score += 0.2
        elif analysis.split_position > 0:
            score += 0.1

        # Check 4: Presence of real segments
        total_checks += 1
        if len(analysis.real_segments) > 0:
            score += 0.1

        # Check 5: Timing pattern reasonableness
        total_checks += 1
        if len(analysis.timing_pattern) > 0:
            avg_timing = sum(analysis.timing_pattern) / len(analysis.timing_pattern)
            if 0.001 <= avg_timing <= 0.1:  # Reasonable timing
                score += 0.1

        return score

    def compare_sequences(
        self, recon_packets: List[PacketInfo], zapret_packets: List[PacketInfo]
    ) -> Dict[str, Any]:
        """
        Compare two packet sequences and identify differences.

        Args:
            recon_packets: Recon packet sequence
            zapret_packets: Zapret packet sequence

        Returns:
            Dictionary with comparison results
        """
        comparison = {
            "recon_analysis": self.analyze_fake_disorder_sequence(recon_packets),
            "zapret_analysis": self.analyze_fake_disorder_sequence(zapret_packets),
            "differences": [],
            "recommendations": [],
        }

        recon_analysis = comparison["recon_analysis"]
        zapret_analysis = comparison["zapret_analysis"]

        # Compare fake packet detection
        if recon_analysis.fake_packet_detected != zapret_analysis.fake_packet_detected:
            comparison["differences"].append(
                {
                    "type": "fake_packet_detection",
                    "recon": recon_analysis.fake_packet_detected,
                    "zapret": zapret_analysis.fake_packet_detected,
                    "severity": "critical",
                }
            )

        # Compare TTL patterns
        if recon_analysis.ttl_pattern != zapret_analysis.ttl_pattern:
            comparison["differences"].append(
                {
                    "type": "ttl_pattern",
                    "recon": recon_analysis.ttl_pattern,
                    "zapret": zapret_analysis.ttl_pattern,
                    "severity": "high",
                }
            )

        # Compare split positions
        if recon_analysis.split_position != zapret_analysis.split_position:
            comparison["differences"].append(
                {
                    "type": "split_position",
                    "recon": recon_analysis.split_position,
                    "zapret": zapret_analysis.split_position,
                    "severity": "high",
                }
            )

        # Compare overlap sizes
        if recon_analysis.overlap_size != zapret_analysis.overlap_size:
            comparison["differences"].append(
                {
                    "type": "overlap_size",
                    "recon": recon_analysis.overlap_size,
                    "zapret": zapret_analysis.overlap_size,
                    "severity": "medium",
                }
            )

        # Generate recommendations
        if recon_analysis.zapret_compliance < 0.8:
            comparison["recommendations"].append(
                "Improve recon compliance with zapret patterns"
            )

        if any(d["severity"] == "critical" for d in comparison["differences"]):
            comparison["recommendations"].append(
                "Address critical differences in fake packet generation"
            )

        if any(d["type"] == "ttl_pattern" for d in comparison["differences"]):
            comparison["recommendations"].append(
                "Fix TTL parameter handling - ensure TTL=3 for fake packets"
            )

        if any(d["type"] == "split_position" for d in comparison["differences"]):
            comparison["recommendations"].append(
                "Correct split position calculation - verify split_pos=3 implementation"
            )

        return comparison

    def get_analysis_summary(self, packets: List[PacketInfo]) -> Dict[str, Any]:
        """
        Get comprehensive analysis summary for packet sequence.

        Args:
            packets: List of PacketInfo objects

        Returns:
            Dictionary with analysis summary
        """
        fake_disorder = self.analyze_fake_disorder_sequence(packets)
        timing = self.analyze_timing_patterns(packets)
        splits = self.detect_split_positions(packets)
        overlaps = self.calculate_overlap_sizes(packets)

        return {
            "packet_count": len(packets),
            "fake_disorder": {
                "fake_detected": fake_disorder.fake_packet_detected,
                "split_position": fake_disorder.split_position,
                "overlap_size": fake_disorder.overlap_size,
                "compliance": fake_disorder.zapret_compliance,
                "real_segments": len(fake_disorder.real_segments),
            },
            "timing": timing.get_timing_summary(),
            "splits": {
                "method": splits.split_method,
                "positions": splits.actual_positions,
                "accuracy": splits.split_accuracy,
            },
            "overlaps": overlaps.get_overlap_summary(),
            "quality_score": (
                fake_disorder.zapret_compliance
                + splits.split_accuracy
                + overlaps.overlap_accuracy
            )
            / 3,
        }
