"""
Strategy analyzer for extracting and comparing DPI bypass strategies from PCAP files.
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from .packet_info import PacketInfo
from .strategy_config import StrategyConfig, StrategyDifference, StrategyComparison


@dataclass
class FakeDisorderPattern:
    """Pattern detected in fake+disorder strategy."""

    fake_packet_index: int
    fake_packet: PacketInfo
    real_segments: List[PacketInfo]
    split_position: int
    overlap_size: int
    ttl_pattern: List[int]
    timing_gaps: List[float]
    checksum_corruption: bool


class StrategyAnalyzer:
    """Analyzes and compares DPI bypass strategies from PCAP data."""

    def __init__(self):
        self.known_patterns = self._load_known_patterns()

    def _load_known_patterns(self) -> Dict[str, Any]:
        """Load known strategy patterns for recognition."""
        return {
            "fake_disorder": {
                "fake_ttl_range": (1, 5),
                "real_ttl_range": (60, 255),
                "typical_split_positions": [1, 2, 3, 4, 5],
                "common_overlaps": [0, 1, 2, 3, 4, 5],
            },
            "fooling_methods": {
                "badsum": {"checksum_corruption": True},
                "badseq": {"sequence_manipulation": True},
                "md5sig": {"tcp_option_manipulation": True},
            },
        }

    def parse_strategy_from_pcap(
        self, packets: List[PacketInfo], domain: str = ""
    ) -> StrategyConfig:
        """Extract strategy configuration from PCAP packet sequence."""
        config = StrategyConfig(source="pcap_analysis")

        if not packets:
            return config

        # Analyze packet sequence for strategy patterns
        fake_disorder_pattern = self._detect_fake_disorder_pattern(packets)
        if fake_disorder_pattern:
            config.dpi_desync = "fake,fakeddisorder"
            config.split_pos = fake_disorder_pattern.split_position
            config.split_seqovl = fake_disorder_pattern.overlap_size

            # Extract TTL from fake packet
            if fake_disorder_pattern.fake_packet:
                config.ttl = fake_disorder_pattern.fake_packet.ttl

            # Detect fooling methods
            config.fooling = self._detect_fooling_methods(fake_disorder_pattern)

        # Detect other strategy types
        split_pattern = self._detect_split_pattern(packets)
        if split_pattern and not fake_disorder_pattern:
            config.dpi_desync = "split"
            config.split_pos = split_pattern["position"]

        disorder_pattern = self._detect_disorder_pattern(packets)
        if disorder_pattern and not fake_disorder_pattern:
            config.dpi_desync = "disorder"

        # Set confidence based on pattern clarity
        config.confidence = self._calculate_confidence(packets, config)

        return config

    def _detect_fake_disorder_pattern(
        self, packets: List[PacketInfo]
    ) -> Optional[FakeDisorderPattern]:
        """Detect fake+disorder pattern in packet sequence."""
        if len(packets) < 3:
            return None

        # Look for ClientHello packets
        client_hello_packets = [p for p in packets if p.is_client_hello]
        if not client_hello_packets:
            return None

        # Find potential fake packets (low TTL, bad checksum)
        fake_candidates = []
        for i, packet in enumerate(packets):
            if self._is_likely_fake_packet(packet):
                fake_candidates.append((i, packet))

        if not fake_candidates:
            return None

        # Analyze each fake candidate
        for fake_idx, fake_packet in fake_candidates:
            pattern = self._analyze_fake_disorder_sequence(
                packets, fake_idx, fake_packet
            )
            if pattern:
                return pattern

        return None

    def _is_likely_fake_packet(self, packet: PacketInfo) -> bool:
        """Check if packet is likely a fake packet."""
        fake_indicators = [
            packet.ttl <= 5,  # Low TTL
            not packet.checksum_valid,  # Bad checksum
            packet.payload_length == 0 and "PSH" in packet.flags,  # Empty PSH
            packet.sequence_num == 0,  # Zero sequence
        ]

        return sum(fake_indicators) >= 1

    def _analyze_fake_disorder_sequence(
        self, packets: List[PacketInfo], fake_idx: int, fake_packet: PacketInfo
    ) -> Optional[FakeDisorderPattern]:
        """Analyze sequence around fake packet for disorder pattern."""
        # Look for real segments after fake packet
        real_segments = []
        for i in range(fake_idx + 1, min(fake_idx + 5, len(packets))):
            packet = packets[i]
            if (
                packet.ttl > 30  # Normal TTL
                and packet.payload_length > 0  # Has payload
                and packet.src_ip == fake_packet.src_ip  # Same connection
                and packet.dst_ip == fake_packet.dst_ip
            ):
                real_segments.append(packet)

        if len(real_segments) < 2:
            return None

        # Calculate split position and overlap
        split_pos, overlap = self._calculate_split_and_overlap(
            fake_packet, real_segments
        )

        if split_pos is None:
            return None

        # Extract timing patterns
        timing_gaps = []
        for i in range(1, len(real_segments)):
            gap = real_segments[i].timestamp - real_segments[i - 1].timestamp
            timing_gaps.append(gap)

        # Extract TTL pattern
        ttl_pattern = [fake_packet.ttl] + [seg.ttl for seg in real_segments]

        # Check checksum corruption
        checksum_corruption = not fake_packet.checksum_valid

        return FakeDisorderPattern(
            fake_packet_index=fake_idx,
            fake_packet=fake_packet,
            real_segments=real_segments,
            split_position=split_pos,
            overlap_size=overlap,
            ttl_pattern=ttl_pattern,
            timing_gaps=timing_gaps,
            checksum_corruption=checksum_corruption,
        )

    def _calculate_split_and_overlap(
        self, fake_packet: PacketInfo, real_segments: List[PacketInfo]
    ) -> Tuple[Optional[int], int]:
        """Calculate split position and overlap size from packet sequence."""
        if len(real_segments) < 2:
            return None, 0

        # Find ClientHello in real segments
        client_hello_segment = None
        for segment in real_segments:
            if segment.is_client_hello and segment.payload_length > 0:
                client_hello_segment = segment
                break

        if not client_hello_segment:
            return None, 0

        # Analyze payload split
        first_segment = real_segments[0]
        second_segment = real_segments[1] if len(real_segments) > 1 else None

        if not second_segment:
            return None, 0

        # Calculate split position based on payload sizes
        if first_segment.payload_length > 0:
            # Split position is likely the size of first segment
            split_pos = first_segment.payload_length

            # Check for overlap by comparing sequence numbers
            seq_diff = second_segment.sequence_num - first_segment.sequence_num
            expected_seq_diff = first_segment.payload_length
            overlap = max(0, expected_seq_diff - seq_diff)

            return split_pos, overlap

        return None, 0

    def _detect_fooling_methods(self, pattern: FakeDisorderPattern) -> List[str]:
        """Detect fooling methods from fake disorder pattern."""
        methods = []

        if pattern.checksum_corruption:
            methods.append("badsum")

        # Check for sequence manipulation
        if pattern.fake_packet.sequence_num == 0:
            methods.append("badseq")

        # Check for TCP options manipulation (simplified)
        if len(pattern.fake_packet.raw_data) > 60:  # Likely has TCP options
            methods.append("md5sig")

        return methods

    def _detect_split_pattern(
        self, packets: List[PacketInfo]
    ) -> Optional[Dict[str, Any]]:
        """Detect simple split pattern."""
        client_hello_packets = [p for p in packets if p.is_client_hello]
        if not client_hello_packets:
            return None

        # Look for split ClientHello
        for packet in client_hello_packets:
            if packet.payload_length < 100:  # Likely split
                return {"position": packet.payload_length}

        return None

    def _detect_disorder_pattern(
        self, packets: List[PacketInfo]
    ) -> Optional[Dict[str, Any]]:
        """Detect disorder pattern."""
        # Look for out-of-order packets
        for i in range(1, len(packets)):
            if (
                packets[i].sequence_num < packets[i - 1].sequence_num
                and packets[i].src_ip == packets[i - 1].src_ip
            ):
                return {"detected": True}

        return None

    def _calculate_confidence(
        self, packets: List[PacketInfo], config: StrategyConfig
    ) -> float:
        """Calculate confidence score for detected strategy."""
        if not config.dpi_desync:
            return 0.0

        confidence = 0.5  # Base confidence

        # Increase confidence based on clear patterns
        if config.has_strategy("fake") and config.ttl and config.ttl <= 5:
            confidence += 0.2

        if config.split_pos and 1 <= config.split_pos <= 10:
            confidence += 0.2

        if config.fooling:
            confidence += 0.1

        return min(1.0, confidence)

    def compare_strategies(
        self, recon_config: StrategyConfig, zapret_config: StrategyConfig
    ) -> StrategyComparison:
        """Compare two strategy configurations and identify differences."""
        differences = []

        # Compare strategy types
        if recon_config.dpi_desync != zapret_config.dpi_desync:
            differences.append(
                StrategyDifference(
                    parameter="dpi_desync",
                    recon_value=recon_config.dpi_desync,
                    zapret_value=zapret_config.dpi_desync,
                    impact_level="CRITICAL",
                    description="Different strategy types will result in different packet sequences",
                )
            )

        # Compare split position
        if recon_config.split_pos != zapret_config.split_pos:
            impact = (
                "CRITICAL"
                if abs((recon_config.split_pos or 0) - (zapret_config.split_pos or 0))
                > 2
                else "HIGH"
            )
            differences.append(
                StrategyDifference(
                    parameter="split_pos",
                    recon_value=recon_config.split_pos,
                    zapret_value=zapret_config.split_pos,
                    impact_level=impact,
                    description="Different split positions will affect packet segmentation",
                )
            )

        # Compare split overlap
        if recon_config.split_seqovl != zapret_config.split_seqovl:
            differences.append(
                StrategyDifference(
                    parameter="split_seqovl",
                    recon_value=recon_config.split_seqovl,
                    zapret_value=zapret_config.split_seqovl,
                    impact_level="HIGH",
                    description="Different overlap sizes will affect sequence numbers",
                )
            )

        # Compare TTL
        if recon_config.get_effective_ttl() != zapret_config.get_effective_ttl():
            differences.append(
                StrategyDifference(
                    parameter="ttl",
                    recon_value=recon_config.get_effective_ttl(),
                    zapret_value=zapret_config.get_effective_ttl(),
                    impact_level="CRITICAL",
                    description="Different TTL values will affect fake packet behavior",
                )
            )

        # Compare fooling methods
        recon_fooling = set(recon_config.fooling)
        zapret_fooling = set(zapret_config.fooling)

        if recon_fooling != zapret_fooling:
            missing_methods = zapret_fooling - recon_fooling
            extra_methods = recon_fooling - zapret_fooling

            if missing_methods:
                differences.append(
                    StrategyDifference(
                        parameter="fooling_missing",
                        recon_value=list(recon_fooling),
                        zapret_value=list(zapret_fooling),
                        impact_level="HIGH",
                        description=f"Missing fooling methods: {', '.join(missing_methods)}",
                    )
                )

            if extra_methods:
                differences.append(
                    StrategyDifference(
                        parameter="fooling_extra",
                        recon_value=list(recon_fooling),
                        zapret_value=list(zapret_fooling),
                        impact_level="MEDIUM",
                        description=f"Extra fooling methods: {', '.join(extra_methods)}",
                    )
                )

        # Compare fake packet parameters
        if recon_config.fake_tls != zapret_config.fake_tls:
            differences.append(
                StrategyDifference(
                    parameter="fake_tls",
                    recon_value=recon_config.fake_tls,
                    zapret_value=zapret_config.fake_tls,
                    impact_level="MEDIUM",
                    description="Different fake TLS packets may affect DPI detection",
                )
            )

        return StrategyComparison(
            recon_config=recon_config,
            zapret_config=zapret_config,
            differences=differences,
        )

    def validate_strategy_parameters(self, config: StrategyConfig) -> Dict[str, Any]:
        """Validate strategy parameters for correctness."""
        validation_result = {"valid": True, "warnings": [], "errors": []}

        # Validate TTL
        if config.ttl is not None:
            if config.ttl < 1 or config.ttl > 255:
                validation_result["errors"].append(f"Invalid TTL value: {config.ttl}")
                validation_result["valid"] = False
            elif config.ttl > 10 and config.has_strategy("fake"):
                validation_result["warnings"].append(
                    f"High TTL ({config.ttl}) for fake strategy may not be effective"
                )

        # Validate split position
        if config.split_pos is not None:
            if config.split_pos < 1:
                validation_result["errors"].append(
                    f"Invalid split position: {config.split_pos}"
                )
                validation_result["valid"] = False
            elif config.split_pos > 100:
                validation_result["warnings"].append(
                    f"Large split position ({config.split_pos}) may be ineffective"
                )

        # Validate strategy combinations
        if config.has_strategy("fake") and not config.fooling:
            validation_result["warnings"].append(
                "Fake strategy without fooling methods may be ineffective"
            )

        if config.has_strategy("fakeddisorder") and config.split_pos is None:
            validation_result["errors"].append(
                "Fake disorder strategy requires split_pos parameter"
            )
            validation_result["valid"] = False

        return validation_result

    def extract_effective_parameters(self, packets: List[PacketInfo]) -> Dict[str, Any]:
        """Extract effective parameters actually used in packet sequence."""
        params = {}

        if not packets:
            return params

        # Extract TTL values
        ttl_values = [p.ttl for p in packets if p.ttl > 0]
        if ttl_values:
            params["ttl_range"] = (min(ttl_values), max(ttl_values))
            params["unique_ttls"] = list(set(ttl_values))

        # Extract timing patterns
        if len(packets) > 1:
            timing_gaps = []
            for i in range(1, len(packets)):
                gap = packets[i].timestamp - packets[i - 1].timestamp
                timing_gaps.append(gap)
            params["timing_gaps"] = timing_gaps
            params["avg_timing_gap"] = sum(timing_gaps) / len(timing_gaps)

        # Extract payload patterns
        payload_sizes = [p.payload_length for p in packets if p.payload_length > 0]
        if payload_sizes:
            params["payload_sizes"] = payload_sizes
            params["total_payload"] = sum(payload_sizes)

        # Extract connection info
        connections = set()
        for packet in packets:
            connections.add(packet.get_connection_key())
        params["unique_connections"] = len(connections)

        # Extract fake packet indicators
        fake_packets = [p for p in packets if p.is_fake_packet()]
        params["fake_packet_count"] = len(fake_packets)

        if fake_packets:
            params["fake_packet_ttls"] = [p.ttl for p in fake_packets]
            params["fake_packet_checksums"] = [p.checksum_valid for p in fake_packets]

        return params
