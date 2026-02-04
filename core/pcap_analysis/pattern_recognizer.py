"""
Pattern recognition and anomaly detection for DPI evasion analysis.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import statistics
from .packet_info import PacketInfo
from .strategy_config import StrategyConfig


class PacketRole(Enum):
    """Role of packet in DPI bypass sequence."""

    FAKE_PACKET = "fake"
    REAL_PACKET = "real"
    SPLIT_SEGMENT = "split_segment"
    DISORDER_SEGMENT = "disorder_segment"
    NORMAL_TRAFFIC = "normal"
    UNKNOWN = "unknown"


class EvasionTechnique(Enum):
    """DPI evasion techniques."""

    TTL_MANIPULATION = "ttl_manipulation"
    CHECKSUM_CORRUPTION = "checksum_corruption"
    SEQUENCE_MANIPULATION = "sequence_manipulation"
    PAYLOAD_SPLITTING = "payload_splitting"
    PACKET_DISORDER = "packet_disorder"
    FAKE_PACKET_INJECTION = "fake_packet_injection"
    TIMING_MANIPULATION = "timing_manipulation"


class AnomalyType(Enum):
    """Types of anomalies in packet patterns."""

    MISSING_FAKE_PACKET = "missing_fake_packet"
    INCORRECT_TTL = "incorrect_ttl"
    VALID_CHECKSUM_IN_FAKE = "valid_checksum_in_fake"
    WRONG_SPLIT_POSITION = "wrong_split_position"
    INCORRECT_SEQUENCE_OVERLAP = "incorrect_sequence_overlap"
    TIMING_DEVIATION = "timing_deviation"
    UNEXPECTED_PACKET_ORDER = "unexpected_packet_order"
    MISSING_FOOLING_METHOD = "missing_fooling_method"
    EXTRA_PACKETS = "extra_packets"


@dataclass
class EvasionPattern:
    """Represents a detected DPI evasion pattern."""

    technique: EvasionTechnique
    packets: List[PacketInfo]
    confidence: float  # 0.0 to 1.0
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Post-initialization validation."""
        self.confidence = max(0.0, min(1.0, self.confidence))


@dataclass
class FakePacketPattern:
    """Pattern for fake packet detection."""

    packet: PacketInfo
    is_fake: bool
    fake_indicators: List[str]
    confidence: float
    expected_ttl: Optional[int] = None
    expected_checksum_invalid: bool = False

    def get_fake_score(self) -> float:
        """Calculate fake packet score based on indicators."""
        if not self.fake_indicators:
            return 0.0

        # Weight different indicators
        weights = {
            "low_ttl": 0.4,
            "bad_checksum": 0.3,
            "zero_sequence": 0.2,
            "empty_payload_with_psh": 0.1,
            "timing_anomaly": 0.1,
        }

        score = 0.0
        for indicator in self.fake_indicators:
            score += weights.get(indicator, 0.05)

        return min(1.0, score)


@dataclass
class SplitPattern:
    """Pattern for payload splitting detection."""

    segments: List[PacketInfo]
    split_position: int
    overlap_size: int
    total_payload_size: int
    is_valid_split: bool
    confidence: float

    def validate_split(self, expected_pos: Optional[int] = None) -> bool:
        """Validate if split matches expected parameters."""
        if expected_pos is not None:
            return abs(self.split_position - expected_pos) <= 1
        return self.is_valid_split


@dataclass
class Anomaly:
    """Represents an anomaly in packet patterns."""

    anomaly_type: AnomalyType
    description: str
    affected_packets: List[PacketInfo]
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    confidence: float
    expected_behavior: str
    actual_behavior: str
    fix_suggestion: str = ""

    def __post_init__(self):
        """Post-initialization processing."""
        if not self.fix_suggestion:
            self.fix_suggestion = (
                f"Adjust implementation to match expected behavior: {self.expected_behavior}"
            )


class PatternRecognizer:
    """Pattern recognition and anomaly detection for DPI evasion analysis."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize pattern recognizer with configuration."""
        self.config = config or {}

        # Detection thresholds
        self.fake_ttl_threshold = self.config.get("fake_ttl_threshold", 5)
        self.timing_anomaly_threshold = self.config.get("timing_anomaly_threshold", 0.1)  # seconds
        self.confidence_threshold = self.config.get("confidence_threshold", 0.7)

        # Pattern cache
        self._pattern_cache: Dict[str, List[EvasionPattern]] = {}
        self._anomaly_cache: Dict[str, List[Anomaly]] = {}

    def recognize_dpi_evasion_patterns(self, packets: List[PacketInfo]) -> List[EvasionPattern]:
        """Recognize DPI evasion patterns in packet sequence."""
        if not packets:
            return []

        # Generate cache key
        cache_key = self._generate_cache_key(packets)
        if cache_key in self._pattern_cache:
            return self._pattern_cache[cache_key]

        patterns = []

        # Detect different evasion techniques
        patterns.extend(self._detect_ttl_manipulation(packets))
        patterns.extend(self._detect_checksum_corruption(packets))
        patterns.extend(self._detect_fake_packet_injection(packets))
        patterns.extend(self._detect_payload_splitting(packets))
        patterns.extend(self._detect_packet_disorder(packets))
        patterns.extend(self._detect_sequence_manipulation(packets))
        patterns.extend(self._detect_timing_manipulation(packets))

        # Cache results
        self._pattern_cache[cache_key] = patterns

        return patterns

    def detect_fake_packet_patterns(self, packets: List[PacketInfo]) -> List[FakePacketPattern]:
        """Detect fake packet patterns with specific characteristics."""
        fake_patterns = []

        for packet in packets:
            fake_indicators = []
            confidence = 0.0

            # Check TTL (TTL=3 is common for fake packets)
            if packet.ttl <= self.fake_ttl_threshold:
                fake_indicators.append("low_ttl")
                confidence += 0.4

            # Check checksum validity
            if not packet.checksum_valid:
                fake_indicators.append("bad_checksum")
                confidence += 0.3

            # Check for zero sequence number
            if packet.sequence_num == 0:
                fake_indicators.append("zero_sequence")
                confidence += 0.2

            # Check for empty payload with PSH flag
            if packet.payload_length == 0 and "PSH" in packet.flags:
                fake_indicators.append("empty_payload_with_psh")
                confidence += 0.1

            # Create fake packet pattern
            is_fake = len(fake_indicators) >= 2 or confidence >= 0.5

            fake_pattern = FakePacketPattern(
                packet=packet,
                is_fake=is_fake,
                fake_indicators=fake_indicators,
                confidence=min(1.0, confidence),
                expected_ttl=3,
                expected_checksum_invalid=True,
            )

            fake_patterns.append(fake_pattern)

        return fake_patterns

    def detect_real_packet_patterns(self, packets: List[PacketInfo]) -> List[PacketInfo]:
        """Detect real packet patterns with correct characteristics."""
        real_packets = []

        for packet in packets:
            # Real packet indicators
            is_real = (
                packet.ttl > self.fake_ttl_threshold
                and packet.checksum_valid
                and packet.sequence_num > 0
                and (packet.payload_length > 0 or "SYN" in packet.flags or "FIN" in packet.flags)
            )

            if is_real:
                real_packets.append(packet)

        return real_packets

    def detect_anomalies(
        self,
        recon_patterns: List[EvasionPattern],
        zapret_patterns: List[EvasionPattern],
        recon_packets: List[PacketInfo],
        zapret_packets: List[PacketInfo],
    ) -> List[Anomaly]:
        """Detect anomalies by comparing recon and zapret patterns."""
        anomalies = []

        # Compare pattern counts
        anomalies.extend(self._detect_missing_patterns(recon_patterns, zapret_patterns))

        # Compare fake packet patterns
        anomalies.extend(self._detect_fake_packet_anomalies(recon_packets, zapret_packets))

        # Compare split patterns
        anomalies.extend(self._detect_split_anomalies(recon_packets, zapret_packets))

        # Compare timing patterns
        anomalies.extend(self._detect_timing_anomalies(recon_packets, zapret_packets))

        # Compare sequence patterns
        anomalies.extend(self._detect_sequence_anomalies(recon_packets, zapret_packets))

        return anomalies

    def classify_packet_roles(self, packets: List[PacketInfo]) -> Dict[int, PacketRole]:
        """Classify the role of each packet in the DPI bypass sequence."""
        roles = {}

        # Detect fake packets
        fake_patterns = self.detect_fake_packet_patterns(packets)
        fake_packet_indices = {i for i, fp in enumerate(fake_patterns) if fp.is_fake}

        # Detect split segments
        split_patterns = self._detect_payload_splitting(packets)
        split_packet_indices = set()
        for pattern in split_patterns:
            if pattern.technique == EvasionTechnique.PAYLOAD_SPLITTING:
                for packet in pattern.packets:
                    try:
                        idx = packets.index(packet)
                        split_packet_indices.add(idx)
                    except ValueError:
                        continue

        # Classify each packet
        for i, packet in enumerate(packets):
            if i in fake_packet_indices:
                roles[i] = PacketRole.FAKE_PACKET
            elif i in split_packet_indices:
                roles[i] = PacketRole.SPLIT_SEGMENT
            elif packet.is_client_hello:
                roles[i] = PacketRole.REAL_PACKET
            elif packet.payload_length > 0:
                roles[i] = PacketRole.REAL_PACKET
            elif "SYN" in packet.flags or "FIN" in packet.flags:
                roles[i] = PacketRole.NORMAL_TRAFFIC
            else:
                roles[i] = PacketRole.UNKNOWN

        return roles

    def identify_bypass_techniques(self, patterns: List[EvasionPattern]) -> List[EvasionTechnique]:
        """Identify bypass techniques from detected patterns."""
        techniques = set()

        for pattern in patterns:
            if pattern.confidence >= self.confidence_threshold:
                techniques.add(pattern.technique)

        return list(techniques)

    def validate_zapret_compliance(
        self, packets: List[PacketInfo], expected_strategy: StrategyConfig
    ) -> float:
        """Validate compliance with expected zapret behavior."""
        if not packets or not expected_strategy:
            return 0.0

        compliance_score = 0.0
        total_checks = 0

        # Check TTL compliance
        if expected_strategy.ttl:
            fake_patterns = self.detect_fake_packet_patterns(packets)
            fake_packets = [fp.packet for fp in fake_patterns if fp.is_fake]

            if fake_packets:
                ttl_compliance = sum(
                    1 for p in fake_packets if p.ttl == expected_strategy.ttl
                ) / len(fake_packets)
                compliance_score += ttl_compliance
                total_checks += 1

        # Check fooling method compliance
        if expected_strategy.fooling:
            fooling_compliance = self._check_fooling_compliance(packets, expected_strategy.fooling)
            compliance_score += fooling_compliance
            total_checks += 1

        # Check split position compliance
        if expected_strategy.split_pos:
            split_compliance = self._check_split_compliance(packets, expected_strategy.split_pos)
            compliance_score += split_compliance
            total_checks += 1

        # Check strategy type compliance
        if expected_strategy.dpi_desync:
            strategy_compliance = self._check_strategy_compliance(packets, expected_strategy)
            compliance_score += strategy_compliance
            total_checks += 1

        return compliance_score / max(1, total_checks)

    def _detect_ttl_manipulation(self, packets: List[PacketInfo]) -> List[EvasionPattern]:
        """Detect TTL manipulation patterns."""
        patterns = []

        # Group packets by TTL
        ttl_groups = {}
        for packet in packets:
            ttl = packet.ttl
            if ttl not in ttl_groups:
                ttl_groups[ttl] = []
            ttl_groups[ttl].append(packet)

        # Look for low TTL patterns (fake packets)
        for ttl, ttl_packets in ttl_groups.items():
            if ttl <= self.fake_ttl_threshold and len(ttl_packets) > 0:
                confidence = min(1.0, len(ttl_packets) * 0.3)

                pattern = EvasionPattern(
                    technique=EvasionTechnique.TTL_MANIPULATION,
                    packets=ttl_packets,
                    confidence=confidence,
                    description=f"TTL manipulation detected: {len(ttl_packets)} packets with TTL={ttl}",
                    parameters={"ttl": ttl, "packet_count": len(ttl_packets)},
                )
                patterns.append(pattern)

        return patterns

    def _detect_checksum_corruption(self, packets: List[PacketInfo]) -> List[EvasionPattern]:
        """Detect checksum corruption patterns."""
        patterns = []

        bad_checksum_packets = [p for p in packets if not p.checksum_valid]

        if bad_checksum_packets:
            confidence = min(1.0, len(bad_checksum_packets) * 0.4)

            pattern = EvasionPattern(
                technique=EvasionTechnique.CHECKSUM_CORRUPTION,
                packets=bad_checksum_packets,
                confidence=confidence,
                description=f"Checksum corruption detected in {len(bad_checksum_packets)} packets",
                parameters={"corrupted_count": len(bad_checksum_packets)},
            )
            patterns.append(pattern)

        return patterns

    def _detect_fake_packet_injection(self, packets: List[PacketInfo]) -> List[EvasionPattern]:
        """Detect fake packet injection patterns."""
        patterns = []

        fake_patterns = self.detect_fake_packet_patterns(packets)
        fake_packets = [fp.packet for fp in fake_patterns if fp.is_fake]

        if fake_packets:
            confidence = statistics.mean([fp.confidence for fp in fake_patterns if fp.is_fake])

            pattern = EvasionPattern(
                technique=EvasionTechnique.FAKE_PACKET_INJECTION,
                packets=fake_packets,
                confidence=confidence,
                description=f"Fake packet injection detected: {len(fake_packets)} fake packets",
                parameters={"fake_count": len(fake_packets)},
            )
            patterns.append(pattern)

        return patterns

    def _detect_payload_splitting(self, packets: List[PacketInfo]) -> List[EvasionPattern]:
        """Detect payload splitting patterns."""
        patterns = []

        # Look for TLS ClientHello packets that might be split
        client_hello_packets = [p for p in packets if p.is_client_hello]

        for ch_packet in client_hello_packets:
            # Look for subsequent packets that might be split segments
            ch_index = packets.index(ch_packet)
            subsequent_packets = packets[ch_index : ch_index + 5]  # Look at next few packets

            # Check for split pattern
            split_segments = []
            total_payload = 0

            for packet in subsequent_packets:
                if (
                    packet.src_ip == ch_packet.src_ip
                    and packet.dst_ip == ch_packet.dst_ip
                    and packet.src_port == ch_packet.src_port
                    and packet.dst_port == ch_packet.dst_port
                    and packet.payload_length > 0
                ):

                    split_segments.append(packet)
                    total_payload += packet.payload_length

            if len(split_segments) > 1:
                confidence = min(1.0, len(split_segments) * 0.3)

                pattern = EvasionPattern(
                    technique=EvasionTechnique.PAYLOAD_SPLITTING,
                    packets=split_segments,
                    confidence=confidence,
                    description=f"Payload splitting detected: {len(split_segments)} segments, {total_payload} bytes total",
                    parameters={
                        "segment_count": len(split_segments),
                        "total_payload": total_payload,
                        "split_position": (
                            split_segments[0].payload_length if split_segments else 0
                        ),
                    },
                )
                patterns.append(pattern)

        return patterns

    def _detect_packet_disorder(self, packets: List[PacketInfo]) -> List[EvasionPattern]:
        """Detect packet disorder patterns."""
        patterns = []

        # Group packets by connection
        connections = {}
        for packet in packets:
            conn_key = packet.get_connection_key()
            if conn_key not in connections:
                connections[conn_key] = []
            connections[conn_key].append(packet)

        # Check for sequence number disorders
        for conn_key, conn_packets in connections.items():
            if len(conn_packets) < 2:
                continue

            # Sort by timestamp
            conn_packets.sort(key=lambda p: p.timestamp)

            # Check for sequence number disorders
            disorder_count = 0
            for i in range(1, len(conn_packets)):
                prev_seq = conn_packets[i - 1].sequence_num
                curr_seq = conn_packets[i].sequence_num

                # Skip zero sequence numbers (likely fake packets)
                if prev_seq == 0 or curr_seq == 0:
                    continue

                # Check if sequence numbers are not in order
                if curr_seq < prev_seq:
                    disorder_count += 1

            if disorder_count > 0:
                confidence = min(1.0, disorder_count * 0.4)

                pattern = EvasionPattern(
                    technique=EvasionTechnique.PACKET_DISORDER,
                    packets=conn_packets,
                    confidence=confidence,
                    description=f"Packet disorder detected: {disorder_count} out-of-order packets",
                    parameters={"disorder_count": disorder_count},
                )
                patterns.append(pattern)

        return patterns

    def _detect_sequence_manipulation(self, packets: List[PacketInfo]) -> List[EvasionPattern]:
        """Detect sequence number manipulation patterns."""
        patterns = []

        # Look for unusual sequence number patterns
        zero_seq_packets = [p for p in packets if p.sequence_num == 0 and p.payload_length > 0]

        if zero_seq_packets:
            confidence = min(1.0, len(zero_seq_packets) * 0.5)

            pattern = EvasionPattern(
                technique=EvasionTechnique.SEQUENCE_MANIPULATION,
                packets=zero_seq_packets,
                confidence=confidence,
                description=f"Sequence manipulation detected: {len(zero_seq_packets)} packets with zero sequence",
                parameters={"zero_seq_count": len(zero_seq_packets)},
            )
            patterns.append(pattern)

        return patterns

    def _detect_timing_manipulation(self, packets: List[PacketInfo]) -> List[EvasionPattern]:
        """Detect timing manipulation patterns."""
        patterns = []

        if len(packets) < 2:
            return patterns

        # Calculate inter-packet delays
        delays = []
        for i in range(1, len(packets)):
            delay = packets[i].timestamp - packets[i - 1].timestamp
            delays.append(delay)

        if not delays:
            return patterns

        # Look for unusual timing patterns
        mean_delay = statistics.mean(delays)

        # Find packets with unusual timing
        timing_anomaly_packets = []
        for i, delay in enumerate(delays):
            if abs(delay - mean_delay) > self.timing_anomaly_threshold:
                timing_anomaly_packets.extend([packets[i], packets[i + 1]])

        if timing_anomaly_packets:
            confidence = min(1.0, len(timing_anomaly_packets) * 0.2)

            pattern = EvasionPattern(
                technique=EvasionTechnique.TIMING_MANIPULATION,
                packets=timing_anomaly_packets,
                confidence=confidence,
                description=f"Timing manipulation detected: {len(timing_anomaly_packets)} packets with unusual timing",
                parameters={
                    "mean_delay": mean_delay,
                    "anomaly_threshold": self.timing_anomaly_threshold,
                    "anomaly_count": len(timing_anomaly_packets),
                },
            )
            patterns.append(pattern)

        return patterns

    def _detect_missing_patterns(
        self,
        recon_patterns: List[EvasionPattern],
        zapret_patterns: List[EvasionPattern],
    ) -> List[Anomaly]:
        """Detect missing patterns in recon compared to zapret."""
        anomalies = []

        # Group patterns by technique
        recon_techniques = {p.technique for p in recon_patterns}
        zapret_techniques = {p.technique for p in zapret_patterns}

        # Find missing techniques
        missing_techniques = zapret_techniques - recon_techniques

        for technique in missing_techniques:
            zapret_pattern = next(p for p in zapret_patterns if p.technique == technique)

            anomaly = Anomaly(
                anomaly_type=(
                    AnomalyType.MISSING_FAKE_PACKET
                    if technique == EvasionTechnique.FAKE_PACKET_INJECTION
                    else AnomalyType.EXTRA_PACKETS
                ),
                description=f"Missing {technique.value} pattern in recon",
                affected_packets=[],
                severity="CRITICAL",
                confidence=0.9,
                expected_behavior=f"Should implement {technique.value}",
                actual_behavior="Pattern not detected",
                fix_suggestion=f"Implement {technique.value} in recon to match zapret behavior",
            )
            anomalies.append(anomaly)

        return anomalies

    def _detect_fake_packet_anomalies(
        self, recon_packets: List[PacketInfo], zapret_packets: List[PacketInfo]
    ) -> List[Anomaly]:
        """Detect anomalies in fake packet patterns."""
        anomalies = []

        recon_fake_patterns = self.detect_fake_packet_patterns(recon_packets)
        zapret_fake_patterns = self.detect_fake_packet_patterns(zapret_packets)

        recon_fake_packets = [fp.packet for fp in recon_fake_patterns if fp.is_fake]
        zapret_fake_packets = [fp.packet for fp in zapret_fake_patterns if fp.is_fake]

        # Check for missing fake packets
        if len(zapret_fake_packets) > len(recon_fake_packets):
            anomaly = Anomaly(
                anomaly_type=AnomalyType.MISSING_FAKE_PACKET,
                description=f"Missing fake packets: zapret has {len(zapret_fake_packets)}, recon has {len(recon_fake_packets)}",
                affected_packets=recon_fake_packets,
                severity="CRITICAL",
                confidence=0.9,
                expected_behavior=f"Should have {len(zapret_fake_packets)} fake packets",
                actual_behavior=f"Has {len(recon_fake_packets)} fake packets",
                fix_suggestion="Add missing fake packet injection in recon",
            )
            anomalies.append(anomaly)

        # Check TTL values in fake packets
        if recon_fake_packets and zapret_fake_packets:
            recon_ttls = [p.ttl for p in recon_fake_packets]
            zapret_ttls = [p.ttl for p in zapret_fake_packets]

            if recon_ttls and zapret_ttls:
                recon_avg_ttl = statistics.mean(recon_ttls)
                zapret_avg_ttl = statistics.mean(zapret_ttls)

                if abs(recon_avg_ttl - zapret_avg_ttl) > 1:
                    anomaly = Anomaly(
                        anomaly_type=AnomalyType.INCORRECT_TTL,
                        description=f"TTL mismatch in fake packets: recon avg={recon_avg_ttl:.1f}, zapret avg={zapret_avg_ttl:.1f}",
                        affected_packets=recon_fake_packets,
                        severity="HIGH",
                        confidence=0.8,
                        expected_behavior=f"Fake packets should have TTL={zapret_avg_ttl:.0f}",
                        actual_behavior=f"Fake packets have TTL={recon_avg_ttl:.0f}",
                        fix_suggestion=f"Set fake packet TTL to {zapret_avg_ttl:.0f}",
                    )
                    anomalies.append(anomaly)

        return anomalies

    def _detect_split_anomalies(
        self, recon_packets: List[PacketInfo], zapret_packets: List[PacketInfo]
    ) -> List[Anomaly]:
        """Detect anomalies in payload splitting patterns."""
        anomalies = []

        recon_split_patterns = self._detect_payload_splitting(recon_packets)
        zapret_split_patterns = self._detect_payload_splitting(zapret_packets)

        # Compare split positions
        if recon_split_patterns and zapret_split_patterns:
            recon_split_pos = recon_split_patterns[0].parameters.get("split_position", 0)
            zapret_split_pos = zapret_split_patterns[0].parameters.get("split_position", 0)

            if abs(recon_split_pos - zapret_split_pos) > 1:
                anomaly = Anomaly(
                    anomaly_type=AnomalyType.WRONG_SPLIT_POSITION,
                    description=f"Split position mismatch: recon={recon_split_pos}, zapret={zapret_split_pos}",
                    affected_packets=recon_split_patterns[0].packets,
                    severity="HIGH",
                    confidence=0.8,
                    expected_behavior=f"Should split at position {zapret_split_pos}",
                    actual_behavior=f"Splits at position {recon_split_pos}",
                    fix_suggestion=f"Adjust split position to {zapret_split_pos}",
                )
                anomalies.append(anomaly)

        return anomalies

    def _detect_timing_anomalies(
        self, recon_packets: List[PacketInfo], zapret_packets: List[PacketInfo]
    ) -> List[Anomaly]:
        """Detect timing anomalies between recon and zapret."""
        anomalies = []

        if len(recon_packets) < 2 or len(zapret_packets) < 2:
            return anomalies

        # Calculate timing patterns
        recon_delays = [
            recon_packets[i].timestamp - recon_packets[i - 1].timestamp
            for i in range(1, len(recon_packets))
        ]
        zapret_delays = [
            zapret_packets[i].timestamp - zapret_packets[i - 1].timestamp
            for i in range(1, len(zapret_packets))
        ]

        if recon_delays and zapret_delays:
            recon_avg_delay = statistics.mean(recon_delays)
            zapret_avg_delay = statistics.mean(zapret_delays)

            if abs(recon_avg_delay - zapret_avg_delay) > self.timing_anomaly_threshold:
                anomaly = Anomaly(
                    anomaly_type=AnomalyType.TIMING_DEVIATION,
                    description=f"Timing deviation: recon avg={recon_avg_delay:.3f}s, zapret avg={zapret_avg_delay:.3f}s",
                    affected_packets=recon_packets,
                    severity="MEDIUM",
                    confidence=0.7,
                    expected_behavior=f"Average delay should be ~{zapret_avg_delay:.3f}s",
                    actual_behavior=f"Average delay is {recon_avg_delay:.3f}s",
                    fix_suggestion="Adjust packet timing to match zapret behavior",
                )
                anomalies.append(anomaly)

        return anomalies

    def _detect_sequence_anomalies(
        self, recon_packets: List[PacketInfo], zapret_packets: List[PacketInfo]
    ) -> List[Anomaly]:
        """Detect sequence number anomalies."""
        anomalies = []

        # Compare sequence number patterns
        recon_zero_seq = [p for p in recon_packets if p.sequence_num == 0]
        zapret_zero_seq = [p for p in zapret_packets if p.sequence_num == 0]

        if len(zapret_zero_seq) > len(recon_zero_seq):
            anomaly = Anomaly(
                anomaly_type=AnomalyType.INCORRECT_SEQUENCE_OVERLAP,
                description=f"Missing zero sequence packets: zapret has {len(zapret_zero_seq)}, recon has {len(recon_zero_seq)}",
                affected_packets=recon_zero_seq,
                severity="HIGH",
                confidence=0.8,
                expected_behavior=f"Should have {len(zapret_zero_seq)} packets with zero sequence",
                actual_behavior=f"Has {len(recon_zero_seq)} packets with zero sequence",
                fix_suggestion="Add sequence number manipulation to match zapret",
            )
            anomalies.append(anomaly)

        return anomalies

    def _check_fooling_compliance(
        self, packets: List[PacketInfo], fooling_methods: List[str]
    ) -> float:
        """Check compliance with fooling methods."""
        if not fooling_methods:
            return 1.0

        compliance_score = 0.0

        # Check for badsum compliance
        if "badsum" in fooling_methods:
            fake_patterns = self.detect_fake_packet_patterns(packets)
            fake_packets = [fp.packet for fp in fake_patterns if fp.is_fake]

            if fake_packets:
                bad_checksum_count = sum(1 for p in fake_packets if not p.checksum_valid)
                compliance_score += bad_checksum_count / len(fake_packets)
            else:
                compliance_score += 0.5  # Partial compliance if no fake packets detected

        # Check for badseq compliance
        if "badseq" in fooling_methods:
            zero_seq_packets = [p for p in packets if p.sequence_num == 0]
            if zero_seq_packets:
                compliance_score += 1.0
            else:
                compliance_score += 0.5

        return compliance_score / len(fooling_methods)

    def _check_split_compliance(self, packets: List[PacketInfo], expected_split_pos: int) -> float:
        """Check compliance with split position."""
        split_patterns = self._detect_payload_splitting(packets)

        if not split_patterns:
            return 0.0

        # Check if any split pattern matches expected position
        for pattern in split_patterns:
            actual_split_pos = pattern.parameters.get("split_position", 0)
            if abs(actual_split_pos - expected_split_pos) <= 1:
                return 1.0

        return 0.0

    def _check_strategy_compliance(
        self, packets: List[PacketInfo], strategy: StrategyConfig
    ) -> float:
        """Check overall strategy compliance."""
        compliance_factors = []

        # Check for fake packet presence if strategy includes fake
        if strategy.has_strategy("fake"):
            fake_patterns = self.detect_fake_packet_patterns(packets)
            fake_count = sum(1 for fp in fake_patterns if fp.is_fake)
            compliance_factors.append(1.0 if fake_count > 0 else 0.0)

        # Check for disorder if strategy includes disorder
        if strategy.has_strategy("fakeddisorder") or strategy.disorder:
            disorder_patterns = self._detect_packet_disorder(packets)
            compliance_factors.append(1.0 if disorder_patterns else 0.0)

        return statistics.mean(compliance_factors) if compliance_factors else 1.0

    def _generate_cache_key(self, packets: List[PacketInfo]) -> str:
        """Generate cache key for packet sequence."""
        if not packets:
            return "empty"

        # Use packet count, first/last timestamps, and payload sizes as key
        key_parts = [
            str(len(packets)),
            f"{packets[0].timestamp:.3f}",
            f"{packets[-1].timestamp:.3f}",
            str(sum(p.payload_length for p in packets)),
        ]

        return "_".join(key_parts)
